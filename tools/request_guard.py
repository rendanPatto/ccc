#!/usr/bin/env python3
"""
request_guard.py — practical request safety helper for Claude Code autopilot loops.

This helper adds a thin, file-backed guard layer around active requests:
- preflight: scope check, safe-method gate, breaker gate, rate-limit wait
- record: audit log write + breaker state update from the response
- status: show current per-host guard state

It does not replace any existing tool. It is an optional helper for live testing.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.audit_log import AuditLog
from memory.target_profile import default_memory_dir, load_target_profile, target_filename
from scope_checker import ScopeChecker

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
FAILURE_STATUSES = {403, 429}
DEFAULT_RECON_RPS = 10.0
DEFAULT_TEST_RPS = 1.0
DEFAULT_BREAKER_THRESHOLD = 5
DEFAULT_BREAKER_COOLDOWN = 60.0


def load_runtime_config() -> dict:
    """Load optional repo-local config.json."""
    config_path = Path(BASE_DIR) / "config.json"
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def resolve_ctf_mode(explicit: bool | None = None) -> bool:
    """Resolve CTF mode from explicit override or repo config."""
    if explicit is not None:
        return explicit
    return bool(load_runtime_config().get("ctf_mode", False))


def parse_csv(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def normalize_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    if "://" in raw:
        return raw
    if raw.startswith("//"):
        return f"https:{raw}"
    return f"https://{raw.lstrip('/')}"


def parse_host(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return parsed.hostname or ""


def guard_state_path(memory_dir: str | Path, target: str) -> Path:
    return Path(memory_dir) / "guards" / target_filename(target)


def _default_host_state() -> dict:
    return {
        "last_request_ts": 0.0,
        "failures": 0,
        "tripped_until": 0.0,
        "last_error": "",
    }


def load_guard_state(memory_dir: str | Path, target: str) -> dict:
    path = guard_state_path(memory_dir, target)
    if not path.exists():
        return {"target": target, "settings": {}, "hosts": {}}

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"target": target, "settings": {}, "hosts": {}}

    hosts = {}
    for host, item in (raw.get("hosts") or {}).items():
        if not isinstance(host, str) or not isinstance(item, dict):
            continue
        hosts[host] = {
            "last_request_ts": float(item.get("last_request_ts", 0.0) or 0.0),
            "failures": max(0, int(item.get("failures", 0) or 0)),
            "tripped_until": float(item.get("tripped_until", 0.0) or 0.0),
            "last_error": str(item.get("last_error", "") or ""),
        }

    settings = {}
    raw_settings = raw.get("settings") or {}
    if isinstance(raw_settings, dict):
        for key in ("recon_rps", "test_rps", "breaker_threshold", "breaker_cooldown"):
            if key in raw_settings:
                settings[key] = raw_settings[key]

    return {"target": target, "settings": settings, "hosts": hosts}


def save_guard_state(memory_dir: str | Path, target: str, state: dict) -> Path:
    path = guard_state_path(memory_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "settings": state.get("settings", {}),
        "hosts": state.get("hosts", {}),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def _resolve_scope_lists(
    profile: dict | None,
    target: str,
    *,
    scope_domains: list[str] | None = None,
    excluded_domains: list[str] | None = None,
    excluded_classes: list[str] | None = None,
) -> tuple[list[str], list[str], list[str], str]:
    snapshot = profile.get("scope_snapshot", {}) if profile else {}
    if not isinstance(snapshot, dict):
        snapshot = {}

    if scope_domains:
        domains = scope_domains
        scope_source = "cli"
    else:
        domains = [item for item in snapshot.get("in_scope", []) if isinstance(item, str)]
        scope_source = "profile" if domains else "missing"

    if excluded_domains:
        excluded = excluded_domains
    else:
        excluded = [item for item in snapshot.get("out_of_scope", []) if isinstance(item, str)]

    if excluded_classes:
        classes = excluded_classes
    else:
        classes = [item for item in snapshot.get("excluded_classes", []) if isinstance(item, str)]

    domains = [item.strip() for item in domains if item and item.strip()]
    excluded = [item.strip() for item in excluded if item and item.strip()]
    classes = [item.strip().lower() for item in classes if item and item.strip()]

    # Lightweight fallback for the exact target only. Wildcards must still be explicit.
    if not domains and target:
        domains = [target]
        scope_source = "target_fallback"

    return domains, excluded, classes, scope_source


def build_scope_checker(
    profile: dict | None,
    target: str,
    *,
    ctf_mode: bool = False,
    scope_domains: list[str] | None = None,
    excluded_domains: list[str] | None = None,
    excluded_classes: list[str] | None = None,
) -> tuple[ScopeChecker | None, dict]:
    if ctf_mode:
        return ScopeChecker([], unrestricted=True), {
            "source": "ctf_mode",
            "domains": ["*"],
            "excluded_domains": [],
            "excluded_classes": [],
            "ctf_mode": True,
            "unrestricted": True,
        }

    domains, excluded, classes, scope_source = _resolve_scope_lists(
        profile,
        target,
        scope_domains=scope_domains,
        excluded_domains=excluded_domains,
        excluded_classes=excluded_classes,
    )
    if not domains:
        return None, {
            "source": "missing",
            "domains": [],
            "excluded_domains": excluded,
            "excluded_classes": classes,
            "ctf_mode": False,
            "unrestricted": False,
        }

    return ScopeChecker(domains, excluded, classes), {
        "source": scope_source,
        "domains": domains,
        "excluded_domains": excluded,
        "excluded_classes": classes,
        "ctf_mode": False,
        "unrestricted": False,
    }


def _resolve_settings(
    profile: dict | None,
    *,
    recon_rps: float | None = None,
    test_rps: float | None = None,
    breaker_threshold: int | None = None,
    breaker_cooldown: float | None = None,
) -> tuple[dict, dict]:
    snapshot = profile.get("scope_snapshot", {}) if profile else {}
    if not isinstance(snapshot, dict):
        snapshot = {}

    values = {}
    sources = {}
    settings_map = {
        "recon_rps": (recon_rps, snapshot.get("recon_rps"), DEFAULT_RECON_RPS),
        "test_rps": (test_rps, snapshot.get("test_rps"), DEFAULT_TEST_RPS),
        "breaker_threshold": (
            breaker_threshold,
            snapshot.get("breaker_threshold"),
            DEFAULT_BREAKER_THRESHOLD,
        ),
        "breaker_cooldown": (
            breaker_cooldown,
            snapshot.get("breaker_cooldown"),
            DEFAULT_BREAKER_COOLDOWN,
        ),
    }

    for key, (cli_value, profile_value, default_value) in settings_map.items():
        if cli_value is not None:
            values[key] = cli_value
            sources[key] = "cli"
        elif profile_value is not None:
            values[key] = profile_value
            sources[key] = "profile"
        else:
            values[key] = default_value
            sources[key] = "default"

    values["recon_rps"] = max(float(values["recon_rps"]), 0.1)
    values["test_rps"] = max(float(values["test_rps"]), 0.1)
    values["breaker_threshold"] = max(int(values["breaker_threshold"]), 1)
    values["breaker_cooldown"] = max(float(values["breaker_cooldown"]), 1.0)
    return values, sources


def _interval_seconds(settings: dict, is_recon: bool) -> float:
    rate = settings["recon_rps"] if is_recon else settings["test_rps"]
    return 1.0 / rate


def _iso_utc(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _remaining_seconds(tripped_until: float, now_ts: float) -> float:
    return round(max(0.0, float(tripped_until or 0.0) - now_ts), 3)


def _breaker_summary(host: str, host_state: dict, threshold: int, now_ts: float) -> dict:
    return {
        "host": host,
        "failures": int(host_state.get("failures", 0) or 0),
        "threshold": threshold,
        "tripped": _remaining_seconds(host_state.get("tripped_until", 0.0), now_ts) > 0,
        "remaining_seconds": _remaining_seconds(host_state.get("tripped_until", 0.0), now_ts),
        "last_error": host_state.get("last_error", "") or "",
    }


def _is_breaker_failure(response_status: int | None, error: str | None) -> bool:
    if response_status in FAILURE_STATUSES:
        return True

    if not error:
        return False

    lowered = error.lower()
    return any(token in lowered for token in ("timeout", "timed out", "connection", "tls", "ssl"))


def preflight_request(
    *,
    memory_dir: str | Path,
    target: str,
    url: str,
    method: str,
    session_id: str | None = None,
    vuln_class: str | None = None,
    mode: str = "normal",
    is_recon: bool = False,
    scope_domains: list[str] | None = None,
    excluded_domains: list[str] | None = None,
    excluded_classes: list[str] | None = None,
    recon_rps: float | None = None,
    test_rps: float | None = None,
    breaker_threshold: int | None = None,
    breaker_cooldown: float | None = None,
    ctf_mode: bool | None = None,
    sleep: bool = True,
    now_ts: float | None = None,
) -> dict:
    """Run request preflight checks and optionally wait for the rate limit slot."""
    normalized_url = normalize_url(url)
    normalized_method = (method or "").upper()
    host = parse_host(normalized_url)
    audit = AuditLog(Path(memory_dir) / "audit.jsonl")
    profile = load_target_profile(memory_dir, target)
    active_ctf_mode = resolve_ctf_mode(ctf_mode)
    checker, scope_info = build_scope_checker(
        profile,
        target,
        ctf_mode=active_ctf_mode,
        scope_domains=scope_domains,
        excluded_domains=excluded_domains,
        excluded_classes=excluded_classes,
    )
    settings, setting_sources = _resolve_settings(
        profile,
        recon_rps=recon_rps,
        test_rps=test_rps,
        breaker_threshold=breaker_threshold,
        breaker_cooldown=breaker_cooldown,
    )
    current_ts = float(now_ts if now_ts is not None else time.time())

    if not host:
        audit.log_request(
            url=normalized_url or url,
            method=normalized_method,
            scope_check="fail",
            session_id=session_id,
            error="invalid or hostless URL",
        )
        return {
            "allowed": False,
            "action": "block_url",
            "reason": "invalid or hostless URL",
            "url": normalized_url or url,
            "host": "",
            "method": normalized_method,
            "scope": scope_info,
            "ctf_mode": active_ctf_mode,
        }

    if active_ctf_mode:
        state = load_guard_state(memory_dir, target)
        state["settings"] = settings
        host_state = state["hosts"].get(host, _default_host_state())
        host_state["last_request_ts"] = current_ts
        host_state["failures"] = 0
        host_state["tripped_until"] = 0.0
        host_state["last_error"] = ""
        state["hosts"][host] = host_state
        save_guard_state(memory_dir, target, state)

        return {
            "allowed": True,
            "action": "allow_ctf",
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "mode": mode,
            "is_recon": is_recon,
            "scope_check": "skip",
            "scope": scope_info,
            "wait_seconds": 0.0,
            "interval_seconds": 0.0,
            "settings": settings,
            "setting_sources": setting_sources,
            "breaker": _breaker_summary(host, host_state, settings["breaker_threshold"], current_ts),
            "ctf_mode": True,
        }

    if checker is None or not checker.is_in_scope(normalized_url):
        audit.log_request(
            url=normalized_url,
            method=normalized_method,
            scope_check="fail",
            session_id=session_id,
            error="out of scope",
        )
        return {
            "allowed": False,
            "action": "block_scope",
            "reason": "out of scope",
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "scope": scope_info,
            "ctf_mode": active_ctf_mode,
        }

    if vuln_class and not checker.is_vuln_class_allowed(vuln_class):
        error = f"excluded vuln class: {vuln_class}"
        audit.log_request(
            url=normalized_url,
            method=normalized_method,
            scope_check="pass",
            session_id=session_id,
            error=error,
        )
        return {
            "allowed": False,
            "action": "block_vuln_class",
            "reason": error,
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "scope": scope_info,
            "ctf_mode": active_ctf_mode,
        }

    if mode == "yolo" and normalized_method not in SAFE_METHODS:
        error = "unsafe method requires approval in yolo mode"
        audit.log_request(
            url=normalized_url,
            method=normalized_method,
            scope_check="pass",
            session_id=session_id,
            error=error,
        )
        return {
            "allowed": False,
            "action": "block_method",
            "reason": error,
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "scope": scope_info,
            "ctf_mode": active_ctf_mode,
        }

    state = load_guard_state(memory_dir, target)
    state["settings"] = settings
    host_state = state["hosts"].get(host, _default_host_state())
    remaining = _remaining_seconds(host_state.get("tripped_until", 0.0), current_ts)
    if remaining > 0:
        error = f"circuit breaker active for {remaining:.3f}s"
        audit.log_request(
            url=normalized_url,
            method=normalized_method,
            scope_check="pass",
            session_id=session_id,
            error=error,
        )
        return {
            "allowed": False,
            "action": "block_breaker",
            "reason": error,
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "scope": scope_info,
            "breaker": _breaker_summary(host, host_state, settings["breaker_threshold"], current_ts),
            "ctf_mode": active_ctf_mode,
        }

    interval = _interval_seconds(settings, is_recon=is_recon)
    wait_seconds = round(max(0.0, host_state.get("last_request_ts", 0.0) + interval - current_ts), 3)
    effective_ts = current_ts
    if wait_seconds > 0:
        if sleep:
            time.sleep(wait_seconds)
            effective_ts = time.time()
        else:
            effective_ts = current_ts + wait_seconds

    host_state["last_request_ts"] = float(effective_ts)
    state["hosts"][host] = host_state
    save_guard_state(memory_dir, target, state)

    return {
        "allowed": True,
        "action": "allow",
        "url": normalized_url,
        "host": host,
        "method": normalized_method,
        "mode": mode,
        "is_recon": is_recon,
        "scope_check": "pass",
        "scope": scope_info,
        "wait_seconds": wait_seconds,
        "interval_seconds": round(interval, 3),
        "settings": settings,
        "setting_sources": setting_sources,
        "breaker": _breaker_summary(host, host_state, settings["breaker_threshold"], effective_ts),
        "ctf_mode": active_ctf_mode,
    }


def record_request(
    *,
    memory_dir: str | Path,
    target: str,
    url: str,
    method: str,
    response_status: int | None = None,
    error: str | None = None,
    finding_id: str | None = None,
    session_id: str | None = None,
    scope_check: str | None = None,
    scope_domains: list[str] | None = None,
    excluded_domains: list[str] | None = None,
    excluded_classes: list[str] | None = None,
    breaker_threshold: int | None = None,
    breaker_cooldown: float | None = None,
    ctf_mode: bool | None = None,
    now_ts: float | None = None,
) -> dict:
    """Record a completed request and update breaker state."""
    normalized_url = normalize_url(url)
    normalized_method = (method or "").upper()
    host = parse_host(normalized_url)
    profile = load_target_profile(memory_dir, target)
    active_ctf_mode = resolve_ctf_mode(ctf_mode)
    checker, scope_info = build_scope_checker(
        profile,
        target,
        ctf_mode=active_ctf_mode,
        scope_domains=scope_domains,
        excluded_domains=excluded_domains,
        excluded_classes=excluded_classes,
    )
    settings, setting_sources = _resolve_settings(
        profile,
        breaker_threshold=breaker_threshold,
        breaker_cooldown=breaker_cooldown,
    )
    current_ts = float(now_ts if now_ts is not None else time.time())

    if scope_check:
        normalized_scope_check = scope_check
    elif active_ctf_mode:
        normalized_scope_check = "skip"
    elif checker is None:
        normalized_scope_check = "skip"
    else:
        normalized_scope_check = "pass" if checker.is_in_scope(normalized_url) else "fail"

    audit = AuditLog(Path(memory_dir) / "audit.jsonl")
    audit.log_request(
        url=normalized_url,
        method=normalized_method,
        scope_check=normalized_scope_check,
        response_status=response_status,
        finding_id=finding_id,
        session_id=session_id,
        error=error,
    )

    state = load_guard_state(memory_dir, target)
    state["settings"] = settings
    host_state = state["hosts"].get(host, _default_host_state()) if host else _default_host_state()

    if active_ctf_mode:
        action = "recorded_ctf"
        if host:
            host_state["last_request_ts"] = current_ts
            host_state["failures"] = 0
            host_state["tripped_until"] = 0.0
            host_state["last_error"] = ""
            state["hosts"][host] = host_state
            save_guard_state(memory_dir, target, state)

        return {
            "target": target,
            "url": normalized_url,
            "host": host,
            "method": normalized_method,
            "response_status": response_status,
            "error": error or "",
            "scope_check": normalized_scope_check,
            "action": action,
            "just_tripped": False,
            "scope": scope_info,
            "settings": settings,
            "setting_sources": setting_sources,
            "breaker": _breaker_summary(host, host_state, settings["breaker_threshold"], current_ts) if host else None,
            "ctf_mode": True,
        }

    just_tripped = False
    action = "recorded"
    if host:
        if _is_breaker_failure(response_status, error):
            host_state["failures"] = int(host_state.get("failures", 0) or 0) + 1
            host_state["last_error"] = error or str(response_status or "")
            action = "failure"
            if host_state["failures"] >= settings["breaker_threshold"]:
                next_trip = current_ts + settings["breaker_cooldown"]
                if next_trip > float(host_state.get("tripped_until", 0.0) or 0.0):
                    host_state["tripped_until"] = next_trip
                just_tripped = True
                action = "tripped"
        elif response_status is not None or error is None:
            host_state["failures"] = 0
            host_state["tripped_until"] = 0.0
            host_state["last_error"] = ""
            action = "success"

        state["hosts"][host] = host_state
        save_guard_state(memory_dir, target, state)

    return {
        "target": target,
        "url": normalized_url,
        "host": host,
        "method": normalized_method,
        "response_status": response_status,
        "error": error or "",
        "scope_check": normalized_scope_check,
        "action": action,
        "just_tripped": just_tripped,
        "scope": scope_info,
        "settings": settings,
        "setting_sources": setting_sources,
        "breaker": _breaker_summary(host, host_state, settings["breaker_threshold"], current_ts) if host else None,
        "ctf_mode": active_ctf_mode,
    }


def load_guard_status(
    memory_dir: str | Path,
    target: str,
    *,
    breaker_threshold: int | None = None,
    now_ts: float | None = None,
) -> dict:
    """Return the current persisted guard state in a display-friendly format."""
    state = load_guard_state(memory_dir, target)
    current_ts = float(now_ts if now_ts is not None else time.time())
    hosts = []
    persisted_threshold = state.get("settings", {}).get("breaker_threshold")
    threshold = breaker_threshold or persisted_threshold or DEFAULT_BREAKER_THRESHOLD
    for host, host_state in sorted(state["hosts"].items()):
        remaining = _remaining_seconds(host_state.get("tripped_until", 0.0), current_ts)
        hosts.append({
            "host": host,
            "last_request_ts": host_state.get("last_request_ts", 0.0),
            "last_request_at": _iso_utc(host_state.get("last_request_ts", 0.0)),
            "failures": int(host_state.get("failures", 0) or 0),
            "threshold": threshold,
            "tripped": remaining > 0,
            "remaining_seconds": remaining,
            "last_error": host_state.get("last_error", "") or "",
        })

    tripped_hosts = sum(1 for item in hosts if item["tripped"])
    ready_hosts = len(hosts) - tripped_hosts
    return {
        "target": target,
        "settings": state.get("settings", {}),
        "hosts": hosts,
        "tracked_hosts": len(hosts),
        "tripped_hosts": tripped_hosts,
        "ready_hosts": ready_hosts,
        "ctf_mode": resolve_ctf_mode(),
    }


def format_guard_output(payload: dict, command: str) -> str:
    """Format CLI output for humans."""
    if command == "status":
        lines = [
            f"REQUEST GUARD: {payload['target']}",
            "═══════════════════════════════════════",
        ]
        if not payload["hosts"]:
            lines.append("No tracked hosts yet.")
            return "\n".join(lines)

        lines.append(
            f"Tracked: {payload.get('tracked_hosts', len(payload['hosts']))} total — "
            f"{payload.get('tripped_hosts', 0)} tripped, {payload.get('ready_hosts', 0)} ready"
        )
        for item in payload["hosts"]:
            state = "TRIPPED" if item["tripped"] else "ready"
            lines.append(
                f"{item['host']} — {state} — failures {item['failures']}/{item['threshold']}"
            )
            if item["remaining_seconds"]:
                lines.append(f"  cooldown: {item['remaining_seconds']:.3f}s")
            if item["last_request_at"]:
                lines.append(f"  last request: {item['last_request_at']}")
            if item["last_error"]:
                lines.append(f"  last error: {item['last_error']}")
        return "\n".join(lines)

    if payload.get("allowed") is False:
        return (
            f"BLOCKED {payload['method']} {payload['url']}\n"
            f"Reason: {payload['reason']}"
        )

    if command == "preflight":
        return (
            f"ALLOW {payload['method']} {payload['url']}\n"
            f"Wait: {payload['wait_seconds']:.3f}s\n"
            f"Breaker: {payload['breaker']['failures']}/{payload['breaker']['threshold']}"
        )

    return (
        f"RECORDED {payload['method']} {payload['url']}\n"
        f"Action: {payload['action']}\n"
        f"Scope: {payload['scope_check']}"
    )


def _add_common_guard_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON")


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope-domains", default="", help="Comma-separated allowlist domains")
    parser.add_argument("--excluded-domains", default="", help="Comma-separated blocklist domains")
    parser.add_argument("--excluded-classes", default="", help="Comma-separated excluded vuln classes")


def _memory_dir_from_args(value: str) -> str:
    return value or str(default_memory_dir(BASE_DIR))


def main() -> None:
    parser = argparse.ArgumentParser(description="Practical request guard for autopilot loops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser("preflight", help="Run preflight checks before a request")
    _add_common_guard_args(preflight_parser)
    _add_scope_args(preflight_parser)
    preflight_parser.add_argument("--url", required=True, help="Target URL")
    preflight_parser.add_argument("--method", required=True, help="HTTP method")
    preflight_parser.add_argument("--session-id", default="", help="Optional session ID")
    preflight_parser.add_argument("--vuln-class", default="", help="Optional vuln class for policy checks")
    preflight_parser.add_argument(
        "--mode",
        default="normal",
        choices=["paranoid", "normal", "yolo"],
        help="Autopilot mode",
    )
    preflight_parser.add_argument("--recon", action="store_true", help="Use recon rate limit instead of test rate limit")
    preflight_parser.add_argument("--recon-rps", type=float, default=None, help="Override recon RPS")
    preflight_parser.add_argument("--test-rps", type=float, default=None, help="Override test RPS")
    preflight_parser.add_argument("--breaker-threshold", type=int, default=None, help="Override breaker failure threshold")
    preflight_parser.add_argument("--breaker-cooldown", type=float, default=None, help="Override breaker cooldown seconds")
    preflight_parser.add_argument("--no-wait", action="store_true", help="Return wait time without sleeping")

    record_parser = subparsers.add_parser("record", help="Record the request result and update breaker state")
    _add_common_guard_args(record_parser)
    _add_scope_args(record_parser)
    record_parser.add_argument("--url", required=True, help="Target URL")
    record_parser.add_argument("--method", required=True, help="HTTP method")
    record_parser.add_argument("--status", type=int, default=None, help="HTTP response status")
    record_parser.add_argument("--error", default="", help="Optional request error")
    record_parser.add_argument("--finding-id", default="", help="Optional finding ID")
    record_parser.add_argument("--session-id", default="", help="Optional session ID")
    record_parser.add_argument(
        "--scope-check",
        default="",
        choices=["", "pass", "fail", "skip"],
        help="Optional explicit scope check result",
    )
    record_parser.add_argument("--breaker-threshold", type=int, default=None, help="Override breaker failure threshold")
    record_parser.add_argument("--breaker-cooldown", type=float, default=None, help="Override breaker cooldown seconds")

    status_parser = subparsers.add_parser("status", help="Show current guard state")
    _add_common_guard_args(status_parser)
    status_parser.add_argument("--breaker-threshold", type=int, default=None, help="Display threshold override")

    args = parser.parse_args()
    memory_dir = _memory_dir_from_args(args.memory_dir)

    if args.command == "preflight":
        payload = preflight_request(
            memory_dir=memory_dir,
            target=args.target,
            url=args.url,
            method=args.method,
            session_id=args.session_id or None,
            vuln_class=args.vuln_class or None,
            mode=args.mode,
            is_recon=args.recon,
            scope_domains=parse_csv(args.scope_domains),
            excluded_domains=parse_csv(args.excluded_domains),
            excluded_classes=parse_csv(args.excluded_classes),
            recon_rps=args.recon_rps,
            test_rps=args.test_rps,
            breaker_threshold=args.breaker_threshold,
            breaker_cooldown=args.breaker_cooldown,
            sleep=not args.no_wait,
        )
    elif args.command == "record":
        payload = record_request(
            memory_dir=memory_dir,
            target=args.target,
            url=args.url,
            method=args.method,
            response_status=args.status,
            error=args.error or None,
            finding_id=args.finding_id or None,
            session_id=args.session_id or None,
            scope_check=args.scope_check or None,
            scope_domains=parse_csv(args.scope_domains),
            excluded_domains=parse_csv(args.excluded_domains),
            excluded_classes=parse_csv(args.excluded_classes),
            breaker_threshold=args.breaker_threshold,
            breaker_cooldown=args.breaker_cooldown,
        )
    else:
        payload = load_guard_status(
            memory_dir,
            args.target,
            breaker_threshold=args.breaker_threshold,
        )

    if args.json:
        print(json.dumps(payload, indent=2))
        return

    print(format_guard_output(payload, args.command))


if __name__ == "__main__":
    main()
