#!/usr/bin/env python3
"""
Bug Bounty Hunt Orchestrator
Main script that chains target selection, recon, scanning, and reporting.

Usage:
    python3 hunt.py                         # Full pipeline: select targets + hunt
    python3 hunt.py --target <domain>       # Hunt a specific target
    python3 hunt.py --quick --target <domain>  # Quick scan mode
    python3 hunt.py --target <domain> --agent  # Autonomous agent mode
    python3 hunt.py --recon-only --target <domain>  # Only run recon
    python3 hunt.py --scan-only --target <domain>   # Only run vuln scanner (requires prior recon)
    python3 hunt.py --status                # Show current progress
    python3 hunt.py --setup-wordlists       # Download common wordlists
    python3 hunt.py --cve-hunt --target <domain>   # Run CVE hunter
    python3 hunt.py --zero-day --target <domain>   # Run zero-day fuzzer
"""

import argparse
import base64
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
RECON_DIR = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from memory.hunt_journal import HuntJournal
from memory.schemas import make_journal_entry
from memory.target_profile import default_memory_dir, load_target_profile, make_target_profile, save_target_profile

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

HUNT_MEMORY_DIR = default_memory_dir(BASE_DIR)
URL_SSL_CTX = ssl._create_unverified_context()
_SEEN_GUARD_BLOCKS: set[tuple[str, str, str, str, str]] = set()


def load_config():
    """Load optional repo config.json. Missing or invalid config is ignored."""
    config_path = os.path.join(BASE_DIR, "config.json")
    if not os.path.exists(config_path):
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def is_ctf_mode(config=None):
    """Return whether local CTF mode is enabled in repo config."""
    if config is None:
        config = load_config()
    return bool((config or {}).get("ctf_mode", False))


def resolve_autopilot_mode(args) -> str:
    """Resolve CLI checkpoint mode with paranoid as the safe default."""
    if getattr(args, "yolo", False):
        return "yolo"
    if getattr(args, "normal", False):
        return "normal"
    return "paranoid"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def run_cmd(cmd, cwd=None, timeout=600):
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=cwd, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def _resolve_recon_dir(domain):
    """Return the canonical recon directory for a target."""
    return os.path.join(RECON_DIR, domain)


def _resolve_findings_dir(domain, create=False):
    """Return the canonical findings directory for a target."""
    path = os.path.join(FINDINGS_DIR, domain)
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _first_existing_path(paths):
    """Return the first existing file path from a sequence."""
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


def _recon_file_candidates(domain, *relative_paths):
    """Build recon file candidates for new and legacy output layouts."""
    recon_dir = _resolve_recon_dir(domain)
    return [os.path.join(recon_dir, rel) for rel in relative_paths]


def _read_text_lines(path, limit=None):
    """Read non-empty text lines from a file."""
    if not path or not os.path.isfile(path):
        return []

    items = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.strip()
            if not value:
                continue
            items.append(value)
            if limit and len(items) >= limit:
                break
    return items


def _write_text_lines(path, lines):
    """Write deduped lines to a UTF-8 text file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    unique_lines = _dedupe_keep_order([line.strip() for line in lines if line and line.strip()])
    with open(path, "w", encoding="utf-8") as f:
        if unique_lines:
            f.write("\n".join(unique_lines) + "\n")
    return unique_lines


def _append_text(path, text):
    """Append text to a file, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def _command_exists(tool):
    """Check whether a tool is available in PATH."""
    success, _ = run_cmd(f"command -v {shlex.quote(tool)}")
    return success


def _guard_scope_domains(target):
    """Build a conservative scope list for hunt-side guarded requests.

    This keeps the original single-target workflow usable by allowing the
    exact target plus its subdomains, without pretending to know broader
    program scope.
    """
    normalized = (target or "").strip().lower()
    if not normalized:
        return []
    if normalized.startswith("*."):
        return [normalized]
    if normalized == "localhost":
        return [normalized]
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", normalized):
        return [normalized]
    return _dedupe_keep_order([normalized, f"*.{normalized}"])


def _fetch_url_raw(url, *, headers=None, timeout=10, method="GET"):
    """Fetch a URL and return (status, body, headers dict)."""
    request = Request(url, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=timeout, context=URL_SSL_CTX) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.getcode(), body, dict(response.headers.items())
    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}
    except (URLError, ValueError):
        return None, "", {}


def _fetch_url(
    url,
    *,
    headers=None,
    timeout=10,
    method="GET",
    target="",
    use_guard=False,
    is_recon=False,
    vuln_class="",
):
    """Fetch a URL and optionally run request-guard preflight/record around it."""
    if not use_guard or not target:
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    try:
        from request_guard import preflight_request, record_request
    except Exception:
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    config = load_config()
    ctf_mode = is_ctf_mode(config)
    scope_domains = _guard_scope_domains(target)
    session_id = f"hunt-{target}-{os.getpid()}"

    try:
        preflight = preflight_request(
            memory_dir=HUNT_MEMORY_DIR,
            target=target,
            url=url,
            method=method,
            session_id=session_id,
            vuln_class=vuln_class or None,
            mode="normal",
            is_recon=is_recon,
            scope_domains=scope_domains or None,
            ctf_mode=ctf_mode,
        )
    except Exception as exc:
        log("warn", f"request_guard preflight failed for {url}: {exc} — continuing without guard")
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    if not preflight.get("allowed"):
        reason = preflight.get("reason") or preflight.get("action") or "blocked"
        _log_guard_block(
            target=target,
            url=url,
            method=method,
            reason=reason,
            action=str(preflight.get("action") or "blocked"),
            host=str(preflight.get("host") or ""),
            is_recon=is_recon,
        )
        log("warn", f"request_guard blocked {method.upper()} {url}: {reason}")
        return None, "", {}

    status, body, response_headers = _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)
    record_error = None if status is not None else "request failed"
    try:
        record_request(
            memory_dir=HUNT_MEMORY_DIR,
            target=target,
            url=url,
            method=method,
            response_status=status,
            error=record_error,
            session_id=session_id,
            scope_domains=scope_domains or None,
            ctf_mode=ctf_mode,
        )
    except Exception as exc:
        log("warn", f"request_guard record failed for {url}: {exc}")

    return status, body, response_headers


def _log_guard_block(
    *,
    target: str,
    url: str,
    method: str,
    reason: str,
    action: str,
    host: str = "",
    is_recon: bool = False,
) -> None:
    """Persist a lightweight journal note for notable request-guard blocks.

    Dedupe identical host/action/reason events within the current process so
    tight loops do not flood hunt-memory.
    """
    normalized_target = str(target or "").strip()
    normalized_url = str(url or "").strip()
    normalized_method = str(method or "GET").upper()
    normalized_reason = str(reason or action or "blocked").strip()
    normalized_action = str(action or "blocked").strip()
    normalized_host = str(host or "").strip()
    if not normalized_target or not normalized_url:
        return

    signature = (
        normalized_target,
        normalized_host or normalized_url,
        normalized_action,
        normalized_reason,
        "recon" if is_recon else "hunt",
    )
    if signature in _SEEN_GUARD_BLOCKS:
        return
    _SEEN_GUARD_BLOCKS.add(signature)

    try:
        journal = HuntJournal(os.path.join(HUNT_MEMORY_DIR, "journal.jsonl"))
        entry = make_journal_entry(
            target=normalized_target,
            action="recon" if is_recon else "hunt",
            vuln_class="guard_block",
            endpoint=normalized_url,
            result="informational",
            severity="none",
            technique="request_guard",
            notes=(
                f"request_guard blocked {normalized_method} {normalized_url}. "
                f"Host: {normalized_host or 'unknown'}. "
                f"Action: {normalized_action}. "
                f"Reason: {normalized_reason}."
            ),
            tags=["guard_block", "auto_logged", normalized_action],
        )
        journal.append(entry)
    except Exception as exc:
        log("warn", f"Auto guard-block memory failed (non-fatal): {exc}")


def _decoded_jwt_segment(segment):
    """Base64url-decode a JWT segment into JSON if possible."""
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(segment + padding).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def _collect_live_urls(domain, limit=None):
    """Collect live URLs from both new and legacy recon layouts."""
    recon_dir = _resolve_recon_dir(domain)
    urls = []

    urls.extend(_read_text_lines(_first_existing_path(_recon_file_candidates(domain, "live/urls.txt", "live-hosts.txt")), limit=limit))

    httpx_full = _first_existing_path(_recon_file_candidates(domain, "live/httpx_full.txt"))
    if httpx_full:
        for line in _read_text_lines(httpx_full, limit=limit):
            first = line.split()[0]
            if first.startswith(("http://", "https://")):
                urls.append(first)
            if limit and len(urls) >= limit:
                break

    return _dedupe_keep_order(urls)[:limit] if limit else _dedupe_keep_order(urls)


def _collect_all_urls(domain, limit=None):
    """Collect all known URLs from recon output."""
    urls = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/all.txt", "urls.txt")), limit=limit)
    return _dedupe_keep_order(urls)[:limit] if limit else _dedupe_keep_order(urls)


def _collect_param_urls(domain, limit=None):
    """Collect parameterized URLs from recon output or derive from all URLs."""
    paths = _recon_file_candidates(
        domain,
        "urls/with_params.txt",
        "idor-candidates.txt",
        "ssrf-candidates.txt",
        "redirect-candidates.txt",
        "sqli-candidates.txt",
        "xss-candidates.txt",
    )
    urls = []
    for path in paths:
        urls.extend(_read_text_lines(path, limit=limit))

    if not urls:
        urls.extend(url for url in _collect_all_urls(domain, limit=limit) if "?" in url)

    urls = _dedupe_keep_order(urls)
    return urls[:limit] if limit else urls


def _collect_api_endpoints(domain, limit=None):
    """Collect API endpoints from recon output or derive them from URLs."""
    endpoints = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/api_endpoints.txt", "api-endpoints.txt")), limit=limit)
    if not endpoints:
        endpoints = [
            url for url in _collect_all_urls(domain, limit=limit)
            if re.search(r"(/api/|/v[0-9]+/|/graphql|/rest/)", url, re.I)
        ]
    endpoints = _dedupe_keep_order(endpoints)
    return endpoints[:limit] if limit else endpoints


def _collect_js_urls(domain, limit=None):
    """Collect JavaScript asset URLs from recon output or derive them from URL history."""
    js_urls = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/js_files.txt")), limit=limit)
    if not js_urls:
        js_urls = [url for url in _collect_all_urls(domain, limit=limit) if re.search(r"\.js(\?|$)", url, re.I)]
    js_urls = _dedupe_keep_order(js_urls)
    return js_urls[:limit] if limit else js_urls


def _dedupe_keep_order(items):
    """Deduplicate while preserving input order."""
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _normalize_endpoint(value):
    """Normalize URLs/paths to path-style endpoints for target profiles."""
    if not value:
        return None

    raw = value.strip()
    if not raw:
        return None

    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    if raw.startswith("/"):
        return raw

    return f"/{raw.lstrip('/')}"


def _read_endpoints(path, limit=500):
    """Read and normalize endpoint candidates from a text file."""
    if not os.path.isfile(path):
        return []

    endpoints = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            endpoint = _normalize_endpoint(line)
            if endpoint:
                endpoints.append(endpoint)
            if len(endpoints) >= limit:
                break

    return _dedupe_keep_order(endpoints)


def _extract_recon_candidates(domain):
    """Collect candidate endpoints for later resume/intel workflows."""
    recon_dir = _resolve_recon_dir(domain)
    files = [
        os.path.join(recon_dir, "urls", "api_endpoints.txt"),
        os.path.join(recon_dir, "urls", "with_params.txt"),
        os.path.join(recon_dir, "js", "endpoints.txt"),
        os.path.join(recon_dir, "api-endpoints.txt"),
        os.path.join(recon_dir, "idor-candidates.txt"),
        os.path.join(recon_dir, "ssrf-candidates.txt"),
        os.path.join(recon_dir, "redirect-candidates.txt"),
    ]

    endpoints = []
    for path in files:
        endpoints.extend(_read_endpoints(path))
    return _dedupe_keep_order(endpoints)


def _extract_recon_tech_stack(domain, limit=12):
    """Collect a normalized tech stack from recon/live/httpx_full.txt."""
    httpx_path = _first_existing_path(_recon_file_candidates(domain, "live/httpx_full.txt"))
    if not httpx_path or not os.path.isfile(httpx_path):
        return []

    techs = []
    with open(httpx_path, encoding="utf-8") as f:
        for line in f:
            matches = re.findall(r"\[([^\]]+)\]", line)
            if len(matches) < 3:
                continue

            for tech in matches[2].split(","):
                normalized = tech.strip().lower()
                if normalized and not normalized.isdigit():
                    techs.append(normalized)

            if len(techs) >= limit:
                break

    return _dedupe_keep_order(techs)[:limit]


def _load_report_findings(domain):
    """Load simplified findings from reports/<target>/INDEX.json if present."""
    index_path = os.path.join(REPORTS_DIR, domain, "INDEX.json")
    if not os.path.isfile(index_path):
        return []

    try:
        with open(index_path, encoding="utf-8") as f:
            index = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings = []
    for report in index.get("reports", []):
        findings.append({
            "id": report.get("id", ""),
            "title": report.get("title", ""),
            "severity": report.get("severity", ""),
            "type": report.get("type", ""),
            "url": report.get("url", ""),
        })
    return findings


def _update_target_profile(domain, *, elapsed_minutes=0, recon_completed=False):
    """Persist minimal hunt state so resume/intel can read it later."""
    profile = load_target_profile(HUNT_MEMORY_DIR, domain)
    if profile is None:
        profile = make_target_profile(
            domain,
            scope_snapshot={"in_scope": [domain], "fetched_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")},
            tested_endpoints=[],
            untested_endpoints=[],
            findings=[],
            hunt_sessions=0,
            total_time_minutes=0,
        )

    profile["last_hunted"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    profile["hunt_sessions"] = int(profile.get("hunt_sessions", 0)) + 1
    profile["total_time_minutes"] = round(float(profile.get("total_time_minutes", 0)) + elapsed_minutes, 2)

    tech_stack = _extract_recon_tech_stack(domain)
    if tech_stack:
        profile["tech_stack"] = tech_stack

    if recon_completed:
        discovered = _extract_recon_candidates(domain)
        tested = _dedupe_keep_order(profile.get("tested_endpoints", []))
        remaining = [ep for ep in discovered if ep not in set(tested)]
        profile["untested_endpoints"] = remaining

    findings = _load_report_findings(domain)
    if findings:
        profile["findings"] = findings
        tested_endpoints = _dedupe_keep_order(
            profile.get("tested_endpoints", [])
            + [_normalize_endpoint(item.get("url", "")) for item in findings]
        )
        profile["tested_endpoints"] = tested_endpoints
        remaining = [ep for ep in profile.get("untested_endpoints", []) if ep not in set(tested_endpoints)]
        profile["untested_endpoints"] = remaining

    save_target_profile(HUNT_MEMORY_DIR, profile)


def _session_vuln_classes(domain, *, recon_completed=False, scan_completed=False, cve_hunt=False, zero_day=False):
    """Derive a minimal list of vuln classes/scan modes attempted in the session."""
    classes = []
    for item in _load_report_findings(domain):
        label = str(item.get("type") or item.get("vuln_class") or "").strip().lower()
        if label:
            classes.append(label)

    if not classes:
        if scan_completed:
            classes.append("vuln_scan")
        elif recon_completed:
            classes.append("recon")

    if cve_hunt:
        classes.append("cve")
    if zero_day:
        classes.append("zero_day")

    return _dedupe_keep_order(classes)


def _auto_log_session_summary(
    domain,
    *,
    action="hunt",
    recon_completed=False,
    scan_completed=False,
    cve_hunt=False,
    zero_day=False,
    session_id=None,
):
    """Auto-log a non-fatal session summary to hunt memory."""
    try:
        profile = load_target_profile(HUNT_MEMORY_DIR, domain) or {}
        findings = _load_report_findings(domain)
        endpoints_tested = profile.get("tested_endpoints", []) if isinstance(profile, dict) else []
        vuln_classes = _session_vuln_classes(
            domain,
            recon_completed=recon_completed,
            scan_completed=scan_completed,
            cve_hunt=cve_hunt,
            zero_day=zero_day,
        )
        journal = HuntJournal(os.path.join(HUNT_MEMORY_DIR, "journal.jsonl"))
        journal.log_session_summary(
            target=domain,
            action=action,
            endpoints_tested=endpoints_tested,
            vuln_classes_tried=vuln_classes,
            findings_count=len(findings),
            session_id=session_id,
        )
    except Exception as exc:
        log("warn", f"Auto session memory failed (non-fatal): {exc}")


def check_tools():
    """Check which tools are installed."""
    tools = ["subfinder", "httpx", "nuclei", "ffuf", "nmap", "amass", "gau", "dalfox", "subjack"]
    installed = []
    missing = []

    for tool in tools:
        success, _ = run_cmd(f"command -v {tool}")
        if success:
            installed.append(tool)
        else:
            missing.append(tool)

    return installed, missing


def setup_wordlists():
    """Download common wordlists for fuzzing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "params.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    }

    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath):
            log("ok", f"Wordlist exists: {name}")
            continue

        log("info", f"Downloading {name}...")
        success, output = run_cmd(f'curl -sL "{url}" -o "{filepath}"')
        if success and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed to download {name}")

    log("ok", f"Wordlists ready in {WORDLIST_DIR}")


def select_targets(top_n=10):
    """Run target selector."""
    log("info", "Running target selector...")
    script = os.path.join(TOOLS_DIR, "target_selector.py")
    success, output = run_cmd(
        f'python3 "{script}" --top {top_n}',
        timeout=60
    )
    print(output)

    if not success:
        log("err", "Target selection failed")
        return []

    # Load selected targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        return data.get("targets", [])

    return []


def run_recon(domain, quick=False):
    """Run recon engine on a domain."""
    log("info", f"Running recon on {domain}...")
    script = os.path.join(TOOLS_DIR, "recon_engine.sh")
    quick_flag = "--quick" if quick else ""

    # Run with live output
    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{domain}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)  # 30 min timeout
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Recon timed out for {domain}")
        return False


def run_vuln_scan(domain, quick=False):
    """Run vulnerability scanner on recon results."""
    recon_dir = _resolve_recon_dir(domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data found for {domain}. Run recon first.")
        return False

    log("info", f"Running vulnerability scanner on {domain}...")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    quick_flag = "--quick" if quick else ""

    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{recon_dir}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Vulnerability scan timed out for {domain}")
        return False


def _run_nuclei_scan(urls, *, tags, output_path, severity=None, rate_limit=20, concurrency=10):
    """Run nuclei against a URL list and write findings to output_path."""
    urls = _dedupe_keep_order(urls)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not urls or not _command_exists("nuclei"):
        return False

    input_path = os.path.join(os.path.dirname(output_path), "_nuclei_targets.txt")
    _write_text_lines(input_path, urls)
    severity_flag = f" -severity {shlex.quote(severity)}" if severity else ""
    cmd = (
        f'nuclei -l {shlex.quote(input_path)} -tags {shlex.quote(tags)}'
        f'{severity_flag} -silent -rate-limit {rate_limit} -concurrency {concurrency}'
        f' -output {shlex.quote(output_path)}'
    )
    success, _ = run_cmd(cmd, cwd=BASE_DIR, timeout=600)
    return success and os.path.exists(output_path)


def _extract_js_endpoints(js_text):
    """Extract path-style endpoints from JavaScript bundles."""
    pattern = re.compile(r"""["']([a-zA-Z0-9_./?=&%-]*(?:/[a-zA-Z0-9_./?=&%-]+)+)["']""")
    endpoints = []
    for match in pattern.findall(js_text):
        endpoint = _normalize_endpoint(match)
        if endpoint and len(endpoint) <= 240:
            endpoints.append(endpoint)
    return _dedupe_keep_order(endpoints)


def _extract_secret_candidates(js_text):
    """Extract secret-like key/value strings from JavaScript content."""
    pattern = re.compile(
        r"""(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["'\s:=]+([a-zA-Z0-9_\-]{8,})"""
    )
    return _dedupe_keep_order([f"{name}={value}" for name, value in pattern.findall(js_text)])


def run_js_analysis(domain):
    """Extract endpoints and secret-like strings from discovered JS assets."""
    recon_dir = _resolve_recon_dir(domain)
    js_dir = os.path.join(recon_dir, "js")
    os.makedirs(js_dir, exist_ok=True)

    js_urls = _collect_js_urls(domain, limit=50)
    if not js_urls:
        log("warn", f"No JS files found for {domain}")
        return False

    endpoints = []
    secrets = []
    for js_url in js_urls:
        status, body, _ = _fetch_url(js_url, timeout=10)
        if status != 200 or not body:
            continue
        endpoints.extend(_extract_js_endpoints(body))
        secrets.extend(_extract_secret_candidates(body))

    endpoints_path = os.path.join(js_dir, "endpoints.txt")
    secrets_path = os.path.join(js_dir, "potential_secrets.txt")
    endpoints = _write_text_lines(endpoints_path, endpoints)
    secrets = _write_text_lines(secrets_path, secrets)

    return bool(endpoints or secrets)


def run_secret_hunt(domain):
    """Persist secret-like findings from JS analysis into findings artifacts."""
    recon_dir = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    exposure_dir = os.path.join(findings_dir, "exposure")
    os.makedirs(exposure_dir, exist_ok=True)

    js_secrets_path = os.path.join(recon_dir, "js", "potential_secrets.txt")
    if not os.path.isfile(js_secrets_path):
        run_js_analysis(domain)

    secrets = _read_text_lines(js_secrets_path, limit=200)
    output_path = os.path.join(exposure_dir, "js_secrets.txt")
    secrets = _write_text_lines(output_path, secrets)

    # Carry forward exposed config files from recon if present.
    config_file_hits = _read_text_lines(os.path.join(recon_dir, "exposure", "config_files.txt"), limit=100)
    if config_file_hits:
        _write_text_lines(os.path.join(exposure_dir, "config_files.txt"), config_file_hits)

    return bool(secrets or config_file_hits)


def run_repo_source_hunt(domain, repo_url="", repo_path="", allow_large_repo=False):
    """Run standalone repo source scanning and persist findings under findings/<domain>/exposure."""
    if not repo_url and not repo_path:
        log("warn", "run_repo_source_hunt requires --repo-url or --repo-path")
        return False

    from source_hunt import run_source_hunt

    result = run_source_hunt(
        target=domain,
        repo_url=repo_url,
        repo_path=repo_path,
        allow_large_repo=allow_large_repo,
        interactive=False,
    )
    if result.get("status") == "confirmation_required":
        log("warn", "Repository exceeds source-hunt threshold. Re-run with --allow-large-repo after approval.")
        return False
    return result.get("status") == "ok"


def run_param_discovery(domain):
    """Mine interesting parameter names from recon output and optionally brute-force with arjun."""
    recon_dir = _resolve_recon_dir(domain)
    params_dir = os.path.join(recon_dir, "params")
    os.makedirs(params_dir, exist_ok=True)

    param_urls = _collect_param_urls(domain, limit=300)
    live_urls = _collect_live_urls(domain, limit=10)

    interesting = []
    for url in param_urls:
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if value:
                interesting.append(f"{key}={value}")
            else:
                interesting.append(key)

    if _command_exists("arjun"):
        for idx, url in enumerate(live_urls[:5], start=1):
            output_path = os.path.join(params_dir, f"arjun_{idx}.txt")
            cmd = f'arjun -u {shlex.quote(url)} -oT {shlex.quote(output_path)}'
            run_cmd(cmd, cwd=BASE_DIR, timeout=180)
            interesting.extend(_read_text_lines(output_path, limit=100))

    interesting = _write_text_lines(os.path.join(params_dir, "interesting_params.txt"), interesting)
    return bool(interesting)


def run_post_param_discovery(domain, cookies=""):
    """Discover HTML POST forms and their parameter names from live targets."""
    recon_dir = _resolve_recon_dir(domain)
    params_dir = os.path.join(recon_dir, "params")
    os.makedirs(params_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=10)
    if not live_urls:
        return False

    headers = {"Cookie": cookies} if cookies else {}
    form_re = re.compile(r"<form[^>]*method=['\"]?post['\"]?[^>]*>(.*?)</form>", re.I | re.S)
    action_re = re.compile(r"""action=['"]([^'"]+)['"]""", re.I)
    input_re = re.compile(r"""name=['"]([^'"]+)['"]""", re.I)
    post_forms = {}

    for url in live_urls:
        status, body, _ = _fetch_url(
            url,
            headers=headers,
            timeout=10,
            target=domain,
            use_guard=True,
            is_recon=True,
        )
        if status != 200 or not body:
            continue

        for form_html in form_re.findall(body):
            action_match = action_re.search(form_html)
            action = urljoin(url, action_match.group(1)) if action_match else url
            names = _dedupe_keep_order(input_re.findall(form_html))
            if names:
                post_forms[action] = {"source": url, "params": names}

    if _command_exists("arjun"):
        for idx, action in enumerate(list(post_forms)[:3], start=1):
            output_path = os.path.join(params_dir, f"arjun_post_{idx}.txt")
            cmd = f'arjun -u {shlex.quote(action)} -m POST -oT {shlex.quote(output_path)}'
            run_cmd(cmd, cwd=BASE_DIR, timeout=180)
            extra_params = _read_text_lines(output_path, limit=100)
            if extra_params:
                post_forms.setdefault(action, {"source": action, "params": []})
                post_forms[action]["params"] = _dedupe_keep_order(post_forms[action]["params"] + extra_params)

    output_path = os.path.join(params_dir, "post_params.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(post_forms, f, indent=2, sort_keys=True)

    return bool(post_forms)


def run_api_fuzz(domain):
    """Run lightweight, non-destructive API access checks and candidate extraction."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    idor_dir = os.path.join(findings_dir, "idor")
    auth_dir = os.path.join(findings_dir, "auth_bypass")
    os.makedirs(idor_dir, exist_ok=True)
    os.makedirs(auth_dir, exist_ok=True)

    api_urls = _collect_api_endpoints(domain, limit=40)
    if not api_urls:
        return False

    idor_candidates = []
    unauth_access = []
    for url in api_urls:
        if re.search(r"[?&](id|user_id|uid|account|profile|order|invoice|ticket|message_id|comment_id|file_id)=", url, re.I):
            idor_candidates.append(url)
        if re.search(r"/[0-9]{1,8}(/|$|\?)", url):
            idor_candidates.append(url)

    for url in api_urls[:20]:
        status, body, _ = _fetch_url(
            url,
            timeout=8,
            target=domain,
            use_guard=True,
            vuln_class="idor",
        )
        if status == 200 and len(body) > 500:
            unauth_access.append(f"{status} {len(body)} {url}")

    idor_candidates = _write_text_lines(os.path.join(idor_dir, "idor_candidates.txt"), idor_candidates)
    unauth_access = _write_text_lines(os.path.join(auth_dir, "unauth_api_access.txt"), unauth_access)
    return bool(idor_candidates or unauth_access)


def run_cors_check(domain):
    """Check live targets for simple reflected CORS issues and nuclei hits."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    misconfig_dir = os.path.join(findings_dir, "misconfig")
    os.makedirs(misconfig_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=20)
    output_path = os.path.join(misconfig_dir, "cors.txt")
    findings = []

    for url in live_urls:
        status, _, headers = _fetch_url(
            url,
            headers={"Origin": "https://evil.com"},
            timeout=8,
            target=domain,
            use_guard=True,
            vuln_class="cors",
        )
        allow_origin = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
        allow_creds = headers.get("Access-Control-Allow-Credentials") or headers.get("access-control-allow-credentials")
        if allow_origin in {"https://evil.com", "*"}:
            findings.append(f"{status or 'NA'} {url} ACAO={allow_origin} ACAC={allow_creds or '-'}")

    if live_urls:
        _run_nuclei_scan(live_urls, tags="cors", output_path=output_path)
        findings.extend(_read_text_lines(output_path, limit=200))

    findings = _write_text_lines(output_path, findings)
    return bool(findings)


def run_cms_exploit(domain):
    """Run CMS-focused checks when recon suggests WordPress/Drupal/Joomla/Magento."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    cms_dir = os.path.join(findings_dir, "cves")
    os.makedirs(cms_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=20)
    if not live_urls:
        return False

    findings = []
    tech_stack = set(_extract_recon_tech_stack(domain))
    indicators = {
        "wordpress": ["/wp-json/wp/v2/users", "/xmlrpc.php"],
        "drupal": ["/user/login", "/CHANGELOG.txt"],
        "joomla": ["/administrator/manifests/files/joomla.xml"],
        "magento": ["/rest/V1/store/storeConfigs"],
    }

    for base_url in live_urls[:10]:
        for cms_name, paths in indicators.items():
            if tech_stack and cms_name not in tech_stack and cms_name not in base_url.lower():
                continue
            for path in paths:
                status, _, _ = _fetch_url(
                    urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
                    timeout=8,
                    target=domain,
                    use_guard=True,
                    vuln_class="cve",
                )
                if status and status not in {404, 401}:
                    findings.append(f"{cms_name} {status} {urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))}")

    if live_urls:
        _run_nuclei_scan(live_urls, tags="wordpress,drupal,joomla,magento", output_path=os.path.join(cms_dir, "cms_templates.txt"), severity="medium,high,critical")
        findings.extend(_read_text_lines(os.path.join(cms_dir, "cms_templates.txt"), limit=200))

    findings = _write_text_lines(os.path.join(cms_dir, "cms_findings.txt"), findings)
    return bool(findings)


def run_rce_scan(domain):
    """Run high-signal nuclei tags for RCE-adjacent issues."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=30)
    output_path = os.path.join(review_dir, "rce_scan.txt")
    if not live_urls:
        return False

    findings = []
    if _run_nuclei_scan(live_urls, tags="rce,ssti,jndi", output_path=output_path, severity="medium,high,critical"):
        findings.extend(_read_text_lines(output_path, limit=200))

    findings = _write_text_lines(output_path, findings)
    return bool(findings)


def run_sqlmap_targeted(domain):
    """Run sqlmap against a small sample of parameterized URLs."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)

    param_urls = _collect_param_urls(domain, limit=5)
    output_path = os.path.join(review_dir, "sqlmap_targeted.txt")
    if not param_urls:
        return False

    if not _command_exists("sqlmap"):
        _write_text_lines(output_path, param_urls)
        return True

    summaries = []
    for url in param_urls:
        cmd = (
            f'sqlmap -u {shlex.quote(url)} --batch --smart --level=2 --risk=1 '
            f'--disable-coloring --threads=1'
        )
        success, output = run_cmd(cmd, cwd=BASE_DIR, timeout=240)
        snippet = output[:1200].replace("\r", "")
        if success or snippet:
            summaries.append(f"URL: {url}\n{snippet}\n")

    summaries = _write_text_lines(output_path, summaries)
    return bool(summaries)


def run_sqlmap_request_file(request_file, domain=None, level=5, risk=3):
    """Run sqlmap against a saved raw HTTP request file."""
    if not os.path.isfile(request_file):
        return False

    findings_dir = _resolve_findings_dir(domain or "ad-hoc", create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)
    output_path = os.path.join(review_dir, "sqlmap_request_file.txt")

    if not _command_exists("sqlmap"):
        _write_text_lines(output_path, [request_file])
        return True

    cmd = (
        f'sqlmap -r {shlex.quote(request_file)} --batch --level={int(level)} --risk={int(risk)} '
        '--disable-coloring --threads=1'
    )
    success, output = run_cmd(cmd, cwd=BASE_DIR, timeout=300)
    if success or output:
        _append_text(output_path, output[:4000] + ("\n" if output else ""))
        return True
    return False


def run_jwt_audit(domain):
    """Search recon artifacts for JWTs and summarize their headers/claims."""
    recon_dir = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    jwt_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(jwt_dir, exist_ok=True)

    jwt_re = re.compile(r"\b([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
    tokens = []
    for root, _, files in os.walk(recon_dir):
        for filename in files:
            if not filename.endswith((".txt", ".json", ".md", ".log")):
                continue
            path = os.path.join(root, filename)
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            tokens.extend(jwt_re.findall(content))

    tokens = _dedupe_keep_order(tokens)[:25]
    summaries = []
    for token in tokens:
        parts = token.split(".")
        header = _decoded_jwt_segment(parts[0]) or {}
        payload = _decoded_jwt_segment(parts[1]) or {}
        summaries.append(
            f"alg={header.get('alg', '?')} typ={header.get('typ', '?')} "
            f"claims={','.join(sorted(payload.keys())[:8]) or '-'} token={token[:80]}"
        )

    all_urls = _collect_all_urls(domain, limit=500)
    jwks_hits = [url for url in all_urls if re.search(r"jwks\.json|openid-configuration", url, re.I)]
    if jwks_hits:
        summaries.extend([f"jwks {url}" for url in jwks_hits])

    output_path = os.path.join(jwt_dir, "jwt_audit.txt")
    summaries = _write_text_lines(output_path, summaries)
    return bool(summaries)


def generate_reports(domain):
    """Generate reports for findings."""
    findings_dir = os.path.join(FINDINGS_DIR, domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0

    log("info", f"Generating reports for {domain}...")
    script = os.path.join(TOOLS_DIR, "report_generator.py")
    success, output = run_cmd(f'python3 "{script}" "{findings_dir}"')
    print(output)

    # Count generated reports
    report_dir = os.path.join(REPORTS_DIR, domain)
    if os.path.isdir(report_dir):
        return len([f for f in os.listdir(report_dir) if f.endswith(".md") and f != "SUMMARY.md"])
    return 0


def show_status():
    """Show current pipeline status."""
    print(f"\n{BOLD}{'='*50}{NC}")
    print(f"{BOLD}  Bug Bounty Pipeline Status{NC}")
    print(f"{BOLD}{'='*50}{NC}\n")

    # Check tools
    installed, missing = check_tools()
    print(f"  Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # Check targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"  Selected targets: {data.get('total_targets', 0)}")
    else:
        print("  Selected targets: None (run target selector first)")

    # Check recon results
    if os.path.isdir(RECON_DIR):
        recon_targets = [d for d in os.listdir(RECON_DIR) if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"  Recon completed: {len(recon_targets)} targets")
        for t in recon_targets:
            subs_file = os.path.join(RECON_DIR, t, "subdomains", "all.txt")
            live_file = os.path.join(RECON_DIR, t, "live", "urls.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            print(f"    - {t}: {subs} subdomains, {live} live hosts")

    # Check findings
    if os.path.isdir(FINDINGS_DIR):
        finding_targets = [d for d in os.listdir(FINDINGS_DIR) if os.path.isdir(os.path.join(FINDINGS_DIR, d))]
        print(f"  Scanned targets: {len(finding_targets)}")
        for t in finding_targets:
            summary = os.path.join(FINDINGS_DIR, t, "summary.txt")
            if os.path.exists(summary):
                with open(summary) as f:
                    content = f.read()
                total_match = content.split("TOTAL FINDINGS:")
                if len(total_match) > 1:
                    total = total_match[1].strip().split("\n")[0].strip()
                    print(f"    - {t}: {total} findings")

    # Check reports
    if os.path.isdir(REPORTS_DIR):
        report_targets = [d for d in os.listdir(REPORTS_DIR) if os.path.isdir(os.path.join(REPORTS_DIR, d))]
        print(f"  Reports generated: {len(report_targets)} targets")
        for t in report_targets:
            reports = [f for f in os.listdir(os.path.join(REPORTS_DIR, t)) if f.endswith(".md") and f != "SUMMARY.md"]
            print(f"    - {t}: {len(reports)} reports")

    print(f"\n{'='*50}\n")


def print_dashboard(results):
    """Print final summary dashboard."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — Summary Dashboard{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_findings = 0
    total_reports = 0

    for r in results:
        status_icon = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status_icon}] {r['domain']}")
        print(f"       Recon: {'Done' if r.get('recon') else 'Skipped'} | "
              f"Scan: {'Done' if r.get('scan') else 'Skipped'} | "
              f"Reports: {r.get('reports', 0)}")
        if r.get("autopilot_mode"):
            print(f"       Autopilot mode: {r['autopilot_mode']}")
        total_findings += r.get("findings", 0)
        total_reports += r.get("reports", 0)

    print(f"\n  Total reports generated: {total_reports}")
    print(f"\n  Reports directory: {REPORTS_DIR}/")
    print(f"\n{'='*60}")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review each report in the reports/ directory")
        print("  2. Manually verify findings before submitting")
        print("  3. Add PoC screenshots where applicable")
        print("  4. Submit via HackerOne program pages")
        print(f"\n{'='*60}\n")


def run_cve_hunt(domain):
    """Run CVE hunter on a target."""
    log("info", f"Running CVE hunter on {domain}...")
    script = os.path.join(TOOLS_DIR, "cve_hunter.py")
    recon_dir = os.path.join(RECON_DIR, domain)
    recon_flag = f'--recon-dir "{recon_dir}"' if os.path.isdir(recon_dir) else ""

    try:
        proc = subprocess.Popen(
            f'python3 "{script}" "{domain}" {recon_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=600)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"CVE hunt timed out for {domain}")
        return False


def run_zero_day_fuzzer(domain, deep=False):
    """Run zero-day fuzzer on a target."""
    log("info", f"Running zero-day fuzzer on {domain}...")
    script = os.path.join(TOOLS_DIR, "zero_day_fuzzer.py")
    deep_flag = "--deep" if deep else ""

    # Check if we have recon data with live URLs
    recon_dir = os.path.join(RECON_DIR, domain)
    if os.path.isdir(recon_dir):
        cmd = f'python3 "{script}" "https://{domain}" --recon-dir "{recon_dir}" {deep_flag}'
    else:
        cmd = f'python3 "{script}" "https://{domain}" {deep_flag}'

    try:
        proc = subprocess.Popen(cmd, shell=True, cwd=BASE_DIR)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Zero-day fuzzer timed out for {domain}")
        return False


def hunt_target(domain, quick=False, recon_only=False, scan_only=False, cve_hunt=False, zero_day=False, ctf_mode=False):
    """Run the full hunt pipeline on a single target."""
    started = time.monotonic()
    result = {"domain": domain, "success": True, "recon": False, "scan": False, "reports": 0, "ctf_mode": ctf_mode}

    if ctf_mode:
        log("warn", "CTF mode enabled — treating the provided target as local practice scope.")

    if not scan_only:
        result["recon"] = run_recon(domain, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing anyway...")

    if recon_only:
        elapsed_minutes = (time.monotonic() - started) / 60.0
        _update_target_profile(domain, elapsed_minutes=elapsed_minutes, recon_completed=result["recon"])
        _auto_log_session_summary(
            domain,
            recon_completed=result["recon"],
            scan_completed=False,
            cve_hunt=False,
            zero_day=False,
        )
        return result

    result["scan"] = run_vuln_scan(domain, quick=quick)

    # CVE hunting (only when explicitly requested)
    if cve_hunt:
        run_cve_hunt(domain)

    # Zero-day fuzzing (disabled by default — high false positive rate)
    if zero_day:
        log("warn", "Zero-day fuzzer enabled — results require manual verification")
        run_zero_day_fuzzer(domain, deep=not quick)

    result["reports"] = generate_reports(domain)
    elapsed_minutes = (time.monotonic() - started) / 60.0
    recon_available = result["recon"] or os.path.isdir(os.path.join(RECON_DIR, domain))
    _update_target_profile(domain, elapsed_minutes=elapsed_minutes, recon_completed=recon_available)
    _auto_log_session_summary(
        domain,
        recon_completed=recon_available,
        scan_completed=result["scan"],
        cve_hunt=cve_hunt,
        zero_day=zero_day,
    )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Hunt Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py                            Full pipeline (select + hunt)
  python3 hunt.py --target example.com       Hunt specific target
  python3 hunt.py --quick --target example.com  Quick scan
  python3 hunt.py --target example.com --agent   Autonomous agent mode
  python3 hunt.py --status                   Show progress
  python3 hunt.py --setup-wordlists          Download wordlists
        """
    )
    parser.add_argument("--target", type=str, help="Specific target domain to hunt")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (fewer checks)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance")
    parser.add_argument("--scan-only", action="store_true", help="Only run vulnerability scanner")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--setup-wordlists", action="store_true", help="Download wordlists")
    parser.add_argument("--cve-hunt", action="store_true", help="Run CVE hunter")
    parser.add_argument("--zero-day", action="store_true", help="Run zero-day fuzzer")
    parser.add_argument("--select-targets", action="store_true", help="Only run target selection")
    parser.add_argument("--top", type=int, default=10, help="Number of targets to select")
    parser.add_argument("--agent", action="store_true", help="Run autonomous agent mode for a target")
    parser.add_argument("--langgraph", action="store_true", help="Use LangGraph backend in agent mode")
    parser.add_argument("--resume", type=str, help="Resume agent session ID")
    parser.add_argument("--cookie", type=str, default="", help="Session cookie for agent POST discovery")
    parser.add_argument("--scope-lock", action="store_true", help="Keep agent recon on the exact target only")
    parser.add_argument("--max-urls", type=int, default=100, help="Max URLs for agent recon (default 100)")
    parser.add_argument("--max-steps", type=int, default=20, help="Max autonomous agent steps (default 20)")
    parser.add_argument("--time", type=float, default=2.0, help="Agent time budget in hours (default 2)")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--paranoid", action="store_true", help="Frequent checkpoints (default)")
    mode_group.add_argument("--normal", action="store_true", help="Batch related findings before checkpointing")
    mode_group.add_argument("--yolo", action="store_true", help="Keep moving with minimal checkpoints")
    args = parser.parse_args()
    config = load_config()
    ctf_mode = is_ctf_mode(config)
    autopilot_mode = resolve_autopilot_mode(args)

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║     Bug Bounty Automation Pipeline       ║
╚══════════════════════════════════════════╝{NC}
    """)

    if ctf_mode:
        log("warn", "CTF mode enabled — scope/program checks are relaxed for local practice.")
    elif args.agent:
        log("info", f"Autopilot checkpoint mode: {autopilot_mode}")

    # Status check
    if args.status:
        show_status()
        return

    # Setup wordlists
    if args.setup_wordlists:
        setup_wordlists()
        return

    # Check tools
    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        log("warn", f"Missing tools: {', '.join(missing)}")
        log("warn", "Run: bash tools/install_tools.sh")

    # Target selection only
    if args.select_targets:
        select_targets(top_n=args.top)
        return

    # Report only
    if args.report_only:
        if args.target:
            generate_reports(args.target)
        else:
            if os.path.isdir(FINDINGS_DIR):
                for d in os.listdir(FINDINGS_DIR):
                    if os.path.isdir(os.path.join(FINDINGS_DIR, d)):
                        generate_reports(d)
        return

    if args.agent:
        if not args.target:
            log("err", "--agent requires --target")
            sys.exit(1)

        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        from agent import run_agent_hunt

        try:
            result = run_agent_hunt(
                args.target,
                scope_lock=args.scope_lock,
                max_urls=args.max_urls,
                max_steps=args.max_steps,
                time_budget_hours=args.time,
                cookies=args.cookie,
                resume_session_id=args.resume,
                use_langgraph=args.langgraph,
                ctf_mode=ctf_mode,
                autopilot_mode=autopilot_mode,
            )
        except RuntimeError as exc:
            log("err", str(exc))
            sys.exit(1)
        print_dashboard([result])
        return

    # Hunt specific target
    if args.target:
        log("info", f"Hunting target: {args.target}")

        # Setup wordlists if missing
        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        result = hunt_target(
            args.target,
            quick=args.quick,
            recon_only=args.recon_only,
            scan_only=args.scan_only,
            cve_hunt=args.cve_hunt,
            zero_day=args.zero_day,
            ctf_mode=ctf_mode,
        )
        print_dashboard([result])
        return

    # Full pipeline: select targets then hunt each
    log("info", "Starting full pipeline...")

    # Setup wordlists
    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    # Select targets
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets selected. Exiting.")
        sys.exit(1)

    # Hunt each target
    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            log("warn", f"No domains for {target.get('name', 'unknown')} — skipping")
            continue

        # Hunt the primary domain
        primary_domain = domains[0]
        log("info", f"[{i+1}/{len(targets)}] Hunting: {target.get('name', primary_domain)}")
        log("info", f"  Domain: {primary_domain}")
        log("info", f"  Program: {target.get('url', 'N/A')}")

        result = hunt_target(primary_domain, quick=args.quick, ctf_mode=ctf_mode)
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()
