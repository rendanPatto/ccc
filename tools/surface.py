#!/usr/bin/env python3
"""
surface.py — rank cached recon output using hunt memory context.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.pattern_db import PatternDB
from memory.target_profile import default_memory_dir, load_target_profile


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _read_httpx_hosts(recon_dir: Path) -> tuple[dict[str, dict], set[str]]:
    """Parse live/httpx_full.txt into host metadata and 403-only hosts."""
    httpx_path = recon_dir / "live" / "httpx_full.txt"
    hosts = {}
    status403 = set()
    if not httpx_path.is_file():
        return hosts, status403

    with open(httpx_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if not parts:
                continue
            url = parts[0]
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path
            matches = re.findall(r"\[([^\]]+)\]", line)
            status = matches[0] if len(matches) >= 1 else ""
            title = matches[1] if len(matches) >= 2 else ""
            techs = []
            if len(matches) >= 3:
                techs = [item.strip().lower() for item in matches[2].split(",") if item.strip()]
            hosts[host] = {
                "url": url,
                "host": host,
                "status": status,
                "title": title,
                "tech_stack": techs,
            }
            if status == "403":
                status403.add(host)
    return hosts, status403


def _candidate_reason(path: str, query_keys: list[str]) -> tuple[str, str]:
    lower = path.lower()
    if "graphql" in lower:
        return "GraphQL surface", "field-level auth checks and mutation abuse"
    if lower.startswith("/ws") or "websocket" in lower or lower.endswith("/ws"):
        return "WebSocket candidate", "authorization checks on subscribe/send actions"
    if any(key in {"id", "user_id", "account_id", "order_id"} or key.endswith("_id") for key in query_keys):
        return "ID-bearing parameter", "ID swap and sibling endpoint access control checks"
    if re.search(r"/\d{1,8}(?:/|$)", path):
        return "Sequential object reference", "numeric ID swap on GET/PUT/DELETE"
    if query_keys:
        return "Parameterized endpoint", "input tampering and auth boundary checks"
    return "API endpoint", "baseline authz and business-logic checks"


def load_surface_context(repo_root: str | Path, target: str, memory_dir: str | Path | None = None) -> dict:
    """Load recon + memory data for surface ranking."""
    repo_root = Path(repo_root)
    recon_dir = repo_root / "recon" / target
    if not recon_dir.is_dir():
        return {"target": target, "available": False}

    hosts, status403_hosts = _read_httpx_hosts(recon_dir)
    api_urls = _read_lines(recon_dir / "urls" / "api_endpoints.txt")
    param_urls = _read_lines(recon_dir / "urls" / "with_params.txt")
    js_endpoints = _read_lines(recon_dir / "js" / "endpoints.txt")

    profile = None
    pattern_matches = []
    if memory_dir:
        profile = load_target_profile(memory_dir, target)
        tech_stack = profile.get("tech_stack", []) if profile else []
        if tech_stack:
            pattern_db = PatternDB(Path(memory_dir) / "patterns.jsonl")
            for pattern in pattern_db.match(tech_stack=tech_stack):
                if pattern.get("target") == target:
                    continue
                pattern_matches.append({
                    "target": pattern.get("target", ""),
                    "technique": pattern.get("technique", ""),
                    "vuln_class": pattern.get("vuln_class", ""),
                    "payout": pattern.get("payout", 0),
                })

    return {
        "target": target,
        "available": True,
        "recon_dir": str(recon_dir),
        "hosts": hosts,
        "status403_hosts": status403_hosts,
        "api_urls": api_urls,
        "param_urls": param_urls,
        "js_endpoints": js_endpoints,
        "profile": profile,
        "pattern_matches": _dedupe_keep_order(
            [json.dumps(item, sort_keys=True) for item in pattern_matches]
        ),
    }


def rank_surface(context: dict) -> dict:
    """Rank attack surface candidates into P1/P2/Kill sections."""
    if not context.get("available"):
        return {"available": False, "target": context.get("target", "")}

    profile = context.get("profile") or {}
    tested_endpoints = set(profile.get("tested_endpoints", []))
    untested_endpoints = set(profile.get("untested_endpoints", []))
    profile_tech = {tech.lower() for tech in profile.get("tech_stack", [])}

    pattern_matches = [
        json.loads(item) if isinstance(item, str) else item
        for item in context.get("pattern_matches", [])
    ]
    pattern_techniques = []
    for item in pattern_matches:
        technique = item.get("technique", "")
        vuln_class = item.get("vuln_class", "")
        payout = item.get("payout", 0)
        suffix = f" (${payout:.0f})" if payout else ""
        pattern_techniques.append(f"{item.get('target', '')}: {technique} [{vuln_class}]{suffix}")

    candidates = []
    raw_urls = _dedupe_keep_order(context["api_urls"] + context["param_urls"])
    js_full_urls = []
    default_host = ""
    if context["hosts"]:
        default_host = next(iter(context["hosts"].values())).get("url", "")
    for endpoint in context["js_endpoints"]:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            js_full_urls.append(endpoint)
        elif default_host:
            js_full_urls.append(default_host.rstrip("/") + endpoint)

    raw_urls = _dedupe_keep_order(raw_urls + js_full_urls)

    for raw_url in raw_urls:
        parsed = urlparse(raw_url)
        host = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        query_keys = [key.lower() for key in re.findall(r"[?&]([^=&]+)=", raw_url)]
        score = 0
        reasons = []
        reason_label, suggested = _candidate_reason(path, query_keys)
        reasons.append(reason_label)

        if "graphql" in path.lower() or "ws" in path.lower():
            score += 8
        if re.search(r"/\d{1,8}(?:/|$)", path) or any(
            key in {"id", "user_id", "account_id", "order_id"} or key.endswith("_id")
            for key in query_keys
        ):
            score += 5
        if raw_url in context["api_urls"] or "/api/" in path.lower():
            score += 4
        if query_keys:
            score += 2
        if host and ":" in host:
            port = host.rsplit(":", 1)[-1]
            if port not in {"80", "443"}:
                score += 2
                reasons.append("non-standard port")

        host_tech = set(context["hosts"].get(host, {}).get("tech_stack", []))
        if profile_tech and host_tech & profile_tech:
            score += 2
            reasons.append("tech stack overlap")

        if path in untested_endpoints:
            score += 3
            reasons.append("untested in memory")
        if path in tested_endpoints:
            score -= 3
            reasons.append("tested before")

        for item in pattern_matches:
            if item.get("technique") and profile_tech:
                score += 1
                break

        entry = {
            "url": raw_url,
            "host": host,
            "path": path,
            "score": score,
            "reasons": reasons,
            "suggested": suggested,
            "tech_stack": context["hosts"].get(host, {}).get("tech_stack", []),
            "tested": path in tested_endpoints,
        }
        candidates.append(entry)

    kill = []
    for host, item in context["hosts"].items():
        lower_host = host.lower()
        title = item.get("title", "").lower()
        if any(token in lower_host for token in ("docs.", "status.", "blog.", "static.", "cdn.")):
            kill.append({"host": host, "reason": "likely docs/static/support host"})
            continue
        if host in context["status403_hosts"]:
            kill.append({"host": host, "reason": "403-only host from recon"})
            continue
        if any(token in title for token in ("documentation", "status page", "help center")):
            kill.append({"host": host, "reason": f"title suggests low-value surface: {item.get('title', '')}"})

    candidates.sort(key=lambda item: item["score"], reverse=True)
    p1 = [item for item in candidates if item["score"] >= 8][:8]
    p2 = [item for item in candidates if 3 <= item["score"] < 8][:8]

    return {
        "available": True,
        "target": context["target"],
        "p1": p1,
        "p2": p2,
        "kill": _dedupe_keep_order([json.dumps(item, sort_keys=True) for item in kill]),
        "memory": {
            "tested_count": len(tested_endpoints),
            "untested_count": len(untested_endpoints),
            "pattern_suggestions": pattern_techniques[:3],
        },
        "stats": {
            "total_candidates": len(candidates),
            "p1": len(p1),
            "p2": len(p2),
            "kill": len(kill),
        },
    }


def format_surface_output(ranked: dict, target: str) -> str:
    """Format ranked surface output for terminal display."""
    if not ranked.get("available"):
        return (
            f"No recon data found for {target}.\n"
            f"Run /recon {target} first."
        )

    kill_items = [
        json.loads(item) if isinstance(item, str) else item
        for item in ranked.get("kill", [])
    ]

    lines = [
        f"ATTACK SURFACE: {target}",
        "═══════════════════════════════════════",
        "",
        "Priority 1 (start here):",
    ]
    if ranked["p1"]:
        for idx, item in enumerate(ranked["p1"], 1):
            reason = ", ".join(item["reasons"][:2])
            lines.append(f"{idx}. {item['url']} — {reason}")
            if item["tech_stack"]:
                lines.append(f"   Tech: {', '.join(item['tech_stack'])}")
            lines.append(f"   Suggested: {item['suggested']}")
    else:
        lines.append("1. No clear P1 candidates from cached recon.")

    lines.extend(["", "Priority 2 (after P1):"])
    if ranked["p2"]:
        for idx, item in enumerate(ranked["p2"], 1):
            reason = ", ".join(item["reasons"][:2])
            lines.append(f"{idx}. {item['url']} — {reason}")
            lines.append(f"   Suggested: {item['suggested']}")
    else:
        lines.append("1. No P2 candidates. Consider re-running recon.")

    lines.extend(["", "Kill List (skip):"])
    if kill_items:
        for item in kill_items[:5]:
            lines.append(f"- {item['host']} — {item['reason']}")
    else:
        lines.append("- No obvious low-value hosts from cached recon.")

    lines.extend(["", "Memory:"])
    for item in ranked["memory"]["pattern_suggestions"]:
        lines.append(f"- Pattern: {item}")
    lines.append(
        f"- Tested endpoints: {ranked['memory']['tested_count']}, untested remain: {ranked['memory']['untested_count']}"
    )

    lines.extend([
        "",
        "Stats:",
        f"- Total candidates: {ranked['stats']['total_candidates']}",
        f"- P1: {ranked['stats']['p1']}",
        f"- P2: {ranked['stats']['p2']}",
        f"- Kill list: {ranked['stats']['kill']}",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rank cached recon output using hunt memory")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    context = load_surface_context(BASE_DIR, args.target, memory_dir=memory_dir)
    ranked = rank_surface(context)
    if args.json:
        print(json.dumps(ranked, indent=2))
        return
    print(format_surface_output(ranked, args.target))


if __name__ == "__main__":
    main()
