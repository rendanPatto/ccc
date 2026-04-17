#!/usr/bin/env python3
"""
resume.py — summarize prior hunt state for a target from hunt memory.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.target_profile import default_memory_dir, load_target_profile

_SESSION_SUMMARY_RE = re.compile(
    r"Endpoints tested:\s*(?P<endpoints_count>\d+)\.\s*"
    r"Vuln classes tried:\s*(?P<vuln_classes>.*?)\.\s*"
    r"Findings:\s*(?P<findings_count>\d+)\."
    r"(?:\s*Session:\s*(?P<session_id>[^.]+)\.)?"
)


def format_minutes(total_minutes: int | float) -> str:
    minutes = int(round(float(total_minutes or 0)))
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins:02d}m"


def _split_preview_list(raw: str) -> list[str]:
    value = str(raw or "").strip()
    if not value or value in {"none", "session"}:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_session_summary_entry(entry: dict) -> dict:
    """Parse the standardized auto session summary journal entry into structured fields."""
    notes = str(entry.get("notes", "") or "")
    endpoint_preview = _split_preview_list(str(entry.get("endpoint", "")))
    parsed = {
        "ts": entry.get("ts", ""),
        "action": entry.get("action", ""),
        "session_id": "",
        "findings_count": 0,
        "endpoints_count": len(endpoint_preview),
        "endpoints_preview": endpoint_preview[:3],
        "vuln_classes": [],
        "raw_notes": notes,
    }

    match = _SESSION_SUMMARY_RE.search(notes)
    if not match:
        return parsed

    parsed["session_id"] = (match.group("session_id") or "").strip()
    parsed["findings_count"] = int(match.group("findings_count") or 0)
    parsed["endpoints_count"] = int(match.group("endpoints_count") or 0)

    vuln_classes_raw = (match.group("vuln_classes") or "").strip()
    if vuln_classes_raw and vuln_classes_raw != "none":
        parsed["vuln_classes"] = [
            item.strip()
            for item in vuln_classes_raw.split(",")
            if item.strip()
        ]

    return parsed


def latest_session_summary(entries: list[dict]) -> dict | None:
    """Return the most recent auto-logged session summary entry, if any."""
    session_entries = [
        entry for entry in entries
        if entry.get("vuln_class") == "session_summary"
    ]
    if not session_entries:
        return None
    return parse_session_summary_entry(session_entries[-1])


def recent_guard_blocks(entries: list[dict], *, limit: int = 3) -> list[dict]:
    """Return the most recent auto-logged request-guard block notes."""
    blocks = []
    for entry in reversed(entries):
        if entry.get("vuln_class") != "guard_block":
            continue
        blocks.append({
            "ts": entry.get("ts", ""),
            "action": entry.get("action", ""),
            "endpoint": entry.get("endpoint", ""),
            "notes": str(entry.get("notes", "") or ""),
        })
        if len(blocks) >= limit:
            break
    return list(reversed(blocks))


def load_resume_summary(memory_dir: str | Path, target: str) -> dict | None:
    """Load the minimum data needed to resume a target hunt."""
    memory_dir = Path(memory_dir)
    profile = load_target_profile(memory_dir, target)
    if profile is None:
        return None

    journal = HuntJournal(memory_dir / "journal.jsonl")
    entries = journal.query(target=target)
    confirmed_entries = [entry for entry in entries if entry.get("result") == "confirmed"]
    confirmed_payout = round(sum(float(entry.get("payout", 0) or 0) for entry in confirmed_entries), 2)
    latest_session = latest_session_summary(entries)

    pattern_db = PatternDB(memory_dir / "patterns.jsonl")
    pattern_matches = []
    seen = set()
    for pattern in pattern_db.match(tech_stack=profile.get("tech_stack", [])):
        if pattern.get("target") == target:
            continue
        key = (pattern.get("target", ""), pattern.get("technique", ""), pattern.get("vuln_class", ""))
        if key in seen:
            continue
        seen.add(key)
        pattern_matches.append({
            "target": pattern.get("target", ""),
            "technique": pattern.get("technique", ""),
            "vuln_class": pattern.get("vuln_class", ""),
            "payout": pattern.get("payout", 0),
        })

    findings = profile.get("findings", [])
    finding_titles = []
    for finding in findings[:3]:
        vuln = finding.get("vuln_class") or finding.get("type") or "finding"
        endpoint = finding.get("endpoint") or finding.get("url") or ""
        payout = finding.get("payout", 0)
        finding_titles.append({
            "vuln_class": vuln,
            "endpoint": endpoint,
            "payout": payout,
        })

    return {
        "target": target,
        "sessions": int(profile.get("hunt_sessions", 0)),
        "last_hunted": profile.get("last_hunted", ""),
        "total_time_minutes": round(float(profile.get("total_time_minutes", 0) or 0), 2),
        "tech_stack": profile.get("tech_stack", []),
        "tested_endpoints": profile.get("tested_endpoints", []),
        "untested_endpoints": profile.get("untested_endpoints", []),
        "findings": findings,
        "finding_titles": finding_titles,
        "journal_entries": len(entries),
        "confirmed_findings": len(confirmed_entries),
        "confirmed_payout": confirmed_payout,
        "pattern_matches": pattern_matches[:5],
        "matched_targets": len({item["target"] for item in pattern_matches}),
        "latest_session_summary": latest_session,
        "recent_guard_blocks": recent_guard_blocks(entries),
    }


def format_resume_output(summary: dict | None, target: str) -> str:
    """Format a resume summary for terminal display."""
    if summary is None:
        return (
            f"No previous hunt data for {target}.\n"
            f"Run /recon {target} first, then /hunt {target}."
        )

    lines = [
        f"RESUME: {target}",
        "═══════════════════════════════════════",
        "",
        "Hunt History:",
        f"  Sessions:    {summary['sessions']}",
        f"  Last hunt:   {summary['last_hunted'] or 'unknown'}",
        f"  Total time:  {format_minutes(summary['total_time_minutes'])}",
        f"  Journal:     {summary['journal_entries']} entries",
    ]

    if summary["confirmed_findings"]:
        lines.append(
            f"  Findings:    {summary['confirmed_findings']} confirmed (${summary['confirmed_payout']:.0f} total)"
        )
    else:
        lines.append("  Findings:    0 confirmed")

    if summary["finding_titles"]:
        lines.append("")
        lines.append("Recent Findings:")
        for item in summary["finding_titles"]:
            payout = f" (${item['payout']:.0f})" if item.get("payout") else ""
            endpoint = f" on {item['endpoint']}" if item.get("endpoint") else ""
            lines.append(f"  - {item['vuln_class']}{endpoint}{payout}")

    latest_session = summary.get("latest_session_summary")
    if latest_session:
        lines.append("")
        lines.append("Latest Session Snapshot:")
        lines.append(f"  Time: {latest_session.get('ts') or 'unknown'}")
        if latest_session.get("session_id"):
            lines.append(f"  Session: {latest_session['session_id']}")
        tried = latest_session.get("vuln_classes", [])
        lines.append(
            f"  Tried: {', '.join(tried) if tried else 'none'}"
        )
        lines.append(
            f"  Findings in session: {int(latest_session.get('findings_count', 0) or 0)}"
        )
        preview = latest_session.get("endpoints_preview", [])
        if preview:
            lines.append(f"  Endpoint sample: {', '.join(preview)}")

    guard_blocks = summary.get("recent_guard_blocks", [])
    if guard_blocks:
        lines.append("")
        lines.append("Recent Guard Blocks:")
        for item in guard_blocks[:3]:
            details = item.get("notes", "") or item.get("endpoint", "")
            lines.append(f"  - {details}")

    lines.append("")
    lines.append("Untested Surface:")
    untested = summary["untested_endpoints"]
    if untested:
        lines.append(f"  {len(untested)} endpoints from last recon:")
        for idx, endpoint in enumerate(untested[:5], 1):
            lines.append(f"  {idx}. {endpoint}")
    else:
        lines.append("  No cached untested endpoints. Consider re-running recon.")

    lines.append("")
    lines.append("Memory Suggestions:")
    if summary["tech_stack"]:
        lines.append(f"  Tech stack: [{', '.join(summary['tech_stack'])}]")
    if summary["pattern_matches"]:
        lines.append(f"  Matches {summary['matched_targets']} past targets:")
        for item in summary["pattern_matches"][:3]:
            payout = f" (${item['payout']:.0f})" if item.get("payout") else ""
            lines.append(
                f"  - {item['target']}: {item['technique']} [{item['vuln_class']}]{payout}"
            )
    else:
        lines.append("  No cross-target pattern matches yet.")

    lines.extend([
        "",
        "Actions:",
        "  [r] Resume hunting untested endpoints",
        "  [n] Re-run recon first (surface may have changed)",
        "  [s] Show full hunt journal for this target",
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resume a target hunt from hunt memory")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    summary = load_resume_summary(memory_dir, args.target)

    if args.json:
        print(json.dumps({"summary": summary}, indent=2))
        return

    print(format_resume_output(summary, args.target))


if __name__ == "__main__":
    main()
