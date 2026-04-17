#!/usr/bin/env python3
"""
autopilot_state.py — combine resume + surface context into one practical state view.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.target_profile import default_memory_dir
from request_guard import load_guard_status
from resume import load_resume_summary
from surface import load_surface_context, rank_surface


def _matches_resume_target(url: str, resume_targets: list[str]) -> bool:
    """Check whether a ranked URL matches any remembered resume target path."""
    parsed = urlparse(url or "")
    normalized = parsed.path or "/"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    for target in resume_targets:
        candidate = str(target or "").strip()
        if not candidate:
            continue
        if normalized == candidate or normalized.endswith(candidate):
            return True
    return False


def _build_recommended_targets(
    p1: list[dict],
    guard_status: dict,
    resume_targets: list[str] | None = None,
    *,
    prefer_resume_targets: bool = False,
) -> list[dict]:
    """Prefer non-tripped hosts first, then optionally front-load resume targets within a bucket."""
    host_status = {
        item.get("host", ""): item
        for item in guard_status.get("hosts", [])
        if item.get("host")
    }

    preferred = resume_targets or []
    recommended = []
    for item in p1:
        status = host_status.get(item.get("host", ""), {})
        recommended.append({
            "url": item.get("url", ""),
            "host": item.get("host", ""),
            "suggested": item.get("suggested", ""),
            "score": item.get("score", 0),
            "tripped": bool(status.get("tripped", False)),
            "remaining_seconds": float(status.get("remaining_seconds", 0.0) or 0.0),
            "matches_resume_target": _matches_resume_target(item.get("url", ""), preferred),
        })

    recommended.sort(
        key=lambda item: (
            item["tripped"],
            0 if (prefer_resume_targets and item["matches_resume_target"]) else 1,
            -item["score"],
            item["url"],
        )
    )
    return recommended[:5]


def _build_resume_targets(summary: dict | None) -> list[str]:
    """Prefer continuing the latest session focus, then fall back to untested endpoints."""
    if not summary:
        return []

    latest_session = summary.get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]
    if preview:
        return list(dict.fromkeys(preview))[:3]

    untested = [item for item in summary.get("untested_endpoints", []) if item]
    if not untested:
        return []
    return untested[:3]


def _pick_next_action(has_recon: bool, ranked: dict, resume_summary: dict | None) -> str:
    """Bias toward resumable session context before widening to generic P1/P2 surface."""
    if not has_recon:
        return "run_recon"

    resume_targets = _build_resume_targets(resume_summary)
    latest_session = (resume_summary or {}).get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]

    if latest_session and preview:
        return "continue_last_focus"
    if latest_session and resume_targets:
        return "resume_untested"

    if ranked.get("p1"):
        return "hunt_p1"
    if ranked.get("p2"):
        return "hunt_p2"
    if resume_summary and resume_summary.get("untested_endpoints"):
        return "resume_untested"
    return "refresh_recon"


def _describe_next_step(state: dict) -> str:
    """Render a human-friendly next-step hint from the computed state."""
    action = state.get("next_action", "")
    target = state.get("target", "target")
    resume_targets = state.get("resume_targets", []) or []
    recommended_targets = state.get("recommended_targets", []) or []
    tripped_hosts = (state.get("guard_status", {}) or {}).get("tripped_hosts", []) or []

    if action == "run_recon":
        return f"run /recon {target} first."
    if action == "continue_last_focus":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "the last focus endpoints"
        return f"continue testing the last focus first: {focus}."
    if action == "resume_untested":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "cached untested endpoints"
        return f"resume the cached untested surface first: {focus}."
    if action == "hunt_p1":
        if recommended_targets:
            first_item = recommended_targets[0]
            first = first_item["url"]
            if first_item.get("tripped"):
                return (
                    f"the top P1 host is cooling down; avoid it for now and pivot until cooldown clears: "
                    f"{first}."
                )
            if tripped_hosts:
                return f"avoid cooling hosts and start with the top ready P1 target: {first}."
            return f"start with the top P1 target: {first}."
        return "start with the top P1 target."
    if action == "hunt_p2":
        return "widen into the P2 surface after P1 paths are exhausted."
    if action == "refresh_recon":
        return f"refresh recon before going deeper on {target}."
    return "follow the highest-confidence target shown below."


def _build_guard_hint(guard_status: dict, recommended_targets: list[dict]) -> str:
    """Render an operator/agent-friendly guard hint for immediate action."""
    tripped_hosts = [item for item in (guard_status.get("tripped_hosts", []) or []) if item.get("host")]
    ready_target = next((item for item in recommended_targets if not item.get("tripped")), None)

    if tripped_hosts:
        blocked = ", ".join(
            f"{item['host']} ({float(item.get('remaining_seconds', 0.0) or 0.0):.1f}s)"
            for item in tripped_hosts[:3]
        )
        if ready_target:
            return (
                f"avoid cooling hosts: {blocked}; prefer the ready host "
                f"{ready_target.get('host', '')} via {ready_target.get('url', '')}"
            )
        return (
            f"all tracked hot hosts are cooling down: {blocked}; pivot to quieter surface, "
            f"repo/source artifacts, or recon refresh until cooldown clears"
        )

    if ready_target and int(guard_status.get("tracked_hosts", 0) or 0) > 0:
        return f"prefer the ready host {ready_target.get('host', '')} via {ready_target.get('url', '')}"

    return ""


def _has_repo_source_artifacts(repo_root: str, target: str) -> bool:
    return bool(_list_repo_source_artifacts(repo_root, target))


def _list_repo_source_artifacts(repo_root: str, target: str) -> list[str]:
    exposure_dir = os.path.join(repo_root, "findings", target, "exposure")
    if not os.path.isdir(exposure_dir):
        return []

    known_artifacts = (
        "repo_source_meta.json",
        "repo_secrets.json",
        "repo_ci_findings.json",
        "repo_summary.md",
    )
    return [
        name for name in known_artifacts
        if os.path.isfile(os.path.join(exposure_dir, name))
    ]


def build_autopilot_state(repo_root: str, target: str, memory_dir: str | None = None) -> dict:
    """Build a practical autopilot bootstrap state for a target."""
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resume_summary = load_resume_summary(resolved_memory_dir, target)
    ranked = rank_surface(load_surface_context(repo_root, target, memory_dir=resolved_memory_dir))
    guard_status = load_guard_status(resolved_memory_dir, target)
    tripped_hosts = [item for item in guard_status.get("hosts", []) if item.get("tripped")]
    repo_source_artifacts = _list_repo_source_artifacts(repo_root, target)
    repo_source_available = bool(repo_source_artifacts)

    has_recon = bool(ranked.get("available"))
    has_memory = resume_summary is not None
    resume_targets = _build_resume_targets(resume_summary)

    tech_stack = []
    if resume_summary and resume_summary.get("tech_stack"):
        tech_stack = resume_summary["tech_stack"]
    elif has_recon:
        p1 = ranked.get("p1", [])
        if p1:
            tech_stack = p1[0].get("tech_stack", [])

    next_action = _pick_next_action(has_recon, ranked, resume_summary)
    prefer_resume_targets = next_action == "continue_last_focus"
    recommended_targets = (
        _build_recommended_targets(
            ranked.get("p1", []),
            guard_status,
            resume_targets,
            prefer_resume_targets=prefer_resume_targets,
        )
        if has_recon else []
    )
    guard_state = {
        "tracked_hosts": guard_status.get("tracked_hosts", 0),
        "tripped_hosts": tripped_hosts,
        "settings": guard_status.get("settings", {}),
    }

    return {
        "target": target,
        "memory_dir": resolved_memory_dir,
        "has_recon": has_recon,
        "has_memory": has_memory,
        "repo_source_available": repo_source_available,
        "repo_source_artifacts": repo_source_artifacts,
        "resume_summary": resume_summary,
        "surface": ranked if has_recon else None,
        "guard_status": guard_state,
        "guard_hint": _build_guard_hint(guard_state, recommended_targets),
        "tech_stack": tech_stack,
        "next_action": next_action,
        "resume_targets": resume_targets,
        "recommended_targets": recommended_targets,
    }


def format_autopilot_state(state: dict) -> str:
    """Format autopilot bootstrap state for terminal display."""
    summary = state.get("resume_summary") or {}
    latest_session = summary.get("latest_session_summary") or {}

    if not state["has_recon"]:
        lines = [
            f"AUTOPILOT STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            "Recon: missing",
            f"Memory: {'available' if state['has_memory'] else 'missing'}",
        ]
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
        if state.get("repo_source_available"):
            lines.append("Repo source: available — use read_repo_source_summary")
        lines.append(f"Next: {_describe_next_step(state)}")
        guard_hint = str(state.get("guard_hint", "") or "").strip()
        if guard_hint:
            lines.append(f"Guard hint: {guard_hint}")
        return "\n".join(lines) + "\n"

    surface = state["surface"] or {}
    lines = [
        f"AUTOPILOT STATE: {state['target']}",
        "═══════════════════════════════════════",
        "",
        f"Recon: ready",
        f"Memory: {'available' if state['has_memory'] else 'missing'}",
        f"Next action: {state['next_action']}",
        f"Next step: {_describe_next_step(state)}",
    ]

    guard_status = state.get("guard_status", {})
    lines.append(
        f"Guard: {guard_status.get('tracked_hosts', 0)} tracked host(s), {len(guard_status.get('tripped_hosts', []))} tripped"
    )
    guard_hint = str(state.get("guard_hint", "") or "").strip()
    if guard_hint:
        lines.append(f"Guard hint: {guard_hint}")
    if state.get("repo_source_available"):
        lines.append("Repo source: available — use read_repo_source_summary")

    if state["tech_stack"]:
        lines.append(f"Tech stack: {', '.join(state['tech_stack'])}")

    if summary:
        lines.append(f"Sessions: {summary.get('sessions', 0)}")
        lines.append(f"Untested endpoints: {len(summary.get('untested_endpoints', []))}")
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
            if latest_session.get("endpoints_preview"):
                lines.append(
                    f"Last endpoints: {', '.join(latest_session['endpoints_preview'][:2])}"
                )
        if state.get("resume_targets"):
            lines.append(f"Resume targets: {', '.join(state['resume_targets'][:3])}")

    lines.append(f"P1 targets: {surface.get('stats', {}).get('p1', 0)}")
    lines.append(f"P2 targets: {surface.get('stats', {}).get('p2', 0)}")

    tripped_hosts = guard_status.get("tripped_hosts", [])
    if tripped_hosts:
        lines.append("Cooling down hosts:")
        for item in tripped_hosts[:3]:
            lines.append(
                f"- {item['host']} ({item['remaining_seconds']:.1f}s remaining)"
            )

    if state["recommended_targets"]:
        lines.append("")
        lines.append("Recommended first targets:")
        for idx, item in enumerate(state["recommended_targets"], 1):
            suffix = (
                f" [cooldown {item['remaining_seconds']:.1f}s]"
                if item.get("tripped")
                else ""
            )
            lines.append(
                f"{idx}. {item['url']} — {item['suggested']} (score {item['score']}){suffix}"
            )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build combined autopilot state for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    state = build_autopilot_state(BASE_DIR, args.target, memory_dir=args.memory_dir or None)
    if args.json:
        print(json.dumps(state, indent=2))
        return
    print(format_autopilot_state(state))


if __name__ == "__main__":
    main()
