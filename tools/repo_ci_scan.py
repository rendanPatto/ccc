from __future__ import annotations

import re
from pathlib import Path

import yaml

from repo_scan_models import RepoFinding

UNTRUSTED_EVENTS = {"pull_request", "pull_request_target", "issue_comment"}
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_CONTEXT_RE = re.compile(
    r"\${{\s*github\.event\.(pull_request|issue|comment)\.(title|body|head\.ref|head\.label)\s*}}"
)


def _workflow_files(repo_path: str) -> list[Path]:
    workflow_root = Path(repo_path) / ".github" / "workflows"
    if not workflow_root.is_dir():
        return []
    return sorted(
        path for path in workflow_root.iterdir() if path.suffix.lower() in {".yml", ".yaml"}
    )


def _event_names(raw_on) -> set[str]:
    if isinstance(raw_on, str):
        return {raw_on}
    if isinstance(raw_on, list):
        return {str(item) for item in raw_on}
    if isinstance(raw_on, dict):
        return {str(name) for name in raw_on.keys()}
    return set()


def _append_finding(
    findings: list[RepoFinding],
    rule_id: str,
    file_path: str,
    title: str,
    severity: str,
    metadata: dict | None = None,
) -> None:
    findings.append(
        RepoFinding(
            rule_id=rule_id,
            category="ci",
            severity=severity,
            confidence="high",
            source="builtin",
            file_path=file_path,
            line_number=None,
            match_type="workflow-rule",
            title=title,
            evidence_snippet=file_path,
            remediation="Review the workflow trigger, runner trust boundary, and action pinning",
            metadata=metadata or {},
        )
    )


def scan_repo_ci(repo_path: str) -> list[RepoFinding]:
    findings: list[RepoFinding] = []

    for workflow_file in _workflow_files(repo_path):
        raw_text = workflow_file.read_text(encoding="utf-8", errors="replace")
        workflow = yaml.safe_load(raw_text) or {}
        raw_on = workflow.get("on")
        if raw_on is None and True in workflow:
            raw_on = workflow.get(True)
        events = _event_names(raw_on)
        relative_path = workflow_file.relative_to(repo_path).as_posix()
        jobs = workflow.get("jobs") or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            runs_on = job.get("runs-on")
            if isinstance(runs_on, list):
                runner_labels = {str(item) for item in runs_on}
            elif runs_on:
                runner_labels = {str(runs_on)}
            else:
                runner_labels = set()

            steps = job.get("steps") or []
            uses_values = [str(step.get("uses") or "") for step in steps if isinstance(step, dict)]
            run_values = [str(step.get("run") or "") for step in steps if isinstance(step, dict)]

            if "pull_request_target" in events and any(value.startswith("actions/checkout@") for value in uses_values):
                _append_finding(
                    findings,
                    "pull-request-target-checkout",
                    relative_path,
                    "pull_request_target workflow checks out attacker-controlled code",
                    "high",
                    {"job": job_name},
                )

            if runner_labels & {"self-hosted"} and events & UNTRUSTED_EVENTS:
                _append_finding(
                    findings,
                    "self-hosted-untrusted-trigger",
                    relative_path,
                    "Self-hosted runner processes untrusted trigger source",
                    "high",
                    {"job": job_name},
                )

            if any(UNSAFE_CONTEXT_RE.search(run_text) for run_text in run_values):
                _append_finding(
                    findings,
                    "unsafe-user-input-in-run",
                    relative_path,
                    "User-controlled GitHub context is interpolated directly into run steps",
                    "high",
                    {"job": job_name},
                )

            for uses_value in uses_values:
                if not uses_value or uses_value.startswith(("actions/", "docker://", "./")):
                    continue
                if "@" not in uses_value:
                    continue
                ref = uses_value.split("@", 1)[1]
                if not SHA_PIN_RE.fullmatch(ref):
                    _append_finding(
                        findings,
                        "unpinned-third-party-action",
                        relative_path,
                        "Third-party GitHub Action is not pinned to a full commit SHA",
                        "medium",
                        {"job": job_name, "uses": uses_value},
                    )

    deduped: dict[tuple[str, str, str], RepoFinding] = {}
    for finding in findings:
        job_name = str(finding.metadata.get("job") or "")
        deduped.setdefault((finding.rule_id, finding.file_path, job_name), finding)
    return list(deduped.values())
