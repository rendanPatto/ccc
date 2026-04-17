from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from repo_scan_models import RepoFinding

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "dist", "build", "__pycache__", ".venv"}
MAX_TEXT_FILE_BYTES = 1024 * 1024

HIGH_SIGNAL_RULES = [
    ("private-key-rsa", re.compile(r"BEGIN RSA PRIVATE KEY"), "Private RSA key material found"),
    ("private-key-openssh", re.compile(r"BEGIN OPENSSH PRIVATE KEY"), "OpenSSH private key material found"),
    ("private-key-ec", re.compile(r"BEGIN EC PRIVATE KEY"), "EC private key material found"),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID found"),
    ("github-token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"), "GitHub token found"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token found"),
    ("stripe-key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"), "Stripe key found"),
    ("bearer-token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"), "Hardcoded bearer token found"),
]
LOW_CONFIDENCE_KEYS = re.compile(r"(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|password|token)")
LOW_CONFIDENCE_VALUE = re.compile(r"""["']([A-Za-z0-9/_+=.\-]{12,})["']""")
CONFIG_FILE_PATTERNS = [
    re.compile(r"(^|/)\.env(\..+)?$"),
    re.compile(r"(^|/)config[^/]*\.(yml|yaml|json)$", re.I),
    re.compile(r"(^|/)secrets\.[^/]+$", re.I),
    re.compile(r"(^|/)service[-_ ]account[^/]*\.json$", re.I),
]


def _iter_repo_files(repo_path: str):
    root = Path(repo_path)
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for filename in files:
            file_path = Path(current_root) / filename
            if file_path.stat().st_size > MAX_TEXT_FILE_BYTES:
                continue
            yield file_path, file_path.relative_to(root).as_posix()


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:2048]:
        return ""
    return data.decode("utf-8", errors="replace")


def _mask_secret(value: str) -> str:
    compact = value.strip()
    if len(compact) <= 8:
        return compact
    return f"{compact[:4]}...{compact[-4:]}"


def _append_finding(findings: list[RepoFinding], **kwargs) -> None:
    findings.append(RepoFinding(**kwargs))


def _scan_builtin(repo_path: str) -> list[RepoFinding]:
    findings: list[RepoFinding] = []

    for file_path, relative_path in _iter_repo_files(repo_path):
        text = _read_text(file_path)
        if not text:
            continue

        for pattern in CONFIG_FILE_PATTERNS:
            if pattern.search(relative_path):
                _append_finding(
                    findings,
                    rule_id="config-env-file" if ".env" in relative_path else "config-sensitive-file",
                    category="config",
                    severity="high" if ".env" in relative_path or "service" in relative_path.lower() else "medium",
                    confidence="high",
                    source="builtin",
                    file_path=relative_path,
                    line_number=1,
                    match_type="filename",
                    title="Sensitive configuration file committed to repository",
                    evidence_snippet=relative_path,
                    remediation="Remove the file from source control and rotate any exposed credentials",
                )
                break

        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern, title in HIGH_SIGNAL_RULES:
                match = pattern.search(line)
                if not match:
                    continue
                secret_value = match.group(0)
                _append_finding(
                    findings,
                    rule_id=rule_id,
                    category="secret",
                    severity="high",
                    confidence="high",
                    source="builtin",
                    file_path=relative_path,
                    line_number=line_number,
                    match_type="pattern",
                    title=title,
                    secret_preview=_mask_secret(secret_value),
                    evidence_snippet=line.strip()[:200],
                    remediation="Rotate the secret and remove it from source control",
                )

            if LOW_CONFIDENCE_KEYS.search(line):
                value_match = LOW_CONFIDENCE_VALUE.search(line)
                if value_match:
                    _append_finding(
                        findings,
                        rule_id="named-secret-value",
                        category="secret",
                        severity="medium",
                        confidence="medium",
                        source="builtin",
                        file_path=relative_path,
                        line_number=line_number,
                        match_type="named-value",
                        title="Named secret-like value found",
                        secret_preview=_mask_secret(value_match.group(1)),
                        evidence_snippet=line.strip()[:200],
                        remediation="Review the value, remove it from source control, and rotate if valid",
                    )

    deduped: dict[tuple[str, str, int | None, str], RepoFinding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line_number, finding.secret_preview)
        deduped.setdefault(key, finding)
    return list(deduped.values())


def _run_gitleaks(repo_path: str) -> list[RepoFinding]:
    if not shutil.which("gitleaks"):
        return []

    with tempfile.NamedTemporaryFile(prefix="gitleaks-", suffix=".json", delete=False) as handle:
        report_path = handle.name

    try:
        command = [
            "gitleaks",
            "dir",
            repo_path,
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--no-git",
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode not in {0, 1}:
            return []
        payload = json.loads(Path(report_path).read_text(encoding="utf-8") or "[]")
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    findings: list[RepoFinding] = []
    for item in payload:
        secret = str(item.get("Secret") or "")
        findings.append(
            RepoFinding(
                rule_id=str(item.get("RuleID") or "gitleaks"),
                category="secret",
                severity="high",
                confidence="high",
                source="gitleaks",
                file_path=str(item.get("File") or ""),
                line_number=int(item.get("StartLine") or 0) or None,
                match_type="external",
                title=str(item.get("Description") or "External scanner finding"),
                secret_preview=_mask_secret(secret),
                evidence_snippet=str(item.get("Match") or secret)[:200],
                remediation="Review the finding, remove the secret from source control, and rotate it",
            )
        )
    return findings


def scan_repo_secrets(repo_path: str) -> list[RepoFinding]:
    findings = _scan_builtin(repo_path)
    findings.extend(_run_gitleaks(repo_path))

    deduped: dict[tuple[str, str, int | None, str], RepoFinding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line_number, finding.secret_preview)
        deduped.setdefault(key, finding)
    return list(deduped.values())
