"""Tests for repository secret and config scanning."""

import json
import subprocess

import repo_secret_scan


def test_scan_repo_secrets_finds_high_signal_material(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / ".env").write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n", encoding="utf-8")
    (repo_dir / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")

    findings = repo_secret_scan.scan_repo_secrets(str(repo_dir))

    rule_ids = {finding.rule_id for finding in findings}
    assert "config-env-file" in rule_ids
    assert "aws-access-key" in rule_ids
    assert "private-key-rsa" in rule_ids


def test_scan_repo_secrets_requires_name_and_value_for_low_confidence_hits(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "settings.js").write_text("const password = '';\n", encoding="utf-8")

    findings = repo_secret_scan.scan_repo_secrets(str(repo_dir))

    assert findings == []


def test_scan_repo_secrets_merges_gitleaks_findings(monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    report_payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "API key detected",
            "File": "config/prod.env",
            "StartLine": 12,
            "Secret": "ghp_example_secret_value",
        }
    ]

    monkeypatch.setattr(repo_secret_scan.shutil, "which", lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)

    def fake_run(command, capture_output, text):
        assert command[0] == "gitleaks"
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(report_payload, handle)
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(repo_secret_scan.subprocess, "run", fake_run)

    findings = repo_secret_scan.scan_repo_secrets(str(repo_dir))

    assert len(findings) == 1
    assert findings[0].source == "gitleaks"
    assert findings[0].rule_id == "generic-api-key"
    assert findings[0].file_path == "config/prod.env"
    assert findings[0].line_number == 12
