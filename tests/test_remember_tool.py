"""Tests for tools/remember.py."""

import json
import sys

import pytest

import remember
from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.target_profile import load_target_profile, save_target_profile
from remember import remember_finding


class TestRememberFinding:

    def test_writes_journal_updates_profile_and_saves_pattern(self, tmp_hunt_dir, sample_target_profile):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        summary = remember_finding(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            vuln_class="idor",
            endpoint="https://api.target.com/api/v2/users/42/export?format=json",
            result="confirmed",
            severity="high",
            payout=1500,
            technique="numeric_id_swap_with_put_method",
            notes="Confirmed with attacker token against victim object",
            tags=["api_version_diff", "idor"],
        )

        assert summary["journal_saved"] is True
        assert summary["finding_saved"] is True
        assert summary["pattern_saved"] is True
        assert "/api/v2/users/42/export?format=json" == summary["endpoint"]

        entries = HuntJournal(tmp_hunt_dir / "journal.jsonl").read_all()
        assert len(entries) == 1
        assert entries[0]["action"] == "remember"
        assert entries[0]["endpoint"] == "/api/v2/users/42/export?format=json"

        profile = load_target_profile(tmp_hunt_dir, "target.com")
        assert "/api/v2/users/42/export?format=json" in profile["tested_endpoints"]
        assert "/api/v2/users/{id}/export" in profile["untested_endpoints"]
        assert any(item["vuln_class"] == "idor" for item in profile["findings"])

        patterns = PatternDB(tmp_hunt_dir / "patterns.jsonl").read_all()
        assert len(patterns) == 1
        assert patterns[0]["technique"] == "numeric_id_swap_with_put_method"

    def test_creates_profile_when_missing_and_skips_pattern_without_tech_stack(self, tmp_hunt_dir):
        summary = remember_finding(
            memory_dir=tmp_hunt_dir,
            target="fresh.com",
            vuln_class="xss",
            endpoint="/search",
            result="confirmed",
            severity="medium",
            payout=500,
            technique="reflected_probe",
            notes="No stored tech stack yet",
            tags=["search"],
        )

        assert summary["journal_saved"] is True
        assert summary["pattern_saved"] is False

        profile = load_target_profile(tmp_hunt_dir, "fresh.com")
        assert profile is not None
        assert "/search" in profile["tested_endpoints"]
        assert profile["findings"][0]["vuln_class"] == "xss"

    def test_rejected_finding_only_updates_test_history(self, tmp_hunt_dir, sample_target_profile):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        summary = remember_finding(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            vuln_class="ssrf",
            endpoint="/api/proxy",
            result="rejected",
            severity="none",
            technique="metadata_probe",
            notes="No callback",
            tags=["ssrf"],
            tech_stack=["nextjs", "nodejs"],
        )

        assert summary["pattern_saved"] is False
        assert summary["finding_saved"] is False

        profile = load_target_profile(tmp_hunt_dir, "target.com")
        assert "/api/proxy" in profile["tested_endpoints"]
        assert profile["findings"] == []
        assert profile["tech_stack"][-1] == "nodejs"

        patterns = PatternDB(tmp_hunt_dir / "patterns.jsonl").read_all()
        assert patterns == []


class TestRememberFromValidate:

    def test_loads_prefill_from_validate_summary(self, tmp_path):
        summary_path = tmp_path / "validation-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "endpoint": "https://api.target.com/api/v2/orders/42",
                    "vuln_class": "IDOR",
                    "severity": "HIGH",
                    "all_gates_passed": True,
                    "impact": "Read another user's order",
                }
            ),
            encoding="utf-8",
        )

        prefill = remember.load_validate_prefill(summary_path)

        assert prefill["target"] == "target.com"
        assert prefill["endpoint"] == "https://api.target.com/api/v2/orders/42"
        assert prefill["vuln_class"] == "idor"
        assert prefill["severity"] == "high"
        assert prefill["result"] == "confirmed"
        assert prefill["notes"] == "Read another user's order"

    def test_main_can_import_fields_from_validate_summary(self, tmp_hunt_dir, monkeypatch, capsys):
        summary_path = tmp_hunt_dir / "validation-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "endpoint": "https://api.target.com/api/v2/orders/42",
                    "vuln_class": "idor",
                    "severity": "high",
                    "result": "confirmed",
                    "notes": "Validated via PoC",
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "remember.py",
                "--from-validate",
                "--validate-json",
                str(summary_path),
                "--memory-dir",
                str(tmp_hunt_dir),
                "--technique",
                "numeric_id_swap",
                "--payout",
                "1200",
                "--tech-stack",
                "nextjs,graphql",
            ],
        )

        remember.main()

        out = capsys.readouterr().out
        assert "REMEMBERED" in out
        assert str(summary_path) in out

        entries = HuntJournal(tmp_hunt_dir / "journal.jsonl").read_all()
        assert len(entries) == 1
        assert entries[0]["target"] == "target.com"
        assert entries[0]["vuln_class"] == "idor"
        assert entries[0]["result"] == "confirmed"
        assert entries[0]["endpoint"] == "/api/v2/orders/42"
        assert entries[0]["notes"] == "Validated via PoC"

        profile = load_target_profile(tmp_hunt_dir, "target.com")
        assert "/api/v2/orders/42" in profile["tested_endpoints"]

        patterns = PatternDB(tmp_hunt_dir / "patterns.jsonl").read_all()
        assert len(patterns) == 1
        assert patterns[0]["technique"] == "numeric_id_swap"

    def test_loads_current_directory_summary_before_repo_fallback(self, tmp_path, monkeypatch):
        cwd = tmp_path / "findings" / "target-program-idor"
        cwd.mkdir(parents=True)
        cwd_summary = cwd / "validation-summary.json"
        cwd_summary.write_text(
            json.dumps(
                {
                    "target": "cwd.target.com",
                    "endpoint": "https://cwd.target.com/api/demo",
                    "vuln_class": "ssrf",
                    "result": "partial",
                }
            ),
            encoding="utf-8",
        )

        repo_root = tmp_path / "repo"
        fallback = repo_root / "findings" / "last-validate.json"
        fallback.parent.mkdir(parents=True)
        fallback.write_text(
            json.dumps(
                {
                    "target": "fallback.target.com",
                    "endpoint": "https://fallback.target.com/api/demo",
                    "vuln_class": "idor",
                    "result": "confirmed",
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(remember, "BASE_DIR", str(repo_root), raising=False)
        monkeypatch.chdir(cwd)

        prefill = remember.load_validate_prefill()

        assert prefill["target"] == "cwd.target.com"
        assert prefill["vuln_class"] == "ssrf"
        assert prefill["result"] == "partial"

    def test_main_uses_current_directory_summary_when_validate_json_missing(self, tmp_hunt_dir, tmp_path, monkeypatch, capsys):
        cwd = tmp_path / "findings" / "target-program-idor"
        cwd.mkdir(parents=True)
        (cwd / "validation-summary.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "endpoint": "https://api.target.com/api/v2/auto",
                    "vuln_class": "idor",
                    "severity": "medium",
                    "result": "confirmed",
                    "notes": "Loaded from cwd summary",
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.chdir(cwd)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "remember.py",
                "--from-validate",
                "--memory-dir",
                str(tmp_hunt_dir),
            ],
        )

        remember.main()

        out = capsys.readouterr().out
        assert "REMEMBERED" in out
        assert str(cwd / "validation-summary.json") in out

        entries = HuntJournal(tmp_hunt_dir / "journal.jsonl").read_all()
        assert len(entries) == 1
        assert entries[0]["endpoint"] == "/api/v2/auto"
        assert entries[0]["notes"] == "Loaded from cwd summary"
