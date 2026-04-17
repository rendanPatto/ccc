"""Tests for the standalone source-hunt orchestration."""

import json

import source_hunt
from repo_scan_models import RepoFinding, RepoSourceMeta


def test_run_source_hunt_writes_all_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(source_hunt, "BASE_DIR", tmp_path)

    source_meta = RepoSourceMeta(
        source_kind="local_path",
        repo_path=str(tmp_path / "repo"),
        size_bytes=123,
        file_count=2,
        probe_complete=True,
    )
    monkeypatch.setattr(
        source_hunt,
        "acquire_repo_source",
        lambda **kwargs: (source_meta, str(tmp_path / "repo"), None),
    )
    monkeypatch.setattr(
        source_hunt,
        "scan_repo_secrets",
        lambda repo_path: [
            RepoFinding(
                rule_id="aws-access-key",
                category="secret",
                severity="high",
                confidence="high",
                source="builtin",
                file_path=".env",
                line_number=1,
                match_type="pattern",
                title="AWS access key ID found",
                secret_preview="AKIA...CDEF",
                evidence_snippet="AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                remediation="Rotate and remove",
            )
        ],
    )
    monkeypatch.setattr(source_hunt, "scan_repo_ci", lambda repo_path: [])

    result = source_hunt.run_source_hunt(target="example.com", repo_path=str(tmp_path / "repo"))

    exposure_dir = tmp_path / "findings" / "example.com" / "exposure"
    assert result["status"] == "ok"
    assert json.loads((exposure_dir / "repo_source_meta.json").read_text(encoding="utf-8"))["source_kind"] == "local_path"
    assert len(json.loads((exposure_dir / "repo_secrets.json").read_text(encoding="utf-8"))) == 1
    assert (exposure_dir / "repo_summary.md").read_text(encoding="utf-8").startswith("# Repository Source Hunt Summary")


def test_run_source_hunt_returns_confirmation_required(monkeypatch, tmp_path):
    monkeypatch.setattr(source_hunt, "BASE_DIR", tmp_path)

    source_meta = RepoSourceMeta(
        source_kind="github_public",
        repo_url="https://github.com/octo/demo",
        repo_ref="main",
        size_bytes=source_hunt.MAX_REPO_SIZE_BYTES + 1,
        file_count=10,
        probe_complete=True,
        threshold_exceeded=True,
        threshold_reasons=["size_bytes"],
    )

    def fake_acquire_repo_source(**kwargs):
        raise source_hunt.RepoConfirmationRequired(source_meta)

    monkeypatch.setattr(source_hunt, "acquire_repo_source", fake_acquire_repo_source)

    result = source_hunt.run_source_hunt(target="example.com", repo_url="octo/demo")

    exposure_dir = tmp_path / "findings" / "example.com" / "exposure"
    assert result["status"] == "confirmation_required"
    assert json.loads((exposure_dir / "repo_source_meta.json").read_text(encoding="utf-8"))["status"] == "confirmation_required"
    assert json.loads((exposure_dir / "repo_secrets.json").read_text(encoding="utf-8")) == []
