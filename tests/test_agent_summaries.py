"""Regression tests for agent summaries against the current recon layout."""

import json
from pathlib import Path

import agent


def _build_dispatcher(domain, session_file):
    memory = agent.HuntMemory(str(session_file))
    return agent.ToolDispatcher(domain, memory)


def test_read_recon_summary_uses_current_layout(monkeypatch, tmp_path):
    domain = "target.com"
    recon_dir = tmp_path / "recon" / domain
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "params").mkdir(parents=True)

    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        "https://www.target.com [200] [Home] [Cloudflare] [2000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "all.txt").write_text(
        "https://api.target.com/graphql\nhttps://www.target.com/app.js\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://www.target.com/profile?id=42\n",
        encoding="utf-8",
    )
    (recon_dir / "params" / "post_params.json").write_text(
        json.dumps({"https://api.target.com/login": {"params": ["email", "password"]}}),
        encoding="utf-8",
    )

    hunt = agent._h()
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))

    dispatcher = _build_dispatcher(domain, tmp_path / "agent_session.json")
    summary = dispatcher._read_recon_files(domain)

    assert "=== Live hosts (2 total) ===" in summary
    assert "https://api.target.com/graphql" in summary
    assert "=== Tech stack ===" in summary
    assert "next.js" in summary
    assert "graphql" in summary
    assert "=== POST params (1 forms) ===" in summary
    assert "https://api.target.com/login -> email, password" in summary


def test_read_recon_summary_mentions_repo_source_artifacts(monkeypatch, tmp_path):
    domain = "target.com"
    recon_dir = tmp_path / "recon" / domain
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )

    exposure_dir = tmp_path / "findings" / domain / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 1\n",
        encoding="utf-8",
    )

    hunt = agent._h()
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))

    dispatcher = _build_dispatcher(domain, tmp_path / "agent_session.json")
    summary = dispatcher._read_recon_files(domain)

    assert "=== Repo source artifacts ===" in summary
    assert "read_repo_source_summary" in summary


def test_summarize_params_reads_current_param_outputs(monkeypatch, tmp_path):
    domain = "target.com"
    params_dir = tmp_path / "recon" / domain / "params"
    params_dir.mkdir(parents=True)
    (params_dir / "interesting_params.txt").write_text("id\nuser_id\n", encoding="utf-8")
    (params_dir / "arjun_1.txt").write_text("debug\n", encoding="utf-8")
    (params_dir / "arjun_2.txt").write_text("redirect\n", encoding="utf-8")

    hunt = agent._h()
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))

    dispatcher = _build_dispatcher(domain, tmp_path / "agent_session.json")
    summary = dispatcher._summarize_params(domain, ok=True)

    assert "run_param_discovery: OK" in summary
    assert "interesting_params.txt: 2 candidates" in summary
    assert "arjun outputs: 2 files" in summary


def test_summarize_repo_source_reads_repo_artifacts(monkeypatch, tmp_path):
    domain = "target.com"
    exposure_dir = tmp_path / "findings" / domain / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text(
        json.dumps(
            {
                "source_kind": "github_public",
                "repo_url": "https://github.com/octo/demo",
                "repo_ref": "main",
                "size_bytes": 123,
                "file_count": 4,
                "probe_complete": True,
                "threshold_exceeded": False,
                "clone_performed": True,
                "status": "ok",
            }
        ),
        encoding="utf-8",
    )
    (exposure_dir / "repo_secrets.json").write_text(json.dumps([{"rule_id": "aws-access-key"}]), encoding="utf-8")
    (exposure_dir / "repo_ci_findings.json").write_text(
        json.dumps([{"rule_id": "unpinned-third-party-action"}]),
        encoding="utf-8",
    )
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 1\n",
        encoding="utf-8",
    )

    hunt = agent._h()
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))

    dispatcher = _build_dispatcher(domain, tmp_path / "agent_session.json")
    summary = dispatcher._summarize_repo_source(domain, ok=True)
    findings_text = dispatcher._read_findings_files(domain)

    assert "run_repo_source_hunt: OK" in summary
    assert "repo_secrets.json: 1 findings" in summary
    assert "repo_ci_findings.json: 1 findings" in summary
    assert "[repo_summary.md]" in summary
    assert "run_repo_source_hunt: OK" in findings_text
    assert "repo_secrets.json: 1 findings" in findings_text
    assert "repo_summary.md" in findings_text
