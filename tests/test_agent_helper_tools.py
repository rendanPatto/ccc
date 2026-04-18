"""Regression tests for helper tools wired into the agent tool router."""

import json

import agent
from tools import intel_engine


def _build_dispatcher(domain, session_file):
    memory = agent.HuntMemory(str(session_file))
    return agent.ToolDispatcher(domain, memory)


def test_helper_tools_are_exposed_in_tool_names():
    assert "read_autopilot_state" in agent.TOOL_NAMES
    assert "read_guard_status" in agent.TOOL_NAMES
    assert "read_repo_source_summary" in agent.TOOL_NAMES
    assert "read_resume_summary" in agent.TOOL_NAMES
    assert "read_surface_summary" in agent.TOOL_NAMES
    assert "run_intel" in agent.TOOL_NAMES
    assert "remember_finding" in agent.TOOL_NAMES


def test_dispatch_autopilot_state_reads_combined_bootstrap_context(tmp_hunt_dir, tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (tmp_hunt_dir / "targets" / "target-com.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "tech_stack": ["nextjs", "graphql"],
                "tested_endpoints": [],
                "untested_endpoints": ["/graphql"],
                "findings": [],
                "hunt_sessions": 2,
                "total_time_minutes": 30,
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [GraphQL API] [GraphQL,Next.js] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )

    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch(
        "read_autopilot_state",
        {"repo_root": str(tmp_path), "memory_dir": str(tmp_hunt_dir)},
    )

    assert "AUTOPILOT STATE: target.com" in output
    assert "Next action: hunt_p1" in output
    assert "Recommended first targets:" in output
    assert "https://api.target.com/graphql" in output


def test_dispatch_guard_status_reads_breaker_state(monkeypatch, tmp_hunt_dir, tmp_path):
    from tools import request_guard as request_guard_tool

    (tmp_hunt_dir / "targets" / "target-com.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "scope_snapshot": {
                    "in_scope": ["api.target.com"],
                    "breaker_threshold": 1,
                    "breaker_cooldown": 30,
                },
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )

    request_guard_tool.record_request(
        memory_dir=tmp_hunt_dir,
        target="target.com",
        url="https://api.target.com/graphql",
        method="GET",
        response_status=429,
        breaker_threshold=1,
        breaker_cooldown=30,
        now_ts=100.0,
    )
    monkeypatch.setattr(request_guard_tool.time, "time", lambda: 105.0)

    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch("read_guard_status", {"memory_dir": str(tmp_hunt_dir)})

    assert "REQUEST GUARD: target.com" in output
    assert "Tracked: 1 total — 1 tripped, 0 ready" in output
    assert "api.target.com — TRIPPED" in output
    assert "cooldown:" in output


def test_dispatch_repo_source_summary_reads_existing_exposure(monkeypatch, tmp_path):
    exposure_dir = tmp_path / "findings" / "target.com" / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text(
        json.dumps(
            {
                "source_kind": "github_public",
                "repo_url": "https://github.com/octo/demo",
                "repo_ref": "main",
                "size_bytes": 456,
                "file_count": 8,
                "probe_complete": True,
                "threshold_exceeded": False,
                "clone_performed": True,
                "status": "ok",
            }
        ),
        encoding="utf-8",
    )
    (exposure_dir / "repo_secrets.json").write_text(
        json.dumps([{"rule_id": "aws-access-key"}]),
        encoding="utf-8",
    )
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

    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch("read_repo_source_summary", {})

    assert "run_repo_source_hunt: OK" in output
    assert "repo_secrets.json: 1 findings" in output
    assert "repo_ci_findings.json: 1 findings" in output
    assert "[repo_summary.md]" in output


def test_dispatch_resume_summary_reads_memory(tmp_hunt_dir, tmp_path):
    target_profile = {
        "target": "target.com",
        "first_hunted": "2026-04-01T00:00:00Z",
        "last_hunted": "2026-04-14T00:00:00Z",
        "tech_stack": ["nextjs", "graphql"],
        "tested_endpoints": ["/api/me"],
        "untested_endpoints": ["/graphql"],
        "findings": [],
        "hunt_sessions": 2,
        "total_time_minutes": 45,
        "schema_version": 1,
    }
    (tmp_hunt_dir / "targets" / "target-com.json").write_text(
        json.dumps(target_profile),
        encoding="utf-8",
    )

    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch("read_resume_summary", {"memory_dir": str(tmp_hunt_dir)})

    assert "PICKUP: target.com" in output
    assert "Untested Surface:" in output
    assert "/graphql" in output
    assert "[r] Continue hunting untested endpoints" in output


def test_dispatch_surface_summary_ranks_cached_recon(tmp_hunt_dir, tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (tmp_hunt_dir / "targets" / "target-com.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "tech_stack": ["graphql"],
                "tested_endpoints": [],
                "untested_endpoints": ["/graphql"],
                "findings": [],
                "hunt_sessions": 1,
                "total_time_minutes": 10,
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [GraphQL API] [GraphQL,Next.js] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )

    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch(
        "read_surface_summary",
        {"repo_root": str(tmp_path), "memory_dir": str(tmp_hunt_dir)},
    )

    assert "ATTACK SURFACE: target.com" in output
    assert "Priority 1 (start here):" in output
    assert "https://api.target.com/graphql" in output


def test_dispatch_run_intel_uses_recon_tech_fallback(monkeypatch, tmp_hunt_dir, tmp_path):
    domain = "target.com"
    recon_dir = tmp_path / "recon" / domain / "live"
    recon_dir.mkdir(parents=True)
    (recon_dir / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n",
        encoding="utf-8",
    )

    hunt = agent._h()
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))

    captured = {}

    def fake_fetch_all_intel(techs, target, program=""):
        captured["techs"] = techs
        return [
            {
                "id": "CVE-2026-0001",
                "source": "NVD",
                "tech": "nextjs",
                "severity": "CRITICAL",
                "summary": "Test CVE",
                "published": "2026-04-01T00:00:00Z",
            }
        ]

    monkeypatch.setattr(intel_engine, "fetch_all_intel", fake_fetch_all_intel)

    dispatcher = _build_dispatcher(domain, tmp_path / "agent_session.json")
    output = dispatcher.dispatch("run_intel", {"memory_dir": str(tmp_hunt_dir)})

    assert "next.js" in captured["techs"]
    assert "graphql" in captured["techs"]
    assert "INTEL: target.com" in output
    assert "CVE-2026-0001" in output


def test_dispatch_remember_finding_persists_memory(tmp_hunt_dir, tmp_path):
    dispatcher = _build_dispatcher("target.com", tmp_path / "agent_session.json")
    output = dispatcher.dispatch(
        "remember_finding",
        {
            "memory_dir": str(tmp_hunt_dir),
            "vuln_class": "idor",
            "endpoint": "https://target.com/api/users/42",
            "result": "confirmed",
            "severity": "high",
            "technique": "numeric_id_swap",
            "notes": "Confirmed with victim object access",
            "tags": ["api", "idor"],
            "tech_stack": ["nextjs", "graphql"],
        },
    )

    assert "REMEMBERED" in output
    assert "Pattern saved:" in output

    profile_path = tmp_hunt_dir / "targets" / "target-com.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    assert "/api/users/42" in profile["tested_endpoints"]
    assert any(item["vuln_class"] == "idor" for item in profile["findings"])
