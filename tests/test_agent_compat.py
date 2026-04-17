"""Compatibility tests for agent.py against the current tools/hunt.py layout."""

from pathlib import Path

import agent


def test_agent_only_exposes_wired_and_dispatcher_tools():
    supported = agent._h().supported_tool_names()
    dispatcher_only = {
        "read_autopilot_state",
        "read_guard_status",
        "read_repo_source_summary",
        "read_resume_summary",
        "read_surface_summary",
        "run_intel",
        "remember_finding",
        "read_recon_summary",
        "read_findings_summary",
        "update_working_memory",
        "finish",
    }

    assert agent.TOOL_NAMES == supported | dispatcher_only
    assert "run_sqlmap_on_file" in agent.TOOL_NAMES
    assert "run_sqlmap_request_file" not in agent.TOOL_NAMES
    assert {"setup_wordlists", "select_targets", "show_status", "hunt_target"} & agent.TOOL_NAMES == set()


def test_hunt_compat_maps_private_function_to_public_tool_name():
    supported = agent._h().supported_tool_names()

    assert "run_sqlmap_on_file" in supported
    assert "run_sqlmap_request_file" not in supported


def test_hunt_compat_session_dir_creation(monkeypatch, tmp_path):
    hunt = agent._h()
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))

    session_id, recon_dir = hunt._activate_recon_session(
        "example.com",
        requested_session_id="latest",
        create=True,
    )

    assert session_id
    assert Path(recon_dir).is_dir()
    assert Path(recon_dir).parts[-4:] == ("example.com", "sessions", session_id, "recon")


def test_phase_flags_map_run_prefixed_steps():
    flags = agent._phase_flags(
        [
            "check_tools",
            "run_recon",
            "run_vuln_scan",
            "run_sqlmap_on_file",
            "run_post_param_discovery",
            "run_cve_hunt",
            "generate_reports",
            "read_resume_summary",
        ]
    )

    assert flags["tool_check"] is True
    assert flags["recon"] is True
    assert flags["scan"] is True
    assert flags["sqlmap"] is True
    assert flags["post_param_discovery"] is True
    assert flags["jwt_audit"] is False
    assert flags["cve_hunt"] is True
    assert flags["zero_day_fuzzer"] is False
    assert flags["reports_generated"] is True
