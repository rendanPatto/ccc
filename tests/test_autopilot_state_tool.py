"""Tests for tools/autopilot_state.py."""

import time

from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from autopilot_state import _build_recommended_targets, build_autopilot_state, format_autopilot_state
from request_guard import record_request


class TestAutopilotState:

    def test_recommended_targets_frontload_last_focus_within_same_guard_bucket(self):
        recommended = _build_recommended_targets(
            [
                {
                    "url": "https://api.target.com/api/v2/users/123",
                    "host": "api.target.com",
                    "suggested": "idor checks",
                    "score": 18,
                },
                {
                    "url": "https://api.target.com/graphql",
                    "host": "api.target.com",
                    "suggested": "field auth checks",
                    "score": 10,
                },
            ],
            {"hosts": []},
            ["/graphql"],
            prefer_resume_targets=True,
        )

        assert recommended[0]["url"] == "https://api.target.com/graphql"
        assert recommended[0]["matches_resume_target"] is True
        assert recommended[1]["matches_resume_target"] is False

    def test_requires_recon_when_missing(self, tmp_path):
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is False
        assert state["has_memory"] is True
        assert state["next_action"] == "run_recon"

    def test_prefers_p1_targets_when_recon_ready(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/report?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["graphql"],
            payout=900,
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is True
        assert state["has_memory"] is True
        assert state["next_action"] == "hunt_p1"
        assert state["recommended_targets"]
        assert "graphql" in state["recommended_targets"][0]["url"]

    def test_prefers_continue_last_focus_when_recent_session_exists(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/graphql"],
            untested_endpoints=["/api/v2/users/123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/graphql"],
            vuln_classes_tried=["recon", "idor"],
            findings_count=1,
            session_id="sess-focus",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "continue_last_focus"
        assert state["resume_targets"] == ["/graphql"]
        assert state["recommended_targets"][0]["url"] == "https://api.target.com/graphql"

    def test_prefers_resume_untested_when_recent_session_has_no_endpoint_preview(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=["recon"],
            findings_count=0,
            session_id="sess-resume",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "resume_untested"
        assert state["resume_targets"] == ["/graphql", "/api/v2/report?id=123"]

    def test_formats_state(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/users"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 2, "p2": 1}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [
                {
                    "url": "https://api.target.com/graphql",
                    "suggested": "field-level auth checks",
                    "score": 14,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
        })
        assert "AUTOPILOT STATE: target.com" in output
        assert "Next action: hunt_p1" in output
        assert "Next step: start with the top P1 target: https://api.target.com/graphql." in output
        assert "https://api.target.com/graphql" in output
        assert "Last session: 1 finding(s), tried recon, idor" in output
        assert "Last endpoints: /graphql" in output
        assert "Resume targets: /graphql" in output

    def test_formats_continue_last_focus_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "continue_last_focus",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [],
        })

        assert "Next action: continue_last_focus" in output
        assert "Next step: continue testing the last focus first: /graphql." in output

    def test_formats_resume_untested_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "resume_untested",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/v2/report?id=123"],
                "latest_session_summary": {
                    "findings_count": 0,
                    "vuln_classes": ["recon"],
                    "endpoints_preview": [],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql", "/api/v2/report?id=123"],
            "recommended_targets": [],
        })

        assert "Next action: resume_untested" in output
        assert "Next step: resume the cached untested surface first: /graphql, /api/v2/report?id=123." in output

    def test_includes_guard_state_and_marks_tripped_hosts(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]",
                "https://files.target.com [200] [Files] [nginx] [1000]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/download?id=1"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=2,
        ))
        now_ts = time.time()
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=now_ts,
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["guard_status"]["tracked_hosts"] == 1
        assert len(state["guard_status"]["tripped_hosts"]) == 1
        assert state["guard_status"]["tripped_hosts"][0]["host"] == "api.target.com"
        assert "avoid cooling hosts" in state["guard_hint"]
        assert state["recommended_targets"][0]["host"] == "files.target.com"
        assert state["recommended_targets"][0]["tripped"] is False
        assert any(item["tripped"] for item in state["recommended_targets"])
        output = format_autopilot_state(state)
        assert "Guard hint:" in output
        assert "files.target.com" in output

    def test_build_autopilot_state_includes_recent_guard_blocks(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql"],
            tested_endpoints=[],
            untested_endpoints=["/graphql"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))
        HuntJournal(memory_dir / "journal.jsonl").append(make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="guard_block",
            endpoint="https://api.target.com/graphql",
            result="informational",
            severity="none",
            technique="request_guard",
            notes=(
                "request_guard blocked GET https://api.target.com/graphql. "
                "Host: api.target.com. Action: block_breaker. "
                "Reason: circuit breaker active."
            ),
            tags=["guard_block", "auto_logged", "block_breaker"],
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert len(state["recent_guard_blocks"]) == 1
        assert state["recent_guard_blocks"][0]["endpoint"] == "https://api.target.com/graphql"
        assert "block_breaker" in state["recent_guard_blocks"][0]["notes"]

    def test_includes_repo_source_hint_when_artifacts_exist(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok"}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 1\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["repo_source_available"] is True
        assert state["repo_source_artifacts"] == ["repo_source_meta.json", "repo_summary.md"]
        assert "Repo source: available" in output
        assert "read_repo_source_summary" in output

    def test_formats_recent_guard_blocks_section(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "guard_hint": "prefer the ready host files.target.com via https://files.target.com/download?id=1",
            "repo_source_available": False,
            "resume_targets": [],
            "recommended_targets": [
                {
                    "url": "https://files.target.com/download?id=1",
                    "suggested": "idor checks",
                    "score": 9,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
            "recent_guard_blocks": [
                {
                    "action": "hunt",
                    "endpoint": "https://api.target.com/graphql",
                    "notes": (
                        "request_guard blocked GET https://api.target.com/graphql. "
                        "Host: api.target.com. Action: block_breaker. "
                        "Reason: circuit breaker active."
                    ),
                }
            ],
        })

        assert "Recent guard blocks:" in output
        assert "https://api.target.com/graphql" in output
        assert "block_breaker" in output
