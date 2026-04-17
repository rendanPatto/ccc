"""Integration-style smoke test for the Claude Code helper workflow."""

from autopilot_state import build_autopilot_state
from memory.target_profile import make_target_profile, save_target_profile
from remember import remember_finding
from request_guard import preflight_request, record_request
from resume import load_resume_summary


class TestClaudeCodeHelperFlow:

    def test_helper_chain_from_state_to_resume(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/42/export\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/api/v2/users/42/export"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "hunt_p1"
        first_target = state["recommended_targets"][0]
        assert first_target["url"] == "https://api.target.com/graphql"

        preflight = preflight_request(
            memory_dir=memory_dir,
            target="target.com",
            url=first_target["url"],
            method="GET",
            session_id="cc-flow-1",
            sleep=False,
            now_ts=100.0,
        )
        assert preflight["allowed"] is True

        recorded = record_request(
            memory_dir=memory_dir,
            target="target.com",
            url=first_target["url"],
            method="GET",
            response_status=200,
            session_id="cc-flow-1",
            now_ts=101.0,
        )
        assert recorded["action"] == "success"

        remembered = remember_finding(
            memory_dir=memory_dir,
            target="target.com",
            vuln_class="idor",
            endpoint=first_target["url"],
            result="confirmed",
            severity="high",
            payout=900,
            technique="field_auth_bypass",
            notes="Confirmed during Claude Code helper flow",
        )
        assert remembered["journal_saved"] is True
        assert remembered["finding_saved"] is True

        resume = load_resume_summary(memory_dir, "target.com")
        assert resume is not None
        assert resume["confirmed_findings"] == 1
        assert "/graphql" in resume["tested_endpoints"]
        assert any(item["endpoint"] == "/graphql" for item in resume["findings"])
