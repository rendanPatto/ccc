"""Tests for tools/request_guard.py."""

from memory.audit_log import AuditLog
from memory.target_profile import make_target_profile, save_target_profile
from request_guard import load_guard_status, preflight_request, record_request


def _save_profile(tmp_hunt_dir, target="target.com", scope_snapshot=None):
    save_target_profile(
        tmp_hunt_dir,
        make_target_profile(
            target,
            scope_snapshot=scope_snapshot
            or {
                "in_scope": ["target.com", "*.target.com", "api.target.com"],
                "out_of_scope": ["blog.target.com"],
                "excluded_classes": ["dos"],
            },
        ),
    )


class TestRequestGuardPreflight:

    def test_blocks_out_of_scope_and_logs_audit(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir)

        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://evil.com/api",
            method="GET",
            session_id="sess-1",
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is False
        assert result["action"] == "block_scope"

        entries = AuditLog(tmp_hunt_dir / "audit.jsonl").read_all()
        assert len(entries) == 1
        assert entries[0]["scope_check"] == "fail"
        assert entries[0]["error"] == "out of scope"

    def test_blocks_unsafe_yolo_method(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir)

        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/api/v1/users/1",
            method="PATCH",
            mode="yolo",
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is False
        assert result["action"] == "block_method"

    def test_uses_persisted_rate_limit_window(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "test_rps": 2})

        first = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=100.0,
        )
        second = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=100.2,
        )

        assert first["allowed"] is True
        assert first["wait_seconds"] == 0.0
        assert second["allowed"] is True
        assert second["wait_seconds"] == 0.3

    def test_ctf_mode_allows_out_of_scope_unsafe_and_skips_wait(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir)

        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://127.0.0.1:8080/admin",
            method="PATCH",
            vuln_class="dos",
            mode="yolo",
            ctf_mode=True,
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is True
        assert result["action"] == "allow_ctf"
        assert result["scope_check"] == "skip"
        assert result["wait_seconds"] == 0.0
        assert result["ctf_mode"] is True


class TestRequestGuardRecord:

    def test_trips_breaker_and_blocks_follow_up_request(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 2, "breaker_cooldown": 30})

        first = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            now_ts=100.0,
        )
        second = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            error="timeout",
            now_ts=105.0,
        )
        blocked = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=110.0,
        )

        assert first["action"] == "failure"
        assert second["action"] == "tripped"
        assert second["breaker"]["tripped"] is True
        assert blocked["allowed"] is False
        assert blocked["action"] == "block_breaker"
        assert blocked["breaker"]["remaining_seconds"] == 25.0

    def test_success_resets_failures(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 3})

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            now_ts=100.0,
        )
        result = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=200,
            now_ts=101.0,
        )

        assert result["action"] == "success"
        assert result["breaker"]["failures"] == 0
        assert result["breaker"]["tripped"] is False

    def test_status_reports_tracked_hosts(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 2, "breaker_cooldown": 30})

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            now_ts=100.0,
        )

        status = load_guard_status(tmp_hunt_dir, "target.com", breaker_threshold=2, now_ts=105.0)
        assert status["tracked_hosts"] == 1
        assert status["tripped_hosts"] == 0
        assert status["ready_hosts"] == 1
        assert status["hosts"][0]["host"] == "api.target.com"
        assert status["hosts"][0]["failures"] == 1

    def test_status_reports_tripped_and_ready_counts(self, tmp_hunt_dir):
        _save_profile(
            tmp_hunt_dir,
            scope_snapshot={"in_scope": ["*.target.com"], "breaker_threshold": 1, "breaker_cooldown": 30},
        )

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            now_ts=100.0,
        )
        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://files.target.com/download?id=1",
            method="GET",
            response_status=200,
            now_ts=101.0,
        )

        status = load_guard_status(tmp_hunt_dir, "target.com", now_ts=105.0)
        assert status["tracked_hosts"] == 2
        assert status["tripped_hosts"] == 1
        assert status["ready_hosts"] == 1

    def test_ctf_mode_does_not_trip_breaker(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 1, "breaker_cooldown": 30})

        first = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://127.0.0.1:8080/admin",
            method="PATCH",
            response_status=403,
            ctf_mode=True,
            now_ts=100.0,
        )
        second = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://127.0.0.1:8080/admin",
            method="DELETE",
            mode="yolo",
            ctf_mode=True,
            sleep=False,
            now_ts=101.0,
        )

        assert first["action"] == "recorded_ctf"
        assert first["scope_check"] == "skip"
        assert second["allowed"] is True
        assert second["action"] == "allow_ctf"

        status = load_guard_status(tmp_hunt_dir, "target.com", now_ts=102.0)
        assert status["tracked_hosts"] == 1
        assert status["hosts"][0]["tripped"] is False
        assert status["hosts"][0]["failures"] == 0
