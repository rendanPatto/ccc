"""Tests for memory/target_profile.py."""

from memory.target_profile import (
    default_memory_dir,
    load_target_profile,
    make_target_profile,
    save_target_profile,
    target_filename,
    target_profile_path,
)


class TestTargetProfileHelpers:

    def test_target_filename_normalizes_domain(self):
        assert target_filename("api.target.com") == "api-target-com.json"

    def test_target_profile_path_uses_targets_dir(self, tmp_hunt_dir):
        path = target_profile_path(tmp_hunt_dir, "target.com")
        assert path.name == "target-com.json"
        assert path.parent.name == "targets"

    def test_make_save_and_load_profile(self, tmp_hunt_dir):
        profile = make_target_profile(
            "target.com",
            tested_endpoints=["/api/v1/users"],
            untested_endpoints=["/api/v2/export"],
            findings=[{"id": "idor_001", "severity": "high"}],
            hunt_sessions=1,
        )
        save_target_profile(tmp_hunt_dir, profile)
        loaded = load_target_profile(tmp_hunt_dir, "target.com")

        assert loaded is not None
        assert loaded["target"] == "target.com"
        assert loaded["tested_endpoints"] == ["/api/v1/users"]
        assert loaded["untested_endpoints"] == ["/api/v2/export"]
        assert loaded["hunt_sessions"] == 1

    def test_default_memory_dir_uses_base_dir(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HUNT_MEMORY_DIR", raising=False)
        assert default_memory_dir(tmp_path) == tmp_path / "hunt-memory"
