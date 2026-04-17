"""Regression tests for CTF mode integration in hunt.py and agent.py."""

from pathlib import Path

import agent
import hunt


def test_hunt_load_config_and_is_ctf_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    (tmp_path / "config.json").write_text('{"ctf_mode": true}', encoding="utf-8")

    config = hunt.load_config()

    assert config["ctf_mode"] is True
    assert hunt.is_ctf_mode(config) is True


def test_resolve_ctf_mode_prefers_explicit_override(monkeypatch):
    monkeypatch.setattr(agent, "_load_agent_runtime_config", lambda: {"ctf_mode": True})

    assert agent._resolve_ctf_mode() is True
    assert agent._resolve_ctf_mode(False) is False


def test_build_agent_system_changes_for_ctf_mode():
    normal_prompt = agent._build_agent_system(ctf_mode=False)
    ctf_prompt = agent._build_agent_system(ctf_mode=True)

    assert "authorized bug bounty program or VAPT engagement" in normal_prompt
    assert "All provided targets are considered in-scope." in ctf_prompt
    assert "Do not spend time on program acceptance" in ctf_prompt
    assert "authorized bug bounty program or VAPT engagement" not in ctf_prompt
