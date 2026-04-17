"""Regression tests for autopilot mode wiring across hunt.py and agent.py."""

import sys

import agent
import hunt
from memory.hunt_journal import HuntJournal


def test_normalize_autopilot_mode_defaults_to_paranoid():
    assert agent._normalize_autopilot_mode(None) == "paranoid"
    assert agent._normalize_autopilot_mode("") == "paranoid"
    assert agent._normalize_autopilot_mode("YOLO") == "yolo"
    assert agent._normalize_autopilot_mode("unknown") == "paranoid"


def test_build_agent_system_includes_mode_guidance():
    paranoid_prompt = agent._build_agent_system(ctf_mode=False, autopilot_mode="paranoid")
    normal_prompt = agent._build_agent_system(ctf_mode=False, autopilot_mode="normal")
    yolo_prompt = agent._build_agent_system(ctf_mode=False, autopilot_mode="yolo")

    assert "Checkpoint mode: paranoid" in paranoid_prompt
    assert "Checkpoint mode: normal" in normal_prompt
    assert "Checkpoint mode: yolo" in yolo_prompt
    assert "frequent checkpoints" in paranoid_prompt.lower()
    assert "batch related findings" in normal_prompt.lower()
    assert "keep moving" in yolo_prompt.lower()
    assert "prefer the highest-score non-tripped target first" in paranoid_prompt


def test_build_agent_bootstrap_context_surfaces_guard_guidance(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": (
            "avoid cooling hosts: api.target.com (25.0s); prefer the ready host "
            "files.target.com via https://files.target.com/download?id=1"
        ),
        "guard_status": {
            "tripped_hosts": [
                {"host": "api.target.com", "remaining_seconds": 25.0},
            ]
        },
        "resume_targets": ["/graphql"],
        "resume_summary": {
            "latest_session_summary": {
                "vuln_classes": ["idor"],
                "findings_count": 1,
            }
        },
        "recommended_targets": [
            {
                "url": "https://files.target.com/download?id=1",
                "suggested": "idor checks",
                "tripped": False,
            }
        ],
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Guard hint:" in output
    assert "Avoid now: api.target.com (25.0s)" in output
    assert "Top ready target: https://files.target.com/download?id=1 (idor checks)" in output


def test_active_bootstrap_context_only_applies_on_first_step(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_context = "resume target: /graphql"

    assert agent._active_bootstrap_context(memory) == "resume target: /graphql"

    memory.step_count = 1
    assert agent._active_bootstrap_context(memory) == ""


def test_langgraph_context_omits_bootstrap_after_first_step(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_context = "resume target: /graphql"

    first = agent._build_context_for_langgraph("example.com", memory)
    assert "Bootstrap:" in first
    assert "resume target: /graphql" in first

    memory.step_count = 1
    later = agent._build_context_for_langgraph("example.com", memory)
    assert "Bootstrap:" not in later


def test_run_agent_hunt_returns_autopilot_mode(monkeypatch, tmp_path):
    captured = {}

    class FakeHunt:
        def _activate_recon_session(self, domain, *, requested_session_id="latest", create=True):
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-001" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-001", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, autopilot_mode, **kwargs):
            captured["autopilot_mode"] = autopilot_mode

        def run(self):
            return {"domain": "example.com", "success": True, "steps": 0, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt(
        "example.com",
        autopilot_mode="yolo",
        ctf_mode=True,
    )

    assert captured["autopilot_mode"] == "yolo"
    assert result["autopilot_mode"] == "yolo"


def test_run_agent_hunt_auto_logs_session_summary(monkeypatch, tmp_path):
    memory_dir = tmp_path / "hunt-memory"

    class FakeHunt:
        BASE_DIR = str(tmp_path)

        def _activate_recon_session(self, domain, *, requested_session_id="latest", create=True):
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-002" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-002", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, memory, **kwargs):
            memory.completed_steps.extend(["run_recon", "run_vuln_scan"])
            memory.findings_log.append(
                {
                    "tool": "run_vuln_scan",
                    "severity": "high",
                    "text": "IDOR on /api/users/1",
                    "ts": "2026-04-17T00:00:00",
                }
            )

        def run(self):
            return {"domain": "example.com", "success": True, "steps": 2, "findings": 1, "reports": 1}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "default_memory_dir", lambda _base=None: memory_dir)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt("example.com", autopilot_mode="normal")
    entries = HuntJournal(memory_dir / "journal.jsonl").query(
        target="example.com",
        vuln_class="session_summary",
    )

    assert result["success"] is True
    assert len(entries) == 1
    assert entries[0]["action"] == "hunt"
    assert "auto_logged" in entries[0]["tags"]
    assert "sess-002" in entries[0]["notes"]
    assert "recon" in entries[0]["notes"]
    assert "vuln_scan" in entries[0]["notes"]


def test_run_agent_hunt_session_summary_uses_remembered_profile_findings(monkeypatch, tmp_path):
    memory_dir = tmp_path / "hunt-memory"

    class FakeHunt:
        BASE_DIR = str(tmp_path)

        def _activate_recon_session(self, domain, *, requested_session_id="latest", create=True):
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-003" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-003", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, domain, **kwargs):
            self.domain = domain

        def run(self):
            from remember import remember_finding

            remember_finding(
                memory_dir=memory_dir,
                target=self.domain,
                vuln_class="idor",
                endpoint="https://api.example.com/api/users/1",
                result="confirmed",
                severity="high",
                notes="Persisted through remember_finding",
            )
            return {"domain": self.domain, "success": True, "steps": 1, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "default_memory_dir", lambda _base=None: memory_dir)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt("example.com")
    entries = HuntJournal(memory_dir / "journal.jsonl").query(
        target="example.com",
        vuln_class="session_summary",
    )

    assert result["success"] is True
    assert len(entries) == 1
    assert entries[0]["endpoint"] == "/api/users/1"
    assert "idor" in entries[0]["notes"]
    assert "Findings: 1." in entries[0]["notes"]


def test_hunt_main_passes_autopilot_mode_to_agent(monkeypatch, tmp_path):
    captured = {}

    def fake_run_agent_hunt(*args, **kwargs):
        captured["autopilot_mode"] = kwargs["autopilot_mode"]
        return {
            "domain": "example.com",
            "success": True,
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "autopilot_mode": kwargs["autopilot_mode"],
        }

    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "load_config", lambda: {})
    monkeypatch.setattr(hunt, "is_ctf_mode", lambda config: False)
    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "print_dashboard", lambda result: None)
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--target", "example.com", "--agent", "--yolo"])

    hunt.main()

    assert captured["autopilot_mode"] == "yolo"
