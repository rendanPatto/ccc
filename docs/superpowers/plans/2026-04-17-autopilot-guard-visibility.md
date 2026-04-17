# Autopilot Guard Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface recent request-guard block history into autopilot state output and agent bootstrap context without changing request behavior or target ranking.

**Architecture:** Reuse the existing `recent_guard_blocks` data already returned by `load_resume_summary()`. Thread that data through `build_autopilot_state()`, render a compact summary in `format_autopilot_state()`, and add the same compact summary to `agent._build_agent_bootstrap_context()` so the agent sees recent guard friction before acting.

**Tech Stack:** Python, pytest, existing `tools/resume.py` summary shape, existing autopilot/agent formatting helpers.

---

### Task 1: Expose recent guard blocks in autopilot state and formatted state output

**Files:**
- Modify: `tools/autopilot_state.py`
- Test: `tests/test_autopilot_state_tool.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_build_autopilot_state_includes_recent_guard_blocks(tmp_path):
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
    journal = HuntJournal(memory_dir / "journal.jsonl")
    journal.append(make_journal_entry(
        target="target.com",
        action="hunt",
        vuln_class="guard_block",
        endpoint="https://api.target.com/graphql",
        result="informational",
        severity="none",
        technique="request_guard",
        notes="request_guard blocked GET https://api.target.com/graphql. Host: api.target.com. Action: block_breaker. Reason: circuit breaker active.",
        tags=["guard_block", "auto_logged", "block_breaker"],
    ))

    state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

    assert len(state["recent_guard_blocks"]) == 1
    assert state["recent_guard_blocks"][0]["endpoint"] == "https://api.target.com/graphql"


def test_format_autopilot_state_includes_recent_guard_blocks_section():
    state = {
        "target": "target.com",
        "has_recon": True,
        "has_memory": True,
        "next_action": "hunt_p1",
        "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
        "guard_hint": "prefer the ready host files.target.com via https://files.target.com/download?id=1",
        "repo_source_available": False,
        "tech_stack": ["next.js"],
        "resume_summary": {},
        "resume_targets": [],
        "surface": {"stats": {"p1": 1, "p2": 0}},
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
                "notes": "request_guard blocked GET https://api.target.com/graphql. Host: api.target.com. Action: block_breaker. Reason: circuit breaker active.",
            }
        ],
    }

    output = format_autopilot_state(state)

    assert "Recent guard blocks:" in output
    assert "https://api.target.com/graphql" in output
    assert "block_breaker" in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "recent_guard_blocks"
```

Expected: FAIL because `build_autopilot_state()` does not yet return `recent_guard_blocks` and formatted output does not yet include the new section.

- [ ] **Step 3: Write the minimal implementation**

```python
# in build_autopilot_state(...)
recent_guard_blocks = []
if resume_summary:
    recent_guard_blocks = resume_summary.get("recent_guard_blocks", []) or []

return {
    # existing fields...
    "recent_guard_blocks": recent_guard_blocks,
}

# in format_autopilot_state(...)
guard_blocks = state.get("recent_guard_blocks", []) or []
if guard_blocks:
    lines.append("")
    lines.append("Recent guard blocks:")
    for item in guard_blocks[:3]:
        details = item.get("notes", "") or item.get("endpoint", "")
        lines.append(f"- {details}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "recent_guard_blocks"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/autopilot_state.py tests/test_autopilot_state_tool.py
git commit -m "feat: surface recent guard blocks in autopilot state"
```

### Task 2: Surface recent guard blocks in agent bootstrap context

**Files:**
- Modify: `agent.py`
- Test: `tests/test_autopilot_mode.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_agent_bootstrap_context_surfaces_recent_guard_blocks(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "avoid cooling hosts: api.target.com (25.0s); prefer the ready host files.target.com via https://files.target.com/download?id=1",
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
        "recent_guard_blocks": [
            {
                "action": "hunt",
                "endpoint": "https://api.target.com/graphql",
                "notes": "request_guard blocked GET https://api.target.com/graphql. Host: api.target.com. Action: block_breaker. Reason: circuit breaker active.",
            }
        ],
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Recent guard blocks:" in output
    assert "https://api.target.com/graphql" in output
    assert "block_breaker" in output
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "recent_guard_blocks"
```

Expected: FAIL because `_build_agent_bootstrap_context()` does not yet render recent guard block summaries.

- [ ] **Step 3: Write minimal implementation**

```python
recent_guard_blocks = state.get("recent_guard_blocks", []) or []
if recent_guard_blocks:
    lines.append("Recent guard blocks:")
    for item in recent_guard_blocks[:3]:
        details = str(item.get("notes", "") or item.get("endpoint", "")).strip()
        if details:
            lines.append(f"- {details}")
```

Place this block after the current guard-status / avoid-now context so it complements existing guidance instead of replacing it.

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "recent_guard_blocks"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent.py tests/test_autopilot_mode.py
git commit -m "feat: add recent guard history to agent bootstrap"
```

### Task 3: Run focused regression verification for the full visibility path

**Files:**
- Modify: none
- Test: `tests/test_autopilot_state_tool.py`
- Test: `tests/test_autopilot_mode.py`
- Test: `tests/test_resume_tool.py`

- [ ] **Step 1: Run the focused regression suite**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_resume_tool.py
```

Expected: PASS. The new visibility path should coexist with existing resume and bootstrap behavior.

- [ ] **Step 2: Run a broader guard-related sanity suite**

Run:
```bash
pytest -q tests/test_hunt_wrappers.py tests/test_request_guard_tool.py tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_resume_tool.py
```

Expected: PASS. No changes to request behavior or ranking behavior.

- [ ] **Step 3: Record completion status**

```bash
git status --short
```

Expected: only the intended implementation, test, and spec/plan files appear as modified or added.
