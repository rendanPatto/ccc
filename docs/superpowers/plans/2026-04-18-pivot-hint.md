# Pivot Hint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface a short, read-only `pivot_hint` into autopilot state output and agent bootstrap context so Claude Code can make better next-step judgments without changing execution logic.

**Architecture:** Add a small helper in `tools/autopilot_state.py` that synthesizes one hint from existing guard and repo-source signals, attach it to the returned state, render it in `format_autopilot_state()`, and render the same hint in `agent._build_agent_bootstrap_context()`. The hint is advisory only and must not affect `next_action`, ranking, or request behavior.

**Tech Stack:** Python, pytest, existing autopilot-state/agent bootstrap formatting and repo-source summary fields.

---

### Task 1: Add pivot hint synthesis to autopilot state

**Files:**
- Modify: `tools/autopilot_state.py`
- Test: `tests/test_autopilot_state_tool.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_build_autopilot_state_includes_repo_first_pivot_hint_when_blocked_and_repo_findings_exist(tmp_path):
    repo_root = tmp_path
    recon_dir = repo_root / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        "https://files.target.com [200] [Files] [nginx] [1000]\n"
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
    )
    (recon_dir / "urls" / "with_params.txt").write_text("")
    (recon_dir / "js" / "endpoints.txt").write_text("")

    exposure_dir = repo_root / "findings" / "target.com" / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text(
        '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
        encoding="utf-8",
    )
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 0\n",
        encoding="utf-8",
    )

    memory_dir = tmp_path / "hunt-memory"
    (memory_dir / "targets").mkdir(parents=True)
    save_target_profile(memory_dir, make_target_profile(
        "target.com",
        tech_stack=["graphql", "next.js"],
        tested_endpoints=[],
        untested_endpoints=["/graphql", "/download?id=1"],
        scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
        hunt_sessions=1,
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

    assert state["pivot_hint"] == "avoid blocked live API for now; inspect repo source findings first."


def test_format_autopilot_state_shows_pivot_hint():
    output = format_autopilot_state({
        "target": "target.com",
        "has_recon": True,
        "has_memory": True,
        "tech_stack": ["next.js"],
        "next_action": "hunt_p1",
        "resume_summary": {},
        "surface": {"stats": {"p1": 1, "p2": 0}},
        "guard_status": {"tracked_hosts": 1, "tripped_hosts": [{"host": "api.target.com", "remaining_seconds": 20.0}], "settings": {}},
        "guard_hint": "avoid cooling hosts: api.target.com (20.0s); prefer the ready host files.target.com via https://files.target.com/download?id=1",
        "repo_source_available": True,
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=0",
            "secret_findings": 2,
            "ci_findings": 0,
        },
        "resume_targets": [],
        "recommended_targets": [],
        "recent_guard_blocks": [],
        "pivot_hint": "avoid blocked live API for now; inspect repo source findings first.",
    })

    assert "Pivot hint: avoid blocked live API for now; inspect repo source findings first." in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "pivot_hint"
```

Expected: FAIL because `build_autopilot_state()` does not yet return `pivot_hint` and formatted output does not yet include it.

- [ ] **Step 3: Write the minimal implementation**

```python
# in tools/autopilot_state.py

def _build_pivot_hint(state_inputs...) -> str:
    tripped_hosts = ...
    recent_guard_blocks = ...
    repo_source_summary = ...
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    ci_findings = int(repo_source_summary.get("ci_findings", 0) or 0)
    has_blocked_surface = bool(tripped_hosts or recent_guard_blocks)
    has_repo_findings = secret_findings > 0 or ci_findings > 0

    if has_blocked_surface and has_repo_findings:
        return "avoid blocked live API for now; inspect repo source findings first."
    if has_blocked_surface:
        return "avoid retrying the blocked surface now; continue with the next ready target."
    if secret_findings > 0:
        return "repo source shows secrets; verify credential usability before widening live probing."
    if ci_findings > 0:
        return "repo source shows CI risks; review workflow attack surface before rerunning source hunt."
    return ""

# attach to returned state
"pivot_hint": pivot_hint,

# in format_autopilot_state(...)
pivot_hint = str(state.get("pivot_hint", "") or "").strip()
if pivot_hint:
    lines.append(f"Pivot hint: {pivot_hint}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "pivot_hint"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/autopilot_state.py tests/test_autopilot_state_tool.py
git commit -m "feat: add pivot hints to autopilot state"
```

### Task 2: Surface pivot hint in agent bootstrap context

**Files:**
- Modify: `agent.py`
- Test: `tests/test_autopilot_mode.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_agent_bootstrap_context_surfaces_pivot_hint(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "avoid cooling hosts: api.target.com (25.0s); prefer the ready host files.target.com via https://files.target.com/download?id=1",
        "guard_status": {"tripped_hosts": [{"host": "api.target.com", "remaining_seconds": 25.0}]},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "recent_guard_blocks": [],
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=0",
            "secret_findings": 2,
            "ci_findings": 0,
        },
        "pivot_hint": "avoid blocked live API for now; inspect repo source findings first.",
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Pivot hint: avoid blocked live API for now; inspect repo source findings first." in output
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "pivot_hint"
```

Expected: FAIL because bootstrap context does not yet render `pivot_hint`.

- [ ] **Step 3: Write minimal implementation**

```python
pivot_hint = str(state.get("pivot_hint", "") or "").strip()
if pivot_hint:
    lines.append(f"Pivot hint: {pivot_hint}")
```

Place this after the existing guard/repo summary context and before the top-target summary so it reads as operational guidance.

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "pivot_hint"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent.py tests/test_autopilot_mode.py
git commit -m "feat: surface pivot hints in agent bootstrap"
```

### Task 3: Run focused regression verification

**Files:**
- Modify: none
- Test: `tests/test_autopilot_state_tool.py`
- Test: `tests/test_autopilot_mode.py`
- Test: `tests/test_agent_summaries.py`
- Test: `tests/test_hunt_wrappers.py`

- [ ] **Step 1: Run focused pivot/autopilot regression suite**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py
```

Expected: PASS.

- [ ] **Step 2: Run broader confidence suite**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_summaries.py tests/test_agent_helper_tools.py tests/test_hunt_wrappers.py
```

Expected: PASS. No change to request behavior, ranking, or source-hunt execution.

- [ ] **Step 3: Record completion status**

Run:
```bash
git status --short
```

Expected: only intended implementation/test/spec/plan files plus known local untracked files.
