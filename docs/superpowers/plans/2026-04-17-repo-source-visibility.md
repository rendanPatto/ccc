# Repo Source Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface a compact repository source-hunt summary into autopilot state output and agent bootstrap context without changing source-hunt behavior or autopilot decisions.

**Architecture:** Read existing exposure artifacts under `findings/<target>/exposure/`, extract a very small repo-source summary in `tools/autopilot_state.py`, render that summary in formatted autopilot output, and pass the same summary into `agent._build_agent_bootstrap_context()`.

**Tech Stack:** Python, pytest, JSON/Markdown parsing of existing source-hunt artifacts.

---

### Task 1: Add compact repo-source summary extraction to autopilot state

**Files:**
- Modify: `tools/autopilot_state.py`
- Test: `tests/test_autopilot_state_tool.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_build_autopilot_state_includes_repo_source_summary(tmp_path):
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
        '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
        encoding="utf-8",
    )
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 1\n",
        encoding="utf-8",
    )

    memory_dir = tmp_path / "hunt-memory"
    (memory_dir / "targets").mkdir(parents=True)
    save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

    state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

    assert state["repo_source_summary"]["source_kind"] == "local_path"
    assert state["repo_source_summary"]["secret_findings"] == 2
    assert state["repo_source_summary"]["ci_findings"] == 1


def test_format_autopilot_state_shows_repo_source_summary():
    output = format_autopilot_state({
        "target": "target.com",
        "has_recon": True,
        "has_memory": True,
        "tech_stack": ["next.js"],
        "next_action": "hunt_p1",
        "resume_summary": {},
        "surface": {"stats": {"p1": 1, "p2": 0}},
        "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
        "guard_hint": "",
        "repo_source_available": True,
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=1",
            "source_kind": "local_path",
            "secret_findings": 2,
            "ci_findings": 1,
        },
        "resume_targets": [],
        "recommended_targets": [],
        "recent_guard_blocks": [],
    })

    assert "Repo source: local_path, secrets=2, ci=1" in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "repo_source_summary"
```

Expected: FAIL because `build_autopilot_state()` does not yet expose `repo_source_summary` and formatted output does not yet use it.

- [ ] **Step 3: Write the minimal implementation**

```python
# add helper in tools/autopilot_state.py
# - read repo_source_meta.json when present
# - parse secret/ci counts from repo_summary.md when present
# - return compact dict with summary_hint

repo_source_summary = _load_repo_source_summary(repo_root, target)

return {
    # existing fields...
    "repo_source_summary": repo_source_summary,
}

# in format_autopilot_state(...)
repo_source_summary = state.get("repo_source_summary") or {}
summary_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
if summary_hint:
    lines.append(f"Repo source: {summary_hint}")
elif state.get("repo_source_available"):
    lines.append("Repo source: available — use read_repo_source_summary")
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py -k "repo_source_summary"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/autopilot_state.py tests/test_autopilot_state_tool.py
git commit -m "feat: surface repo source summary in autopilot state"
```

### Task 2: Surface repo-source summary in agent bootstrap context

**Files:**
- Modify: `agent.py`
- Test: `tests/test_autopilot_mode.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_agent_bootstrap_context_surfaces_repo_source_summary(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "",
        "guard_status": {"tripped_hosts": []},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "recent_guard_blocks": [],
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=1",
            "source_kind": "local_path",
            "secret_findings": 2,
            "ci_findings": 1,
        },
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Repo source summary: local_path, secrets=2, ci=1" in output
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "repo_source_summary"
```

Expected: FAIL because agent bootstrap does not yet render repo-source summary.

- [ ] **Step 3: Write minimal implementation**

```python
repo_source_summary = state.get("repo_source_summary") or {}
repo_source_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
if repo_source_hint:
    lines.append(f"Repo source summary: {repo_source_hint}")
```

Place this near the existing bootstrap context hints, before the top-target summary.

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
pytest -q tests/test_autopilot_mode.py -k "repo_source_summary"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent.py tests/test_autopilot_mode.py
git commit -m "feat: add repo source summary to agent bootstrap"
```

### Task 3: Run focused regression verification

**Files:**
- Modify: none
- Test: `tests/test_autopilot_state_tool.py`
- Test: `tests/test_autopilot_mode.py`
- Test: `tests/test_agent_summaries.py`
- Test: `tests/test_source_hunt_cli.py`

- [ ] **Step 1: Run focused repo-source/autopilot regression suite**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_summaries.py tests/test_source_hunt_cli.py
```

Expected: PASS.

- [ ] **Step 2: Run broader confidence suite**

Run:
```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_summaries.py tests/test_agent_helper_tools.py tests/test_source_hunt_cli.py tests/test_hunt_wrappers.py
```

Expected: PASS. No change to source-hunt execution or autopilot decisions.

- [ ] **Step 3: Record completion status**

Run:
```bash
git status --short
```

Expected: only intended implementation/test/spec/plan files plus known local untracked files.
