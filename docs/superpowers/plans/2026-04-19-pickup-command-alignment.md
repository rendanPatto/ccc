# Pickup Command Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align the public "continue previous hunt" command to official `/pickup` while keeping a thin `/resume` compatibility layer.

**Architecture:** Keep the internal Python implementation centered on `tools/resume.py` and `resume_*` helpers, but switch all user-facing command docs and terminal output to `/pickup`. Preserve `/resume` only as a compatibility doc entry so future upstream syncs stay shallow and local enhancements remain isolated.

**Tech Stack:** Markdown command docs, Python 3 CLI formatter, pytest

---

## File structure

- `commands/pickup.md` — new primary slash-command doc aligned to upstream wording
- `commands/resume.md` — compatibility page pointing users to `/pickup`
- `README.md` — public workflow table and examples should recommend `/pickup`
- `CLAUDE.md` — plugin guide command inventory should list `/pickup` and reserve `/resume` only as legacy context if needed
- `commands/autopilot.md` — post-run guidance should point to `/pickup`
- `commands/remember.md` — memory feedback loop should point to `/pickup`
- `tools/resume.py` — keep implementation name, but switch display strings from `RESUME` / "Resume hunting" to `PICKUP` / "Continue hunting"
- `tests/test_resume_tool.py` — assert the new `PICKUP` output wording and keep no-history behavior stable

### Task 1: Add the `/pickup` primary command doc and demote `/resume` to compatibility

**Files:**
- Create: `commands/pickup.md`
- Modify: `commands/resume.md`

- [ ] **Step 1: Write the command-doc content before touching existing files**

Create `commands/pickup.md` with this content:

```md
---
description: Pick up a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. Usage: /pickup target.com
---

# /pickup

Pick up where you left off on a target.

> **Renamed from `/resume`** — `/resume` is a reserved Claude Code command. Use `/pickup` to continue a previous hunt.

## What This Does

1. Reads the target profile from `hunt-memory/targets/<target>.json`
2. Shows hunt history (sessions, findings, payouts)
3. Lists untested endpoints from last recon
4. Suggests techniques based on tech stack + pattern DB
5. Asks: continue hunting or re-run recon?

## Usage

```
/pickup target.com
```

## Output

```
PICKUP: target.com
═══════════════════════════════════════

Hunt History:
  Sessions:    3
  Last hunt:   2026-03-24
  Total time:  2h 00m
  Findings:    1 confirmed (IDOR, $1500 paid)

Untested Surface:
  3 endpoints from last recon:
  1. /api/v2/users/{id}/export
  2. /api/v2/users/{id}/share
  3. /api/v2/users/{id}/history

Memory Suggestions:
  Tech stack [Next.js, GraphQL, PostgreSQL] matches 2 targets
  where you found auth bypass. Try introspection → mutation pattern.

Actions:
  [r] Continue hunting untested endpoints
  [n] Re-run recon first (surface may have changed)
  [s] Show full hunt journal for this target
```

## If No Previous Hunt

```
No previous hunt data for target.com.
Run /recon target.com first, then /hunt target.com.
```
```

- [ ] **Step 2: Replace `commands/resume.md` with a compatibility page**

Overwrite `commands/resume.md` with this content:

```md
---
description: Legacy compatibility entry for continuing a previous hunt. Prefer /pickup target.com.
---

# /resume

Legacy compatibility entry for older workflows.

> `/resume` is kept only as a compatibility alias. In Claude Code, use `/pickup target.com`.

## Use This Instead

```
/pickup target.com
```

## Why

- `/pickup` is the official upstream command name
- `/resume` conflicts with reserved Claude Code command semantics
- Future updates in this repo will continue to align around `/pickup`
```

- [ ] **Step 3: Verify the docs look correct**

Run: `sed -n '1,120p' commands/pickup.md && printf '\n---\n' && sed -n '1,80p' commands/resume.md`

Expected: `commands/pickup.md` shows the full primary workflow for `/pickup`, and `commands/resume.md` clearly says it is a legacy compatibility entry.

- [ ] **Step 4: Commit the doc entrypoint change**

```bash
git add commands/pickup.md commands/resume.md
git commit -m "docs: align continue-hunt command to pickup"
```

### Task 2: Update public docs so `/pickup` becomes the default visible entrypoint

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `commands/autopilot.md`
- Modify: `commands/remember.md`

- [ ] **Step 1: Update the public command tables and examples**

Apply these exact string replacements:

```diff
--- README.md
-| `/resume target.com` | Resume previous hunt — shows what's untested |
+| `/pickup target.com` | Pick up previous hunt — shows what's untested |
```

```diff
--- README.md
-- `/resume target.com` shows which endpoints you've tested and which remain
+- `/pickup target.com` shows which endpoints you've tested and which remain
```

```diff
--- CLAUDE.md
-| `/resume` | `/resume target.com` — pick up previous hunt |
+| `/pickup` | `/pickup target.com` — pick up previous hunt |
```

Immediately above the command table in `CLAUDE.md`, add this note:

```md
> `/resume` is a reserved Claude Code command — use `/pickup` to continue a previous hunt.
```

- [ ] **Step 2: Update workflow guidance in command docs**

Apply these exact text edits:

```diff
--- commands/autopilot.md
-like `scope_checker.py`, hunt-memory modules, and the `/remember` `/resume`
+like `scope_checker.py`, hunt-memory modules, and the `/remember` `/pickup`
```

```diff
--- commands/autopilot.md
-- Run `/resume target.com` next time to pick up where you left off
+- Run `/pickup target.com` next time to pick up where you left off
```

```diff
--- commands/remember.md
-- `/resume target.com` shows which endpoints you've tested and which remain
+- `/pickup target.com` shows which endpoints you've tested and which remain
```

- [ ] **Step 3: Audit remaining user-facing `/resume` references**

Run: `rg -n "/resume|/pickup" README.md CLAUDE.md commands agents`

Expected: remaining hits are limited to the intentional compatibility note in `commands/resume.md` and any explicit migration note that explains `/resume` changed to `/pickup`.

- [ ] **Step 4: Commit the public-doc alignment**

```bash
git add README.md CLAUDE.md commands/autopilot.md commands/remember.md
git commit -m "docs: switch public continue-hunt docs to pickup"
```

### Task 3: Update tests first for the new `/pickup` output wording

**Files:**
- Test: `tests/test_resume_tool.py`

- [ ] **Step 1: Change the formatter assertions to the new public wording**

Update the relevant assertions in `tests/test_resume_tool.py` to this exact form:

```python
def test_formats_summary_output(self):
    summary = {
        "target": "target.com",
        "sessions": 3,
        "last_hunted": "2026-03-24T21:00:00Z",
        "total_time_minutes": 125,
        "tech_stack": ["next.js", "graphql"],
        "tested_endpoints": ["/a"],
        "untested_endpoints": ["/b", "/c"],
        "findings": [],
        "finding_titles": [{"vuln_class": "idor", "endpoint": "/api/v2/users/{id}", "payout": 1500}],
        "journal_entries": 4,
        "confirmed_findings": 1,
        "confirmed_payout": 1500,
        "pattern_matches": [{"target": "alpha.com", "technique": "id_swap", "vuln_class": "idor", "payout": 800}],
        "matched_targets": 1,
        "latest_session_summary": {
            "ts": "2026-04-17T00:00:00Z",
            "session_id": "sess-777",
            "findings_count": 1,
            "vuln_classes": ["recon", "idor"],
            "endpoints_preview": ["/graphql"],
        },
    }
    output = format_resume_output(summary, "target.com")
    assert "PICKUP: target.com" in output
    assert "1 confirmed ($1500 total)" in output
    assert "2 endpoints from last recon" in output
    assert "alpha.com: id_swap [idor] ($800)" in output
    assert "Latest Session Snapshot:" in output
    assert "Session: sess-777" in output
    assert "Tried: recon, idor" in output
    assert "[r] Continue hunting untested endpoints" in output
```

Also add this explicit compatibility expectation to the missing-state test:

```python
def test_formats_missing_state(self):
    output = format_resume_output(None, "missing.com")
    assert "No previous hunt data for missing.com." in output
    assert "Run /recon missing.com first, then /hunt missing.com." in output
```

- [ ] **Step 2: Run the resume formatter tests to confirm they fail first**

Run: `pytest -q tests/test_resume_tool.py`

Expected: FAIL because the formatter still emits `RESUME: target.com` and `Resume hunting untested endpoints`.

- [ ] **Step 3: Commit the red test change**

```bash
git add tests/test_resume_tool.py
git commit -m "test: expect pickup wording in resume formatter"
```

### Task 4: Switch the formatter output from `RESUME` to `PICKUP` and verify no regressions

**Files:**
- Modify: `tools/resume.py`
- Test: `tests/test_resume_tool.py`

- [ ] **Step 1: Update only the user-facing formatter strings**

Edit `format_resume_output()` in `tools/resume.py` so the affected lines become exactly:

```python
    lines = [
        f"PICKUP: {target}",
        "═══════════════════════════════════════",
        "",
        "Hunt History:",
        f"  Sessions:    {summary['sessions']}",
        f"  Last hunt:   {summary['last_hunted'] or 'unknown'}",
        f"  Total time:  {format_minutes(summary['total_time_minutes'])}",
        f"  Journal:     {summary['journal_entries']} entries",
    ]
```

And replace the action block with:

```python
    lines.extend([
        "",
        "Actions:",
        "  [r] Continue hunting untested endpoints",
        "  [n] Re-run recon first (surface may have changed)",
        "  [s] Show full hunt journal for this target",
    ])
```

Do not rename `format_resume_output`, `load_resume_summary`, or any `resume_*` data keys.

- [ ] **Step 2: Run the focused tests to confirm they now pass**

Run: `pytest -q tests/test_resume_tool.py`

Expected: PASS with all `tests/test_resume_tool.py` checks green.

- [ ] **Step 3: Run the broader helper-chain regression tests**

Run: `pytest -q tests/test_autopilot_state_tool.py tests/test_claude_code_helper_flow.py tests/test_autopilot_mode.py`

Expected: PASS, proving the public wording change did not break `resume_summary`, `autopilot_state`, or agent bootstrap consumers.

- [ ] **Step 4: Sanity-check the repository state for official alignment**

Run: `rg -n "/resume|/pickup|RESUME:|PICKUP:" README.md CLAUDE.md commands/remember.md commands/autopilot.md commands/pickup.md commands/resume.md tools/resume.py tests/test_resume_tool.py`

Expected: `/pickup` is the dominant public entrypoint; `/resume` remains only in the compatibility page, internal implementation filenames, and intentional migration notes.

- [ ] **Step 5: Commit the formatter alignment**

```bash
git add tools/resume.py tests/test_resume_tool.py README.md CLAUDE.md commands/autopilot.md commands/remember.md commands/pickup.md commands/resume.md
git commit -m "feat: align continue-hunt UX to pickup"
```
