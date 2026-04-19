# Upstream `97d4efb` Migration Alignment — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep legacy CVE/report entrypoints working, but clearly downgrade them to compatibility paths while making `/intel` and `/report` the more obvious primary workflows.

**Architecture:** Add lightweight compatibility messaging in `tools/hunt.py` and align `agent.py` guidance so legacy tool names remain stable but are no longer the primary narrative. Then update the public docs to recommend `/intel` and `/report` first, while mentioning old entrypoints only as compatibility paths. No stubs, no deletions, no memory-layer rewrite.

**Tech Stack:** Python 3, pytest, existing `tools/` wrappers, markdown docs

---

## File structure

- `tools/hunt.py` — add low-noise compatibility notices for `run_cve_hunt()` and `generate_reports()`
- `agent.py` — weaken the legacy-tool narrative in agent guidance without removing tool names
- `tests/test_hunt_wrappers.py` — assert legacy entrypoints still execute while emitting compatibility messaging
- `tests/test_agent_dispatcher_misc.py` — add a narrow regression around unchanged dispatcher output expectations if needed
- `README.md` — make `/intel` and `/report` the primary recommended intel/report workflows
- `CLAUDE.md` — update plugin guide wording so `/intel` and `/report` are primary, while legacy scripts are compatibility-oriented
- `commands/hunt.md` — shift hunt workflow copy away from legacy CVE/report scripts as primary next steps
- `commands/intel.md` — optionally reinforce that `/intel` is the preferred intel path
- `commands/report.md` — optionally reinforce that `/report` is the preferred report path

### Task 1: Add compatibility-path messaging to `tools/hunt.py` with tests first

**Files:**
- Modify: `tools/hunt.py`
- Modify: `tests/test_hunt_wrappers.py`

- [ ] **Step 1: Write the failing tests first**

Append these tests to `tests/test_hunt_wrappers.py`:

```python
def test_run_cve_hunt_logs_compatibility_hint(monkeypatch, tmp_path, capsys):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    (tmp_path / "recon" / domain).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(hunt, "run_legacy_cve_hunt", lambda *args, **kwargs: (True, "ok"))

    assert hunt.run_cve_hunt(domain) is True

    output = capsys.readouterr().out.lower()
    assert "legacy compatibility path" in output
    assert "/intel" in output


def test_generate_reports_logs_compatibility_hint(monkeypatch, tmp_path, capsys):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = tmp_path / "findings" / domain
    report_dir = tmp_path / "reports" / domain
    findings_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    (report_dir / "compat.md").write_text("ok", encoding="utf-8")

    monkeypatch.setattr(hunt, "generate_legacy_reports", lambda *args, **kwargs: (True, "generated"))

    assert hunt.generate_reports(domain) == 1

    output = capsys.readouterr().out.lower()
    assert "legacy compatibility path" in output
    assert "/report" in output
```

- [ ] **Step 2: Run the tests to verify red**

Run: `pytest -q tests/test_hunt_wrappers.py -k "compatibility_hint"`

Expected: FAIL because `tools/hunt.py` does not emit compatibility hints yet.

- [ ] **Step 3: Implement the minimal messaging**

In `tools/hunt.py`, add a tiny helper near the existing logging helpers:

```python
def _log_legacy_path_hint(kind: str, preferred_command: str) -> None:
    """Emit a low-noise note that a legacy compatibility path is being used."""
    log(
        "info",
        f"{kind} is using a legacy compatibility path; prefer {preferred_command} for the primary workflow.",
    )
```

Then update `generate_reports()` to emit the hint before calling the bridge:

```python
    _log_legacy_path_hint("Report generation", "/report")
```

And update `run_cve_hunt()` similarly:

```python
    _log_legacy_path_hint("CVE hunt", "/intel")
```

Do not change return values, function names, or bridge behavior.

- [ ] **Step 4: Run the focused tests to verify green**

Run: `pytest -q tests/test_hunt_wrappers.py`

Expected: PASS.

- [ ] **Step 5: Commit the `hunt.py` compatibility messaging**

```bash
git add tools/hunt.py tests/test_hunt_wrappers.py
git commit -m "feat: mark legacy hunt entrypoints as compatibility paths"
```

### Task 2: Weaken the legacy-tool narrative in `agent.py`

**Files:**
- Modify: `agent.py`
- Modify: `tests/test_agent_dispatcher_misc.py`

- [ ] **Step 1: Write the failing test first**

Append this test to `tests/test_agent_dispatcher_misc.py`:

```python
def test_agent_system_mentions_intel_and_report_as_primary_workflows():
    system = agent._build_agent_system(ctf_mode=False, autopilot_mode="normal")

    assert "/intel" in system
    assert "/report" in system
    assert "compatibility" in system.lower()
```

- [ ] **Step 2: Run the test to verify red**

Run: `pytest -q tests/test_agent_dispatcher_misc.py -k "primary_workflows"`

Expected: FAIL because the current agent prompt talks about `run_cve_hunt` / `generate_reports` without the compatibility framing.

- [ ] **Step 3: Implement the minimal agent guidance change**

In `agent.py`, update the relevant lines inside `_build_agent_system(...)` so the agent keeps the same tool names but treats them as compatibility-oriented paths. Replace:

```text
8. If Drupal or WordPress is detected → run_cms_exploit immediately. If any stack is clearly identified, run_cve_hunt.
...
15. Generate reports with generate_reports before finish when findings or useful artifacts exist.
```

with:

```text
8. If Drupal or WordPress is detected → run_cms_exploit immediately. If any stack is clearly identified, run_cve_hunt as a legacy compatibility path; /intel is the primary intel workflow.
...
15. Generate reports with generate_reports before finish when findings or useful artifacts exist, but treat it as a compatibility path; /report is the primary reporting workflow.
```

Keep the rest of the agent rules unchanged.

- [ ] **Step 4: Run the focused test to verify green**

Run: `pytest -q tests/test_agent_dispatcher_misc.py`

Expected: PASS.

- [ ] **Step 5: Commit the agent narrative update**

```bash
git add agent.py tests/test_agent_dispatcher_misc.py
git commit -m "docs: weaken legacy tool narrative in agent guidance"
```

### Task 3: Align public docs so `/intel` and `/report` are the primary story

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `commands/hunt.md`
- Modify: `commands/intel.md`
- Modify: `commands/report.md`

- [ ] **Step 1: Write the failing doc-regression test first**

Create `tests/test_phase2_docs.py` with this content:

```python
"""Regression checks for phase2 migration wording."""

from pathlib import Path


def test_docs_promote_intel_and_report_as_primary_paths():
    repo = Path(__file__).resolve().parent.parent
    readme = (repo / "README.md").read_text(encoding="utf-8")
    claude = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    hunt = (repo / "commands" / "hunt.md").read_text(encoding="utf-8")

    combined = "\n".join([readme, claude, hunt]).lower()

    assert "/intel" in combined
    assert "/report" in combined
    assert "compatibility path" in combined
```

- [ ] **Step 2: Run the doc test to verify red**

Run: `pytest -q tests/test_phase2_docs.py`

Expected: FAIL because the current docs do not consistently describe the legacy path as compatibility-oriented.

- [ ] **Step 3: Update the docs with minimal wording changes**

Make these targeted wording changes:

- In `README.md`, near the “Quick Start” / direct-tooling sections, add one short note after `/intel` / `/report` examples:

```markdown
> `tools/hunt.py --cve-hunt` and legacy report generation still work, but they are compatibility paths. Prefer `/intel` for intel workflow and `/report` for submission-ready reporting.
```

- In `CLAUDE.md`, under “Tools (Python/shell — in `tools/`)”, revise:

```markdown
- `tools/report_generator.py` — legacy compatibility report backend (prefer `/report`)
- `tools/learn.py` — CVE + disclosure intel backend
- `tools/intel_engine.py` — primary on-demand intel workflow behind `/intel`
```

And add one short note after the command table:

```markdown
> Legacy CVE/report script paths remain available for compatibility, but `/intel` and `/report` are the primary workflows.
```

- In `commands/hunt.md`, add a brief note near the top of “What This Does” or before active testing:

```markdown
> Legacy CVE hunt / report-generation paths are still available for compatibility, but the preferred primary workflows are `/intel` for intel and `/report` for final reporting.
```

- In `commands/intel.md`, add a short note near the title:

```markdown
> Preferred primary intel workflow. Legacy CVE-hunt entrypoints are compatibility paths only.
```

- In `commands/report.md`, add a short note near the title:

```markdown
> Preferred primary reporting workflow. Legacy report-generation entrypoints are compatibility paths only.
```

Keep wording concise; do not rewrite large sections.

- [ ] **Step 4: Run the doc test to verify green**

Run: `pytest -q tests/test_phase2_docs.py`

Expected: PASS.

- [ ] **Step 5: Commit the doc alignment**

```bash
git add README.md CLAUDE.md commands/hunt.md commands/intel.md commands/report.md tests/test_phase2_docs.py
git commit -m "docs: promote intel and report as primary workflows"
```

### Task 4: Final verification and handoff

**Files:**
- Verify only

- [ ] **Step 1: Run the focused Phase 2 suite**

Run:

```bash
pytest -q tests/test_hunt_wrappers.py tests/test_agent_dispatcher_misc.py tests/test_phase2_docs.py
```

Expected: PASS.

- [ ] **Step 2: Run the full regression suite**

Run:

```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 3: Audit the final diff is scoped correctly**

Run:

```bash
git diff --stat main..HEAD
```

Expected touched files are limited to:
- `docs/superpowers/plans/2026-04-20-upstream-97d4efb-migration-phase2.md`
- `tools/hunt.py`
- `agent.py`
- `README.md`
- `CLAUDE.md`
- `commands/hunt.md`
- `commands/intel.md`
- `commands/report.md`
- `tests/test_hunt_wrappers.py`
- `tests/test_agent_dispatcher_misc.py`
- `tests/test_phase2_docs.py`

- [ ] **Step 4: Commit any final verification-only adjustment if needed**

```bash
git add -A
git commit -m "test: cover 97d4efb migration phase2"
```

Only do this if verification uncovers a small last-mile fix. Otherwise skip.
