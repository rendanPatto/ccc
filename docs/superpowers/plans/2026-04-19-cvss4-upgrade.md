# CVSS 4.0 Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Switch the repository's primary validation and reporting path from CVSS 3.1 to CVSS 4.0 across code, terminal output, and public documentation.

**Architecture:** Keep the existing validate/report workflow structure intact, but replace the current CVSS 3.1 scoring core in `tools/validate.py` with a CVSS 4.0 primary path and then update all directly exposed docs to match. Scope stays tight: scoring engine, validate output wording, and the handful of docs/agent prompts that still present CVSS 3.1 as the main version.

**Tech Stack:** Python 3 CLI, pytest, markdown docs

---

## File structure

- `tools/validate.py` — main scoring implementation and terminal wording; the primary behavior change lives here
- `tests/test_validate_cvss4.py` — new focused regression tests for CVSS 4.0 output and severity behavior
- `README.md` — public overview should no longer claim CVSS 3.1
- `CLAUDE.md` — plugin guide should describe report-writing/report generation with CVSS 4.0
- `commands/report.md` — slash command doc should present CVSS 4.0 in generated-report expectations and examples
- `agents/report-writer.md` — report-writing agent prompt should switch its CVSS guidance from 3.1 to 4.0
- `tests/test_validate_ctf_mode.py` — existing validate-adjacent regression tests, rerun to ensure the upgrade does not break validate persistence/CTF behavior

### Task 1: Write failing tests for the new CVSS 4.0 scoring/output contract

**Files:**
- Create: `tests/test_validate_cvss4.py`
- Modify: `tools/validate.py` (later task, not yet)

- [ ] **Step 1: Create focused tests for score metadata and terminal wording**

Create `tests/test_validate_cvss4.py` with this content:

```python
"""Focused tests for CVSS 4.0 behavior in tools/validate.py."""

from __future__ import annotations

import validate


def test_calculate_cvss4_returns_cvss4_vector_prefix():
    score, vector = validate.calculate_cvss4(
        av="N",
        ac="L",
        at="N",
        pr="N",
        ui="N",
        vc="H",
        vi="H",
        va="H",
        sc="N",
        si="N",
        sa="N",
    )

    assert isinstance(score, float)
    assert vector.startswith("CVSS:4.0/")


def test_cvss4_severity_from_score_thresholds():
    assert validate.severity_from_score(0.0) == "NONE"
    assert validate.severity_from_score(3.9) == "LOW"
    assert validate.severity_from_score(6.9) == "MEDIUM"
    assert validate.severity_from_score(8.9) == "HIGH"
    assert validate.severity_from_score(9.0) == "CRITICAL"


def test_validate_output_uses_cvss4_labels(monkeypatch, capsys):
    answers = iter([
        "N",  # AV
        "L",  # AC
        "N",  # AT
        "N",  # PR
        "N",  # UI
        "H",  # VC
        "H",  # VI
        "H",  # VA
        "N",  # SC
        "N",  # SI
        "N",  # SA
    ])

    monkeypatch.setattr(validate, "ask_choice", lambda prompt, choices: next(answers))

    score, vector, sev = validate.ask_cvss_score()

    captured = capsys.readouterr().out
    assert score >= 0.0
    assert vector.startswith("CVSS:4.0/")
    assert sev in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert "CVSS 4.0 Scoring" in captured
    assert "CVSS 4.0 Score:" in captured
```

- [ ] **Step 2: Run the new tests and confirm they fail first**

Run: `pytest -q tests/test_validate_cvss4.py`

Expected: FAIL because `tools/validate.py` still exposes CVSS 3.1-only scoring and labels.

- [ ] **Step 3: Commit the red tests**

```bash
git add tests/test_validate_cvss4.py
git commit -m "test: cover cvss4 validate output"
```

### Task 2: Replace the primary scoring/output path in `tools/validate.py` with CVSS 4.0

**Files:**
- Modify: `tools/validate.py`
- Test: `tests/test_validate_cvss4.py`

- [ ] **Step 1: Replace the top-level CVSS 3.1 section with a CVSS 4.0 scoring block**

In `tools/validate.py`, replace the current `# ─── CVSS 3.1 scoring ───` block with a CVSS 4.0 section. Keep the existing `severity_from_score()` helper name, but update the scoring function to a new primary entrypoint named `calculate_cvss4(...)`.

Minimum contract:

```python
def calculate_cvss4(av, ac, at, pr, ui, vc, vi, va, sc, si, sa) -> tuple[float, str]:
    """Calculate CVSS 4.0 base score and return (score, vector_string)."""
```

The returned vector must start with:

```python
f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
```

Use the upstream-aligned CVSS 4.0 metric set:
- `AV`, `AC`, `AT`, `PR`, `UI`
- `VC`, `VI`, `VA`
- `SC`, `SI`, `SA`

Do not preserve the old `S/C/I/A`-style 3.1 vector as the default output.

- [ ] **Step 2: Replace the interactive prompt flow with CVSS 4.0 metrics**

Update `ask_cvss_score()` so the prompt sequence becomes:

```python
    section("CVSS 4.0 Scoring")
```

And the choices include:
- `AV`, `AC`, `AT`, `PR`, `UI`
- `VC`, `VI`, `VA`
- `SC`, `SI`, `SA`

The final printed score line must be:

```python
print(f"\n  {BOLD}CVSS 4.0 Score: {sev_color}{score} {sev}{RESET}")
```

Then return `(score, vector, sev)` using `calculate_cvss4(...)`.

- [ ] **Step 3: Update internal callers to use the new function name and output contract**

Replace direct calls to the old `calculate_cvss(...)` function with `calculate_cvss4(...)` inside `ask_cvss_score()` and any other internal call sites in `tools/validate.py`.

If any text still says `CVSS 3.1`, update it to `CVSS 4.0` unless it is clearly a migration/history note.

- [ ] **Step 4: Run the focused CVSS 4.0 tests**

Run: `pytest -q tests/test_validate_cvss4.py`

Expected: PASS.

- [ ] **Step 5: Run existing validate-adjacent regressions**

Run: `pytest -q tests/test_validate_ctf_mode.py tests/test_remember_tool.py`

Expected: PASS, proving the version upgrade did not break validate summary persistence or remember prefill flows.

- [ ] **Step 6: Commit the scoring/output upgrade**

```bash
git add tools/validate.py tests/test_validate_cvss4.py
git commit -m "feat: switch validate scoring to cvss4"
```

### Task 3: Switch public docs and report-writing prompts to CVSS 4.0

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `commands/report.md`
- Modify: `agents/report-writer.md`

- [ ] **Step 1: Update the public overview docs**

Apply these exact text-level changes:

```diff
--- README.md
-    nuclei           chain A→B→C      CVSS 3.1
+    nuclei           chain A→B→C      CVSS 4.0
```

```diff
--- CLAUDE.md
-| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
+| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 4.0, human tone |
```

- [ ] **Step 2: Update `/report` command documentation**

In `commands/report.md`, replace the CVSS 3.1 main-path wording with CVSS 4.0 wording in these places:
- frontmatter description
- “What This Generates” bullet about the score/vector
- HackerOne format bullet
- `## CVSS 3.1 Calculation Guide` heading
- any explicit “Include CVSS 3.1 score” instruction

After editing, the guide section heading should be:

```md
## CVSS 4.0 Calculation Guide
```

And the frontmatter should say `CVSS 4.0 score` instead of `CVSS 3.1 score`.

- [ ] **Step 3: Update the report-writer agent prompt**

In `agents/report-writer.md`, update:
- frontmatter description from `CVSS 3.1 calculation included` to `CVSS 4.0 calculation included`
- heading `## CVSS 3.1 Calculation` to `## CVSS 4.0 Calculation`
- the HackerOne markdown template line from `**CVSS 3.1 Score:** ...` to `**CVSS 4.0 Score:** ...`

Do not rewrite unrelated report-writing rules.

- [ ] **Step 4: Audit remaining public CVSS version references**

Run: `rg -n "CVSS 3\.1|CVSS 4\.0|CVSS 4|CVSS 3" README.md CLAUDE.md commands/report.md agents/report-writer.md tools/validate.py`

Expected: CVSS 4.0 is the main visible version across these touched files. Any remaining CVSS 3.1 text must be clearly historical or removed.

- [ ] **Step 5: Commit the doc/prompt alignment**

```bash
git add README.md CLAUDE.md commands/report.md agents/report-writer.md
git commit -m "docs: align report workflow to cvss4"
```

### Task 4: Final verification and handoff check

**Files:**
- Verify only

- [ ] **Step 1: Run the focused CVSS upgrade verification suite**

Run: `pytest -q tests/test_validate_cvss4.py tests/test_validate_ctf_mode.py tests/test_remember_tool.py`

Expected: PASS.

- [ ] **Step 2: Run the full regression suite**

Run: `pytest -q`

Expected: PASS with no regressions.

- [ ] **Step 3: Sanity-check for stale CVSS 3.1 main-path language in touched surfaces**

Run: `rg -n "CVSS 3\.1" README.md CLAUDE.md commands/report.md agents/report-writer.md tools/validate.py`

Expected: no remaining main-path CVSS 3.1 wording in the touched files.

- [ ] **Step 4: Prepare final handoff summary if no extra edits are needed**

If Task 4 requires no further code changes, do not create an empty commit. Instead summarize:
- validate scoring now defaults to CVSS 4.0
- validate terminal output now uses CVSS 4.0 labels
- report docs/prompts now use CVSS 4.0 as the main public version
- full test suite passes
