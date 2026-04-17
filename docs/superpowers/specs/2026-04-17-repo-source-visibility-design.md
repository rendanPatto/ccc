# Repo Source Visibility Enhancement Design

Date: 2026-04-17
Status: Draft approved for spec writing

## Goal

Improve Claude Code CLI practical effectiveness by surfacing a compact repository source-hunt summary into `autopilot_state` output and agent bootstrap context, without changing source-hunt behavior, target ranking, or autopilot next-action logic.

This is a conservative enhancement focused on better runtime awareness:

- reuse existing `findings/<target>/exposure/` artifacts
- summarize only the highest-value source-hunt signals
- expose them in autopilot state
- expose them again in agent bootstrap output

## Why this change

The repo already has a partial repo-source loop:

- `run_source_hunt()` writes `repo_source_meta.json`, `repo_summary.md`, and finding bundles
- `autopilot_state` can detect that repo-source artifacts exist
- the agent already knows it can call `read_repo_source_summary`

But the current behavior is binary:

- repo source available = yes/no
- prompt user/agent to read a summary manually

That means the agent does not know whether the source-hunt artifacts look important enough to inspect first. This enhancement closes that visibility gap while keeping decisions soft and operator-guided.

## Non-goals

This change will **not**:

- modify `run_source_hunt()` behavior
- modify cloning or repo threshold logic
- add new artifact files
- change `next_action`
- change `recommended_targets` sorting
- auto-prioritize repo source over live targets
- parse every individual secret/CI finding into autopilot state

## Recommended approach

### Approach A — compact repo-source summary pass-through (recommended)

Read a very small amount of information from existing source-hunt artifacts and pass it into:

- `tools/autopilot_state.py`
- formatted autopilot state output
- `agent.py` bootstrap context

#### Why this is recommended

- lowest regression risk
- no changes to source-hunt execution
- no changes to attack-surface ranking
- enough context for practical operator/agent decisions

### Approach B — repo-source-aware next action

Adjust `next_action` when source-hunt artifacts look promising.

#### Why not now

- starts changing autopilot behavior
- risks pulling focus away from live targets too aggressively
- larger validation burden

### Approach C — structured secret/CI routing

Map source-hunt findings directly to follow-up vuln classes and exploit paths.

#### Why not now

- too large for a cautious iteration
- better done after visibility proves useful

## Scope

### Files in scope

- `tools/autopilot_state.py`
- `agent.py`
- `tests/test_autopilot_state_tool.py`
- `tests/test_autopilot_mode.py`

### Files intentionally out of scope

- `tools/source_hunt.py`
- `tools/repo_source.py`
- `tools/repo_secret_scan.py`
- `tools/repo_ci_scan.py`
- next-action logic
- ranking logic

## Data source and flow

Existing source artifacts:

- `findings/<target>/exposure/repo_source_meta.json`
- `findings/<target>/exposure/repo_summary.md`

New flow after this change:

`run_source_hunt -> repo artifacts -> autopilot_state summary -> agent bootstrap`

No new persistence layer is added.

## Design details

### 1. `tools/autopilot_state.py`

Add a compact helper that reads repo-source artifacts and returns a small dict when possible.

Expected fields:

- `status`
- `source_kind`
- `clone_performed`
- `secret_findings`
- `ci_findings`
- `summary_hint`

#### Parsing rules

From `repo_source_meta.json`:

- use `status`
- use `source_kind`
- use `clone_performed`

From `repo_summary.md`:

- parse `- Secret findings: N`
- parse `- CI findings: N`
- optionally detect `confirmation required before clone`

#### Output shape

Examples:

- `local_path, secrets=2, ci=1`
- `github, secrets=0, ci=3`
- `confirmation required before clone`

This summary should be stored in state under:

- `repo_source_summary`

### 2. Formatted autopilot state

`format_autopilot_state()` should render one short repo-source line when summary exists.

Examples:

- `Repo source: local_path, secrets=2, ci=1`
- `Repo source: confirmation required before clone`

If only artifacts exist but summary parsing fails, keep the current fallback:

- `Repo source: available — use read_repo_source_summary`

### 3. `agent.py`

`_build_agent_bootstrap_context()` should include one short repo-source line when available.

Examples:

- `Repo source summary: local_path, secrets=2, ci=1`
- `Repo source summary: confirmation required before clone`

This should supplement, not replace, existing guidance about using `read_repo_source_summary`.

## Error handling

This enhancement must stay resilient:

- missing `repo_source_meta.json` should not break output
- missing `repo_summary.md` should not break output
- malformed JSON should degrade gracefully
- failed markdown parsing should fall back to the existing generic repo-source hint

## Testing plan

### `tests/test_autopilot_state_tool.py`

Add or extend tests to verify:

- repo-source summary fields are extracted from exposure artifacts
- formatted autopilot state includes the compact repo-source summary
- generic fallback still works when only artifacts are known

### `tests/test_autopilot_mode.py`

Add or extend tests to verify:

- agent bootstrap includes the repo-source summary line when present

## Verification plan

Primary verification:

- targeted pytest for autopilot-state and agent bootstrap tests

Secondary verification:

- existing repo-source related tests still pass unchanged

Success means:

- autopilot state can summarize repo-source artifacts compactly
- agent bootstrap sees that same summary
- no change to source-hunt execution or autopilot decision logic

## Risk assessment

### Main risk

Overly verbose repo-source context could crowd the bootstrap block.

### Mitigation

- keep summary to one line
- use counts only, not full finding details
- preserve current generic fallback behavior

### Residual risk

Low. This is a read-only summary enhancement.

## Implementation boundaries

This enhancement is complete when:

1. `autopilot_state` exposes `repo_source_summary`
2. formatted autopilot state shows a compact repo-source summary
3. agent bootstrap shows a compact repo-source summary
4. tests cover the new behavior

It is **not** necessary to:

- alter repo-source scanning logic
- resolve unrelated warnings
- restructure existing exposure artifacts

## Follow-up candidates

If this visibility-only enhancement proves useful, the next safe iteration could be:

1. use repo-source summary in higher-level pivot hints
2. selectively suggest source-first workflows when findings counts are high
3. later correlate secret/CI categories with targeted follow-up tools
