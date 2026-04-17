# Autopilot Guard Visibility Enhancement Design

Date: 2026-04-17
Status: Draft approved for spec writing

## Goal

Improve Claude Code CLI practical effectiveness by surfacing recent request-guard block context to `autopilot_state` and agent bootstrap output, without changing request behavior, ranking, or guard policy.

This is a conservative enhancement focused on operator/agent awareness:

- reuse existing guard-block journal data
- expose it in autopilot state
- expose it again in agent bootstrap context
- avoid changing target ordering or hunt execution logic

## Why this change

The repo already has a strong partial loop:

`request_guard block -> hunt journal -> /resume output`

That loop helps after the fact, but the agent does not yet receive the same recent block context during bootstrap. In practice, this means:

- the operator can see recent guard blocks in `/resume`
- `autopilot_state` knows current cooldown/tripped hosts
- but the agent does not get the recent historical block notes as part of its early decision context

This enhancement closes that visibility gap without expanding enforcement scope.

## Non-goals

This change will **not**:

- modify `request_guard` blocking behavior
- change `_fetch_url()` semantics
- add new persistence files or storage layers
- change `recommended_targets` sorting
- automatically down-rank targets based on recent guard-block notes
- broaden guard wiring to more hunt paths

## Recommended approach

### Approach A — visibility-only pass-through (recommended)

Pass existing `recent_guard_blocks` data from the resume/journal layer into:

- `tools/autopilot_state.py`
- formatted autopilot state output
- `agent.py` bootstrap context

#### Why this is recommended

- lowest regression risk
- directly improves practical operator/agent awareness
- uses already-tested data sources
- preserves current ranking and execution behavior

### Approach B — affect target ranking

Use recent guard blocks to lower priority of some targets in `recommended_targets`.

#### Why not now

- more inference-heavy
- higher false-negative risk
- easier to hide useful targets accidentally
- larger behavior change than needed for this iteration

### Approach C — new retry/pivot policy engine

Build block-reason-specific automation for retry timing and pivot choices.

#### Why not now

- too large for a cautious enhancement
- adds decision complexity before visibility is fully proven useful

## Scope

### Files in scope

- `tools/autopilot_state.py`
- `agent.py`
- `tests/test_autopilot_state_tool.py`
- `tests/test_autopilot_mode.py`

### Files intentionally out of scope

- `tools/hunt.py`
- `tools/request_guard.py`
- `tools/resume.py`
- request execution paths
- ranking logic

## Data source and flow

Existing source:

- `tools/resume.py -> load_resume_summary()`
- `recent_guard_blocks(entries)` already extracts the last few guard-block journal entries

New flow after this change:

`request_guard block -> journal.jsonl -> resume summary -> autopilot_state -> agent bootstrap`

No new storage is introduced. The enhancement is a pure read/format/pass-through layer.

## Design details

### 1. `tools/autopilot_state.py`

#### Add to returned state

`build_autopilot_state()` should include:

- `recent_guard_blocks`

Source:

- `resume_summary.get("recent_guard_blocks", [])` when available

#### Formatting behavior

`format_autopilot_state()` should render a short section only when data exists.

Display rules:

- show at most 3 entries
- prefer compact summaries
- avoid dumping full raw notes if they are too verbose

Suggested output shape:

- `Recent guard blocks:`
- `- block_breaker :: https://api.target.com/graphql`
- or equivalent compact line using available fields

This section is informational only.

### 2. `agent.py`

#### Bootstrap context

`_build_agent_bootstrap_context()` should include a short block when `recent_guard_blocks` exists.

Display goals:

- remind the agent what was blocked recently
- discourage immediate retries on the same surface
- keep text short enough to avoid context bloat

Suggested shape:

- `Recent guard blocks: block_breaker https://api.target.com/graphql`
- `Avoid immediate re-test on the same blocked surface unless new evidence appears.`

This is guidance, not a hard rule.

### 3. Summary behavior

The new data should complement, not replace:

- `guard_hint`
- `Avoid now`
- `Top ready target`
- `resume_targets`

The distinction is:

- `guard_hint` = current actionable cooldown guidance
- `recent_guard_blocks` = recent historical friction context

## Error handling

This enhancement should stay resilient:

- if `resume_summary` is missing, `recent_guard_blocks` should default to `[]`
- if an entry is malformed, formatting should skip missing parts gracefully
- output should never fail just because one block note is incomplete

## Testing plan

### `tests/test_autopilot_state_tool.py`

Add or extend tests to verify:

- `build_autopilot_state()` exposes `recent_guard_blocks`
- `format_autopilot_state()` includes a recent-guard-blocks section when present
- formatting remains stable when the list is absent or empty

### `tests/test_autopilot_mode.py`

Add or extend tests to verify:

- `_build_agent_bootstrap_context()` renders recent guard block summaries
- existing bootstrap output (`Guard hint`, `Avoid now`, `Top ready target`) still appears unchanged

## Verification plan

Primary verification:

- targeted pytest for autopilot-state and agent bootstrap tests

Secondary confidence check:

- existing related tests for resume/guard wiring should still pass unchanged

Success means:

- agent bootstrap surfaces recent guard friction
- autopilot state surfaces the same information
- no change to request behavior or ranking behavior

## Risk assessment

### Main risk

Context noise: too much historical guard detail could distract the agent.

### Mitigation

- cap output to 3 items
- keep summaries compact
- do not include full verbose journal bodies unless needed

### Residual risk

Low. This change does not alter enforcement or scanning behavior.

## Implementation boundaries

This enhancement is complete when:

1. `autopilot_state` returns `recent_guard_blocks`
2. formatted autopilot state shows concise recent block history
3. agent bootstrap shows concise recent block history
4. tests cover the new output

This enhancement is **not** complete only because warnings or unrelated cleanup exist. In particular:

- existing `datetime.utcnow()` deprecation warnings are out of scope for this task
- unrelated output polish is out of scope

## Follow-up candidates

If this visibility-only enhancement proves useful, the next safe iteration could be one of:

1. lightly incorporate recent guard blocks into future pivot hints
2. selectively feed block categories into higher-level autopilot narration
3. later evaluate whether ranking should consider recent block history
