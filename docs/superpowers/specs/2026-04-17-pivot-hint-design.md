# Pivot Hint Enhancement Design

Date: 2026-04-17
Status: Draft approved for spec writing

## Goal

Improve Claude Code CLI practical effectiveness by generating a short `pivot_hint` from already-available runtime context, then surfacing it in `autopilot_state` output and agent bootstrap context.

This is a conservative enhancement:

- it uses existing state only
- it gives advice, not commands
- it does not change `next_action`
- it does not change ranking or request behavior

## Why this change

The current autopilot context already exposes useful pieces:

- `guard_hint`
- `recent_guard_blocks`
- `repo_source_summary`
- `recommended_targets`

But those pieces are still somewhat raw. A human operator can connect them mentally; the agent may do so less consistently. A short synthesized pivot hint gives a higher-signal summary of what to do next, without forcing behavior.

## Non-goals

This change will **not**:

- modify `next_action`
- modify `recommended_targets`
- change `request_guard`
- change source-hunt behavior
- auto-run repo/source tools
- enforce a pivot

## Recommended approach

### Approach A — read-only synthesized hint (recommended)

Build a single short hint from existing signals and expose it as:

- `pivot_hint` in state
- a short line in formatted autopilot output
- a short line in agent bootstrap context

#### Why this is recommended

- low risk
- high operator value
- gives the agent more actionable context
- avoids hard-coded decision changes

### Approach B — make hint affect `next_action`

Use the same logic to alter autopilot behavior directly.

#### Why not now

- behavior change is harder to validate
- can overfit to partial signals

## Scope

### Files in scope

- `tools/autopilot_state.py`
- `agent.py`
- `tests/test_autopilot_state_tool.py`
- `tests/test_autopilot_mode.py`

### Files out of scope

- `tools/hunt.py`
- `tools/request_guard.py`
- `tools/source_hunt.py`
- ranking logic
- resume logic

## Input signals

The hint may use these existing inputs:

- `guard_status.tripped_hosts`
- `recent_guard_blocks`
- `repo_source_summary.summary_hint`
- `repo_source_summary.secret_findings`
- `repo_source_summary.ci_findings`
- `recommended_targets`

## Hint rules

Use simple first-match rules. Keep exactly one hint.

### Rule 1: blocked live target + repo source findings

If:

- there are recent guard blocks or tripped hosts
- and repo-source summary shows useful findings (`secret_findings > 0` or `ci_findings > 0`)

Then:

- hint should favor reviewing repo-source evidence before retrying blocked live paths

Example:

- `Pivot hint: avoid blocked live API for now; inspect repo source findings first.`

### Rule 2: blocked live target + no repo findings

If:

- there are recent guard blocks or tripped hosts
- and repo-source summary is absent or empty

Then:

- hint should favor the next ready target instead of retrying blocked surface

Example:

- `Pivot hint: avoid retrying the blocked surface now; continue with the next ready target.`

### Rule 3: repo secrets present

If:

- `secret_findings > 0`

Then:

- hint should suggest verifying token/credential usability

Example:

- `Pivot hint: repo source shows secrets; verify credential usability before widening live probing.`

### Rule 4: repo CI findings present

If:

- `ci_findings > 0`

Then:

- hint should suggest reviewing workflow attack surface

Example:

- `Pivot hint: repo source shows CI risks; review workflow attack surface before rerunning source hunt.`

### Rule 5: no strong signal

Return empty string.

## Priority order

Use this order:

1. blocked live target + repo findings
2. blocked live target + no repo findings
3. repo secrets present
4. repo CI findings present
5. empty

This keeps the hint focused on the most immediate operational choice.

## Output behavior

### In `autopilot_state`

Add:

- `pivot_hint`

### In formatted autopilot output

Show:

- `Pivot hint: ...`

only when the hint is non-empty.

### In `agent.py`

Show:

- `Pivot hint: ...`

only when the hint is non-empty.

## Error handling

This enhancement must remain resilient:

- missing repo summary should be treated as no repo signal
- malformed counts should degrade to zero
- empty hint is acceptable

## Testing plan

### `tests/test_autopilot_state_tool.py`

Add or extend tests to verify:

- blocked host + repo findings yields repo-first pivot hint
- formatted autopilot output includes pivot hint when present

### `tests/test_autopilot_mode.py`

Add or extend tests to verify:

- bootstrap context includes pivot hint when state provides it

## Verification plan

Primary verification:

- targeted pytest for autopilot-state and autopilot-mode tests

Secondary verification:

- existing guard/repo summary tests still pass

## Risk assessment

### Main risk

The hint could become noisy if too generic.

### Mitigation

- keep one hint only
- prioritize immediate operational advice
- return empty string if no strong signal exists

### Residual risk

Low. This is still a read-only, suggestion-only enhancement.

## Implementation boundaries

This enhancement is complete when:

1. `autopilot_state` exposes `pivot_hint`
2. formatted autopilot output shows `pivot_hint`
3. agent bootstrap shows `pivot_hint`
4. tests cover the new behavior

This enhancement does **not** require:

- modifying execution order
- changing target ranking
- adding new persistence
