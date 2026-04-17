---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## CTF Mode

When `ctf_mode: true` is set in `config.json`:
- Skip program scope confirmation and ownership checks
- Treat the provided target as an allowed local practice asset
- Start directly from recon/ranking/hunting instead of waiting on scope validation
- `request_guard.py` becomes audit-only: no scope allowlist enforcement, no unsafe-method gate, no breaker block, and no rate-limit wait

In Claude Code, this runs as an autonomous agent workflow backed by helper tools
like `scope_checker.py`, hunt-memory modules, and the `/remember` `/resume`
`/surface` helper scripts.

Operational rule: prefer starting with `python3 tools/autopilot_state.py --target <target>`
so cached recon, hunt memory, and next-action hints are loaded before active testing.
When live requests begin, wrap them with `python3 tools/request_guard.py preflight ...`
and `python3 tools/request_guard.py record ...` so scope/audit/breaker state stays in sync.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
```

## What This Does

Runs the full hunt cycle without stopping for approval at each step, within the
selected checkpoint mode:

```
1. SCOPE     Load and confirm program scope
2. RECON     Run recon (or use cached if < 7 days old)
3. RANK      Prioritize attack surface (recon-ranker agent)
4. HUNT      Test P1 endpoints systematically
5. VALIDATE  7-Question Gate on findings
6. REPORT    Draft reports for validated findings
7. CHECKPOINT  Present to human for review
```

## Runtime Guarantees

### Bug bounty / VAPT mode

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **PUT/DELETE/PATCH** require human approval in `--yolo` mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

### CTF mode

- **No request-side enforcement** from `request_guard.py`
- **No scope allowlist block**
- **No unsafe-method block in `--yolo`**
- **No circuit-breaker block**
- **No rate-limit wait**
- **Audit logging still remains enabled**

Practical helper for Claude Code:
```bash
python3 tools/request_guard.py preflight --target target.com --url https://api.target.com/graphql --method GET --session-id autopilot-001 --json
python3 tools/request_guard.py record --target target.com --url https://api.target.com/graphql --method GET --status 200 --session-id autopilot-001 --json
```

If the target profile does not yet contain a real `scope_snapshot`, pass
`--scope-domains '*.target.com,api.target.com'` on the helper call.
In `ctf_mode`, this is optional because request-guard enforcement is disabled.

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/resume target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
