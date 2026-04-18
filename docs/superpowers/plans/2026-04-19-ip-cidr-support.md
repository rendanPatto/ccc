# IP/CIDR Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IP and CIDR target support along the upstream `hunt.py` + `recon_engine.sh` direction while preserving local workflow sanity and only patching minimal blockers.

**Architecture:** Start at the upstream-aligned target entrypoints in `tools/hunt.py` and `tools/recon_engine.sh`: detect single-IP vs CIDR input, send each into a reasonable recon path, and keep CIDR semantics as range discovery instead of pretending a whole subnet is one hostname. Only if the existing local guard/scope path blocks these inputs do we add the smallest possible compatibility fix in `tools/scope_checker.py` and related tests.

**Tech Stack:** Python 3 CLI, Bash recon pipeline, pytest

---

## File structure

- `tools/hunt.py` — target parsing/validation and handoff into recon paths; upstream-aligned primary entrypoint
- `tools/recon_engine.sh` — accepts IP/CIDR input and chooses sane recon behavior for each
- `tools/scope_checker.py` — only touched if the current IP/CIDR path is still blocked after the primary implementation
- `tests/test_hunt_target_types.py` — new focused tests for single IP / CIDR / invalid target handling in `hunt.py`
- `tests/test_scope_checker.py` — new or updated only if a compatibility fix is needed in `scope_checker.py`
- `tests/test_recon_engine_script.py` — extend shell-regression coverage if recon script branching changes materially

### Task 1: Add failing tests that describe supported IP/CIDR target behavior in `hunt.py`

**Files:**
- Create: `tests/test_hunt_target_types.py`
- Modify: `tools/hunt.py` (later task, not yet)

- [ ] **Step 1: Write a focused failing test file for target classification**

Create `tests/test_hunt_target_types.py` with these tests:

```python
"""Tests for IP/CIDR target handling in tools/hunt.py."""

from __future__ import annotations

import pytest

import tools.hunt as hunt


class TestTargetTypeDetection:
    def test_accepts_ipv4_target(self):
        parsed = hunt.classify_target("1.2.3.4")
        assert parsed == {"kind": "ip", "value": "1.2.3.4"}

    def test_accepts_ipv4_cidr_target(self):
        parsed = hunt.classify_target("10.10.10.0/24")
        assert parsed == {"kind": "cidr", "value": "10.10.10.0/24"}

    def test_accepts_domain_target(self):
        parsed = hunt.classify_target("example.com")
        assert parsed == {"kind": "domain", "value": "example.com"}

    @pytest.mark.parametrize(
        "raw_target",
        ["999.999.999.999", "10.10.10.0/99", "10.0.0.0/not-a-mask"],
    )
    def test_rejects_invalid_ip_like_targets(self, raw_target):
        with pytest.raises(ValueError, match="invalid IP/CIDR target"):
            hunt.classify_target(raw_target)
```

- [ ] **Step 2: Add one failing test for hunt-side recon handoff semantics**

Append this test to the same file:

```python
def test_recon_command_passes_ip_target_verbatim(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(hunt.subprocess, "run", fake_run)

    ok = hunt.run_recon("1.2.3.4", quick=False)

    assert ok is True
    assert calls
    assert calls[0][-1] == "1.2.3.4"
```

- [ ] **Step 3: Run the new target-type tests and confirm they fail first**

Run: `pytest -q tests/test_hunt_target_types.py`

Expected: FAIL because `classify_target()` does not exist yet and current `hunt.py` has no explicit IP/CIDR classification.

- [ ] **Step 4: Commit the red tests**

```bash
git add tests/test_hunt_target_types.py
git commit -m "test: cover ip and cidr hunt targets"
```

### Task 2: Implement minimal target classification and recon handoff in `tools/hunt.py`

**Files:**
- Modify: `tools/hunt.py`
- Test: `tests/test_hunt_target_types.py`

- [ ] **Step 1: Add explicit target classification helpers**

In `tools/hunt.py`, add a helper section near other utility functions with this shape:

```python
import ipaddress
```

```python
def classify_target(raw_target: str) -> dict[str, str]:
    value = str(raw_target or "").strip()
    if not value:
        raise ValueError("target is required")

    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        return {"kind": "ip", "value": str(ip_obj)}

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid IP/CIDR target: {value}") from exc
        return {"kind": "cidr", "value": str(network)}

    return {"kind": "domain", "value": value}
```

- [ ] **Step 2: Make invalid IP-like targets fail explicitly**

Directly after the CIDR branch above, add a lightweight guard so obviously IP-like junk is rejected instead of silently falling back to domain behavior:

```python
    dot_parts = value.split(".")
    if len(dot_parts) == 4 and all(part.isdigit() for part in dot_parts if part):
        raise ValueError(f"invalid IP/CIDR target: {value}")
```

- [ ] **Step 3: Route `run_recon()` through the classifier but keep the subprocess contract minimal**

Update `run_recon()` so it classifies the target first, then passes the normalized value through to `recon_engine.sh` without renaming the external parameter contract:

```python
    target_info = classify_target(target)
    normalized_target = target_info["value"]
```

Then use `normalized_target` wherever the script argument is currently built.

If classification raises `ValueError`, print/log the message and return `False` rather than continuing with a malformed target.

- [ ] **Step 4: Update CLI help text to stop claiming domain-only input**

Change the `--target` help text from domain-only wording to neutral wording:

```python
parser.add_argument("--target", type=str, help="Specific target (domain, IP, or CIDR) to hunt")
```

Also update the top-of-file usage examples and argparse epilog examples to use the same broader wording where needed.

- [ ] **Step 5: Run the focused hunt target tests**

Run: `pytest -q tests/test_hunt_target_types.py`

Expected: PASS.

- [ ] **Step 6: Run adjacent hunt regressions**

Run: `pytest -q tests/test_autopilot_mode.py tests/test_claude_code_helper_flow.py`

Expected: PASS, proving the new target classifier did not disturb current hunt-side helpers.

- [ ] **Step 7: Commit the hunt-side implementation**

```bash
git add tools/hunt.py tests/test_hunt_target_types.py
git commit -m "feat: add ip and cidr hunt target parsing"
```

### Task 3: Teach `recon_engine.sh` to handle single IP and CIDR sanely

**Files:**
- Modify: `tools/recon_engine.sh`
- Modify: `tests/test_recon_engine_script.py`

- [ ] **Step 1: Add shell regression expectations before changing the script**

Extend `tests/test_recon_engine_script.py` with assertions that enforce the new branches exist in the shell script:

```python
def test_recon_engine_has_ip_and_cidr_branches():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    content = script.read_text(encoding="utf-8")

    assert "TARGET_KIND=\"domain\"" in content
    assert "TARGET_KIND=\"ip\"" in content
    assert "TARGET_KIND=\"cidr\"" in content
    assert "httpx -l \"$RECON_DIR/live/discovery_hosts.txt\"" in content
```

- [ ] **Step 2: Run the shell regression tests and confirm failure**

Run: `pytest -q tests/test_recon_engine_script.py`

Expected: FAIL because the script currently has no IP/CIDR branch markers.

- [ ] **Step 3: Add explicit target-kind detection at the top of `recon_engine.sh`**

Near the current `TARGET=...` setup, add a small classification block:

```bash
TARGET_KIND="domain"
if python3 - <<'PY' "$TARGET"
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
    sys.exit(0)
except ValueError:
    sys.exit(1)
PY
then
    TARGET_KIND="ip"
elif python3 - <<'PY' "$TARGET"
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
    sys.exit(0)
except ValueError:
    sys.exit(1)
PY
then
    TARGET_KIND="cidr"
fi
```

- [ ] **Step 4: Keep domain behavior untouched, but add sane IP/CIDR discovery behavior**

Restructure the early recon phases like this:

- If `TARGET_KIND="domain"`, keep the existing subdomain enumeration flow.
- If `TARGET_KIND="ip"`, skip subdomain enumeration, write the single IP into a discovery file, and feed it directly into the live probing/port scanning stages.
- If `TARGET_KIND="cidr"`, skip subdomain enumeration, expand the range into `"$RECON_DIR/live/discovery_hosts.txt"` using a tiny Python one-liner, cap expansion at a sane size (for example 4096 hosts), then feed those hosts into `httpx`/follow-on stages.

Use this exact expansion pattern for CIDR:

```bash
python3 - <<'PY' "$TARGET" > "$RECON_DIR/live/discovery_hosts.txt"
import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = list(network.hosts())
if len(hosts) > 4096:
    hosts = hosts[:4096]
for host in hosts:
    print(host)
PY
```

And for single IP:

```bash
echo "$TARGET" > "$RECON_DIR/live/discovery_hosts.txt"
```

Then branch the existing `httpx` phase so it uses:

- `subdomains/all.txt` for domains
- `live/discovery_hosts.txt` for IP/CIDR

- [ ] **Step 5: Preserve reasonable output semantics for CIDR**

Add one clear status line before probing CIDR results:

```bash
log_done "CIDR candidates prepared: $(wc -l < "$RECON_DIR/live/discovery_hosts.txt" 2>/dev/null || echo 0) hosts"
```

If the discovery host list is empty, emit a warning and skip downstream probing rather than pretending success.

- [ ] **Step 6: Run the shell regression tests again**

Run: `pytest -q tests/test_recon_engine_script.py`

Expected: PASS.

- [ ] **Step 7: Commit the recon-side implementation**

```bash
git add tools/recon_engine.sh tests/test_recon_engine_script.py
git commit -m "feat: add ip and cidr recon target handling"
```

### Task 4: Patch `scope_checker.py` only if the current path still blocks IP/CIDR

**Files:**
- Modify: `tools/scope_checker.py` (only if needed)
- Create or modify: `tests/test_scope_checker.py`

- [ ] **Step 1: Write a failing scope-compatibility test only if current behavior is blocking**

First inspect whether the active hunt/recon path still calls `ScopeChecker.is_in_scope()` for these targets. If yes, add tests like:

```python
from tools.scope_checker import ScopeChecker


def test_allows_exact_ip_when_listed_in_scope():
    checker = ScopeChecker(domains=["1.2.3.4"])
    assert checker.is_in_scope("https://1.2.3.4/login") is True


def test_allows_ip_within_listed_cidr():
    checker = ScopeChecker(domains=["10.10.10.0/24"])
    assert checker.is_in_scope("https://10.10.10.25/api") is True
```

Only add this task if you can show the current blocker is real.

- [ ] **Step 2: Run the scope tests to confirm red**

Run: `pytest -q tests/test_scope_checker.py`

Expected: FAIL under the current “IP not supported” behavior.

- [ ] **Step 3: Implement the smallest compatibility fix**

Update `tools/scope_checker.py` to use `ipaddress` for IP/CIDR matching instead of unconditional rejection. Keep domain matching logic unchanged.

Core rule:

- exact IP in allowlist matches same IP
- CIDR in allowlist matches IPs inside that range
- domain patterns continue using existing anchored matching

Do not expand this into a larger scope-rule rewrite.

- [ ] **Step 4: Run the focused scope tests plus one no-regression domain test**

Run: `pytest -q tests/test_scope_checker.py`

Expected: PASS.

- [ ] **Step 5: Commit the compatibility patch**

```bash
git add tools/scope_checker.py tests/test_scope_checker.py
git commit -m "fix: allow scoped ip and cidr targets"
```

### Task 5: Final verification and inventory check

**Files:**
- Verify only

- [ ] **Step 1: Run the focused IP/CIDR verification suite**

Run: `pytest -q tests/test_hunt_target_types.py tests/test_recon_engine_script.py tests/test_resume_tool.py tests/test_agent_helper_tools.py`

Expected: PASS.

- [ ] **Step 2: Run the full regression suite**

Run: `pytest -q`

Expected: PASS with no regressions.

- [ ] **Step 3: Sanity-check repository text for stale “IP unsupported” claims in touched surfaces**

Run: `rg -n "IP addresses rejected|NOT supported|scope checker does not support IP" README.md CLAUDE.md tools tests`

Expected: any remaining hits are either intentionally untouched out-of-scope docs or are updated to reflect the new behavior.

- [ ] **Step 4: Summarize what shipped in the final commit if no extra code changes are needed**

If Task 5 requires no new file edits, do not make an empty commit. Instead prepare the final handoff summary listing:

- hunt-side target classification added
- recon-side IP/CIDR handling added
- scope compatibility patched only if it was a real blocker
- tests added/updated and passing
