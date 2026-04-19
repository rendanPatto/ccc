# Upstream Runtime Stability Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Selectively absorb upstream runtime-stability fixes into the local hunt toolchain without changing existing user-facing workflow semantics.

**Architecture:** Introduce one small Python runtime helper for process-group-aware command execution, then wire the affected Python tools onto it with minimal contract changes. For shell scripts, add lightweight timeout compatibility helpers in-place and bound the Dalfox path conservatively so scans are safer on Linux/macOS without changing recon/findings layout.

**Tech Stack:** Python 3, pytest, POSIX shell, subprocess/process groups, existing hunt/recon scripts

---

## File structure

- `tools/runtime_exec.py` — new focused helper module for process-group-aware command execution and timeout cleanup
- `tests/test_runtime_exec.py` — focused regression tests for timeout cleanup and return-shape behavior
- `tools/cve_hunter.py` — swap fragile `subprocess.run(... timeout=...)` helper to shared runtime helper
- `tools/zero_day_fuzzer.py` — same runtime helper migration while preserving current `(success, stdout, stderr)` contract
- `tools/hunt.py` — migrate generic command helper and long-running spawned subprocess waits onto safer cleanup behavior
- `tests/test_hunt_target_types.py` — extend existing wrapper tests to cover forced cleanup on timeout paths
- `tools/recon_engine.sh` — add local timeout compatibility helper (`timeout` → `gtimeout` → direct run fallback)
- `tools/vuln_scanner.sh` — bound Dalfox stage and use timeout helper where needed
- `tests/test_recon_engine_script.py` — extend script regression checks for timeout helper presence/usage
- `tests/test_vuln_scanner_script.py` — new lightweight regression test for bounded Dalfox execution and timeout helper presence

### Task 1: Add shared Python runtime execution helper with failing tests first

**Files:**
- Create: `tools/runtime_exec.py`
- Create: `tests/test_runtime_exec.py`

- [ ] **Step 1: Write the failing tests for process-group cleanup and timeout return shapes**

Create `tests/test_runtime_exec.py` with these focused tests:

```python
"""Regression tests for tools/runtime_exec.py."""

from __future__ import annotations

import signal
import subprocess

import pytest
import runtime_exec


def test_run_shell_command_returns_combined_output(monkeypatch):
    class FakeCompleted:
        returncode = 0
        stdout = "ok stdout\n"
        stderr = "warn stderr\n"

    def fake_popen(*_args, **_kwargs):
        class FakeProc:
            pid = 4242
            returncode = 0

            def communicate(self, timeout=None):
                assert timeout == 30
                return (FakeCompleted.stdout, FakeCompleted.stderr)
        return FakeProc()

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", fake_popen)

    success, output = runtime_exec.run_shell_command("echo ok", timeout=30)

    assert success is True
    assert output == "ok stdout\nwarn stderr\n"


def test_run_shell_command_kills_process_group_on_timeout(monkeypatch):
    events = []

    class FakeProc:
        pid = 9001
        returncode = None

        def communicate(self, timeout=None):
            events.append(("communicate", timeout))
            if timeout == 5:
                raise subprocess.TimeoutExpired(cmd="boom", timeout=5)
            return ("", "")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, output = runtime_exec.run_shell_command("sleep 60", timeout=5)

    assert success is False
    assert "timed out after 5s" in output.lower()
    assert ("killpg", 9001, signal.SIGTERM) in events
    assert ("killpg", 9001, signal.SIGKILL) in events


def test_run_shell_command_split_preserves_stdout_and_stderr(monkeypatch):
    class FakeProc:
        pid = 1337
        returncode = 7

        def communicate(self, timeout=None):
            return ("out", "err")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())

    success, stdout, stderr = runtime_exec.run_shell_command_split("exit 7", timeout=10)

    assert success is False
    assert stdout == "out"
    assert stderr == "err"
```

- [ ] **Step 2: Run the new tests to verify they fail first**

Run: `pytest -q tests/test_runtime_exec.py`

Expected: FAIL because `tools/runtime_exec.py` does not exist yet.

- [ ] **Step 3: Write the minimal shared helper implementation**

Create `tools/runtime_exec.py` with this structure:

```python
"""Shared subprocess execution helpers with process-group cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Callable


def _terminate_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        return

    try:
        proc.communicate(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return

    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        return

    try:
        proc.communicate(timeout=3)
    except Exception:
        return


def _spawn(cmd: str, *, cwd: str | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
    )


def run_shell_command(cmd: str, *, cwd: str | None = None, timeout: int = 600) -> tuple[bool, str]:
    proc = _spawn(cmd, cwd=cwd)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        return False, f"Command timed out after {timeout}s"
    except Exception as exc:
        _terminate_process_group(proc)
        return False, str(exc)
    return proc.returncode == 0, (stdout or "") + (stderr or "")


def run_shell_command_split(cmd: str, *, cwd: str | None = None, timeout: int = 600) -> tuple[bool, str, str]:
    proc = _spawn(cmd, cwd=cwd)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        return False, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        _terminate_process_group(proc)
        return False, "", str(exc)
    return proc.returncode == 0, stdout or "", stderr or ""
```

- [ ] **Step 4: Run the focused helper tests to verify they pass**

Run: `pytest -q tests/test_runtime_exec.py`

Expected: PASS.

- [ ] **Step 5: Commit the helper layer**

```bash
git add tools/runtime_exec.py tests/test_runtime_exec.py
git commit -m "feat: add runtime command helper"
```

### Task 2: Move `cve_hunter.py` and `zero_day_fuzzer.py` onto the shared helper

**Files:**
- Modify: `tools/cve_hunter.py`
- Modify: `tools/zero_day_fuzzer.py`
- Test: `tests/test_runtime_exec.py`

- [ ] **Step 1: Add a failing regression test for preserving `zero_day_fuzzer`’s split return contract**

Append this test to `tests/test_runtime_exec.py`:

```python
def test_run_shell_command_split_timeout_returns_stderr_message(monkeypatch):
    class FakeProc:
        pid = 77
        returncode = None

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="hang", timeout=timeout)

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda *_a, **_k: None)

    success, stdout, stderr = runtime_exec.run_shell_command_split("hang", timeout=9)

    assert success is False
    assert stdout == ""
    assert "timed out after 9s" in stderr.lower()
```

- [ ] **Step 2: Run the test to verify the red state if needed, then keep it green after wiring**

Run: `pytest -q tests/test_runtime_exec.py`

Expected: PASS after Task 1 helper is updated or already satisfies the contract.

- [ ] **Step 3: Replace local `run_cmd()` helpers with shared calls**

Update `tools/cve_hunter.py` imports and helper:

```python
from runtime_exec import run_shell_command


def run_cmd(cmd, timeout=30):
    return run_shell_command(cmd, timeout=timeout)
```

Update `tools/zero_day_fuzzer.py` imports and helper:

```python
from runtime_exec import run_shell_command_split


def run_cmd(cmd, timeout=15):
    return run_shell_command_split(cmd, timeout=timeout)
```

Do not change caller-side parsing logic beyond what is needed to preserve the existing tuple contracts.

- [ ] **Step 4: Run focused regressions covering these codepaths**

Run:
- `pytest -q tests/test_runtime_exec.py`
- `pytest -q tests/test_hunt_wrappers.py`

Expected: PASS.

- [ ] **Step 5: Commit the Python helper migrations**

```bash
git add tools/cve_hunter.py tools/zero_day_fuzzer.py tests/test_runtime_exec.py
git commit -m "refactor: share safer runtime exec helpers"
```

### Task 3: Harden `tools/hunt.py` command execution and long-running waits

**Files:**
- Modify: `tools/hunt.py`
- Modify: `tests/test_hunt_target_types.py`

- [ ] **Step 1: Write the failing tests for timeout cleanup on long-running subprocess waits**

Append these tests to `tests/test_hunt_target_types.py`:

```python
def test_run_recon_kills_process_group_when_wait_times_out(monkeypatch):
    captured = []

    class FakeProc:
        pid = 5150
        returncode = None

        def wait(self, timeout=None):
            raise hunt.subprocess.TimeoutExpired(cmd="recon", timeout=timeout)

    monkeypatch.setattr(hunt.subprocess, "Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(hunt.os, "killpg", lambda pid, sig: captured.append((pid, sig)))

    assert hunt.run_recon("example.com") is False
    assert captured


def test_run_vuln_scan_kills_process_group_when_wait_times_out(monkeypatch, tmp_path):
    recon_root = tmp_path / "recon"
    stored_recon_dir = recon_root / "example.com"
    stored_recon_dir.mkdir(parents=True)
    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))

    captured = []

    class FakeProc:
        pid = 6160
        returncode = None

        def wait(self, timeout=None):
            raise hunt.subprocess.TimeoutExpired(cmd="scan", timeout=timeout)

    monkeypatch.setattr(hunt.subprocess, "Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(hunt.os, "killpg", lambda pid, sig: captured.append((pid, sig)))

    assert hunt.run_vuln_scan("example.com") is False
    assert captured
```

- [ ] **Step 2: Run the targeted tests to confirm failure before the fix**

Run: `pytest -q tests/test_hunt_target_types.py -k "kills_process_group"`

Expected: FAIL because `tools/hunt.py` does not yet clean up process groups on `proc.wait()` timeouts.

- [ ] **Step 3: Implement minimal cleanup helpers inside `tools/hunt.py` and wire them in**

Add imports near the top:

```python
import signal
```

Add helpers near `run_cmd()`:

```python
def _kill_process_group(proc):
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass
    except Exception:
        pass


def run_cmd(cmd, cwd=None, timeout=600):
    from runtime_exec import run_shell_command
    return run_shell_command(cmd, cwd=cwd, timeout=timeout)
```

Then update the long-running `Popen(...).wait(timeout=...)` sites in `run_recon()`, `run_vuln_scan()`, `run_cve_hunt()`, and `run_zero_day_fuzz()` so timeout handling calls `_kill_process_group(proc)` before returning failure.

- [ ] **Step 4: Run focused hunt regressions**

Run:
- `pytest -q tests/test_hunt_target_types.py`
- `pytest -q tests/test_hunt_wrappers.py`
- `pytest -q tests/test_remember_tool.py`

Expected: PASS.

- [ ] **Step 5: Commit the hunt hardening changes**

```bash
git add tools/hunt.py tests/test_hunt_target_types.py
git commit -m "fix: harden hunt subprocess cleanup"
```

### Task 4: Add shell timeout compatibility and bounded Dalfox execution

**Files:**
- Modify: `tools/recon_engine.sh`
- Modify: `tools/vuln_scanner.sh`
- Modify: `tests/test_recon_engine_script.py`
- Create: `tests/test_vuln_scanner_script.py`

- [ ] **Step 1: Write failing script regression tests first**

Create `tests/test_vuln_scanner_script.py`:

```python
"""Regression tests for vuln_scanner.sh stability guards."""

from pathlib import Path


def test_vuln_scanner_bounds_dalfox_and_uses_timeout_helper():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "run_with_timeout()" in text
    assert "timeout_bin()" in text
    assert "dalfox pipe" in text
    assert "--timeout 10" in text
    assert "run_with_timeout" in text
```

Extend `tests/test_recon_engine_script.py` with:

```python
def test_recon_engine_has_timeout_compat_helper():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "timeout_bin()" in text
    assert "gtimeout" in text
    assert "run_with_timeout()" in text
    assert "run_with_timeout 300 amass enum -passive" in text
```

- [ ] **Step 2: Run the script regression tests to verify they fail first**

Run:
- `pytest -q tests/test_recon_engine_script.py`
- `pytest -q tests/test_vuln_scanner_script.py`

Expected: FAIL because the helpers are not present yet.

- [ ] **Step 3: Add timeout compatibility helpers to `tools/recon_engine.sh`**

Add near the logging helpers:

```bash
timeout_bin() {
    if command -v timeout >/dev/null 2>&1; then
        printf '%s\n' timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        printf '%s\n' gtimeout
    else
        printf '%s\n' ""
    fi
}

run_with_timeout() {
    local limit="$1"
    shift
    local timeout_cmd
    timeout_cmd="$(timeout_bin)"
    if [ -n "$timeout_cmd" ]; then
        "$timeout_cmd" "$limit" "$@"
    else
        "$@"
    fi
}
```

Then replace the raw amass timeout call with:

```bash
run_with_timeout 300 amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
```

- [ ] **Step 4: Add bounded Dalfox execution to `tools/vuln_scanner.sh`**

Add the same helper pair near the top of `tools/vuln_scanner.sh`, then wrap Dalfox:

```bash
head -100 "$PARAM_URLS" \
    | run_with_timeout 900 dalfox pipe \
        --silence \
        --no-color \
        --worker 5 \
        --delay 100 \
        --timeout 10 \
        --output "$FINDINGS_DIR/xss/dalfox_results.txt" 2>/dev/null || true
```

If you add dedup, keep it conservative and local to the Dalfox feed only:

```bash
awk '!seen[$0]++' "$PARAM_URLS" | head -100 | run_with_timeout 900 dalfox pipe ...
```

Do not change upstream findings directory layout or broader scanner sequencing.

- [ ] **Step 5: Run focused script regressions**

Run:
- `pytest -q tests/test_recon_engine_script.py`
- `pytest -q tests/test_vuln_scanner_script.py`

Expected: PASS.

- [ ] **Step 6: Commit the shell stability changes**

```bash
git add tools/recon_engine.sh tools/vuln_scanner.sh tests/test_recon_engine_script.py tests/test_vuln_scanner_script.py
git commit -m "fix: align shell runtime stability guards"
```

### Task 5: Final verification and handoff

**Files:**
- Verify only

- [ ] **Step 1: Run the focused runtime-stability verification suite**

Run:

```bash
pytest -q tests/test_runtime_exec.py tests/test_hunt_target_types.py tests/test_hunt_wrappers.py tests/test_recon_engine_script.py tests/test_vuln_scanner_script.py tests/test_remember_tool.py
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
- `docs/superpowers/plans/2026-04-19-upstream-runtime-stability-alignment.md`
- `tools/runtime_exec.py`
- `tests/test_runtime_exec.py`
- `tools/cve_hunter.py`
- `tools/zero_day_fuzzer.py`
- `tools/hunt.py`
- `tests/test_hunt_target_types.py`
- `tools/recon_engine.sh`
- `tools/vuln_scanner.sh`
- `tests/test_recon_engine_script.py`
- `tests/test_vuln_scanner_script.py`

- [ ] **Step 4: Commit any final verification-only adjustments if needed**

```bash
git add -A
git commit -m "test: cover runtime stability alignment"
```

Only do this if verification uncovered a small last-mile test/doc fix. If no changes are needed, skip this commit.
