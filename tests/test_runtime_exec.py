"""Regression tests for tools/runtime_exec.py."""

from __future__ import annotations

import shlex
import signal
import subprocess
import sys

import runtime_exec


def _timeout_test_command() -> str:
    script = (
        "import sys, time; "
        "print('hello', flush=True); "
        "print('err', file=sys.stderr, flush=True); "
        "time.sleep(30)"
    )
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(script)}"


def test_spawn_uses_session_safe_popen_options_and_cwd(monkeypatch):
    captured = {}

    class FakeProc:
        pass

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", fake_popen)

    proc = runtime_exec._spawn("echo ok", cwd="/tmp/example")

    assert isinstance(proc, FakeProc)
    assert captured["args"] == ("echo ok",)
    assert captured["kwargs"]["shell"] is True
    assert captured["kwargs"]["cwd"] == "/tmp/example"
    assert captured["kwargs"]["stdout"] is subprocess.PIPE
    assert captured["kwargs"]["stderr"] is subprocess.PIPE
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["start_new_session"] is True
    assert "preexec_fn" not in captured["kwargs"]



def test_run_shell_command_returns_combined_output(monkeypatch):
    class FakeProc:
        pid = 4242
        returncode = 0

        def communicate(self, timeout=None):
            assert timeout == 30
            return ("ok stdout\n", "warn stderr\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_args, **_kwargs: FakeProc())

    success, output = runtime_exec.run_shell_command("echo ok", timeout=30)

    assert success is True
    assert output == "ok stdout\nwarn stderr\n"



def test_run_shell_command_kills_process_group_on_timeout(monkeypatch):
    events = []
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9001
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            events.append(("communicate", timeout))
            if calls["communicate"] in (1, 2):
                raise subprocess.TimeoutExpired(cmd="boom", timeout=timeout)
            return ("", "")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, output = runtime_exec.run_shell_command("sleep 60", timeout=5)

    assert success is False
    assert "timed out after 5s" in output.lower()
    assert ("killpg", 9001, signal.SIGTERM) in events
    assert ("killpg", 9001, signal.SIGKILL) in events



def test_run_shell_command_timeout_preserves_partial_and_cleanup_output(monkeypatch):
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9002
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            if calls["communicate"] == 1:
                raise subprocess.TimeoutExpired(
                    cmd="slow",
                    timeout=2,
                    output="partial stdout\n",
                    stderr="partial stderr\n",
                )
            return ("cleanup stdout\n", "cleanup stderr\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda *_a, **_k: None)
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, output = runtime_exec.run_shell_command("slow", timeout=2)

    assert success is False
    assert "partial stdout" in output
    assert "partial stderr" in output
    assert "cleanup stdout" in output
    assert "cleanup stderr" in output
    assert "timed out after 2s" in output.lower()



def test_run_shell_command_split_preserves_stdout_and_stderr(monkeypatch):
    class FakeProc:
        pid = 1337
        returncode = 7

        def communicate(self, timeout=None):
            assert timeout == 10
            return ("out", "err")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())

    success, stdout, stderr = runtime_exec.run_shell_command_split("exit 7", timeout=10)

    assert success is False
    assert stdout == "out"
    assert stderr == "err"



def test_run_shell_command_split_kills_process_group_on_timeout(monkeypatch):
    events = []
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9003
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            events.append(("communicate", timeout))
            if calls["communicate"] in (1, 2):
                raise subprocess.TimeoutExpired(cmd="hang", timeout=timeout)
            return ("", "")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, stdout, stderr = runtime_exec.run_shell_command_split("hang", timeout=4)

    assert success is False
    assert stdout == ""
    assert "timed out after 4s" in stderr.lower()
    assert ("killpg", 9003, signal.SIGTERM) in events
    assert ("killpg", 9003, signal.SIGKILL) in events



def test_run_shell_command_split_timeout_preserves_partial_stdout_and_stderr(monkeypatch):
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9004
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            if calls["communicate"] == 1:
                raise subprocess.TimeoutExpired(
                    cmd="slow split",
                    timeout=6,
                    output="partial out\n",
                    stderr="partial err\n",
                )
            return ("cleanup out\n", "cleanup err\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda *_a, **_k: None)
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, stdout, stderr = runtime_exec.run_shell_command_split("slow split", timeout=6)

    assert success is False
    assert stdout == "partial out\ncleanup out\n"
    assert "partial err" in stderr
    assert "cleanup err" in stderr
    assert "timed out after 6s" in stderr.lower()



def test_run_shell_command_timeout_real_subprocess_does_not_duplicate_output():
    success, output = runtime_exec.run_shell_command(_timeout_test_command(), timeout=0.1)

    assert success is False
    assert output.count("hello\n") == 1
    assert output.count("err\n") == 1
    assert "command timed out after 0.1s" in output.lower()



def test_run_shell_command_split_timeout_real_subprocess_does_not_duplicate_output():
    success, stdout, stderr = runtime_exec.run_shell_command_split(_timeout_test_command(), timeout=0.1)

    assert success is False
    assert stdout == "hello\n"
    assert stderr.count("err\n") == 1
    assert "command timed out after 0.1s" in stderr.lower()
