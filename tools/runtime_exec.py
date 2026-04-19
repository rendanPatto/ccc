"""Shared subprocess execution helpers with process-group cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any

TERMINATION_GRACE_SECONDS = 3


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _append_message(stream: str, message: str) -> str:
    if not stream:
        return message
    if stream.endswith("\n"):
        return stream + message
    return stream + "\n" + message


def _merge_streams(existing: str, new: str) -> str:
    if not existing:
        return new
    if not new:
        return existing

    max_overlap = min(len(existing), len(new))
    for overlap in range(max_overlap, 0, -1):
        if existing.endswith(new[:overlap]):
            return existing + new[overlap:]
    return existing + new


def _communicate_for(proc: subprocess.Popen[str], timeout: int | float) -> tuple[str, str, bool]:
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return _to_text(stdout), _to_text(stderr), True
    except subprocess.TimeoutExpired as exc:
        return _to_text(exc.output), _to_text(exc.stderr), False
    except Exception:
        return "", "", True


def _terminate_process_group(proc: subprocess.Popen[str]) -> tuple[str, str]:
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        return "", ""

    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        pass

    stdout, stderr, finished = _communicate_for(proc, TERMINATION_GRACE_SECONDS)
    if finished:
        return stdout, stderr

    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        return stdout, stderr

    kill_stdout, kill_stderr, _finished = _communicate_for(proc, TERMINATION_GRACE_SECONDS)
    return _merge_streams(stdout, kill_stdout), _merge_streams(stderr, kill_stderr)


def _spawn(cmd: str, *, cwd: str | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
) -> tuple[bool, str, str]:
    proc = _spawn(cmd, cwd=cwd)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode == 0, _to_text(stdout), _to_text(stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = _to_text(exc.output)
        stderr = _to_text(exc.stderr)
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_streams(stdout, cleanup_stdout)
        stderr = _merge_streams(stderr, cleanup_stderr)
        stderr = _append_message(stderr, f"Command timed out after {timeout}s")
        return False, stdout, stderr
    except Exception as exc:
        stdout = _to_text(getattr(exc, "output", None))
        stderr = _to_text(getattr(exc, "stderr", None))
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_streams(stdout, cleanup_stdout)
        stderr = _merge_streams(stderr, cleanup_stderr)
        stderr = _append_message(stderr, str(exc))
        return False, stdout, stderr


def run_shell_command(cmd: str, *, cwd: str | None = None, timeout: int | float = 600) -> tuple[bool, str]:
    success, stdout, stderr = _run_shell_command_split(cmd, cwd=cwd, timeout=timeout)
    return success, stdout + stderr


def run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
) -> tuple[bool, str, str]:
    return _run_shell_command_split(cmd, cwd=cwd, timeout=timeout)
