from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from repo_scan_models import RepoSourceMeta

MAX_REPO_SIZE_BYTES = 200 * 1024 * 1024
MAX_REPO_FILE_COUNT = 20_000
GITHUB_API_ROOT = "https://api.github.com"


class RepoConfirmationRequired(RuntimeError):
    def __init__(self, meta: RepoSourceMeta):
        super().__init__("repository exceeds configured thresholds")
        self.meta = meta


def normalize_github_repo(value: str) -> tuple[str, str]:
    cleaned = value.strip()
    for prefix in ("https://github.com/", "http://github.com/"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    parts = [part for part in cleaned.split("/") if part]
    if len(parts) != 2:
        raise ValueError(f"unsupported GitHub repository reference: {value}")
    return parts[0], parts[1]


def _github_get_json(url: str, timeout: int = 15) -> dict:
    request = Request(
        url,
        headers={
            "accept": "application/vnd.github+json",
            "user-agent": "claude-bug-bounty-source-hunt",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    return json.loads(body)


def probe_github_repo(repo_ref: str) -> RepoSourceMeta:
    owner, repo = normalize_github_repo(repo_ref)
    repo_url = f"https://github.com/{owner}/{repo}"

    try:
        metadata = _github_get_json(f"{GITHUB_API_ROOT}/repos/{owner}/{repo}")
        default_branch = str(metadata.get("default_branch") or "HEAD")
        size_bytes = int(metadata.get("size") or 0) * 1024
        tree = _github_get_json(
            f"{GITHUB_API_ROOT}/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
        )
        file_count = sum(1 for entry in tree.get("tree", []) if entry.get("type") == "blob")
        truncated = bool(tree.get("truncated", False))
        probe_complete = True
    except (HTTPError, URLError, ValueError, json.JSONDecodeError):
        default_branch = "HEAD"
        size_bytes = 0
        file_count = 0
        truncated = True
        probe_complete = False

    threshold_reasons: list[str] = []
    if size_bytes > MAX_REPO_SIZE_BYTES:
        threshold_reasons.append("size_bytes")
    if file_count > MAX_REPO_FILE_COUNT:
        threshold_reasons.append("file_count")
    if truncated:
        threshold_reasons.append("tree_truncated")

    return RepoSourceMeta(
        source_kind="github_public",
        repo_url=repo_url,
        repo_ref=default_branch,
        size_bytes=size_bytes,
        file_count=file_count,
        probe_complete=probe_complete,
        threshold_exceeded=bool(threshold_reasons),
        threshold_reasons=threshold_reasons,
        probe_truncated=truncated,
    )


def probe_local_repo(repo_path: str) -> RepoSourceMeta:
    path = Path(repo_path).expanduser().resolve()
    if not path.is_dir():
        raise FileNotFoundError(f"repository path not found: {repo_path}")

    size_bytes = 0
    file_count = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [name for name in dirs if name != ".git"]
        for filename in files:
            file_path = Path(root) / filename
            size_bytes += file_path.stat().st_size
            file_count += 1

    return RepoSourceMeta(
        source_kind="local_path",
        repo_path=str(path),
        size_bytes=size_bytes,
        file_count=file_count,
        probe_complete=True,
        threshold_exceeded=False,
        clone_performed=False,
    )


def _confirm_large_repo(meta: RepoSourceMeta, *, interactive: bool, prompt_fn=input) -> None:
    if not meta.threshold_exceeded:
        return
    if not interactive:
        raise RepoConfirmationRequired(meta)

    reasons = ", ".join(meta.threshold_reasons) or "threshold exceeded"
    answer = prompt_fn(f"Repository is large ({reasons}); clone anyway? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        raise RepoConfirmationRequired(meta)


def clone_github_repo(meta: RepoSourceMeta) -> tuple[str, tempfile.TemporaryDirectory]:
    temp_dir = tempfile.TemporaryDirectory(prefix="source-hunt-")
    repo_dir = Path(temp_dir.name) / "repo"
    command = ["git", "clone", "--depth", "1", "--single-branch", meta.repo_url, str(repo_dir)]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        temp_dir.cleanup()
        error_msg = completed.stderr.strip() or completed.stdout.strip() or "git clone failed"
        raise RuntimeError(error_msg)

    meta.clone_performed = True
    return str(repo_dir), temp_dir


def acquire_repo_source(
    *,
    repo_url: str = "",
    repo_path: str = "",
    allow_large_repo: bool = False,
    interactive: bool = False,
) -> tuple[RepoSourceMeta, str, tempfile.TemporaryDirectory | None]:
    if bool(repo_url) == bool(repo_path):
        raise ValueError("exactly one of repo_url or repo_path is required")

    if repo_path:
        meta = probe_local_repo(repo_path)
        return meta, meta.repo_path, None

    meta = probe_github_repo(repo_url)
    if meta.threshold_exceeded and not allow_large_repo:
        _confirm_large_repo(meta, interactive=interactive)
    repo_dir, temp_dir = clone_github_repo(meta)
    return meta, repo_dir, temp_dir
