import pytest

import repo_source
from repo_scan_models import RepoSourceMeta


def test_normalize_github_repo_accepts_owner_repo():
    assert repo_source.normalize_github_repo("octo/demo") == ("octo", "demo")
    assert repo_source.normalize_github_repo("https://github.com/octo/demo.git") == (
        "octo",
        "demo",
    )


def test_probe_local_repo_counts_files(tmp_path):
    repo_dir = tmp_path / "repo"
    (repo_dir / ".git").mkdir(parents=True)
    (repo_dir / "app").mkdir()
    (repo_dir / "app" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (repo_dir / ".env").write_text("TOKEN=value\n", encoding="utf-8")

    meta = repo_source.probe_local_repo(str(repo_dir))

    assert meta.source_kind == "local_path"
    assert meta.repo_path == str(repo_dir.resolve())
    assert meta.file_count == 2
    assert meta.clone_performed is False
    assert meta.probe_complete is True


def test_probe_github_repo_marks_threshold_when_size_is_too_large(monkeypatch):
    responses = {
        "https://api.github.com/repos/octo/demo": {
            "size": 300_000,
            "default_branch": "main",
            "html_url": "https://github.com/octo/demo",
        },
        "https://api.github.com/repos/octo/demo/git/trees/main?recursive=1": {
            "tree": [{"type": "blob", "path": "README.md"}],
            "truncated": False,
        },
    }
    monkeypatch.setattr(
        repo_source, "_github_get_json", lambda url, timeout=15: responses[url]
    )

    meta = repo_source.probe_github_repo("octo/demo")

    assert meta.source_kind == "github_public"
    assert meta.repo_url == "https://github.com/octo/demo"
    assert meta.threshold_exceeded is True
    assert "size_bytes" in meta.threshold_reasons
    assert meta.size_bytes > repo_source.MAX_REPO_SIZE_BYTES


def test_acquire_repo_source_requires_confirmation_for_large_github_repo(monkeypatch):
    meta = RepoSourceMeta(
        source_kind="github_public",
        repo_url="https://github.com/octo/demo",
        repo_ref="main",
        size_bytes=repo_source.MAX_REPO_SIZE_BYTES + 1,
        file_count=10,
        probe_complete=True,
        threshold_exceeded=True,
        threshold_reasons=["size_bytes"],
    )
    monkeypatch.setattr(repo_source, "probe_github_repo", lambda repo_url: meta)

    with pytest.raises(repo_source.RepoConfirmationRequired):
        repo_source.acquire_repo_source(
            repo_url="octo/demo",
            allow_large_repo=False,
            interactive=False,
        )


def test_acquire_repo_source_allows_large_repo_when_flag_is_set(monkeypatch, tmp_path):
    meta = RepoSourceMeta(
        source_kind="github_public",
        repo_url="https://github.com/octo/demo",
        repo_ref="main",
        size_bytes=repo_source.MAX_REPO_SIZE_BYTES + 1,
        file_count=10,
        probe_complete=True,
        threshold_exceeded=True,
        threshold_reasons=["size_bytes"],
    )
    temp_dir = object()
    monkeypatch.setattr(repo_source, "probe_github_repo", lambda repo_url: meta)
    monkeypatch.setattr(
        repo_source, "clone_github_repo", lambda source_meta: (str(tmp_path / "repo"), temp_dir)
    )

    resolved_meta, repo_dir, tmp_handle = repo_source.acquire_repo_source(
        repo_url="octo/demo",
        allow_large_repo=True,
        interactive=False,
    )

    assert resolved_meta is meta
    assert repo_dir == str(tmp_path / "repo")
    assert tmp_handle is temp_dir
