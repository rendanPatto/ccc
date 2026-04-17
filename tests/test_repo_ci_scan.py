"""Tests for GitHub Actions / CI scanning."""

import repo_ci_scan


def test_scan_repo_ci_flags_pull_request_target_and_unpinned_actions(tmp_path):
    workflow_dir = tmp_path / "repo" / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "unsafe.yml").write_text(
        """
name: unsafe
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
""".strip()
        + "\n",
        encoding="utf-8",
    )

    findings = repo_ci_scan.scan_repo_ci(str(tmp_path / "repo"))

    rule_ids = {finding.rule_id for finding in findings}
    assert "pull-request-target-checkout" in rule_ids
    assert "unpinned-third-party-action" in rule_ids


def test_scan_repo_ci_flags_self_hosted_and_unsafe_interpolation(tmp_path):
    workflow_dir = tmp_path / "repo" / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "runner.yml").write_text(
        """
name: runner
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    findings = repo_ci_scan.scan_repo_ci(str(tmp_path / "repo"))

    rule_ids = {finding.rule_id for finding in findings}
    assert "self-hosted-untrusted-trigger" in rule_ids
    assert "unsafe-user-input-in-run" in rule_ids
