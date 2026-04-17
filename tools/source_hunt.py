from __future__ import annotations

import argparse
import json
from pathlib import Path

from repo_ci_scan import scan_repo_ci
from repo_scan_models import RepoFinding, RepoSourceMeta
from repo_secret_scan import scan_repo_secrets
from repo_source import MAX_REPO_SIZE_BYTES, RepoConfirmationRequired, acquire_repo_source

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent


def _exposure_dir(target: str) -> Path:
    path = BASE_DIR / "findings" / target / "exposure"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def render_repo_summary(
    meta: RepoSourceMeta,
    secret_findings: list[RepoFinding],
    ci_findings: list[RepoFinding],
) -> str:
    lines = [
        "# Repository Source Hunt Summary",
        "",
        f"- Source kind: {meta.source_kind}",
        f"- Repo URL: {meta.repo_url or '(local only)'}",
        f"- Repo path: {meta.repo_path or '(temporary clone)'}",
        f"- Repo ref: {meta.repo_ref or '(n/a)'}",
        f"- Size bytes: {meta.size_bytes}",
        f"- File count: {meta.file_count}",
        f"- Probe complete: {meta.probe_complete}",
        f"- Threshold exceeded: {meta.threshold_exceeded}",
        f"- Clone performed: {meta.clone_performed}",
    ]
    if meta.threshold_reasons:
        lines.append(f"- Threshold reasons: {', '.join(meta.threshold_reasons)}")
    if meta.status == "confirmation_required":
        lines.append("- Scan status: confirmation required before clone")
    else:
        lines.append(f"- Secret findings: {len(secret_findings)}")
        lines.append(f"- CI findings: {len(ci_findings)}")
        for finding in (secret_findings + ci_findings)[:10]:
            location = f"{finding.file_path}:{finding.line_number}" if finding.line_number else finding.file_path
            lines.append(f"- [{finding.severity}] {finding.rule_id} :: {location}")
    return "\n".join(lines) + "\n"


def _write_result_bundle(
    target: str,
    meta: RepoSourceMeta,
    secret_findings: list[RepoFinding],
    ci_findings: list[RepoFinding],
) -> Path:
    exposure_dir = _exposure_dir(target)
    _write_json(exposure_dir / "repo_source_meta.json", meta.to_dict())
    _write_json(exposure_dir / "repo_secrets.json", [finding.to_dict() for finding in secret_findings])
    _write_json(exposure_dir / "repo_ci_findings.json", [finding.to_dict() for finding in ci_findings])
    (exposure_dir / "repo_summary.md").write_text(
        render_repo_summary(meta, secret_findings, ci_findings),
        encoding="utf-8",
    )
    return exposure_dir


def run_source_hunt(
    *,
    target: str,
    repo_url: str = "",
    repo_path: str = "",
    allow_large_repo: bool = False,
    interactive: bool = False,
) -> dict:
    try:
        source_meta, resolved_repo_path, temp_dir = acquire_repo_source(
            repo_url=repo_url,
            repo_path=repo_path,
            allow_large_repo=allow_large_repo,
            interactive=interactive,
        )
    except RepoConfirmationRequired as exc:
        exc.meta.status = "confirmation_required"
        exposure_dir = _write_result_bundle(target, exc.meta, [], [])
        return {
            "status": "confirmation_required",
            "exposure_dir": str(exposure_dir),
            "source_meta": exc.meta.to_dict(),
        }

    try:
        secret_findings = scan_repo_secrets(resolved_repo_path)
        ci_findings = scan_repo_ci(resolved_repo_path)
        exposure_dir = _write_result_bundle(target, source_meta, secret_findings, ci_findings)
        return {
            "status": "ok",
            "exposure_dir": str(exposure_dir),
            "source_meta": source_meta.to_dict(),
            "secret_count": len(secret_findings),
            "ci_count": len(ci_findings),
        }
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Repository source leak and CI risk scanner")
    parser.add_argument("--target", required=True, help="Target/program name used under findings/<target>/")
    parser.add_argument("--repo-url", default="", help="GitHub public repo URL or owner/repo reference")
    parser.add_argument("--repo-path", default="", help="Local repository path already available on disk")
    parser.add_argument(
        "--allow-large-repo",
        action="store_true",
        help=f"Allow clone when the repo exceeds {MAX_REPO_SIZE_BYTES} bytes or file-count thresholds",
    )
    args = parser.parse_args()

    result = run_source_hunt(
        target=args.target,
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        allow_large_repo=args.allow_large_repo,
        interactive=True,
    )
    summary_path = Path(result["exposure_dir"]) / "repo_summary.md"
    print(summary_path.read_text(encoding="utf-8"))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
