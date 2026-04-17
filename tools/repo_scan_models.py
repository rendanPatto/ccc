from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RepoSourceMeta:
    source_kind: str
    repo_url: str = ""
    repo_path: str = ""
    repo_ref: str = ""
    size_bytes: int = 0
    file_count: int = 0
    probe_complete: bool = False
    threshold_exceeded: bool = False
    threshold_reasons: list[str] = field(default_factory=list)
    probe_truncated: bool = False
    clone_performed: bool = False
    status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RepoFinding:
    rule_id: str
    category: str
    severity: str
    confidence: str
    source: str
    file_path: str
    line_number: int | None
    match_type: str
    title: str
    secret_preview: str = ""
    evidence_snippet: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
