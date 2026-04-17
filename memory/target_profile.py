"""
Target profile storage helpers for hunt-memory/targets/<target>.json.

This is the persistent state used by resume/intel-style workflows.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from memory.schemas import CURRENT_SCHEMA_VERSION, SchemaError, validate_target_profile


def now_utc() -> str:
    """Return an ISO8601 UTC timestamp compatible with schema validation."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_memory_dir(base_dir: str | Path | None = None) -> Path:
    """Resolve the default hunt-memory directory.

    Priority:
    1. HUNT_MEMORY_DIR env var
    2. <base_dir>/hunt-memory if base_dir is provided
    3. ./hunt-memory
    """
    env_dir = os.getenv("HUNT_MEMORY_DIR")
    if env_dir:
        return Path(env_dir).expanduser()

    if base_dir is not None:
        return Path(base_dir) / "hunt-memory"

    return Path.cwd() / "hunt-memory"


def target_filename(target: str) -> str:
    """Normalize a target name into the on-disk profile filename."""
    return target.replace(".", "-").replace("/", "-") + ".json"


def target_profile_path(memory_dir: str | Path, target: str) -> Path:
    """Return the expected profile path for a target."""
    return Path(memory_dir) / "targets" / target_filename(target)


def make_target_profile(
    target: str,
    *,
    first_hunted: str | None = None,
    last_hunted: str | None = None,
    tech_stack: list[str] | None = None,
    scope_snapshot: dict | None = None,
    tested_endpoints: list[str] | None = None,
    untested_endpoints: list[str] | None = None,
    findings: list[dict] | None = None,
    hunt_sessions: int = 0,
    total_time_minutes: int | float = 0,
) -> dict:
    """Create a validated target profile dict."""
    ts = now_utc()
    profile = {
        "target": target,
        "first_hunted": first_hunted or ts,
        "last_hunted": last_hunted or ts,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }

    if tech_stack is not None:
        profile["tech_stack"] = tech_stack
    if scope_snapshot is not None:
        profile["scope_snapshot"] = scope_snapshot
    if tested_endpoints is not None:
        profile["tested_endpoints"] = tested_endpoints
    if untested_endpoints is not None:
        profile["untested_endpoints"] = untested_endpoints
    if findings is not None:
        profile["findings"] = findings
    if hunt_sessions:
        profile["hunt_sessions"] = hunt_sessions
    if total_time_minutes:
        profile["total_time_minutes"] = total_time_minutes

    return validate_target_profile(profile)


def load_target_profile(memory_dir: str | Path, target: str) -> dict | None:
    """Load and validate a target profile. Returns None if missing/invalid."""
    path = target_profile_path(memory_dir, target)
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            profile = json.load(f)
        return validate_target_profile(profile)
    except (OSError, json.JSONDecodeError, SchemaError):
        return None


def save_target_profile(memory_dir: str | Path, profile: dict) -> Path:
    """Validate and save a target profile. Returns the written path."""
    validated = validate_target_profile(profile)
    path = target_profile_path(memory_dir, validated["target"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(validated, f, indent=2)
        f.write("\n")
    return path
