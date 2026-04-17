"""Ensure operational helper scripts can be imported without killing pytest."""

import importlib.util
from pathlib import Path


def test_zendesk_tool_import_is_safe():
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "tools" / "zendesk_idor_test.py"
    spec = importlib.util.spec_from_file_location("zendesk_idor_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.__test__ is False
    assert module.SUBDOMAIN == ""
    assert hasattr(module, "require_credentials")
