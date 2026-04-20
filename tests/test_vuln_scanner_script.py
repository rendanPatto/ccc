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


def test_vuln_scanner_marks_auth_flows_for_manual_review():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8").lower()

    assert "auth_flow_review.txt" in text
    assert "manual_review" in text
    assert "mfa" in text
    assert "otp" in text
    assert "saml" in text
    assert "sso" in text
    assert "relaystate" in text
