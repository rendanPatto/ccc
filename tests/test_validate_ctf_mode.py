"""Regression tests for validate.py CTF mode behavior."""

import json

import validate


def test_gate2_in_scope_skips_when_ctf_mode_enabled(capsys):
    passed, notes = validate.gate2_in_scope("ignored-program", skip_scope=True)

    output = capsys.readouterr().out
    assert passed is True
    assert notes["skipped_in_ctf_mode"] is True
    assert "skipping program scope validation" in output.lower()


def test_write_validation_summary_updates_last_validate(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    report_path = tmp_path / "findings" / "target-program-idor" / "hackerone-report.md"
    report_path.parent.mkdir(parents=True)

    info = {
        "target": "target-program",
        "vuln_type": "IDOR",
        "endpoint": "https://api.target.com/api/v2/orders/42",
        "impact": "Read another user's order",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)
    validate.write_validation_summary(summary, report_path)

    report_summary = report_path.parent / "validation-summary.json"
    last_validate = tmp_path / "findings" / "last-validate.json"

    assert report_summary.exists()
    assert last_validate.exists()

    saved = json.loads(report_summary.read_text(encoding="utf-8"))
    assert saved["target"] == "api.target.com"
    assert saved["program"] == "target-program"
    assert saved["vuln_class"] == "idor"
    assert saved["severity"] == "high"
    assert saved["result"] == "confirmed"

    last_saved = json.loads(last_validate.read_text(encoding="utf-8"))
    assert last_saved["report_path"] == str(report_path)
