"""Regression tests for report_generator.py manual workflow."""

from pathlib import Path
import sys

import pytest

import report_generator


def test_create_manual_report_generates_markdown_file(monkeypatch, tmp_path):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    report_file = report_generator.create_manual_report(
        "xss",
        "https://app.example.com/search?q=test",
        param="q",
        evidence="Reflected payload observed in response body.",
    )

    report_path = Path(report_file)
    assert report_path.exists()
    assert report_path.suffix == ".md"

    content = report_path.read_text(encoding="utf-8")
    assert "https://app.example.com/search?q=test" in content
    assert "XSS" in content.upper()
    assert "Parameter: q" in content


def test_attach_poc_images_copies_image_and_appends_markdown(monkeypatch, tmp_path):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    report_file = report_generator.create_manual_report(
        "ssrf",
        "https://api.example.com/fetch?url=http://169.254.169.254/",
        evidence="Server fetched internal metadata endpoint.",
    )

    image_path = tmp_path / "poc.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nfakepng")

    report_generator.attach_poc_images(report_file, [str(image_path)])

    report_path = Path(report_file)
    copied_image = report_path.parent / "poc_screenshots" / "poc.png"
    assert copied_image.exists()

    content = report_path.read_text(encoding="utf-8")
    assert "## PoC Screenshots" in content
    assert "![PoC 1](poc_screenshots/poc.png)" in content


def test_manual_mode_requires_type_and_url(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["report_generator.py", "--manual"])

    with pytest.raises(SystemExit) as excinfo:
        report_generator.main()

    assert excinfo.value.code == 1
    output = capsys.readouterr()
    assert "Manual mode requires --type and --url" in output.out
