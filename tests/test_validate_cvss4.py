"""Tests for CVSS 4.0 scoring in validate.py."""

import validate


def test_calculate_cvss4_returns_cvss4_vector_prefix():
    score, vector = validate.calculate_cvss4(
        av="N",
        ac="L",
        at="N",
        pr="N",
        ui="N",
        vc="H",
        vi="H",
        va="H",
        sc="H",
        si="H",
        sa="H",
    )

    assert isinstance(score, float)
    assert vector.startswith("CVSS:4.0/")


def test_severity_from_score_cvss4_thresholds():
    assert validate.severity_from_score(0.0) == "NONE"
    assert validate.severity_from_score(0.1) == "LOW"
    assert validate.severity_from_score(3.9) == "LOW"
    assert validate.severity_from_score(4.0) == "MEDIUM"
    assert validate.severity_from_score(6.9) == "MEDIUM"
    assert validate.severity_from_score(7.0) == "HIGH"
    assert validate.severity_from_score(8.9) == "HIGH"
    assert validate.severity_from_score(9.0) == "CRITICAL"


def test_ask_cvss_score_uses_cvss4_output(monkeypatch, capsys):
    answers = iter(["N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))

    score, vector, params = validate.ask_cvss_score()

    output = capsys.readouterr().out
    assert "CVSS 4.0 Scoring" in output
    assert "CVSS 4.0 Score:" in output
    assert vector.startswith("CVSS:4.0/")
    assert score >= 0.0
    assert params == {
        "AV": "N",
        "AC": "L",
        "AT": "N",
        "PR": "N",
        "UI": "N",
        "VC": "H",
        "VI": "H",
        "VA": "H",
        "SC": "H",
        "SI": "H",
        "SA": "H",
    }
