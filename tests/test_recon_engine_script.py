"""Regression tests for recon_engine.sh shell pitfalls."""

from pathlib import Path


def test_recon_engine_guards_common_set_e_pitfalls():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "log_vuln()" in text
    assert 'cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt" || true' in text
    assert 'FUZZ_COUNT=$((FUZZ_COUNT + 1))' in text
    assert 'CONTENT_TYPE=$(curl -sI --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1 || true)' in text
