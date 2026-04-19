"""Regression tests for recon_engine.sh shell pitfalls."""

from pathlib import Path


def test_recon_engine_guards_common_set_e_pitfalls():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "log_vuln()" in text
    assert 'TARGET_KIND="domain"' in text
    assert 'TARGET_KIND="ip"' in text
    assert 'TARGET_KIND="cidr"' in text
    assert 'cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt" || true' in text
    assert 'httpx -l "$HTTPX_INPUT_FILE"' in text
    assert 'FUZZ_COUNT=$((FUZZ_COUNT + 1))' in text
    assert 'CONTENT_TYPE=$(curl -sI --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1 || true)' in text
    assert "for host in network.hosts():" in text
    assert "if count >= limit:" in text
    assert 'if [ "$TARGET_KIND" = "domain" ]; then' in text
    assert '-iL "$DISCOVERY_HOSTS_FILE"' in text
