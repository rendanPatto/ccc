"""Regression tests for misc agent dispatcher tool summaries."""

import agent


def _build_dispatcher(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    return agent.ToolDispatcher("target.com", memory)


def test_dispatch_check_tools_formats_installed_and_missing(monkeypatch, tmp_path):
    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    monkeypatch.setattr(hunt, "check_tools", lambda: (["httpx", "nuclei"], ["sqlmap"]))

    output = dispatcher.dispatch("check_tools", {})

    assert "check_tools: 2 installed, 1 missing" in output
    assert "Installed: httpx, nuclei" in output
    assert "Missing: sqlmap" in output


def test_dispatch_generate_reports_summarizes_output(monkeypatch, tmp_path):
    report_dir = tmp_path / "reports" / "target.com"
    report_dir.mkdir(parents=True)
    (report_dir / "001-test.md").write_text("# report\n", encoding="utf-8")

    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "generate_reports", lambda domain: 1)

    output = dispatcher.dispatch("generate_reports", {})

    assert "generate_reports: 1 report(s) generated" in output
    assert "Reports: 001-test.md" in output
