from __future__ import annotations

from pathlib import Path

import pytest

from supply_gate.loaders import findings_from_json_path
from supply_gate.policy import evaluate
from supply_gate.report import render, write_artifacts
from supply_gate.summary import render_markdown


def test_markdown_fail_and_pass(pip_audit_mixed: Path, fixtures: Path) -> None:
    failing = evaluate(findings_from_json_path(pip_audit_mixed))
    md = render_markdown(failing, sbom_path=Path("sbom.cdx.json"))
    assert "**Status:** FAIL" in md
    assert "GHSA-0000-0000-0001" in md
    assert "sbom.cdx.json" in md
    passing = evaluate(findings_from_json_path(fixtures / "empty_pip_audit.json"))
    ok = render_markdown(passing)
    assert "**Status:** PASS" in ok
    assert "_None._" in ok


def test_render_formats(pip_audit_mixed: Path) -> None:
    result = evaluate(findings_from_json_path(pip_audit_mixed))
    assert '"passed": false' in render(result, "json")
    assert '"version": "2.1.0"' in render(result, "sarif")
    assert "# supply-gate" in render(result, "markdown")


def test_render_unknown_format(pip_audit_mixed: Path) -> None:
    result = evaluate(findings_from_json_path(pip_audit_mixed))
    with pytest.raises(ValueError, match="unsupported format"):
        render(result, "xml")


def test_github_step_summary(
    pip_audit_mixed: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step = tmp_path / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    result = evaluate(findings_from_json_path(pip_audit_mixed))
    write_artifacts(
        result,
        sarif_out=tmp_path / "out.sarif",
        summary_out=tmp_path / "out.md",
        sbom_path=tmp_path / "sbom.cdx.json",
    )
    assert (tmp_path / "out.sarif").is_file()
    assert "FAIL" in (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "FAIL" in step.read_text(encoding="utf-8")
