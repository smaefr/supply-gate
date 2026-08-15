from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

from supply_gate.cli import main
from supply_gate.errors import SupplyGateError


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "supply-gate" in capsys.readouterr().out


def test_help() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_audit_from_file(
    pip_audit_mixed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "findings.json"
    assert main(["audit", "--from-file", str(pip_audit_mixed), "--output", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert any(item["cvss"] == 9.8 for item in payload)
    printed = json.loads(capsys.readouterr().out)
    assert len(printed) == len(payload)


def test_audit_markdown_format(pip_audit_mixed: Path) -> None:
    assert main(["audit", "--from-file", str(pip_audit_mixed), "--format", "markdown"]) == 0


def test_audit_missing_file(tmp_path: Path) -> None:
    assert main(["audit", "--from-file", str(tmp_path / "nope.json")]) == 2


def test_sbom_writes(tmp_path: Path, fixtures: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        (fixtures / "pyproject_sample.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    dest = tmp_path / "nested" / "bom.json"
    assert main(["sbom", "--path", str(project), "--output", str(dest)]) == 0
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"


def test_image_from_file(trivy_mixed: Path, tmp_path: Path) -> None:
    dest = tmp_path / "img.json"
    assert (
        main(
            [
                "image",
                "--image",
                "demo:latest",
                "--from-file",
                str(trivy_mixed),
                "--output",
                str(dest),
            ]
        )
        == 0
    )
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert any(item["cvss"] == 9.8 for item in payload)


def test_image_markdown(trivy_mixed: Path) -> None:
    assert (
        main(
            [
                "image",
                "--image",
                "demo:latest",
                "--from-file",
                str(trivy_mixed),
                "--format",
                "markdown",
            ]
        )
        == 0
    )


def test_image_skip_missing_trivy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("supply_gate.cli.run_trivy_image", lambda *a, **k: None)
    assert main(["image", "--image", "demo:latest", "--on-missing-trivy", "skip"]) == 0
    assert "skipping image scan" in capsys.readouterr().err


def test_image_require_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    from supply_gate.errors import TrivyNotFoundError

    def boom(*args, **kwargs):  # noqa: ANN001
        raise TrivyNotFoundError("trivy binary not found")

    monkeypatch.setattr("supply_gate.cli.run_trivy_image", boom)
    assert main(["image", "--image", "demo:latest"]) == 2


def test_policy_fails_on_9_8(
    pip_audit_mixed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "policy",
            "--input",
            str(pip_audit_mixed),
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
        ]
    )
    assert code == 1
    assert "FAIL" in capsys.readouterr().out
    assert (tmp_path / "g.sarif").is_file()


def test_policy_allowlist_passes(pip_audit_mixed: Path, fixtures: Path, tmp_path: Path) -> None:
    code = main(
        [
            "policy",
            "--input",
            str(pip_audit_mixed),
            "--allowlist-file",
            str(fixtures / "allowlist.txt"),
            "--format",
            "json",
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
        ]
    )
    assert code == 0


def test_policy_two_inputs_json(
    pip_audit_mixed: Path, trivy_mixed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "policy",
            "--input",
            str(pip_audit_mixed),
            "--input",
            str(trivy_mixed),
            "--format",
            "json",
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
        ]
    )
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["max_cvss"] == 9.8
    assert len(payload["failing"]) == 2


def test_run_with_fixtures(
    pip_audit_mixed: Path,
    trivy_mixed: Path,
    tmp_path: Path,
    fixtures: Path,
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        (fixtures / "pyproject_sample.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    code = main(
        [
            "run",
            "--path",
            str(project),
            "--audit-json",
            str(pip_audit_mixed),
            "--trivy-json",
            str(trivy_mixed),
            "--threshold",
            "8.0",
            "--sarif-out",
            str(tmp_path / "supply-gate.sarif"),
            "--summary-out",
            str(tmp_path / "supply-gate.md"),
            "--sbom-out",
            str(tmp_path / "sbom.cdx.json"),
            "--format",
            "sarif",
        ]
    )
    assert code == 1
    bom = json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    sarif = json.loads((tmp_path / "supply-gate.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_run_allowlist_and_skip_image(
    pip_audit_mixed: Path,
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        (fixtures / "pyproject_sample.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setattr("supply_gate.cli.run_trivy_image", lambda *a, **k: None)
    code = main(
        [
            "run",
            "--path",
            str(project),
            "--audit-json",
            str(pip_audit_mixed),
            "--image",
            "demo:latest",
            "--on-missing-trivy",
            "skip",
            "--allowlist",
            "GHSA-0000-0000-0001",
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
            "--sbom-out",
            str(tmp_path / "sbom.cdx.json"),
        ]
    )
    assert code == 0


def test_run_with_image_findings(
    pip_audit_mixed: Path,
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from supply_gate.loaders import findings_from_json_path

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        (fixtures / "pyproject_sample.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    extra = findings_from_json_path(fixtures / "trivy_mixed.json")
    monkeypatch.setattr("supply_gate.cli.run_trivy_image", lambda *a, **k: extra)
    code = main(
        [
            "run",
            "--path",
            str(project),
            "--audit-json",
            str(pip_audit_mixed),
            "--image",
            "demo:latest",
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
            "--sbom-out",
            str(tmp_path / "sbom.cdx.json"),
        ]
    )
    assert code == 1


def test_run_invokes_pip_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixtures: Path
) -> None:
    from supply_gate.loaders import findings_from_json_path

    findings = findings_from_json_path(fixtures / "empty_pip_audit.json")
    called: list[Path] = []

    def fake_audit(path: Path):
        called.append(path)
        return findings

    monkeypatch.setattr("supply_gate.cli.run_pip_audit", fake_audit)
    code = main(
        [
            "run",
            "--path",
            str(tmp_path),
            "--sarif-out",
            str(tmp_path / "g.sarif"),
            "--summary-out",
            str(tmp_path / "g.md"),
            "--sbom-out",
            str(tmp_path / "sbom.cdx.json"),
        ]
    )
    assert code == 0
    assert called == [tmp_path]


def test_audit_invokes_pip_audit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("supply_gate.cli.run_pip_audit", lambda path: [])
    assert main(["audit", "--path", str(tmp_path)]) == 0


def test_unknown_command() -> None:
    from argparse import Namespace

    from supply_gate.cli import _dispatch

    with pytest.raises(SupplyGateError, match="unknown command"):
        _dispatch(Namespace(command="nope"))


def test_module_main(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["supply-gate", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("supply_gate", run_name="__main__")
    assert exc.value.code == 0


def test_invalid_json_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert main(["policy", "--input", str(bad)]) == 2


def test_loaders_invalid_json(tmp_path: Path) -> None:
    from supply_gate.errors import SupplyGateError
    from supply_gate.loaders import findings_from_json_path

    missing = tmp_path / "missing.json"
    with pytest.raises(SupplyGateError, match="cannot read"):
        findings_from_json_path(missing)
