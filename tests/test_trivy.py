from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from supply_gate.errors import TrivyError, TrivyNotFoundError
from supply_gate.trivy import findings_from_trivy, load_trivy_file, run_trivy_image


def test_load_mixed_fixture(trivy_mixed: Path) -> None:
    findings = load_trivy_file(trivy_mixed)
    by_id = {item.vuln_id: item for item in findings}
    assert by_id["CVE-0000-9999"].cvss == 9.8
    assert by_id["CVE-0000-1111"].cvss == 4.0
    assert by_id["CVE-0000-2222"].cvss is None
    assert "GHSA-0000-2222-2222" in by_id["CVE-0000-2222"].aliases


def test_invalid_root() -> None:
    with pytest.raises(TrivyError, match="must be an object"):
        findings_from_trivy([])


def test_invalid_results_type() -> None:
    with pytest.raises(TrivyError, match="must be a list"):
        findings_from_trivy({"Results": {}})


def test_skips_non_dict_results() -> None:
    findings = findings_from_trivy(
        {
            "Results": [
                "nope",
                {"Vulnerabilities": "nope"},
                {"Vulnerabilities": [{"VulnerabilityID": "X", "PkgName": "y", "cvss": 2.0}]},
            ]
        }
    )
    assert len(findings) == 1
    assert findings[0].vuln_id == "X"


def test_invalid_json_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(TrivyError, match="invalid Trivy JSON"):
        load_trivy_file(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(TrivyError, match="cannot read"):
        load_trivy_file(tmp_path / "missing.json")


def test_run_trivy_missing_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: None)
    with pytest.raises(TrivyNotFoundError, match="trivy binary not found"):
        run_trivy_image("demo:latest", on_missing="fail")


def test_run_trivy_missing_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: None)
    assert run_trivy_image("demo:latest", on_missing="skip") is None


def test_run_trivy_bad_on_missing() -> None:
    with pytest.raises(TrivyError, match="on_missing"):
        run_trivy_image("demo:latest", on_missing="maybe")


def test_run_trivy_success(
    monkeypatch: pytest.MonkeyPatch, trivy_mixed: Path
) -> None:
    payload = trivy_mixed.read_text(encoding="utf-8")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        assert cmd[1] == "image"
        assert "demo:latest" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=payload, stderr="")

    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr("supply_gate.trivy.subprocess.run", fake_run)
    findings = run_trivy_image("demo:latest")
    assert findings is not None
    assert any(item.cvss == 9.8 for item in findings)


def test_run_trivy_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="scan failed")

    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr("supply_gate.trivy.subprocess.run", fake_run)
    with pytest.raises(TrivyError, match="exited 1"):
        run_trivy_image("demo:latest")


def test_run_trivy_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="not-json", stderr="")

    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr("supply_gate.trivy.subprocess.run", fake_run)
    with pytest.raises(TrivyError, match="invalid JSON"):
        run_trivy_image("demo:latest")


def test_run_trivy_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):  # noqa: ANN001
        raise OSError("cannot exec")

    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr("supply_gate.trivy.subprocess.run", fake_run)
    with pytest.raises(TrivyError, match="failed to execute"):
        run_trivy_image("demo:latest")


def test_run_trivy_empty_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("supply_gate.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr("supply_gate.trivy.subprocess.run", fake_run)
    assert run_trivy_image("demo:latest") == []
