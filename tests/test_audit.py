from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from supply_gate.audit import findings_from_pip_audit, load_pip_audit_file, run_pip_audit
from supply_gate.cvss import extract_cvss
from supply_gate.errors import AuditError


def test_load_mixed_fixture(pip_audit_mixed: Path) -> None:
    findings = load_pip_audit_file(pip_audit_mixed)
    by_id = {item.vuln_id: item for item in findings}
    assert by_id["GHSA-0000-0000-0001"].cvss == 9.8
    assert by_id["PYSEC-0000-2"].cvss == 4.0
    assert "clean-pkg" not in {item.package for item in findings if item.vuln_id}


def test_list_format_and_nested_score(fixtures: Path) -> None:
    findings = load_pip_audit_file(fixtures / "pip_audit_list.json")
    assert len(findings) == 1
    assert findings[0].cvss == 9.8
    assert findings[0].package == "listed-pkg"


def test_empty_dependencies(fixtures: Path) -> None:
    assert load_pip_audit_file(fixtures / "empty_pip_audit.json") == []


def test_invalid_root_type() -> None:
    with pytest.raises(AuditError, match="object or a list"):
        findings_from_pip_audit("nope")


def test_invalid_dependencies_type() -> None:
    with pytest.raises(AuditError, match="must be a list"):
        findings_from_pip_audit({"dependencies": {}})


def test_skips_non_dict_entries() -> None:
    findings = findings_from_pip_audit(
        {
            "dependencies": [
                "skip-me",
                {"name": "x", "version": "1", "vulns": ["nope", {"id": "A", "cvss": 1.0}]},
            ]
        }
    )
    assert len(findings) == 1
    assert findings[0].vuln_id == "A"


def test_invalid_json_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuditError, match="invalid pip-audit JSON"):
        load_pip_audit_file(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AuditError, match="cannot read"):
        load_pip_audit_file(tmp_path / "missing.json")


def test_extract_cvss_walks_lists_and_strings() -> None:
    assert extract_cvss({"score": "7.5"}) == 7.5
    assert extract_cvss([{"V3Score": 1.0}, {"V3Score": 3.2}]) == 3.2
    assert extract_cvss("not-a-number") is None
    assert extract_cvss(True) is None
    assert extract_cvss(None) is None
    assert extract_cvss({"advisory": {"cvss": 6.1}}) == 6.1


def test_run_pip_audit_missing_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: None)
    with pytest.raises(AuditError, match="pip-audit not found"):
        run_pip_audit(tmp_path)


def test_run_pip_audit_exit_1_still_parses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pip_audit_mixed: Path
) -> None:
    payload = pip_audit_mixed.read_text(encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        assert "-r" in cmd
        return subprocess.CompletedProcess(cmd, 1, stdout=payload, stderr="")

    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: "/usr/bin/pip-audit")
    monkeypatch.setattr("supply_gate.audit.subprocess.run", fake_run)
    findings = run_pip_audit(tmp_path)
    assert any(item.cvss == 9.8 for item in findings)


def test_run_pip_audit_project_path_and_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        assert "--project" not in cmd
        assert cmd[-1] == str(tmp_path)
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="boom")

    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: "/usr/bin/pip-audit")
    monkeypatch.setattr("supply_gate.audit.subprocess.run", fake_run)
    with pytest.raises(AuditError, match="exited 2"):
        run_pip_audit(tmp_path)


def test_run_pip_audit_invalid_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="not-json", stderr="")

    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: "/usr/bin/pip-audit")
    monkeypatch.setattr("supply_gate.audit.subprocess.run", fake_run)
    with pytest.raises(AuditError, match="invalid JSON"):
        run_pip_audit(tmp_path)


def test_run_pip_audit_oserror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(*args, **kwargs):  # noqa: ANN001
        raise OSError("cannot exec")

    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: "/usr/bin/pip-audit")
    monkeypatch.setattr("supply_gate.audit.subprocess.run", fake_run)
    with pytest.raises(AuditError, match="failed to execute"):
        run_pip_audit(tmp_path)


def test_run_pip_audit_empty_stdout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("supply_gate.audit.shutil.which", lambda _: "/usr/bin/pip-audit")
    monkeypatch.setattr("supply_gate.audit.subprocess.run", fake_run)
    assert run_pip_audit(tmp_path) == []


def test_roundtrip_dump_is_not_required_for_policy(pip_audit_mixed: Path) -> None:
    data = json.loads(pip_audit_mixed.read_text(encoding="utf-8"))
    assert findings_from_pip_audit(data)
