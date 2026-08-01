from __future__ import annotations

from pathlib import Path

from supply_gate.loaders import findings_from_json_path
from supply_gate.models import Finding
from supply_gate.policy import DEFAULT_THRESHOLD, evaluate, parse_allowlist


def _finding(vuln_id: str, cvss: float | None, *, aliases: tuple[str, ...] = ()) -> Finding:
    return Finding(
        vuln_id=vuln_id,
        package="demo",
        version="1.0",
        cvss=cvss,
        source="test",
        aliases=aliases,
    )


def test_default_threshold_is_8() -> None:
    assert DEFAULT_THRESHOLD == 8.0


def test_cvss_9_8_fails_default_threshold(pip_audit_mixed: Path) -> None:
    findings = findings_from_json_path(pip_audit_mixed)
    result = evaluate(findings)
    assert not result.passed
    assert result.max_cvss == 9.8
    assert result.failing[0].cvss == 9.8
    assert result.failing[0].vuln_id == "GHSA-0000-0000-0001"


def test_cvss_4_0_does_not_fail_alone() -> None:
    result = evaluate([_finding("CVE-0000-0002", 4.0)])
    assert result.passed
    assert result.max_cvss == 4.0
    assert result.failing == ()


def test_mixed_fixtures_only_critical_fails(pip_audit_mixed: Path, trivy_mixed: Path) -> None:
    findings = findings_from_json_path(pip_audit_mixed) + findings_from_json_path(trivy_mixed)
    result = evaluate(findings, threshold=8.0)
    failing_ids = {item.vuln_id for item in result.failing}
    assert failing_ids == {"GHSA-0000-0000-0001", "CVE-0000-9999"}
    assert all(item.cvss is not None and item.cvss >= 8.0 for item in result.failing)


def test_allowlist_by_id_and_alias(pip_audit_mixed: Path) -> None:
    findings = findings_from_json_path(pip_audit_mixed)
    by_id = evaluate(findings, allowlist=["GHSA-0000-0000-0001"])
    assert by_id.passed
    assert by_id.allowlisted[0].vuln_id == "GHSA-0000-0000-0001"
    by_alias = evaluate(findings, allowlist=["cve-0000-0001"])
    assert by_alias.passed


def test_threshold_above_9_8_passes() -> None:
    result = evaluate([_finding("CVE-0000-0001", 9.8)], threshold=9.9)
    assert result.passed


def test_equal_to_threshold_fails() -> None:
    result = evaluate([_finding("CVE-0000-0001", 8.0)], threshold=8.0)
    assert not result.passed


def test_missing_cvss_does_not_fail() -> None:
    result = evaluate([_finding("CVE-0000-2222", None)])
    assert result.passed
    assert result.max_cvss is None


def test_empty_findings_pass() -> None:
    result = evaluate([])
    assert result.passed
    assert result.max_cvss is None


def test_parse_allowlist_file_and_csv(fixtures: Path) -> None:
    ids = parse_allowlist("CVE-0000-1111, extra", fixtures / "allowlist.txt")
    assert "GHSA-0000-0000-0001" in ids
    assert "CVE-0000-9999" in ids
    assert "CVE-0000-1111" in ids
    assert "extra" in ids


def test_parse_allowlist_empty() -> None:
    assert parse_allowlist(None, None) == []
