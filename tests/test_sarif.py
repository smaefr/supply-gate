from __future__ import annotations

from pathlib import Path

from supply_gate.loaders import findings_from_json_path
from supply_gate.policy import evaluate
from supply_gate.sarif import SARIF_SCHEMA, to_sarif


def test_sarif_marks_failing_as_error(pip_audit_mixed: Path) -> None:
    result = evaluate(findings_from_json_path(pip_audit_mixed))
    doc = to_sarif(result)
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "supply-gate"
    by_rule = {item["ruleId"]: item for item in run["results"]}
    assert by_rule["GHSA-0000-0000-0001"]["level"] == "error"
    assert by_rule["PYSEC-0000-2"]["level"] == "warning"
    assert by_rule["GHSA-0000-0000-0001"]["properties"]["security-severity"] == "9.8"


def test_sarif_allowlist_suppression(pip_audit_mixed: Path) -> None:
    result = evaluate(
        findings_from_json_path(pip_audit_mixed),
        allowlist=["GHSA-0000-0000-0001"],
    )
    doc = to_sarif(result)
    critical = next(
        item for item in doc["runs"][0]["results"] if item["ruleId"] == "GHSA-0000-0000-0001"
    )
    assert critical["level"] == "note"
    assert critical["suppressions"][0]["justification"] == "allowlisted"


def test_sarif_missing_cvss_is_note(trivy_mixed: Path) -> None:
    result = evaluate(findings_from_json_path(trivy_mixed))
    unknown = next(
        item for item in to_sarif(result)["runs"][0]["results"] if item["ruleId"] == "CVE-0000-2222"
    )
    assert unknown["level"] == "note"
    assert unknown["properties"]["security-severity"] == "0.0"
