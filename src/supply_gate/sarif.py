from __future__ import annotations

from supply_gate import __version__
from supply_gate.models import Finding, PolicyResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_sarif(result: PolicyResult) -> dict[str, object]:
    failing_ids = {id(item) for item in result.failing}
    allowlisted_ids = {id(item) for item in result.allowlisted}
    rules: list[dict[str, object]] = []
    seen: set[str] = set()
    results: list[dict[str, object]] = []
    for finding in result.findings:
        if finding.vuln_id not in seen:
            seen.add(finding.vuln_id)
            rules.append(_rule(finding))
        entry: dict[str, object] = {
            "ruleId": finding.vuln_id,
            "level": _level(finding, id(finding) in failing_ids, id(finding) in allowlisted_ids),
            "message": {"text": _message(finding)},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": f"{finding.package}@{finding.version}",
                            "kind": "package",
                        }
                    ]
                }
            ],
            "properties": {
                "cvss": finding.cvss,
                "source": finding.source,
                "package": finding.package,
                "security-severity": _security_severity(finding),
            },
        }
        if id(finding) in allowlisted_ids:
            entry["suppressions"] = [
                {
                    "kind": "external",
                    "justification": "allowlisted",
                }
            ]
        results.append(entry)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "supply-gate",
                        "version": __version__,
                        "informationUri": "https://github.com/smaefr/supply-gate",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _rule(finding: Finding) -> dict[str, object]:
    text = finding.title or finding.vuln_id
    return {
        "id": finding.vuln_id,
        "shortDescription": {"text": text},
        "fullDescription": {"text": finding.description or text},
        "helpUri": _help_uri(finding.vuln_id),
        "properties": {
            "security-severity": _security_severity(finding),
            "tags": ["security", "supply-chain", finding.source],
        },
    }


def _help_uri(vuln_id: str) -> str:
    upper = vuln_id.upper()
    if upper.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{upper}"
    if upper.startswith("GHSA-"):
        return f"https://github.com/advisories/{upper.lower()}"
    return "https://osv.dev"


def _security_severity(finding: Finding) -> str:
    if finding.cvss is None:
        return "0.0"
    return f"{finding.cvss:.1f}"


def _level(finding: Finding, failing: bool, allowlisted: bool) -> str:
    if allowlisted:
        return "note"
    if failing:
        return "error"
    if finding.cvss is not None and finding.cvss >= 4.0:
        return "warning"
    return "note"


def _message(finding: Finding) -> str:
    score = "none" if finding.cvss is None else f"{finding.cvss:.1f}"
    pkg = f"{finding.package}@{finding.version}" if finding.package else "unknown package"
    title = finding.title or finding.description or finding.vuln_id
    return f"{finding.vuln_id} in {pkg} (CVSS {score}, {finding.source}): {title}"
