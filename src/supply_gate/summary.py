from __future__ import annotations

from pathlib import Path

from supply_gate.models import Finding, PolicyResult


def render_markdown(
    result: PolicyResult,
    *,
    sbom_path: Path | None = None,
) -> str:
    status = "PASS" if result.passed else "FAIL"
    max_cvss = "n/a" if result.max_cvss is None else f"{result.max_cvss:.1f}"
    lines = [
        "# supply-gate",
        "",
        f"**Status:** {status}",
        f"**Threshold:** CVSS ≥ {result.threshold:.1f}",
        f"**Max CVSS:** {max_cvss}",
        f"**Findings:** {len(result.findings)} "
        f"({len(result.failing)} failing, {len(result.allowlisted)} allowlisted)",
        "",
    ]
    if sbom_path is not None:
        lines.extend([f"**SBOM:** `{sbom_path}`", ""])
    lines.extend(_table("Failing", result.failing))
    lines.extend(_table("Allowlisted", result.allowlisted))
    remaining = [
        item
        for item in result.findings
        if item not in result.failing and item not in result.allowlisted
    ]
    lines.extend(_table("Other findings", remaining))
    if result.passed:
        lines.append("Policy passed: no non-allowlisted finding meets the CVSS threshold.")
    else:
        lines.append(
            "Policy failed: at least one finding has CVSS at or above the threshold."
        )
    lines.append("")
    return "\n".join(lines)


def _table(title: str, findings: tuple[Finding, ...] | list[Finding]) -> list[str]:
    lines = [f"## {title}", ""]
    if not findings:
        lines.extend(["_None._", ""])
        return lines
    lines.extend(
        [
            "| ID | Package | CVSS | Source |",
            "| --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        score = "—" if finding.cvss is None else f"{finding.cvss:.1f}"
        pkg = f"{finding.package}@{finding.version}" if finding.package else "—"
        lines.append(
            f"| `{finding.vuln_id}` | `{pkg}` | {score} | {finding.source} |"
        )
    lines.append("")
    return lines
