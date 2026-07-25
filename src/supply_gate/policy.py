from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from supply_gate.models import Finding, PolicyResult

DEFAULT_THRESHOLD = 8.0


def parse_allowlist(value: str | None = None, path: Path | None = None) -> list[str]:
    """Split a comma/newline list and optionally a file (`#` comments allowed)."""
    ids: list[str] = []
    if value:
        ids.extend(_split_ids(value))
    if path is not None:
        text = path.read_text(encoding="utf-8")
        ids.extend(_split_ids(text))
    return ids


def _split_ids(text: str) -> list[str]:
    found: list[str] = []
    for raw_line in text.replace(",", "\n").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            found.append(line)
    return found


def evaluate(
    findings: Sequence[Finding] | Iterable[Finding],
    *,
    threshold: float = DEFAULT_THRESHOLD,
    allowlist: Sequence[str] | None = None,
) -> PolicyResult:
    """Fail when any non-allowlisted finding has CVSS >= threshold.

    Findings with no numeric CVSS never fail the gate.
    """
    items = tuple(findings)
    allowed = {item.upper() for item in (allowlist or []) if item}
    failing: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in items:
        if finding.all_ids() & allowed:
            suppressed.append(finding)
            continue
        if finding.cvss is not None and finding.cvss >= threshold:
            failing.append(finding)
    scores = [item.cvss for item in items if item.cvss is not None]
    failing_scores = [item.cvss for item in failing if item.cvss is not None]
    return PolicyResult(
        threshold=threshold,
        findings=items,
        failing=tuple(failing),
        allowlisted=tuple(suppressed),
        passed=not failing,
        max_cvss=max(scores) if scores else None,
        max_failing_cvss=max(failing_scores) if failing_scores else None,
        allowlist=tuple(allowed),
    )
