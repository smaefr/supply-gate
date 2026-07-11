from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """A single vulnerability reported by pip-audit or Trivy."""

    vuln_id: str
    package: str
    version: str
    cvss: float | None
    source: str
    title: str = ""
    description: str = ""
    aliases: tuple[str, ...] = ()
    severity: str | None = None
    fix_version: str | None = None

    def all_ids(self) -> frozenset[str]:
        values = {self.vuln_id, *self.aliases}
        return frozenset(item.upper() for item in values if item)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.vuln_id,
            "package": self.package,
            "version": self.version,
            "cvss": self.cvss,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "fix_version": self.fix_version,
        }


@dataclass(frozen=True)
class PolicyResult:
    threshold: float
    findings: tuple[Finding, ...]
    failing: tuple[Finding, ...]
    allowlisted: tuple[Finding, ...]
    passed: bool
    max_cvss: float | None
    max_failing_cvss: float | None = None
    allowlist: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "threshold": self.threshold,
            "max_cvss": self.max_cvss,
            "max_failing_cvss": self.max_failing_cvss,
            "allowlist": list(self.allowlist),
            "failing": [item.to_dict() for item in self.failing],
            "allowlisted": [item.to_dict() for item in self.allowlisted],
            "findings": [item.to_dict() for item in self.findings],
        }
