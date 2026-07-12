from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from supply_gate.cvss import extract_cvss
from supply_gate.errors import AuditError
from supply_gate.models import Finding


def load_pip_audit_file(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditError(f"cannot read pip-audit JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AuditError(f"invalid pip-audit JSON in {path}: {exc}") from exc
    return findings_from_pip_audit(data)


def findings_from_pip_audit(data: Any) -> list[Finding]:
    if isinstance(data, dict):
        deps = data.get("dependencies", [])
    elif isinstance(data, list):
        deps = data
    else:
        raise AuditError("pip-audit JSON must be an object or a list")
    if not isinstance(deps, list):
        raise AuditError("pip-audit 'dependencies' must be a list")
    findings: list[Finding] = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or dep.get("package") or "")
        version = str(dep.get("version") or "")
        vulns = dep.get("vulns") or dep.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if isinstance(vuln, dict):
                findings.append(_finding_from_vuln(name, version, vuln))
    return findings


def _finding_from_vuln(package: str, version: str, vuln: dict[str, Any]) -> Finding:
    vuln_id = str(vuln.get("id") or vuln.get("vulnerability_id") or "UNKNOWN")
    aliases_raw = vuln.get("aliases") or []
    aliases = tuple(str(item) for item in aliases_raw) if isinstance(aliases_raw, list) else ()
    fixes = vuln.get("fix_versions") or []
    fix_version = str(fixes[0]) if isinstance(fixes, list) and fixes else None
    title = str(vuln.get("title") or "")
    description = str(vuln.get("description") or title)
    severity = vuln.get("severity")
    return Finding(
        vuln_id=vuln_id,
        package=package,
        version=version,
        cvss=extract_cvss(vuln),
        source="pip-audit",
        title=title or vuln_id,
        description=description,
        aliases=aliases,
        severity=str(severity) if severity is not None else None,
        fix_version=fix_version,
    )


def run_pip_audit(project: Path) -> list[Finding]:
    """Invoke pip-audit. Exit status 1 (vulns found) is success for parsing."""
    binary = shutil.which("pip-audit")
    if binary is None:
        raise AuditError("pip-audit not found on PATH; pip install pip-audit")
    cmd = [binary, "--format", "json", "--progress-spinner", "off"]
    requirements = project / "requirements.txt"
    if requirements.is_file():
        cmd.extend(["-r", str(requirements)])
    else:
        cmd.extend(["--project", str(project)])
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise AuditError(f"failed to execute pip-audit: {exc}") from exc
    if completed.returncode not in (0, 1):
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AuditError(
            f"pip-audit exited {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    raw = completed.stdout.strip() or "[]"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuditError(f"pip-audit produced invalid JSON: {exc}") from exc
    return findings_from_pip_audit(data)
