from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from supply_gate.cvss import extract_cvss
from supply_gate.errors import TrivyError, TrivyNotFoundError
from supply_gate.models import Finding

MISSING_MESSAGE = (
    "trivy binary not found on PATH; install Trivy "
    "(https://aquasecurity.github.io/trivy/latest/getting-started/installation/)"
)


def load_trivy_file(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TrivyError(f"cannot read Trivy JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TrivyError(f"invalid Trivy JSON in {path}: {exc}") from exc
    return findings_from_trivy(data)


def findings_from_trivy(data: Any) -> list[Finding]:
    if not isinstance(data, dict):
        raise TrivyError("Trivy JSON must be an object")
    results = data.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise TrivyError("Trivy 'Results' must be a list")
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if isinstance(vuln, dict):
                findings.append(_finding_from_vuln(vuln))
    return findings


def _finding_from_vuln(vuln: dict[str, Any]) -> Finding:
    vuln_id = str(vuln.get("VulnerabilityID") or vuln.get("id") or "UNKNOWN")
    package = str(vuln.get("PkgName") or vuln.get("PkgID") or "")
    version = str(vuln.get("InstalledVersion") or "")
    extra_ids = vuln.get("CweIDs") or []
    aliases: list[str] = []
    identifiers = vuln.get("Identifiers") or []
    if isinstance(identifiers, list):
        for ident in identifiers:
            if isinstance(ident, dict) and ident.get("Value"):
                aliases.append(str(ident["Value"]))
            elif isinstance(ident, str):
                aliases.append(ident)
    if isinstance(extra_ids, list):
        aliases.extend(str(item) for item in extra_ids)
    title = str(vuln.get("Title") or "")
    description = str(vuln.get("Description") or title)
    severity = vuln.get("Severity")
    fix = vuln.get("FixedVersion")
    return Finding(
        vuln_id=vuln_id,
        package=package,
        version=version,
        cvss=extract_cvss(vuln),
        source="trivy",
        title=title or vuln_id,
        description=description,
        aliases=tuple(dict.fromkeys(aliases)),
        severity=str(severity) if severity is not None else None,
        fix_version=str(fix) if fix else None,
    )


def run_trivy_image(image: str, *, on_missing: str = "fail") -> list[Finding] | None:
    """Scan a container image. Returns None when Trivy is missing and on_missing=skip."""
    if on_missing not in {"fail", "skip"}:
        raise TrivyError("on_missing must be 'fail' or 'skip'")
    binary = shutil.which("trivy")
    if binary is None:
        if on_missing == "skip":
            return None
        raise TrivyNotFoundError(MISSING_MESSAGE)
    cmd = [binary, "image", "--format", "json", "--quiet", "--timeout", "5m", image]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TrivyError(f"failed to execute trivy: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise TrivyError(
            f"trivy exited {completed.returncode}" + (f": {detail}" if detail else "")
        )
    raw = completed.stdout.strip() or "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrivyError(f"trivy produced invalid JSON: {exc}") from exc
    return findings_from_trivy(data)
