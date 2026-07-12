from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from supply_gate.audit import findings_from_pip_audit
from supply_gate.errors import SupplyGateError
from supply_gate.models import Finding
from supply_gate.trivy import findings_from_trivy


def is_trivy_document(data: Any) -> bool:
    return isinstance(data, dict) and "Results" in data


def findings_from_json_data(data: Any) -> list[Finding]:
    if is_trivy_document(data):
        return findings_from_trivy(data)
    return findings_from_pip_audit(data)


def findings_from_json_path(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SupplyGateError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SupplyGateError(f"invalid JSON in {path}: {exc}") from exc
    return findings_from_json_data(data)
