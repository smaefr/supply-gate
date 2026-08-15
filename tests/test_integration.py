from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from supply_gate.audit import run_pip_audit

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    not os.environ.get("SUPPLY_GATE_INTEGRATION"),
    reason="set SUPPLY_GATE_INTEGRATION=1 to run live pip-audit (needs network)",
)
def test_live_pip_audit(tmp_path: Path) -> None:
    if shutil.which("pip-audit") is None:
        pytest.skip("pip-audit not installed")
    (tmp_path / "requirements.txt").write_text("# no pinned deps\n", encoding="utf-8")
    findings = run_pip_audit(tmp_path)
    assert isinstance(findings, list)
