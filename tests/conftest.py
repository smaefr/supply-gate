from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def pip_audit_mixed(fixtures: Path) -> Path:
    return fixtures / "pip_audit_mixed.json"


@pytest.fixture
def trivy_mixed(fixtures: Path) -> Path:
    return fixtures / "trivy_mixed.json"
