from __future__ import annotations

from pathlib import Path

import pytest

from supply_gate.errors import SbomError
from supply_gate.sbom import generate_sbom


def test_pyproject_and_requirements(tmp_path: Path, fixtures: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        (fixtures / "pyproject_sample.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        (fixtures / "requirements.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    bom = generate_sbom(tmp_path)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["name"] == "sample-app"
    assert bom["metadata"]["component"]["version"] == "1.2.3"
    names = {item["name"] for item in bom["components"]}
    assert "requests" in names
    assert "click" in names
    assert "httpx" in names
    assert "pytest" in names
    assert "orjson" in names
    assert "rich" in names
    assert "urllib3" in names
    assert "flask" in names
    requests = next(item for item in bom["components"] if item["name"] == "requests")
    assert requests["version"] == "2.31.0"
    assert requests["purl"] == "pkg:pypi/requests@2.31.0"


def test_empty_project_still_valid(tmp_path: Path) -> None:
    bom = generate_sbom(tmp_path)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["metadata"]["component"]["name"] == tmp_path.name
    assert bom["components"] == []


def test_invalid_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("??? not toml", encoding="utf-8")
    with pytest.raises(SbomError, match="cannot parse"):
        generate_sbom(tmp_path)


def test_self_repo_sbom() -> None:
    root = Path(__file__).resolve().parents[1]
    bom = generate_sbom(root)
    assert bom["metadata"]["component"]["name"] == "supply-gate"
    names = {item["name"] for item in bom["components"]}
    assert "pytest" in names
    assert "ruff" in names
