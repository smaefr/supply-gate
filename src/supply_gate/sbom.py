from __future__ import annotations

import re
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from supply_gate import __version__
from supply_gate.errors import SbomError

_SPEC_SPLIT = re.compile(r"\s*(===|==|!=|<=|>=|~=|<|>)\s*")


def generate_sbom(project: Path) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document from declared Python dependencies."""
    name, version = _project_identity(project)
    components = _dedupe(
        [
            *_components_from_pyproject(project / "pyproject.toml"),
            *_components_from_requirements(project / "requirements.txt"),
        ]
    )
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "smae",
                    "name": "supply-gate",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": name,
                "version": version,
            },
        },
        "components": components,
    }


def _project_identity(project: Path) -> tuple[str, str]:
    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        data = _load_toml(pyproject)
        meta = data.get("project") or {}
        name = str(meta.get("name") or project.name)
        version = str(meta.get("version") or "0.0.0")
        poetry = (data.get("tool") or {}).get("poetry") or {}
        if name == project.name and poetry.get("name"):
            name = str(poetry["name"])
        if version == "0.0.0" and poetry.get("version"):
            version = str(poetry["version"])
        return name, version
    return project.name, "0.0.0"


def _components_from_pyproject(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    data = _load_toml(path)
    declared: list[str] = []
    project = data.get("project") or {}
    declared.extend(project.get("dependencies") or [])
    extras = project.get("optional-dependencies") or {}
    if isinstance(extras, dict):
        for group in extras.values():
            if isinstance(group, list):
                declared.extend(group)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    components = [_component_from_requirement(item) for item in declared]
    components.extend(_components_from_poetry(poetry.get("dependencies") or {}))
    return [item for item in components if item is not None]


def _components_from_poetry(deps: Any) -> list[dict[str, Any]]:
    if not isinstance(deps, dict):
        return []
    found: list[dict[str, Any]] = []
    for name, spec in deps.items():
        if str(name).lower() == "python":
            continue
        version = None
        if isinstance(spec, str):
            version = spec.lstrip("^~=<>!")
        elif isinstance(spec, dict):
            raw = spec.get("version")
            if isinstance(raw, str):
                version = raw.lstrip("^~=<>!")
        component = _pypi_component(str(name), version)
        if component:
            found.append(component)
    return found


def _components_from_requirements(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    found: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        component = _component_from_requirement(raw)
        if component:
            found.append(component)
    return found


def _component_from_requirement(raw: str) -> dict[str, Any] | None:
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    line = line.split(";", 1)[0].strip()
    if "[" in line and "]" in line:
        name, rest = line.split("[", 1)
        line = name + rest.split("]", 1)[-1]
    name, version = _split_name_version(line)
    return _pypi_component(name, version)


def _split_name_version(line: str) -> tuple[str, str | None]:
    parts = _SPEC_SPLIT.split(line, maxsplit=1)
    name = parts[0].strip()
    if len(parts) >= 3 and parts[1] == "==":
        return name, parts[2].strip().split()[0] or None
    if len(parts) >= 3:
        return name, parts[2].strip().split()[0] or None
    return name, None


def _pypi_component(name: str, version: str | None) -> dict[str, Any] | None:
    normalized = _normalize_name(name)
    if not normalized:
        return None
    purl = f"pkg:pypi/{normalized}"
    if version:
        purl = f"{purl}@{version}"
    component: dict[str, Any] = {
        "type": "library",
        "name": normalized,
        "purl": purl,
        "bom-ref": purl,
    }
    if version:
        component["version"] = version
    return component


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _dedupe(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str | None]] = set()
    unique: list[dict[str, Any]] = []
    for component in components:
        key = (str(component.get("name")), component.get("version"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    return unique


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SbomError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise SbomError(f"{path} did not contain a TOML table")
    return loaded
