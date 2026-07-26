from __future__ import annotations

import json
import os
from pathlib import Path

from supply_gate.models import PolicyResult
from supply_gate.sarif import to_sarif
from supply_gate.summary import render_markdown

SUPPORTED_FORMATS = ("markdown", "json", "sarif")


def render(result: PolicyResult, fmt: str, *, sbom_path: Path | None = None) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2) + "\n"
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2) + "\n"
    if fmt == "markdown":
        return render_markdown(result, sbom_path=sbom_path)
    raise ValueError(f"unsupported format: {fmt}")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, document: object) -> None:
    write_text(path, json.dumps(document, indent=2) + "\n")


def write_artifacts(
    result: PolicyResult,
    *,
    sarif_out: Path | None = None,
    summary_out: Path | None = None,
    github_summary: bool = True,
    sbom_path: Path | None = None,
) -> None:
    markdown = render_markdown(result, sbom_path=sbom_path)
    if sarif_out is not None:
        write_json(sarif_out, to_sarif(result))
    if summary_out is not None:
        write_text(summary_out, markdown)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary and step:
        with open(step, "a", encoding="utf-8") as handle:
            handle.write(markdown)
            if not markdown.endswith("\n"):
                handle.write("\n")
