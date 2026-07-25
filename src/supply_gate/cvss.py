from __future__ import annotations

from typing import Any

_NUMERIC_KEYS = (
    "cvss",
    "cvss_score",
    "cvssScore",
    "score",
    "baseScore",
    "V3Score",
    "V2Score",
    "V3score",
)

_NESTED_KEYS = (
    "CVSS",
    "cvss_v3",
    "cvssV3",
    "cvss_v2",
    "advisory",
)


def _as_score(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def extract_cvss(payload: Any) -> float | None:
    """Return the highest numeric CVSS found in a scanner record."""
    if payload is None:
        return None
    direct = _as_score(payload)
    if direct is not None:
        return direct
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            scores = [score for item in payload if (score := extract_cvss(item)) is not None]
            return max(scores) if scores else None
        return None

    scores: list[float] = []
    for key in _NUMERIC_KEYS:
        score = _as_score(payload.get(key))
        if score is not None:
            scores.append(score)
    for key in _NESTED_KEYS:
        nested = payload.get(key)
        if nested is None:
            continue
        score = extract_cvss(nested)
        if score is not None:
            scores.append(score)
    # Trivy: CVSS.nvd.V3Score, CVSS.redhat.V3Score, …
    extra = payload.get("CVSS")
    if isinstance(extra, dict):
        for source in extra.values():
            score = extract_cvss(source)
            if score is not None:
                scores.append(score)
    return max(scores) if scores else None
