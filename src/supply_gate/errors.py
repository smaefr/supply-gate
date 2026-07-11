from __future__ import annotations


class SupplyGateError(Exception):
    """User-facing CLI error (exit status 2)."""


class AuditError(SupplyGateError):
    """pip-audit could not be run or its output could not be parsed."""


class TrivyError(SupplyGateError):
    """Trivy could not be run or its output could not be parsed."""


class TrivyNotFoundError(TrivyError):
    """Trivy binary is not on PATH."""


class SbomError(SupplyGateError):
    """SBOM generation failed."""
