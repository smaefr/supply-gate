"""Supply-chain gates: pip-audit, CycloneDX SBOM, Trivy, CVSS policy."""

from supply_gate.models import Finding
from supply_gate.policy import DEFAULT_THRESHOLD, PolicyResult, evaluate

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_THRESHOLD",
    "Finding",
    "PolicyResult",
    "evaluate",
    "__version__",
]
