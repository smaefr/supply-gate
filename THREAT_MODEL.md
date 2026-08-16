# Threat model

supply-gate is a **policy gate** in front of two untrusted inputs: Python
packages (PyPI / a lockfile or `pyproject.toml`) and container images. It does
not make those inputs trusted. It fails a CI job when a scanner reports a high
CVSS, and it records what it saw (SARIF, job summary, CycloneDX SBOM).

Trust boundary: **scanner output and this repo's code are in-scope; upstream
packages, images, and third-party installers are not.**

## STRIDE

| ID | Category | Asset / scenario | What goes wrong | Mitigation in this project | Residual risk |
| --- | --- | --- | --- | --- | --- |
| T1 | Tampering | Compromised or hijacked PyPI dependency | Malicious code is installed in CI or production | `pip-audit` on the project path; CycloneDX SBOM for what was declared; CVSS ≥ threshold fails the job | Audits lag disclosures; malicious packages with no CVE sail through |
| T2 | Tampering | Compromised container image or base layer | Untrusted image content runs in deploy | Optional `trivy image` scan; action installs Trivy and **requires** it when `image` is set | Default CI in this repo skips image scan; OS CVEs in public bases are noisy |
| T3 | Tampering | Action supply chain | A tagged composite action, `pip install`, or the Trivy `install.sh` is replaced | Action is the repo itself (`uses: ./` when dogfooding); pin consumers to a commit SHA; MIT-licensed small CLI with **no runtime PyPI deps** | Official Trivy installer is still a remote script; `pip-audit` is still a third-party tool |
| T4 | Spoofing | Forged scanner JSON / identity of a package | Policy parses attacker-controlled JSON as if it were pip-audit/Trivy | Live `run` invokes local binaries; `--audit-json` / `--trivy-json` are for tests and replay | Replay flags will happily trust a file you pass |
| T5 | Information disclosure | Secrets in scan logs or SBOM | Dependency names, versions, and vuln text leak in SARIF / summaries | Summaries list package + vuln id + CVSS only; no credentials in fixtures | Verbose scanner stderr can still print environment details |
| T6 | Denial of service | Gate blocks every build | Unbounded fail-closed (Trivy missing) or fail-open (skip) | `--on-missing-trivy fail` in CI when an image is requested; `skip` only for local/unit paths; `make check` documents skip-if-no-docker | Mis-set `skip` in a workflow silently drops image coverage |
| T7 | Elevation of privilege | Allowlist abuse | A CVSS 9.8 id is added to `--allowlist` so the job stays green | Allowlist matches explicit IDs and aliases only; SARIF marks suppressions; job summary still lists them | Reviewers may rubber-stamp allowlist changes |
| T8 | Repudiation | “The scan was clean” | Findings exist but were not attached to the PR | Always write SARIF + markdown; append `GITHUB_STEP_SUMMARY` when present; CI uploads artifacts `if: always()` | Consumers can drop the upload step |
| T9 | Information disclosure / Tampering | False negatives | Scanner has no CVSS, outdated DB, or a vuln class it does not cover | Findings without a numeric CVSS **do not fail** (documented); fixtures lock parser behavior; SBOM still emitted for later review | Missing score ≠ safe; advisory-only or zero-day deps are invisible to the threshold |
| T10 | Elevation of privilege | Running this action on `pull_request_target` with untrusted workflow | A PR could change `action.yml` / Python and run in a privileged context | Document: consume as a **pinned** action from this repo; do not checkout untrusted Actions from a fork into a privileged workflow | Operators can still wire it unsafely |

## In scope

- Parsing pip-audit JSON and Trivy JSON.
- Numeric CVSS comparison against a threshold.
- Allowlist of vuln IDs.
- CycloneDX generation from `pyproject.toml` / `requirements.txt` (declared deps, not a resolved lock).
- Exit codes, SARIF, and the job summary.

## Out of scope

- Exploit verification or proof-of-concept payloads.
- Signing, SLSA provenance, or attestations.
- Malware analysis of packages that have no published CVE.
- Guaranteeing Trivy or OSV databases are complete.

## False negatives (T9)

The gate fails closed on **tool failure** (missing `pip-audit`; missing Trivy when an image scan is required). It fails **open** on “no CVSS in the record”: a HIGH/CRITICAL row without a score will not trip `--threshold 8.0`. Treat empty scores as a review item, not a pass.

Unit tests use vendored JSON (CVSS 9.8 and 4.0) so policy behavior does not depend on the network or a Trivy install.
