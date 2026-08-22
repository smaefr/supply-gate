# Minimal image so this repo can be scanned with Trivy when desired.
# Default CI runs dependency audit + SBOM only; pass `image:` to the action
# to include a container scan (base-image OS CVEs may fail the CVSS gate).
FROM python:3.12-alpine
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir .
CMD ["supply-gate", "--help"]
