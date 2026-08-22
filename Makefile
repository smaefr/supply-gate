VENV_PYTHON := $(wildcard .venv/bin/python)
PYTHON ?= $(if $(VENV_PYTHON),$(VENV_PYTHON),python3)
PIP ?= $(PYTHON) -m pip

.PHONY: test check lint install

install:
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests

# Local Trivy filesystem scan via Docker.
# Skips cleanly when Docker is not installed — see README.md.
# This is not a substitute for `supply-gate run` (pip-audit + policy).
# Image scan: docker build -t supply-gate:local . && \
#   docker run --rm aquasec/trivy:latest image supply-gate:local
check:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "make check: docker is unavailable; skipping aquasec/trivy."; \
		echo "Install Docker to scan this tree with Trivy locally."; \
	else \
		docker run --rm -v "$(CURDIR):/src:ro" aquasec/trivy:latest fs \
			--scanners vuln --severity HIGH,CRITICAL /src; \
	fi
