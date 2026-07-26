from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from supply_gate import __version__
from supply_gate.audit import run_pip_audit
from supply_gate.errors import SupplyGateError
from supply_gate.loaders import findings_from_json_path
from supply_gate.models import Finding
from supply_gate.policy import DEFAULT_THRESHOLD, evaluate, parse_allowlist
from supply_gate.report import (
    SUPPORTED_FORMATS,
    render,
    write_artifacts,
    write_json,
    write_text,
)
from supply_gate.sbom import generate_sbom
from supply_gate.trivy import run_trivy_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supply-gate",
        description="Supply-chain gates: pip-audit, CycloneDX SBOM, Trivy, CVSS policy.",
    )
    parser.add_argument("--version", action="version", version=f"supply-gate {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="run pip-audit (or parse saved JSON)")
    audit.add_argument("--path", type=Path, default=Path("."), help="Python project path")
    audit.add_argument(
        "--from-file",
        type=Path,
        help="parse pip-audit JSON instead of invoking pip-audit",
    )
    audit.add_argument("--output", type=Path, help="write findings JSON")
    _add_format(audit, default="json")

    sbom = subparsers.add_parser("sbom", help="emit CycloneDX JSON for the Python project")
    sbom.add_argument("--path", type=Path, default=Path("."), help="Python project path")
    sbom.add_argument("--output", type=Path, default=Path("sbom.cdx.json"))

    image = subparsers.add_parser("image", help="scan a container image with Trivy")
    image.add_argument("--image", required=True, help="image name or tarball reference")
    image.add_argument(
        "--from-file",
        type=Path,
        help="parse Trivy JSON instead of invoking trivy",
    )
    image.add_argument(
        "--on-missing-trivy",
        choices=("fail", "skip"),
        default="fail",
        help="when trivy is not on PATH (default: fail)",
    )
    image.add_argument("--output", type=Path, help="write findings JSON")
    _add_format(image, default="json")

    policy = subparsers.add_parser("policy", help="evaluate CVSS against a threshold")
    policy.add_argument(
        "--input",
        dest="inputs",
        type=Path,
        action="append",
        required=True,
        help="pip-audit or Trivy JSON (repeatable)",
    )
    _add_policy_args(policy)
    _add_artifact_args(policy)
    _add_format(policy, default="markdown")

    run = subparsers.add_parser("run", help="audit + sbom + optional image + policy")
    run.add_argument("--path", type=Path, default=Path("."), help="Python project path")
    run.add_argument("--image", help="container image to scan (optional)")
    run.add_argument("--audit-json", type=Path, help="parse pip-audit JSON instead of running it")
    run.add_argument("--trivy-json", type=Path, help="parse Trivy JSON instead of running it")
    run.add_argument(
        "--on-missing-trivy",
        choices=("fail", "skip"),
        default="fail",
        help="when --image is set and trivy is missing (default: fail)",
    )
    run.add_argument("--sbom-out", type=Path, default=Path("sbom.cdx.json"))
    _add_policy_args(run)
    _add_artifact_args(run)
    _add_format(run, default="markdown")
    return parser


def _add_format(parser: argparse.ArgumentParser, *, default: str) -> None:
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default=default,
        help=f"stdout format (default: {default})",
    )


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"fail if CVSS >= this value (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument("--allowlist", default="", help="comma-separated vuln IDs")
    parser.add_argument("--allowlist-file", type=Path, help="file of vuln IDs")


def _add_artifact_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sarif-out", type=Path, default=Path("supply-gate.sarif"))
    parser.add_argument("--summary-out", type=Path, default=Path("supply-gate.md"))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return _dispatch(args)
    except SupplyGateError as exc:
        print(f"supply-gate: {exc}", file=sys.stderr)
        return 2


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "sbom":
        return _cmd_sbom(args)
    if args.command == "image":
        return _cmd_image(args)
    if args.command == "policy":
        return _cmd_policy(args)
    if args.command == "run":
        return _cmd_run(args)
    raise SupplyGateError(f"unknown command: {args.command}")


def _cmd_audit(args: argparse.Namespace) -> int:
    if args.from_file:
        findings = findings_from_json_path(args.from_file)
    else:
        findings = run_pip_audit(args.path)
    payload = [item.to_dict() for item in findings]
    text = json.dumps(payload, indent=2) + "\n"
    if args.output:
        write_text(args.output, text)
    if args.format == "json":
        sys.stdout.write(text)
    else:
        result = evaluate(findings)
        sys.stdout.write(render(result, args.format))
    return 0


def _cmd_sbom(args: argparse.Namespace) -> int:
    document = generate_sbom(args.path)
    write_json(args.output, document)
    sys.stdout.write(json.dumps(document, indent=2) + "\n")
    return 0


def _cmd_image(args: argparse.Namespace) -> int:
    if args.from_file:
        findings = findings_from_json_path(args.from_file)
    else:
        scanned = run_trivy_image(args.image, on_missing=args.on_missing_trivy)
        if scanned is None:
            print("supply-gate: trivy not found; skipping image scan", file=sys.stderr)
            findings = []
        else:
            findings = scanned
    payload = [item.to_dict() for item in findings]
    text = json.dumps(payload, indent=2) + "\n"
    if args.output:
        write_text(args.output, text)
    if args.format == "json":
        sys.stdout.write(text)
    else:
        sys.stdout.write(render(evaluate(findings), args.format))
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    findings: list[Finding] = []
    for path in args.inputs:
        findings.extend(findings_from_json_path(path))
    return _finish_policy(findings, args, sbom_path=None)


def _cmd_run(args: argparse.Namespace) -> int:
    if args.audit_json:
        findings = findings_from_json_path(args.audit_json)
    else:
        findings = run_pip_audit(args.path)
    document = generate_sbom(args.path)
    write_json(args.sbom_out, document)
    if args.trivy_json:
        findings.extend(findings_from_json_path(args.trivy_json))
    elif args.image:
        scanned = run_trivy_image(args.image, on_missing=args.on_missing_trivy)
        if scanned is None:
            print("supply-gate: trivy not found; skipping image scan", file=sys.stderr)
        else:
            findings.extend(scanned)
    return _finish_policy(findings, args, sbom_path=args.sbom_out)


def _finish_policy(
    findings: list[Finding],
    args: argparse.Namespace,
    *,
    sbom_path: Path | None,
) -> int:
    allowlist = parse_allowlist(args.allowlist or None, args.allowlist_file)
    result = evaluate(findings, threshold=args.threshold, allowlist=allowlist)
    write_artifacts(
        result,
        sarif_out=args.sarif_out,
        summary_out=args.summary_out,
        sbom_path=sbom_path,
    )
    sys.stdout.write(render(result, args.format, sbom_path=sbom_path))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
