"""Operator-facing CLI for explicitly authorized local workspace assessments."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from vantage.domain.models import ApprovedScope, Asset, AssetKind, ScanReport, ScanRequest
from vantage.scanning.builtins import build_default_registry
from vantage.scanning.coordinator import ScanCoordinator


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vantage",
        description="Evidence-led security exposure management",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scanners = commands.add_parser("scanners", help="Inspect available scanner engines")
    scanners.add_subparsers(dest="scanners_command", required=True).add_parser(
        "list", help="List registered scanner engines"
    )

    scan = commands.add_parser("scan", help="Run an explicitly authorized local assessment")
    scan_commands = scan.add_subparsers(dest="scan_command", required=True)
    workspace = scan_commands.add_parser(
        "workspace", help="Assess a local IaC/container workspace with CloudSentry"
    )
    workspace.add_argument("path", type=Path, help="Existing local file or directory")
    workspace.add_argument(
        "--authorization-reference",
        required=True,
        help="Ticket, engagement, or written approval reference authorizing this workspace scan",
    )
    workspace.add_argument(
        "--output",
        type=Path,
        help="Write JSON report to a new file; refuses to overwrite an existing file",
    )
    workspace.add_argument(
        "--cloudsentry-executable",
        default="cloudsentry",
        help="Trusted operator-configured CloudSentry executable (default: cloudsentry)",
    )
    workspace.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Maximum scanner runtime in seconds (1-1800; default: 300)",
    )
    return parser


def _list_scanners() -> int:
    registry = build_default_registry()
    entries = registry.list()
    if not entries:
        print("No scanner engines are registered.")
        return 0
    print("SCANNER ID     NAME                                      ACTIVE CHECKS")
    for scanner_id, name, active in entries:
        print(f"{scanner_id:<14} {name:<41} {'yes' if active else 'no'}")
    return 0


def _write_report(report: ScanReport, destination: Path | None) -> None:
    serialized = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if destination is None:
        sys.stdout.write(serialized)
        return
    target = destination.expanduser()
    if not target.parent.exists() or not target.parent.is_dir():
        raise ValueError(f"Output directory does not exist: {target.parent}")
    with target.open("x", encoding="utf-8") as stream:
        stream.write(serialized)
    print(f"Report written to {target}", file=sys.stderr)


def _scan_workspace(args: argparse.Namespace) -> int:
    workspace = args.path.expanduser()
    if not workspace.exists():
        raise ValueError(f"Workspace does not exist: {workspace}")
    if workspace.is_symlink():
        raise ValueError("Workspace root cannot be a symbolic link")
    resolved = workspace.resolve(strict=True)
    if not (resolved.is_file() or resolved.is_dir()):
        raise ValueError("Workspace must be a regular file or directory")
    if not args.authorization_reference.strip():
        raise ValueError("An authorization reference is required")
    if not 1 <= args.timeout <= 1800:
        raise ValueError("--timeout must be between 1 and 1800 seconds")

    print(
        "VANTAGE local workspace assessment\n"
        f"Target: {resolved}\n"
        f"Authorization reference: {args.authorization_reference}\n"
        "Mode: local static IaC/container analysis (no network probing)\n"
        "\nOnly proceed if you own this workspace or have explicit permission to assess it.",
        file=sys.stderr,
    )
    expected = f"AUTHORIZE {resolved}"
    confirmation = input(f"Type exactly '{expected}' to continue: ").strip()
    if confirmation != expected:
        print("Authorization confirmation did not match; no scan was started.", file=sys.stderr)
        return 2

    organization_id = uuid4()
    operator_id = uuid4()
    asset = Asset(
        organization_id=organization_id,
        kind=AssetKind.LOCAL_WORKSPACE,
        canonical_value=str(resolved),
        display_name=resolved.name,
    )
    scope = ApprovedScope(
        organization_id=organization_id,
        asset_id=asset.id,
        approved_by=operator_id,
        authorization_reference=args.authorization_reference.strip(),
        allowed_scanner_ids=frozenset({"cloudsentry"}),
        allow_active_checks=False,
    )
    request = ScanRequest(
        organization_id=organization_id,
        asset_id=asset.id,
        scope_id=scope.id,
        scanner_id="cloudsentry",
        requested_by=operator_id,
    )
    coordinator = ScanCoordinator(
        build_default_registry(
            cloudsentry_executable=args.cloudsentry_executable,
            timeout_seconds=args.timeout,
        )
    )
    report = coordinator.run(asset, scope, request)
    _write_report(report, args.output)
    print(
        f"Assessment {report.state.value}: {len(report.findings)} finding(s), "
        f"{report.files_or_targets_examined} file(s) examined.",
        file=sys.stderr,
    )
    return 0 if report.state.value == "completed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scanners":
            return _list_scanners()
        if args.command == "scan" and args.scan_command == "workspace":
            return _scan_workspace(args)
    except (
        OSError,
        ValueError,
        LookupError,
        PermissionError,
        RuntimeError,
        ValidationError,
    ) as exc:
        print(f"vantage: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
