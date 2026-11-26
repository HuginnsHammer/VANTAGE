import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from vantage.adapters.cloudsentry_runner import (
    CloudSentryExecutionError,
    CloudSentryProcessScanner,
)
from vantage.domain.models import Asset, AssetKind, ScanRequest, ScanState


def make_case(tmp_path: Path):
    workspace = tmp_path / "workspace with spaces"
    workspace.mkdir()
    (workspace / "main.tf").write_text('resource "x" "y" {}', encoding="utf-8")
    org, user = uuid4(), uuid4()
    asset = Asset(
        organization_id=org,
        kind=AssetKind.LOCAL_WORKSPACE,
        canonical_value=str(workspace),
    )
    request = ScanRequest(
        organization_id=org,
        asset_id=asset.id,
        scope_id=uuid4(),
        scanner_id="cloudsentry",
        requested_by=user,
    )
    return asset, request, workspace


def write_executable(tmp_path: Path, source: str) -> str:
    executable = tmp_path / "fake-cloudsentry"
    executable.write_text(f"#!{sys.executable}\n{source}\n", encoding="utf-8")
    executable.chmod(0o755)
    return str(executable)


def test_runner_invokes_cli_without_shell_and_normalizes_report(tmp_path):
    asset, request, workspace = make_case(tmp_path)
    payload = {
        "status": "ok",
        "files_scanned": 1,
        "findings": [{
            "rule_id": "CS-TF-002",
            "title": "World-open ingress",
            "description": "Ingress accepts all IPv4 addresses.",
            "severity": "high",
            "confidence": "high",
            "file_path": str(workspace / "main.tf"),
            "evidence": 'cidr_blocks = ["0.0.0.0/0"]',
            "remediation": "Restrict the CIDR range.",
            "fingerprint": "f" * 24,
        }],
        "errors": [],
        "warnings": [],
    }
    script = (
        "import sys\n"
        f"expected_workspace = {str(workspace)!r}\n"
        "if sys.argv[1:] != ['scan', expected_workspace, '--format', 'json']:\n"
        "    raise SystemExit(9)\n"
        f"sys.stdout.write({json.dumps(json.dumps(payload))})\n"
        "raise SystemExit(1)"
    )
    executable = write_executable(tmp_path, script)
    report = CloudSentryProcessScanner(executable=executable).scan(asset, request)

    assert report.state == ScanState.COMPLETED
    assert len(report.findings) == 1
    assert report.findings[0].verified is False


def test_runner_rejects_symlinked_workspace_contents(tmp_path):
    asset, request, workspace = make_case(tmp_path)
    target = tmp_path / "outside.tf"
    target.write_text('resource "x" "z" {}', encoding="utf-8")
    (workspace / "linked.tf").symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        CloudSentryProcessScanner(executable="/does/not/need/to/exist").scan(asset, request)


def test_runner_enforces_timeout_and_terminates_process_group(tmp_path):
    asset, request, _ = make_case(tmp_path)
    executable = write_executable(tmp_path, "import time\ntime.sleep(5)")
    scanner = CloudSentryProcessScanner(executable=executable, timeout_seconds=1)

    with pytest.raises(CloudSentryExecutionError, match="execution limit"):
        scanner.scan(asset, request)


def test_runner_rejects_output_over_the_combined_byte_limit(tmp_path):
    asset, request, _ = make_case(tmp_path)
    executable = write_executable(
        tmp_path,
        "import sys\nsys.stdout.write('x' * 4096)",
    )
    scanner = CloudSentryProcessScanner(
        executable=executable,
        max_output_bytes=1024,
    )

    with pytest.raises(CloudSentryExecutionError, match="output exceeded"):
        scanner.scan(asset, request)


def test_runner_redacts_secrets_from_unexpected_exit_diagnostics(tmp_path):
    asset, request, _ = make_case(tmp_path)
    secret = "do-not-store-this-scanner-password"
    script = (
        "import sys\n"
        f"sys.stderr.write('password = {json.dumps(secret)}')\n"
        "raise SystemExit(3)"
    )
    executable = write_executable(tmp_path, script)

    with pytest.raises(CloudSentryExecutionError) as captured:
        CloudSentryProcessScanner(executable=executable).scan(asset, request)

    assert secret not in str(captured.value)
    assert "[REDACTED]" in str(captured.value)
