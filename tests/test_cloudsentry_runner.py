import json
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from vantage.adapters.cloudsentry_runner import (
    CloudSentryExecutionError,
    CloudSentryProcessScanner,
)
from vantage.domain.models import Asset, AssetKind, ScanRequest, ScanState


def make_case(tmp_path: Path):
    workspace = tmp_path / "workspace"
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


def test_runner_invokes_cli_without_shell_and_normalizes_report(monkeypatch, tmp_path):
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
            "fingerprint": "f" * 64,
        }],
        "errors": [],
        "warnings": [],
    }
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 1, json.dumps(payload), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    report = CloudSentryProcessScanner().scan(asset, request)

    assert report.state == ScanState.COMPLETED
    assert len(report.findings) == 1
    assert report.findings[0].verified is False
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["timeout"] == 300
    assert seen["command"][-2:] == ["--format", "json"]


def test_runner_rejects_symlinked_workspace_contents(monkeypatch, tmp_path):
    asset, request, workspace = make_case(tmp_path)
    target = tmp_path / "outside.tf"
    target.write_text('resource "x" "z" {}', encoding="utf-8")
    (workspace / "linked.tf").symlink_to(target)

    def unexpected_run(*args, **kwargs):
        raise AssertionError("scanner must not run for a symlinked workspace")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    with pytest.raises(ValueError, match="symbolic link"):
        CloudSentryProcessScanner().scan(asset, request)


def test_runner_enforces_timeout(monkeypatch, tmp_path):
    asset, request, _ = make_case(tmp_path)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(CloudSentryExecutionError, match="execution limit"):
        CloudSentryProcessScanner(timeout_seconds=5).scan(asset, request)


def test_runner_redacts_secrets_from_unexpected_exit_diagnostics(monkeypatch, tmp_path):
    asset, request, _ = make_case(tmp_path)
    secret = "do-not-store-this-scanner-password"

    def failed_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 3, "", f'password = "{secret}"'
        )

    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(CloudSentryExecutionError) as captured:
        CloudSentryProcessScanner().scan(asset, request)

    assert secret not in str(captured.value)
    assert "[REDACTED]" in str(captured.value)
