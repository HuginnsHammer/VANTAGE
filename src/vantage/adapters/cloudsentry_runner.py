"""Bounded local process adapter for the CloudSentry CLI.

The executable path is trusted operator configuration. User-controlled paths are
passed as individual argv values; no shell is involved.
"""
import json
import subprocess
from pathlib import Path
from uuid import UUID

from vantage.adapters.cloudsentry import import_cloudsentry_report
from vantage.domain.models import Asset, AssetKind, ScanReport, ScanRequest


class CloudSentryExecutionError(RuntimeError):
    pass


class CloudSentryProcessScanner:
    scanner_id = "cloudsentry"
    display_name = "CloudSentry local IaC and container auditor"
    supports_active_checks = False

    def __init__(self, executable: str = "cloudsentry", timeout_seconds: int = 300) -> None:
        if not 1 <= timeout_seconds <= 1800:
            raise ValueError("timeout_seconds must be between 1 and 1800")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def scan(self, asset: Asset, request: ScanRequest) -> ScanReport:
        if asset.kind != AssetKind.LOCAL_WORKSPACE:
            raise ValueError("CloudSentry only accepts local_workspace assets")
        workspace = Path(asset.canonical_value)
        if not workspace.is_absolute():
            raise ValueError("Workspace path must be absolute")
        if not workspace.exists() or not (workspace.is_file() or workspace.is_dir()):
            raise ValueError("Workspace must be an existing regular file or directory")
        if workspace.is_symlink():
            raise ValueError("Workspace root cannot be a symbolic link")

        if workspace.is_dir():
            for candidate in workspace.rglob("*"):
                if candidate.is_symlink():
                    raise ValueError(
                        f"Workspace contains a symbolic link; refusing ambiguous scope: {candidate}"
                    )

        command = [
            self.executable,
            "scan",
            str(workspace),
            "--format",
            "json",
        ]
        try:
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise CloudSentryExecutionError(
                f"CloudSentry exceeded its {self.timeout_seconds}-second execution limit"
            ) from exc
        except OSError as exc:
            raise CloudSentryExecutionError(f"Could not start CloudSentry: {exc}") from exc

        if completed.returncode not in (0, 1, 2):
            detail = completed.stderr.strip()[:1000] or "No diagnostic was provided"
            raise CloudSentryExecutionError(
                f"CloudSentry exited unexpectedly ({completed.returncode}): {detail}"
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            detail = completed.stderr.strip()[:1000] or "CloudSentry returned invalid JSON"
            raise CloudSentryExecutionError(detail) from exc
        if not isinstance(payload, dict):
            raise CloudSentryExecutionError("CloudSentry returned a non-object JSON report")

        report = import_cloudsentry_report(
            payload,
            organization_id=asset.organization_id,
            asset_id=asset.id,
        )
        if completed.returncode == 2 and report.state.value == "completed":
            report = report.model_copy(update={"state": "partial" if report.files_or_targets_examined else "failed"})
        return report
