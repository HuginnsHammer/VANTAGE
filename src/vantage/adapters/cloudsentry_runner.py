"""Bounded local process adapter for the CloudSentry CLI.

The executable path is trusted operator configuration. User-controlled paths are
passed as individual argv values; no shell is involved. Output is streamed under
a combined byte limit and the process group is terminated on timeout/overflow.

This is process-level containment, not an OS sandbox or a CPU/memory limit.
"""
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

from vantage.adapters.cloudsentry import import_cloudsentry_report
from vantage.adapters.redaction import redact_sensitive_text
from vantage.domain.models import Asset, AssetKind, ScanReport, ScanRequest, ScanState

DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_ALLOWED_OUTPUT_BYTES = 64 * 1024 * 1024


class CloudSentryExecutionError(RuntimeError):
    pass


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Stop the scanner and descendants started in its isolated process group."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if process.poll() is None:
            process.kill()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_bounded_process(
    command: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Capture stdout/stderr without allowing either stream to grow without bound."""
    if os.name != "posix":
        raise CloudSentryExecutionError(
            "Bounded CloudSentry execution currently requires a POSIX worker"
        )

    process = subprocess.Popen(
        command,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total_output_bytes = 0
    deadline = time.monotonic() + timeout_seconds

    try:
        if process.stdout is None or process.stderr is None:
            raise CloudSentryExecutionError("Could not capture CloudSentry output")

        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, data=stdout)
        selector.register(process.stderr, selectors.EVENT_READ, data=stderr)

        while selector.get_map():
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                _terminate_process_group(process)
                raise subprocess.TimeoutExpired(command, timeout_seconds)

            for key, _ in selector.select(timeout=min(remaining_seconds, 0.25)):
                remaining_bytes = max_output_bytes - total_output_bytes + 1
                try:
                    chunk = os.read(key.fileobj.fileno(), min(65536, remaining_bytes))
                except BlockingIOError:
                    continue

                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue

                total_output_bytes += len(chunk)
                if total_output_bytes > max_output_bytes:
                    _terminate_process_group(process)
                    raise CloudSentryExecutionError(
                        "CloudSentry output exceeded the "
                        f"{max_output_bytes}-byte combined stdout/stderr limit"
                    )
                key.data.extend(chunk)

        returncode = process.wait()
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    finally:
        selector.close()
        if process.poll() is None:
            _terminate_process_group(process)
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        if process.stderr is not None and not process.stderr.closed:
            process.stderr.close()


class CloudSentryProcessScanner:
    scanner_id = "cloudsentry"
    display_name = "CloudSentry local IaC and container auditor"
    supports_active_checks = False

    def __init__(
        self,
        executable: str = "cloudsentry",
        timeout_seconds: int = 300,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        if not 1 <= timeout_seconds <= 1800:
            raise ValueError("timeout_seconds must be between 1 and 1800")
        if not 1024 <= max_output_bytes <= _MAX_ALLOWED_OUTPUT_BYTES:
            raise ValueError("max_output_bytes must be between 1024 and 67108864")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def scan(self, asset: Asset, request: ScanRequest) -> ScanReport:
        if asset.kind != AssetKind.LOCAL_WORKSPACE:
            raise ValueError("CloudSentry only accepts local_workspace assets")
        if request.asset_id != asset.id or request.organization_id != asset.organization_id:
            raise ValueError("Scan request does not match the supplied asset")
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

        command = [self.executable, "scan", str(workspace), "--format", "json"]
        try:
            completed = _run_bounded_process(
                command,
                timeout_seconds=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
            )
        except subprocess.TimeoutExpired as exc:
            raise CloudSentryExecutionError(
                f"CloudSentry exceeded its {self.timeout_seconds}-second execution limit"
            ) from exc
        except CloudSentryExecutionError:
            raise
        except OSError as exc:
            raise CloudSentryExecutionError(f"Could not execute CloudSentry: {exc}") from exc

        if completed.returncode not in (0, 1, 2):
            detail = redact_sensitive_text(completed.stderr.strip())[:1000]
            detail = detail or "No diagnostic was provided"
            raise CloudSentryExecutionError(
                f"CloudSentry exited unexpectedly ({completed.returncode}): {detail}"
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            detail = redact_sensitive_text(completed.stderr.strip())[:1000]
            detail = detail or "CloudSentry returned invalid JSON"
            raise CloudSentryExecutionError(detail) from exc
        if not isinstance(payload, dict):
            raise CloudSentryExecutionError("CloudSentry returned a non-object JSON report")

        report = import_cloudsentry_report(
            payload,
            organization_id=asset.organization_id,
            asset_id=asset.id,
        )
        if completed.returncode == 2 and report.state == ScanState.COMPLETED:
            state = ScanState.PARTIAL if report.files_or_targets_examined else ScanState.FAILED
            report = report.model_copy(update={"state": state})
        return report
