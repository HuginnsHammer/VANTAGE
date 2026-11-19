"""Default scanner registry for the first supported local engine."""
from vantage.adapters.cloudsentry_runner import (
    DEFAULT_MAX_OUTPUT_BYTES,
    CloudSentryProcessScanner,
)
from vantage.scanning.registry import ScannerRegistry


def build_default_registry(
    *,
    cloudsentry_executable: str = "cloudsentry",
    timeout_seconds: int = 300,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(
        CloudSentryProcessScanner(
            executable=cloudsentry_executable,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    )
    return registry
