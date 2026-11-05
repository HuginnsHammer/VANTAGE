"""Default scanner registry for the first supported local engine."""
from vantage.adapters.cloudsentry_runner import CloudSentryProcessScanner
from vantage.scanning.registry import ScannerRegistry


def build_default_registry(
    *, cloudsentry_executable: str = "cloudsentry", timeout_seconds: int = 300
) -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(
        CloudSentryProcessScanner(
            executable=cloudsentry_executable,
            timeout_seconds=timeout_seconds,
        )
    )
    return registry
