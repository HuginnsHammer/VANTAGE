"""Scanner extension contract."""
from typing import Protocol
from vantage.domain.models import Asset, ScanReport, ScanRequest


class Scanner(Protocol):
    scanner_id: str
    display_name: str
    supports_active_checks: bool

    def scan(self, asset: Asset, request: ScanRequest) -> ScanReport:
        """Run only checks declared by the scanner's reviewed policy."""
        ...
