"""Policy gate before scanner dispatch. Persistence and queueing come later."""
from datetime import UTC, datetime

from vantage.domain.models import ApprovedScope, Asset, ScanReport, ScanRequest
from vantage.scanning.registry import ScannerRegistry


class ScopeDenied(PermissionError):
    pass


class ScanCoordinator:
    def __init__(self, registry: ScannerRegistry) -> None:
        self.registry = registry

    def run(self, asset: Asset, scope: ApprovedScope, request: ScanRequest) -> ScanReport:
        if request.organization_id != asset.organization_id:
            raise ScopeDenied("Request organization does not own the asset")
        if request.asset_id != asset.id:
            raise ScopeDenied("Request references a different asset")
        if scope.organization_id != asset.organization_id or scope.asset_id != asset.id:
            raise ScopeDenied("Approved scope does not authorize this asset")
        if scope.expires_at and scope.expires_at <= datetime.now(UTC):
            raise ScopeDenied("Approved scope has expired")
        if request.scope_id != scope.id:
            raise ScopeDenied("Request references a different authorization record")
        if request.scanner_id not in scope.allowed_scanner_ids:
            raise ScopeDenied("Scanner is not permitted by this scope")

        scanner = self.registry.get(request.scanner_id)
        if request.active_checks_requested:
            if not scope.allow_active_checks:
                raise ScopeDenied("Active checks are not approved for this scope")
            if not scanner.supports_active_checks:
                raise ScopeDenied("Selected scanner does not support active checks")

        report = scanner.scan(asset, request)
        if report.organization_id != asset.organization_id or report.asset_id != asset.id:
            raise RuntimeError("Scanner returned a report outside the authorized tenant/asset")
        if report.scanner_id != scanner.scanner_id:
            raise RuntimeError("Scanner returned an unexpected scanner identity")
        return report
