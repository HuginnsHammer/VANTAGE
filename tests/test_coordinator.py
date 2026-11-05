from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from vantage.domain.models import ApprovedScope, Asset, AssetKind, ScanReport, ScanRequest, ScanState
from vantage.scanning.coordinator import ScanCoordinator, ScopeDenied
from vantage.scanning.registry import ScannerRegistry


class StubScanner:
    scanner_id = "stub"
    display_name = "Stub scanner"
    supports_active_checks = False

    def scan(self, asset, request):
        return ScanReport(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            scanner_id=self.scanner_id,
            state=ScanState.COMPLETED,
        )


def setup_case():
    org, user = uuid4(), uuid4()
    asset = Asset(organization_id=org, kind=AssetKind.LOCAL_WORKSPACE, canonical_value="/workspace")
    scope = ApprovedScope(
        organization_id=org,
        asset_id=asset.id,
        approved_by=user,
        authorization_reference="approved-test-scope",
        allowed_scanner_ids=frozenset({"stub"}),
    )
    request = ScanRequest(
        organization_id=org, asset_id=asset.id, scope_id=scope.id,
        scanner_id="stub", requested_by=user,
    )
    registry = ScannerRegistry()
    registry.register(StubScanner())
    return asset, scope, request, ScanCoordinator(registry)


def test_authorized_scan_is_dispatched():
    asset, scope, request, coordinator = setup_case()
    assert coordinator.run(asset, scope, request).state == ScanState.COMPLETED


def test_wrong_asset_is_denied():
    asset, scope, request, coordinator = setup_case()
    other = Asset(
        organization_id=asset.organization_id,
        kind=AssetKind.DOMAIN,
        canonical_value="example.test",
    )
    with pytest.raises(ScopeDenied):
        coordinator.run(other, scope, request)


def test_request_asset_mismatch_is_denied():
    asset, scope, request, coordinator = setup_case()
    mismatched = request.model_copy(update={"asset_id": uuid4()})
    with pytest.raises(ScopeDenied, match="different asset"):
        coordinator.run(asset, scope, mismatched)


def test_expired_scope_is_denied():
    asset, scope, request, coordinator = setup_case()
    expired = scope.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(days=1)})
    with pytest.raises(ScopeDenied):
        coordinator.run(asset, expired, request)


def test_active_checks_require_explicit_approval():
    asset, scope, request, coordinator = setup_case()
    active = request.model_copy(update={"active_checks_requested": True})
    with pytest.raises(ScopeDenied):
        coordinator.run(asset, scope, active)
