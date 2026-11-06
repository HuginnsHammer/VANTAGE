from uuid import uuid4

import pytest

from vantage.domain.models import (
    Confidence, Finding, FindingSeverity, ScanReport, ScanState,
)
from vantage.intelligence.lifecycle import (
    FindingStatus, SQLiteFindingLedger, calculate_risk_score,
)


def make_report(org, asset, *, state=ScanState.COMPLETED, fingerprints=("a" * 32,)):
    findings = tuple(
        Finding(
            organization_id=org, asset_id=asset, scanner_id="cloudsentry",
            rule_id="CS-TF-002", title="Public ingress",
            description="Ingress is open to the world.",
            severity=FindingSeverity.HIGH, confidence=Confidence.HIGH,
            fingerprint=fingerprint,
        )
        for fingerprint in fingerprints
    )
    return ScanReport(
        organization_id=org, asset_id=asset, scanner_id="cloudsentry",
        state=state, findings=findings,
    )


def test_completed_scan_creates_stable_record_and_repeat_increments_count(tmp_path):
    org, asset = uuid4(), uuid4()
    ledger = SQLiteFindingLedger(tmp_path / "ledger.sqlite3")
    first = ledger.apply_report(make_report(org, asset))
    record = ledger.list_findings(organization_id=org, asset_id=asset)[0]
    second = ledger.apply_report(make_report(org, asset))
    repeated = ledger.get(record.id)

    assert first["new"] == 1
    assert second["updated"] == 1
    assert repeated.id == record.id
    assert repeated.occurrence_count == 2
    assert repeated.status == FindingStatus.OPEN
    assert len(ledger.events(record.id)) == 2


def test_partial_scan_never_resolves_missing_findings(tmp_path):
    org, asset = uuid4(), uuid4()
    ledger = SQLiteFindingLedger(tmp_path / "ledger.sqlite3")
    ledger.apply_report(make_report(org, asset, fingerprints=("a" * 32, "b" * 32)))

    result = ledger.apply_report(
        make_report(org, asset, state=ScanState.PARTIAL, fingerprints=("a" * 32,))
    )
    records = ledger.list_findings(organization_id=org, asset_id=asset)

    assert result["absence_resolution_applied"] is False
    assert result["resolved"] == 0
    assert {record.status for record in records} == {FindingStatus.OPEN}


def test_completed_clean_scan_resolves_and_later_observation_reopens(tmp_path):
    org, asset = uuid4(), uuid4()
    ledger = SQLiteFindingLedger(tmp_path / "ledger.sqlite3")
    ledger.apply_report(make_report(org, asset))
    record = ledger.list_findings(organization_id=org, asset_id=asset)[0]

    clean = make_report(org, asset, fingerprints=())
    assert ledger.apply_report(clean)["resolved"] == 1
    assert ledger.get(record.id).status == FindingStatus.RESOLVED

    reopened = ledger.apply_report(make_report(org, asset))
    assert reopened["reopened"] == 1
    assert ledger.get(record.id).status == FindingStatus.REOPENED


def test_manual_disposition_requires_reason_and_is_audited(tmp_path):
    org, asset = uuid4(), uuid4()
    ledger = SQLiteFindingLedger(tmp_path / "ledger.sqlite3")
    ledger.apply_report(make_report(org, asset))
    record = ledger.list_findings(organization_id=org, asset_id=asset)[0]

    with pytest.raises(ValueError, match="reason"):
        ledger.set_status(record.id, FindingStatus.ACCEPTED_RISK, reason=" ")

    updated = ledger.set_status(
        record.id, FindingStatus.ACCEPTED_RISK, reason="Documented compensating control"
    )
    assert updated.status == FindingStatus.ACCEPTED_RISK
    assert ledger.events(record.id)[-1].event_type == "analyst_disposition"


def test_records_survive_reopening_the_database(tmp_path):
    org, asset = uuid4(), uuid4()
    path = tmp_path / "ledger.sqlite3"
    SQLiteFindingLedger(path).apply_report(make_report(org, asset))
    reopened = SQLiteFindingLedger(path)
    assert len(reopened.list_findings(organization_id=org)) == 1


def test_risk_score_is_bounded_and_criticality_is_validated():
    assert calculate_risk_score(
        FindingSeverity.CRITICAL, Confidence.CONFIRMED, asset_criticality=2.0
    ) == 100
    with pytest.raises(ValueError, match="asset_criticality"):
        calculate_risk_score(
            FindingSeverity.HIGH, Confidence.HIGH, asset_criticality=3.0
        )


def test_report_cannot_import_cross_tenant_finding(tmp_path):
    org, asset = uuid4(), uuid4()
    report = make_report(org, asset)
    invalid = report.model_copy(
        update={"findings": (report.findings[0].model_copy(update={"asset_id": uuid4()}),)}
    )
    with pytest.raises(ValueError, match="outside its tenant"):
        SQLiteFindingLedger(tmp_path / "ledger.sqlite3").apply_report(invalid)
