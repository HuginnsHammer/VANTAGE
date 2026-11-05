from uuid import uuid4
from vantage.adapters.cloudsentry import import_cloudsentry_report
from vantage.domain.models import FindingSeverity, ScanState


def test_partial_cloudsentry_scan_stays_partial_and_unverified():
    report = import_cloudsentry_report({
        "status": "partial", "files_scanned": 3,
        "findings": [{"rule_id": "CS-TF-002", "title": "World-open ingress",
          "severity": "high", "confidence": "high", "evidence": "cidr_blocks = [0.0.0.0/0]",
          "file_path": "main.tf", "remediation": "Restrict CIDR.", "fingerprint": "a" * 64}],
        "errors": [{"message": "A file could not be parsed"}],
    }, organization_id=uuid4(), asset_id=uuid4())
    assert report.state == ScanState.PARTIAL
    assert report.findings[0].severity == FindingSeverity.HIGH
    assert report.findings[0].verified is False
    assert report.errors


def test_malformed_fingerprint_is_not_given_an_invented_identity():
    report = import_cloudsentry_report({"status": "ok",
        "findings": [{"rule_id": "CS-X", "fingerprint": "short"}]},
        organization_id=uuid4(), asset_id=uuid4())
    assert report.findings == ()
