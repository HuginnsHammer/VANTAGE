from uuid import uuid4

import pytest

from vantage.adapters.cloudsentry import import_cloudsentry_report
from vantage.domain.models import FindingSeverity, ScanState


def test_partial_cloudsentry_scan_stays_partial_and_unverified():
    report = import_cloudsentry_report(
        {
            "status": "partial",
            "files_scanned": 3,
            "findings": [
                {
                    "rule_id": "CS-TF-002",
                    "title": "World-open ingress",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": "cidr_blocks = [0.0.0.0/0]",
                    "file_path": "main.tf",
                    "remediation": "Restrict CIDR.",
                    "fingerprint": "A" * 24,
                }
            ],
            "errors": [{"message": "A file could not be parsed"}],
        },
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.PARTIAL
    assert report.findings[0].severity == FindingSeverity.HIGH
    assert report.findings[0].verified is False
    assert report.findings[0].fingerprint == "a" * 24
    assert report.errors


def test_malformed_fingerprint_downgrades_complete_scan():
    report = import_cloudsentry_report(
        {
            "status": "ok",
            "files_scanned": 1,
            "findings": [{"rule_id": "CS-X", "fingerprint": "short"}],
        },
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.PARTIAL
    assert report.findings == ()
    assert "fingerprint" in report.errors[0]


@pytest.mark.parametrize("fingerprint", ["g" * 24, "a" * 64])
def test_noncanonical_fingerprint_downgrades_complete_scan(fingerprint):
    report = import_cloudsentry_report(
        {
            "status": "ok",
            "files_scanned": 1,
            "findings": [{"rule_id": "CS-X", "fingerprint": fingerprint}],
        },
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.PARTIAL
    assert report.findings == ()
    assert report.errors


def test_duplicate_fingerprints_downgrade_complete_scan_and_keep_first():
    fingerprint = "b" * 24
    report = import_cloudsentry_report(
        {
            "status": "ok",
            "files_scanned": 1,
            "findings": [
                {"rule_id": "CS-X", "title": "First", "fingerprint": fingerprint},
                {"rule_id": "CS-Y", "title": "Duplicate", "fingerprint": fingerprint},
            ],
        },
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.PARTIAL
    assert len(report.findings) == 1
    assert "duplicate" in report.errors[0]


def test_complete_scan_requires_positive_file_count():
    report = import_cloudsentry_report(
        {"status": "ok", "files_scanned": 0, "findings": []},
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.FAILED
    assert report.files_or_targets_examined == 0
    assert report.errors


def test_malformed_finding_entry_downgrades_complete_scan():
    report = import_cloudsentry_report(
        {"status": "ok", "files_scanned": 1, "findings": [None]},
        organization_id=uuid4(),
        asset_id=uuid4(),
    )
    assert report.state == ScanState.PARTIAL
    assert report.findings == ()
    assert report.errors


def test_scanner_text_is_redacted_before_entering_the_report():
    secrets = {
        "password": "do-not-store-this-password",
        "aws": "AKIA1234567890ABCDEF",
        "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "bearer": "bearer-token-value-123456",
        "private_key": "PRIVATE-KEY-MATERIAL-DO-NOT-STORE",
        "url_password": "database-password-do-not-store",
        "error": "error-secret-do-not-store",
    }
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{secrets['private_key']}\n"
        "-----END RSA PRIVATE KEY-----"
    )
    report = import_cloudsentry_report(
        {
            "status": "partial",
            "files_scanned": 1,
            "findings": [
                {
                    "rule_id": "CS-SECRET-001",
                    "title": "Credential exposure",
                    "description": f"Found token {secrets['github']} and JWT {secrets['jwt']}",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": "\n".join(
                        [
                            f'password = "{secrets["password"]}"',
                            f"Observed AWS key {secrets['aws']}",
                            f"Authorization: Bearer {secrets['bearer']}",
                            pem,
                        ]
                    ),
                    "file_path": "main.tf",
                    "remediation": "Use token = var.database_password and rotate credentials.",
                    "fingerprint": "c" * 24,
                }
            ],
            "errors": [{"message": f"Could not parse password = {secrets['error']}"}],
            "warnings": [
                f"Connection: postgres://scanner:{secrets['url_password']}@db.example.test/vantage"
            ],
        },
        organization_id=uuid4(),
        asset_id=uuid4(),
    )

    serialized = report.model_dump_json()
    for secret in secrets.values():
        assert secret not in serialized
    assert "[REDACTED" in serialized
    assert "var.database_password" in serialized
    assert report.findings[0].evidence[0].redacted is True
