import json
from uuid import uuid4

from vantage.cli import main
from vantage.domain.models import (
    Confidence,
    Finding,
    FindingSeverity,
    ScanReport,
    ScanState,
)


def test_scanners_list(capsys):
    assert main(["scanners", "list"]) == 0
    output = capsys.readouterr().out
    assert "cloudsentry" in output
    assert "ACTIVE CHECKS" in output


def test_workspace_scan_requires_exact_confirmation(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    result = main(
        [
            "scan",
            "workspace",
            str(workspace),
            "--authorization-reference",
            "ENG-1234",
        ]
    )

    assert result == 2
    assert "no scan was started" in capsys.readouterr().err


def test_workspace_scan_exports_report_without_overwriting(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    destination = tmp_path / "report.json"
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: f"AUTHORIZE {workspace.resolve()}"
    )
    report = ScanReport(
        organization_id=uuid4(),
        asset_id=uuid4(),
        scanner_id="cloudsentry",
        state=ScanState.COMPLETED,
        files_or_targets_examined=4,
    )

    class FakeCoordinator:
        def __init__(self, _registry):
            pass

        def run(self, _asset, _scope, _request):
            return report

    monkeypatch.setattr("vantage.cli.ScanCoordinator", FakeCoordinator)

    result = main(
        [
            "scan",
            "workspace",
            str(workspace),
            "--authorization-reference",
            "ENG-1234",
            "--output",
            str(destination),
        ]
    )

    assert result == 0
    assert destination.exists()
    assert '"state": "completed"' in destination.read_text()
    assert "Report written" in capsys.readouterr().err

    assert main(
        [
            "scan",
            "workspace",
            str(workspace),
            "--authorization-reference",
            "ENG-1234",
            "--output",
            str(destination),
        ]
    ) == 2


def test_cli_ledger_persists_and_deduplicates_across_scans(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "state" / "findings.sqlite3"
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: f"AUTHORIZE {workspace.resolve()}"
    )

    class FakeCoordinator:
        def __init__(self, _registry):
            pass

        def run(self, asset, _scope, _request):
            finding = Finding(
                organization_id=asset.organization_id,
                asset_id=asset.id,
                scanner_id="cloudsentry",
                rule_id="CS-TF-002",
                title="Public ingress",
                description="Ingress is exposed.",
                severity=FindingSeverity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint="f" * 32,
            )
            return ScanReport(
                organization_id=asset.organization_id,
                asset_id=asset.id,
                scanner_id="cloudsentry",
                state=ScanState.COMPLETED,
                findings=(finding,),
            )

    monkeypatch.setattr("vantage.cli.ScanCoordinator", FakeCoordinator)
    args = [
        "scan", "workspace", str(workspace),
        "--authorization-reference", "ENG-1234",
        "--ledger", str(ledger),
    ]
    assert main(args) == 0
    capsys.readouterr()
    assert main(args) == 0
    second_output = capsys.readouterr().err
    assert "0 new" in second_output
    assert "1 reopened" not in second_output

    assert main(["findings", "list", "--ledger", str(ledger)]) == 0
    records = json.loads(capsys.readouterr().out)
    assert len(records) == 1
    assert records[0]["occurrence_count"] == 2
    assert records[0]["status"] == "open"
