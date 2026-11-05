"""Normalize CloudSentry JSON output without upgrading uncertain results to verified."""
from uuid import UUID
from vantage.domain.models import Confidence, Evidence, Finding, FindingSeverity, ScanReport, ScanState

_SEVERITIES = {
    "critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}


def import_cloudsentry_report(payload: dict, *, organization_id: UUID, asset_id: UUID) -> ScanReport:
    status = str(payload.get("status", "error")).lower()
    state = {"ok": ScanState.COMPLETED, "partial": ScanState.PARTIAL,
             "error": ScanState.FAILED}.get(status, ScanState.FAILED)
    findings = []
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("fingerprint", ""))
        if len(fingerprint) < 16:
            continue
        confidence = str(item.get("confidence", "unknown")).lower()
        confidence_value = Confidence(confidence) if confidence in Confidence._value2member_map_ else Confidence.UNKNOWN
        evidence = Evidence(
            kind="static_configuration",
            summary=str(item.get("evidence", "Evidence not supplied"))[:2000],
            location=str(item.get("file_path", ""))[:2048] or None,
            source_scanner="cloudsentry",
            redacted=True,
        )
        findings.append(Finding(
            organization_id=organization_id, asset_id=asset_id, scanner_id="cloudsentry",
            rule_id=str(item.get("rule_id", "unknown"))[:160],
            title=str(item.get("title", "Untitled finding"))[:300],
            description=str(item.get("description", ""))[:4000],
            severity=_SEVERITIES.get(str(item.get("severity", "")).lower(), FindingSeverity.UNKNOWN),
            confidence=confidence_value, evidence=(evidence,),
            remediation=str(item.get("remediation", ""))[:4000] or None,
            fingerprint=fingerprint, verified=False,
        ))
    errors = tuple(str(item.get("message", "Unknown scan error"))[:1000]
                   for item in payload.get("errors", []) if isinstance(item, dict))
    warnings = tuple(str(item)[:1000] for item in payload.get("warnings", []))
    if errors and state == ScanState.COMPLETED:
        state = ScanState.PARTIAL
    return ScanReport(
        organization_id=organization_id, asset_id=asset_id, scanner_id="cloudsentry",
        state=state, findings=tuple(findings), errors=errors, warnings=warnings,
        files_or_targets_examined=int(payload.get("files_scanned", 0) or 0),
    )
