"""Normalize CloudSentry JSON output without upgrading uncertain results to verified."""
import re
from uuid import UUID

from vantage.adapters.redaction import redact_sensitive_text
from vantage.domain.models import (
    Confidence,
    Evidence,
    Finding,
    FindingSeverity,
    ScanReport,
    ScanState,
)

_SEVERITIES = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}
# CloudSentry derives this 24-character, lowercase hex identity from SHA-256.
_FINGERPRINT = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_MAX_DIAGNOSTICS = 100


def _append_diagnostic(items: list[str], message: str) -> None:
    if len(items) < _MAX_DIAGNOSTICS:
        items.append(message)


def import_cloudsentry_report(
    payload: dict, *, organization_id: UUID, asset_id: UUID
) -> ScanReport:
    if not isinstance(payload, dict):
        return ScanReport(
            organization_id=organization_id,
            asset_id=asset_id,
            scanner_id="cloudsentry",
            state=ScanState.FAILED,
            errors=("CloudSentry returned a non-object report.",),
        )

    status = str(payload.get("status", "error")).lower()
    state = {
        "ok": ScanState.COMPLETED,
        "partial": ScanState.PARTIAL,
        "error": ScanState.FAILED,
    }.get(status, ScanState.FAILED)
    errors: list[str] = []
    warnings: list[str] = []
    raw_errors = payload.get("errors", [])
    if isinstance(raw_errors, list):
        for item in raw_errors[:_MAX_DIAGNOSTICS]:
            if isinstance(item, dict):
                _append_diagnostic(
                    errors,
                    redact_sensitive_text(item.get("message", "Unknown scan error"))[:1000],
                )
            else:
                _append_diagnostic(errors, "CloudSentry returned a malformed error entry.")
        if len(raw_errors) > _MAX_DIAGNOSTICS:
            _append_diagnostic(errors, "Additional scanner errors omitted.")
    else:
        _append_diagnostic(errors, "CloudSentry errors field is not a list.")

    raw_warnings = payload.get("warnings", [])
    if isinstance(raw_warnings, list):
        warnings.extend(
            redact_sensitive_text(item)[:1000]
            for item in raw_warnings[:_MAX_DIAGNOSTICS]
        )
        if len(raw_warnings) > _MAX_DIAGNOSTICS:
            warnings.append("Additional scanner warnings omitted.")
    else:
        _append_diagnostic(warnings, "CloudSentry warnings field is not a list.")

    raw_files_scanned = payload.get("files_scanned", 0)
    if (
        isinstance(raw_files_scanned, bool)
        or not isinstance(raw_files_scanned, int)
        or raw_files_scanned < 0
    ):
        files_scanned = 0
        _append_diagnostic(errors, "CloudSentry files_scanned must be a non-negative integer.")
    else:
        files_scanned = raw_files_scanned

    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []
        _append_diagnostic(errors, "CloudSentry findings field is not a list.")

    findings = []
    seen_fingerprints: set[str] = set()
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            _append_diagnostic(errors, f"Skipped malformed finding entry at index {index}.")
            continue
        raw_fingerprint = item.get("fingerprint")
        fingerprint = raw_fingerprint.lower() if isinstance(raw_fingerprint, str) else ""
        if not _FINGERPRINT.fullmatch(fingerprint):
            _append_diagnostic(
                errors,
                f"Skipped finding at index {index}: fingerprint must be 24 hexadecimal characters.",
            )
            continue
        if fingerprint in seen_fingerprints:
            _append_diagnostic(errors, f"Skipped duplicate finding fingerprint at index {index}.")
            continue
        seen_fingerprints.add(fingerprint)

        confidence = str(item.get("confidence", "unknown")).lower()
        confidence_value = (
            Confidence(confidence)
            if confidence in Confidence._value2member_map_
            else Confidence.UNKNOWN
        )
        evidence = Evidence(
            kind="static_configuration",
            summary=redact_sensitive_text(
                item.get("evidence", "Evidence not supplied")
            )[:2000],
            location=redact_sensitive_text(item.get("file_path", ""))[:2048] or None,
            source_scanner="cloudsentry",
            # The imported text has passed through the baseline sanitizer. This
            # flag does not imply that every possible secret format is detected.
            redacted=True,
        )
        findings.append(
            Finding(
                organization_id=organization_id,
                asset_id=asset_id,
                scanner_id="cloudsentry",
                rule_id=str(item.get("rule_id", "unknown"))[:160],
                title=redact_sensitive_text(
                    item.get("title", "Untitled finding")
                )[:300],
                description=redact_sensitive_text(item.get("description", ""))[:4000],
                severity=_SEVERITIES.get(
                    str(item.get("severity", "")).lower(), FindingSeverity.UNKNOWN
                ),
                confidence=confidence_value,
                evidence=(evidence,),
                remediation=redact_sensitive_text(
                    item.get("remediation", "")
                )[:4000] or None,
                fingerprint=fingerprint,
                verified=False,
            )
        )

    if status not in {"ok", "partial", "error"}:
        _append_diagnostic(errors, "CloudSentry returned an unrecognized scan status.")
    if state == ScanState.FAILED and not errors:
        _append_diagnostic(errors, "CloudSentry reported an error without diagnostics.")
    if state in {ScanState.COMPLETED, ScanState.PARTIAL} and files_scanned == 0:
        _append_diagnostic(errors, "CloudSentry did not examine any files.")
        state = ScanState.FAILED
    elif errors and state == ScanState.COMPLETED:
        state = ScanState.PARTIAL

    return ScanReport(
        organization_id=organization_id,
        asset_id=asset_id,
        scanner_id="cloudsentry",
        state=state,
        findings=tuple(findings),
        errors=tuple(errors),
        warnings=tuple(warnings),
        files_or_targets_examined=files_scanned,
    )
