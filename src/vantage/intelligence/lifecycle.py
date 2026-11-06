"""Durable finding lifecycle and deterministic risk prioritization.

The SQLite ledger is a local deployment adapter. Its interface is intentionally
small so a PostgreSQL repository can replace it without changing lifecycle policy.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from vantage.domain.models import (
    Confidence,
    Finding,
    FindingSeverity,
    ScanReport,
    ScanState,
)

_SEVERITY_WEIGHT = {
    FindingSeverity.CRITICAL: 100,
    FindingSeverity.HIGH: 75,
    FindingSeverity.MEDIUM: 50,
    FindingSeverity.LOW: 25,
    FindingSeverity.INFO: 10,
    FindingSeverity.UNKNOWN: 15,
}
_CONFIDENCE_FACTOR = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.85,
    Confidence.MEDIUM: 0.65,
    Confidence.LOW: 0.4,
    Confidence.UNKNOWN: 0.25,
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def calculate_risk_score(
    severity: FindingSeverity,
    confidence: Confidence,
    *,
    asset_criticality: float = 1.0,
) -> int:
    """Return a transparent 0-100 priority score, not a probability."""
    if not 0.5 <= asset_criticality <= 2.0:
        raise ValueError("asset_criticality must be between 0.5 and 2.0")
    raw = _SEVERITY_WEIGHT[severity] * _CONFIDENCE_FACTOR[confidence] * asset_criticality
    return max(0, min(100, round(raw)))


class FindingStatus(str):
    OPEN = "open"
    REOPENED = "reopened"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    SUPPRESSED = "suppressed"


class FindingRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID
    organization_id: UUID
    asset_id: UUID
    scanner_id: str
    fingerprint: str
    finding: Finding
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int = Field(ge=1)
    risk_score: int = Field(ge=0, le=100)
    last_scan_id: UUID


class FindingEvent(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID
    finding_id: UUID
    scan_id: UUID | None = None
    event_type: str
    from_status: str | None = None
    to_status: str
    reason: str | None = None
    occurred_at: datetime


class SQLiteFindingLedger:
    """Transactional local ledger; create one instance per database path."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.is_dir():
            raise ValueError("Ledger path must be a file, not a directory")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    scanner_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL CHECK (occurrence_count >= 1),
                    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                    last_scan_id TEXT NOT NULL,
                    UNIQUE (organization_id, asset_id, scanner_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scope_status
                    ON findings (organization_id, asset_id, status);
                CREATE TABLE IF NOT EXISTS finding_events (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES findings(id),
                    scan_id TEXT,
                    event_type TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    reason TEXT,
                    occurred_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_finding_events_finding_time
                    ON finding_events (finding_id, occurred_at);
                """
            )

    def apply_report(
        self, report: ScanReport, *, asset_criticality: float = 1.0
    ) -> dict[str, Any]:
        """Apply one report atomically; absence only resolves on a completed scan."""
        if not 0.5 <= asset_criticality <= 2.0:
            raise ValueError("asset_criticality must be between 0.5 and 2.0")
        scan_id = uuid4()
        now = utc_now()
        seen: set[str] = set()
        counters = {"new": 0, "reopened": 0, "updated": 0, "resolved": 0}
        risk_scores: list[int] = []

        with self._connect() as db:
            for finding in report.findings:
                if (
                    finding.organization_id != report.organization_id
                    or finding.asset_id != report.asset_id
                    or finding.scanner_id != report.scanner_id
                ):
                    raise ValueError("Report contains a finding outside its tenant, asset or scanner")
                key = finding.fingerprint
                if key in seen:
                    continue
                seen.add(key)
                risk = calculate_risk_score(
                    finding.severity, finding.confidence,
                    asset_criticality=asset_criticality,
                )
                risk_scores.append(risk)
                row = db.execute(
                    """SELECT * FROM findings
                    WHERE organization_id=? AND asset_id=? AND scanner_id=? AND fingerprint=?""",
                    (str(report.organization_id), str(report.asset_id), report.scanner_id, key),
                ).fetchone()
                if row is None:
                    record_id = uuid4()
                    status = FindingStatus.OPEN
                    db.execute(
                        """INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            str(record_id), str(report.organization_id), str(report.asset_id),
                            report.scanner_id, key, finding.model_dump_json(), status,
                            now.isoformat(), now.isoformat(), 1, risk, str(scan_id),
                        ),
                    )
                    self._event(db, record_id, scan_id, "first_observed", None, status, None, now)
                    counters["new"] += 1
                    continue

                old_status = row["status"]
                new_status = (
                    FindingStatus.REOPENED if old_status == FindingStatus.RESOLVED
                    else old_status
                )
                db.execute(
                    """UPDATE findings SET finding_json=?, status=?, last_seen_at=?,
                    occurrence_count=occurrence_count+1, risk_score=?, last_scan_id=?
                    WHERE id=?""",
                    (
                        finding.model_dump_json(), new_status, now.isoformat(), risk,
                        str(scan_id), row["id"],
                    ),
                )
                if new_status != old_status:
                    self._event(
                        db, UUID(row["id"]), scan_id, "reopened", old_status,
                        new_status, "Finding observed again after resolution", now,
                    )
                    counters["reopened"] += 1
                else:
                    self._event(
                        db, UUID(row["id"]), scan_id, "observed_again", old_status,
                        old_status, None, now,
                    )
                    counters["updated"] += 1

            if report.state == ScanState.COMPLETED:
                active = db.execute(
                    """SELECT id, fingerprint, status FROM findings
                    WHERE organization_id=? AND asset_id=? AND scanner_id=?
                    AND status IN (?, ?)""",
                    (
                        str(report.organization_id), str(report.asset_id), report.scanner_id,
                        FindingStatus.OPEN, FindingStatus.REOPENED,
                    ),
                ).fetchall()
                for row in active:
                    if row["fingerprint"] in seen:
                        continue
                    db.execute(
                        "UPDATE findings SET status=? WHERE id=?",
                        (FindingStatus.RESOLVED, row["id"]),
                    )
                    self._event(
                        db, UUID(row["id"]), scan_id, "resolved_by_clean_scan",
                        row["status"], FindingStatus.RESOLVED,
                        "Absent from a completed assessment", now,
                    )
                    counters["resolved"] += 1

        return {
            "scan_id": str(scan_id),
            "state": report.state.value,
            "findings_observed": len(seen),
            **counters,
            "risk_score": min(100, sum(risk_scores)),
            "risk_score_semantics": "sum of observed finding priorities, capped at 100",
            "absence_resolution_applied": report.state == ScanState.COMPLETED,
        }

    @staticmethod
    def _event(
        db: sqlite3.Connection, finding_id: UUID, scan_id: UUID | None,
        event_type: str, from_status: str | None, to_status: str,
        reason: str | None, occurred_at: datetime,
    ) -> None:
        db.execute(
            "INSERT INTO finding_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()), str(finding_id), str(scan_id) if scan_id else None,
                event_type, from_status, to_status, reason, occurred_at.isoformat(),
            ),
        )

    def set_status(
        self, finding_id: UUID, status: str, *, reason: str
    ) -> FindingRecord:
        """Record an explicit analyst disposition; never silently discard history."""
        allowed = {FindingStatus.ACCEPTED_RISK, FindingStatus.SUPPRESSED, FindingStatus.OPEN}
        if status not in allowed:
            raise ValueError("Manual status must be accepted_risk, suppressed or open")
        if not reason.strip():
            raise ValueError("A non-empty reason is required for manual disposition")
        now = utc_now()
        with self._connect() as db:
            row = db.execute("SELECT * FROM findings WHERE id=?", (str(finding_id),)).fetchone()
            if row is None:
                raise LookupError(f"Unknown finding: {finding_id}")
            db.execute("UPDATE findings SET status=? WHERE id=?", (status, str(finding_id)))
            self._event(
                db, finding_id, None, "analyst_disposition", row["status"],
                status, reason.strip()[:2000], now,
            )
        return self.get(finding_id)

    def get(self, finding_id: UUID) -> FindingRecord:
        with self._connect() as db:
            row = db.execute("SELECT * FROM findings WHERE id=?", (str(finding_id),)).fetchone()
        if row is None:
            raise LookupError(f"Unknown finding: {finding_id}")
        return self._record(row)

    def list_findings(
        self, *, organization_id: UUID, asset_id: UUID | None = None
    ) -> tuple[FindingRecord, ...]:
        query = "SELECT * FROM findings WHERE organization_id=?"
        params: list[str] = [str(organization_id)]
        if asset_id is not None:
            query += " AND asset_id=?"
            params.append(str(asset_id))
        query += " ORDER BY risk_score DESC, last_seen_at DESC"
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return tuple(self._record(row) for row in rows)

    def events(self, finding_id: UUID) -> tuple[FindingEvent, ...]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM finding_events WHERE finding_id=? ORDER BY occurred_at, id",
                (str(finding_id),),
            ).fetchall()
        return tuple(FindingEvent(
            id=UUID(row["id"]), finding_id=UUID(row["finding_id"]),
            scan_id=UUID(row["scan_id"]) if row["scan_id"] else None,
            event_type=row["event_type"], from_status=row["from_status"],
            to_status=row["to_status"], reason=row["reason"],
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
        ) for row in rows)

    @staticmethod
    def _record(row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            id=UUID(row["id"]), organization_id=UUID(row["organization_id"]),
            asset_id=UUID(row["asset_id"]), scanner_id=row["scanner_id"],
            fingerprint=row["fingerprint"], finding=Finding.model_validate_json(row["finding_json"]),
            status=row["status"], first_seen_at=datetime.fromisoformat(row["first_seen_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            occurrence_count=row["occurrence_count"], risk_score=row["risk_score"],
            last_scan_id=UUID(row["last_scan_id"]),
        )
