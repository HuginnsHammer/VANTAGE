"""Loopback-only local VANTAGE control plane.

This is a single-operator development deployment. It intentionally exposes only
local-workspace static analysis; network assessments and production multi-tenancy
are not implemented here.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from vantage.domain.models import ApprovedScope, Asset, AssetKind, ScanRequest
from vantage.intelligence.lifecycle import SQLiteFindingLedger
from vantage.scanning.builtins import build_default_registry
from vantage.scanning.coordinator import ScanCoordinator

ROOT = Path(__file__).resolve().parents[3]
LOCAL_ORG_ID = uuid5(NAMESPACE_URL, "vantage-local-operator-profile-v1")
LOCAL_ACTOR_ID = uuid5(NAMESPACE_URL, "vantage-local-operator-v1")


class WorkspacePreview(BaseModel):
    path: str = Field(min_length=1, max_length=2048)


class WorkspaceCreate(WorkspacePreview):
    authorization_reference: str = Field(min_length=3, max_length=500)
    confirmation: str = Field(min_length=10, max_length=2200)
    display_name: str | None = Field(default=None, max_length=255)


class FindingDisposition(BaseModel):
    status: str
    reason: str = Field(min_length=3, max_length=2000)


def utc_iso() -> str:
    return datetime.now(UTC).isoformat()


def resolve_workspace(raw: str) -> Path:
    candidate = Path(raw).expanduser()
    if candidate.is_symlink():
        raise HTTPException(422, "Workspace root cannot be a symbolic link.")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(422, f"Workspace cannot be resolved: {exc}") from exc
    if not (resolved.is_file() or resolved.is_dir()):
        raise HTTPException(422, "Workspace must be a regular file or directory.")
    if resolved.is_file() and not os.access(resolved, os.R_OK):
        raise HTTPException(422, "Workspace file is not readable.")
    if resolved.is_dir() and not os.access(resolved, os.R_OK | os.X_OK):
        raise HTTPException(422, "Workspace directory is not readable.")
    return resolved


def create_app(
    data_dir: Path | str | None = None,
    cloudsentry_executable: str | None = None,
) -> FastAPI:
    state_dir = Path(data_dir or os.environ.get(
        "VANTAGE_DATA_DIR", Path.home() / ".local/share/vantage"
    )).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    db_path = state_dir / "control-plane.sqlite3"
    ledger_path = state_dir / "findings.sqlite3"
    executable = cloudsentry_executable or os.environ.get(
        "VANTAGE_CLOUDSENTRY_EXECUTABLE", "cloudsentry"
    )
    ledger = SQLiteFindingLedger(ledger_path)

    @contextmanager
    def connect() -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(db_path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                canonical_value TEXT NOT NULL,
                display_name TEXT,
                created_at TEXT NOT NULL,
                authorization_reference TEXT NOT NULL,
                scope_id TEXT NOT NULL UNIQUE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS uq_local_asset
                ON assets (organization_id, kind, canonical_value);
            CREATE TABLE IF NOT EXISTS scopes (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                authorization_reference TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                expires_at TEXT,
                allowed_scanner_ids TEXT NOT NULL,
                allow_active_checks INTEGER NOT NULL DEFAULT 0,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL REFERENCES assets(id),
                scanner_id TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                report_json TEXT,
                error TEXT,
                ledger_summary_json TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_scans_asset_created
                ON scans (asset_id, created_at DESC);
        """)

    app = FastAPI(
        title="VANTAGE Local Control Plane",
        version="0.2.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.data_dir = state_dir
    app.state.db_path = db_path
    app.state.ledger = ledger
    app.state.cloudsentry_executable = executable
    os.chmod(db_path, 0o600)

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            host = request.client.host if request.client else ""
            if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
                return JSONResponse(
                    {"detail": "The local control plane only accepts loopback clients."},
                    status_code=403,
                )
        return await call_next(request)

    def asset_from_row(row: sqlite3.Row) -> Asset:
        return Asset(
            id=UUID(row["asset_id"]),
            organization_id=UUID(row["asset_organization_id"]),
            kind=AssetKind(row["asset_kind"]),
            canonical_value=row["asset_canonical_value"],
            display_name=row["asset_display_name"],
            created_at=datetime.fromisoformat(row["asset_created_at"]),
        )

    def scope_from_row(row: sqlite3.Row) -> ApprovedScope:
        keys = set(row.keys())
        organization_id = (
            row["asset_organization_id"]
            if "asset_organization_id" in keys
            else row["organization_id"]
        )
        asset_id = row["asset_id"] if "asset_id" in keys else row["id"]
        with connect() as db:
            scope = db.execute("SELECT * FROM scopes WHERE id=?", (row["scope_id"],)).fetchone()
        if scope is None or scope["revoked_at"]:
            raise HTTPException(403, "No active authorization scope exists for this asset.")
        if scope["expires_at"] and datetime.fromisoformat(scope["expires_at"]) <= datetime.now(UTC):
            raise HTTPException(403, "The authorization scope has expired.")
        return ApprovedScope(
            id=UUID(scope["id"]),
            organization_id=UUID(organization_id),
            asset_id=UUID(asset_id),
            approved_by=LOCAL_ACTOR_ID,
            authorization_reference=scope["authorization_reference"],
            approved_at=datetime.fromisoformat(scope["approved_at"]),
            expires_at=datetime.fromisoformat(scope["expires_at"]) if scope["expires_at"] else None,
            allowed_scanner_ids=frozenset(json.loads(scope["allowed_scanner_ids"])),
            allow_active_checks=bool(scope["allow_active_checks"]),
        )

    @app.get("/api/v1/health")
    def health():
        located = shutil.which(executable) if os.path.sep not in executable else (
            executable if Path(executable).is_file() and os.access(executable, os.X_OK) else None
        )
        return {
            "status": "ok",
            "service": "VANTAGE local control plane",
            "mode": "local-single-operator",
            "database": "sqlite",
            "scanner": "cloudsentry",
            "scanner_available": bool(located),
            "scanner_executable": located,
            "network_scanning": False,
        }

    @app.get("/api/v1/overview")
    def overview():
        with connect() as db:
            assets = db.execute("SELECT COUNT(*) AS n FROM assets").fetchone()["n"]
            scans = db.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
            running = db.execute(
                "SELECT COUNT(*) AS n FROM scans WHERE state IN ('queued','running')"
            ).fetchone()["n"]
        findings = ledger.list_findings(organization_id=LOCAL_ORG_ID)
        active = [item for item in findings if item.status in {"open", "reopened"}]
        return {
            "assets": assets,
            "scans": scans,
            "active_findings": len(active),
            "critical": sum(item.finding.severity.value == "critical" for item in active),
            "high": sum(item.finding.severity.value == "high" for item in active),
            "running_scans": running,
        }

    @app.post("/api/v1/assets/preview")
    def preview_workspace(payload: WorkspacePreview):
        resolved = resolve_workspace(payload.path)
        return {
            "resolved_path": str(resolved),
            "confirmation_phrase": f"AUTHORIZE {resolved}",
            "kind": "local_workspace",
            "notice": "This registers a local path. A scan runs only after a separate action.",
        }

    @app.get("/api/v1/assets")
    def list_assets():
        with connect() as db:
            rows = db.execute(
                "SELECT * FROM assets WHERE organization_id=? ORDER BY created_at DESC",
                (str(LOCAL_ORG_ID),),
            ).fetchall()
        return {"items": [
            {
                "id": row["id"], "kind": row["kind"],
                "canonical_value": row["canonical_value"],
                "display_name": row["display_name"],
                "created_at": row["created_at"],
                "authorization_reference": row["authorization_reference"],
            } for row in rows
        ]}

    @app.post("/api/v1/assets")
    def create_asset(payload: WorkspaceCreate):
        resolved = resolve_workspace(payload.path)
        expected = f"AUTHORIZE {resolved}"
        if payload.confirmation != expected:
            raise HTTPException(422, {
                "message": "The authorization confirmation did not match.",
                "expected_confirmation": expected,
            })
        reference = payload.authorization_reference.strip()
        if len(reference) < 3:
            raise HTTPException(422, "Provide a meaningful authorization reference.")
        asset = Asset(
            organization_id=LOCAL_ORG_ID,
            kind=AssetKind.LOCAL_WORKSPACE,
            canonical_value=str(resolved),
            display_name=(payload.display_name or resolved.name or str(resolved))[:255],
        )
        scope = ApprovedScope(
            organization_id=LOCAL_ORG_ID,
            asset_id=asset.id,
            approved_by=LOCAL_ACTOR_ID,
            authorization_reference=reference,
            allowed_scanner_ids=frozenset({"cloudsentry"}),
            allow_active_checks=False,
        )
        try:
            with connect() as db:
                db.execute(
                    "INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(asset.id), str(asset.organization_id), asset.kind.value,
                     asset.canonical_value, asset.display_name, asset.created_at.isoformat(),
                     reference, str(scope.id)),
                )
                db.execute(
                    "INSERT INTO scopes VALUES (?, ?, ?, ?, ?, ?, 0, NULL)",
                    (str(scope.id), str(asset.id), reference, scope.approved_at.isoformat(),
                     scope.expires_at.isoformat() if scope.expires_at else None,
                     json.dumps(sorted(scope.allowed_scanner_ids))),
                )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "This workspace is already registered.") from exc
        return {"id": str(asset.id), "display_name": asset.display_name,
                "canonical_value": asset.canonical_value, "kind": asset.kind.value,
                "created_at": asset.created_at.isoformat()}

    def run_scan(scan_id: str) -> None:
        with connect() as db:
            row = db.execute(
                """SELECT scans.id AS scan_id, scans.asset_id AS asset_id,
                   scans.scanner_id, scans.state, assets.organization_id AS asset_organization_id,
                   assets.kind AS asset_kind, assets.canonical_value AS asset_canonical_value,
                   assets.display_name AS asset_display_name, assets.created_at AS asset_created_at,
                   assets.scope_id AS scope_id
                   FROM scans JOIN assets ON assets.id=scans.asset_id WHERE scans.id=?""",
                (scan_id,),
            ).fetchone()
            if row is None:
                return
            db.execute(
                "UPDATE scans SET state='running', started_at=? WHERE id=?",
                (utc_iso(), scan_id),
            )
        try:
            asset = asset_from_row(row)
            scope = scope_from_row(row)
            request = ScanRequest(
                organization_id=asset.organization_id,
                asset_id=asset.id,
                scope_id=scope.id,
                scanner_id="cloudsentry",
                requested_by=LOCAL_ACTOR_ID,
                active_checks_requested=False,
            )
            registry = build_default_registry(cloudsentry_executable=executable)
            report = ScanCoordinator(registry).run(asset, scope, request)
            summary = ledger.apply_report(report)
            with connect() as db:
                db.execute(
                    """UPDATE scans SET state=?, completed_at=?, report_json=?,
                       ledger_summary_json=?, error=NULL WHERE id=?""",
                    (report.state.value, utc_iso(), report.model_dump_json(),
                     json.dumps(summary), scan_id),
                )
        except Exception as exc:
            with connect() as db:
                db.execute(
                    "UPDATE scans SET state='failed', completed_at=?, error=? WHERE id=?",
                    (utc_iso(), str(exc)[:2000], scan_id),
                )

    @app.post("/api/v1/assets/{asset_id}/scans", status_code=202)
    def start_scan(asset_id: UUID, background_tasks: BackgroundTasks):
        with connect() as db:
            row = db.execute(
                "SELECT * FROM assets WHERE id=? AND organization_id=?",
                (str(asset_id), str(LOCAL_ORG_ID)),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Asset not found.")
            scope = scope_from_row(row)
            if "cloudsentry" not in scope.allowed_scanner_ids:
                raise HTTPException(403, "CloudSentry is not permitted by this scope.")
            scan_id = uuid4()
            db.execute(
                "INSERT INTO scans "
                "(id, asset_id, scanner_id, state, created_at) VALUES (?, ?, ?, ?, ?)",
                (str(scan_id), str(asset_id), "cloudsentry", "queued", utc_iso()),
            )
        background_tasks.add_task(run_scan, str(scan_id))
        return {"id": str(scan_id), "asset_id": str(asset_id), "state": "queued"}

    @app.get("/api/v1/scans")
    def list_scans():
        with connect() as db:
            rows = db.execute(
                """SELECT scans.*, assets.display_name, assets.canonical_value
                   FROM scans JOIN assets ON assets.id=scans.asset_id
                   ORDER BY scans.created_at DESC LIMIT 100"""
            ).fetchall()
        return {"items": [{
            "id": row["id"], "asset_id": row["asset_id"],
            "asset_name": row["display_name"] or row["canonical_value"],
            "scanner_id": row["scanner_id"], "state": row["state"],
            "created_at": row["created_at"], "started_at": row["started_at"],
            "completed_at": row["completed_at"], "error": row["error"],
            "summary": (
                json.loads(row["ledger_summary_json"]) if row["ledger_summary_json"] else None
            ),
        } for row in rows]}

    @app.get("/api/v1/findings")
    def list_findings(asset_id: UUID | None = None, status: str | None = None):
        findings = ledger.list_findings(organization_id=LOCAL_ORG_ID, asset_id=asset_id)
        items = []
        for record in findings:
            if status and record.status != status:
                continue
            items.append({
                "id": str(record.id), "asset_id": str(record.asset_id),
                "scanner_id": record.scanner_id, "fingerprint": record.fingerprint,
                "title": record.finding.title, "description": record.finding.description,
                "severity": record.finding.severity.value,
                "confidence": record.finding.confidence.value,
                "status": record.status, "risk_score": record.risk_score,
                "remediation": record.finding.remediation,
                "evidence": [item.model_dump(mode="json") for item in record.finding.evidence],
                "first_seen_at": record.first_seen_at.isoformat(),
                "last_seen_at": record.last_seen_at.isoformat(),
                "occurrence_count": record.occurrence_count,
            })
        return {"items": items}

    @app.patch("/api/v1/findings/{finding_id}")
    def update_finding(finding_id: UUID, payload: FindingDisposition):
        try:
            record = ledger.get(finding_id)
            if record.organization_id != LOCAL_ORG_ID:
                raise HTTPException(404, "Finding not found.")
            updated = ledger.set_status(finding_id, payload.status, reason=payload.reason)
        except LookupError as exc:
            raise HTTPException(404, "Finding not found.") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": str(updated.id), "status": updated.status}

    @app.get("/api/v1/findings/{finding_id}/history")
    def finding_history(finding_id: UUID):
        try:
            record = ledger.get(finding_id)
        except LookupError as exc:
            raise HTTPException(404, "Finding not found.") from exc
        if record.organization_id != LOCAL_ORG_ID:
            raise HTTPException(404, "Finding not found.")
        return {"items": [event.model_dump(mode="json") for event in ledger.events(finding_id)]}

    @app.get("/api/v1/scans/{scan_id}")
    def get_scan(scan_id: UUID):
        with connect() as db:
            row = db.execute(
                """SELECT scans.*, assets.display_name FROM scans
                   JOIN assets ON assets.id=scans.asset_id WHERE scans.id=?""",
                (str(scan_id),),
            ).fetchone()
        if row is None:
            raise HTTPException(404, "Scan not found.")
        return {
            "id": row["id"], "asset_id": row["asset_id"],
            "asset_name": row["display_name"], "scanner_id": row["scanner_id"],
            "state": row["state"], "created_at": row["created_at"],
            "started_at": row["started_at"], "completed_at": row["completed_at"],
            "error": row["error"],
            "summary": (
                json.loads(row["ledger_summary_json"]) if row["ledger_summary_json"] else None
            ),
        }

    @app.get("/app", include_in_schema=False)
    @app.get("/app.html", include_in_schema=False)
    def application_ui():
        return FileResponse(ROOT / "app.html")

    @app.get("/", include_in_schema=False)
    def public_site():
        return FileResponse(ROOT / "index.html")

    app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")
    return app


app = create_app()
