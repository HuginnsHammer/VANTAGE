"""Canonical, vendor-neutral VANTAGE domain contracts."""
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AssetKind(StrEnum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    WEB_APPLICATION = "web_application"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"
    REPOSITORY = "repository"
    LOCAL_WORKSPACE = "local_workspace"


class ScanState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Asset(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    kind: AssetKind
    canonical_value: str = Field(min_length=1, max_length=2048)
    display_name: str | None = Field(default=None, max_length=255)
    created_at: datetime = Field(default_factory=utc_now)


class ApprovedScope(BaseModel):
    """A target is not scan-authorized until authority is recorded."""
    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    asset_id: UUID
    approved_by: UUID
    authorization_reference: str = Field(min_length=3, max_length=500)
    approved_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    allowed_scanner_ids: frozenset[str] = frozenset()
    allow_active_checks: bool = False


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1, max_length=2000)
    location: str | None = Field(default=None, max_length=2048)
    observed_at: datetime = Field(default_factory=utc_now)
    source_scanner: str = Field(min_length=1, max_length=120)
    redacted: bool = True
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    asset_id: UUID
    scanner_id: str
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity = FindingSeverity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    evidence: tuple[Evidence, ...] = ()
    remediation: str | None = None
    fingerprint: str = Field(min_length=16, max_length=128)
    verified: bool = False
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)


class ScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    organization_id: UUID
    asset_id: UUID
    scope_id: UUID
    scanner_id: str = Field(min_length=2, max_length=120)
    requested_by: UUID
    active_checks_requested: bool = False
    parameters: dict[str, str | int | bool] = Field(default_factory=dict)


class ScanReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    organization_id: UUID
    asset_id: UUID
    scanner_id: str
    state: ScanState
    findings: tuple[Finding, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    files_or_targets_examined: int = 0
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
