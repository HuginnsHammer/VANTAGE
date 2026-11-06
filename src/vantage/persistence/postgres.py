"""PostgreSQL control-plane schema and tenant transaction helpers.

Authenticate an OIDC identity, resolve active membership, and only then establish
organization context. PostgreSQL row-level security is a second boundary, not a
replacement for service-layer authorization.
"""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative metadata for the VANTAGE PostgreSQL control plane."""


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint("kind IN ('personal', 'organization')", name="ck_org_kind"),
        CheckConstraint("status IN ('active', 'suspended', 'deleting')", name="ck_org_status"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class UserIdentity(Base):
    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),)
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        CheckConstraint("role IN ('owner', 'admin', 'security_analyst', 'operator', 'viewer')", name="ck_membership_role"),
        CheckConstraint("status IN ('active', 'invited', 'suspended')", name="ck_membership_status"),
    )
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("user_identities.id", ondelete="RESTRICT"), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_projects_org_id"),
        UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        Index("ix_projects_org_created", "organization_id", "created_at"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Environment(Base):
    __tablename__ = "environments"
    __table_args__ = (
        UniqueConstraint("organization_id", "project_id", "id", name="uq_environments_org_project_id"),
        UniqueConstraint("organization_id", "project_id", "name", name="uq_environments_project_name"),
        ForeignKeyConstraint(["organization_id", "project_id"], ["projects.organization_id", "projects.id"], ondelete="CASCADE"),
        CheckConstraint("kind IN ('development', 'staging', 'production', 'other')", name="ck_environment_kind"),
        Index("ix_environments_org_project", "organization_id", "project_id"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    project_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AssetRecord(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_assets_org_id"),
        UniqueConstraint("organization_id", "environment_id", "kind", "canonical_value", name="uq_assets_environment_identity"),
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "project_id"], ["projects.organization_id", "projects.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "project_id", "environment_id"], ["environments.organization_id", "environments.project_id", "environments.id"], ondelete="CASCADE"),
        CheckConstraint("kind IN ('domain', 'ip_address', 'web_application', 'api', 'cloud_resource', 'repository', 'local_workspace')", name="ck_asset_kind"),
        CheckConstraint("environment_id IS NULL OR project_id IS NOT NULL", name="ck_asset_environment_requires_project"),
        Index("ix_assets_org_kind", "organization_id", "kind"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    environment_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ApprovedScopeRecord(Base):
    __tablename__ = "approved_scopes"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "asset_id"], ["assets.organization_id", "assets.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "approved_by"], ["memberships.organization_id", "memberships.user_id"], ondelete="RESTRICT"),
        CheckConstraint("status IN ('pending', 'approved', 'revoked', 'expired')", name="ck_scope_status"),
        CheckConstraint("expires_at IS NULL OR expires_at > approved_at", name="ck_scope_expiry_after_approval"),
        Index("ix_scopes_org_asset_status", "organization_id", "asset_id", "status"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    approved_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    allow_active_checks: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_scanner_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        Index("ix_audit_org_time", "organization_id", "occurred_at"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    actor_user_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("user_identities.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


TENANT_TABLES = ("organizations", "memberships", "projects", "environments", "assets", "approved_scopes", "audit_events")


def create_postgres_engine(database_url: str) -> Engine:
    """Create a PostgreSQL engine; refuse accidental SQLite or other URLs."""
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise ValueError("VANTAGE control-plane persistence requires a PostgreSQL URL")
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return create_engine(database_url, pool_pre_ping=True, pool_recycle=1800)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def set_tenant_context(
    session: Session,
    organization_id: UUID | None,
    actor_id: UUID | None = None,
) -> None:
    """Set transaction-local RLS context after authenticating the actor."""
    if not session.in_transaction():
        raise RuntimeError("Tenant context must be set inside an active transaction")
    session.execute(
        text(
            "SELECT set_config('vantage.organization_id', :organization_id, true), "
            "set_config('vantage.actor_id', :actor_id, true)"
        ),
        {
            "organization_id": str(organization_id) if organization_id else "",
            "actor_id": str(actor_id) if actor_id else "",
        },
    )


def validate_runtime_role(engine: Engine) -> None:
    """Refuse database identities that can bypass tenant row-level security."""
    with engine.connect() as connection:
        role = connection.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        if role.rolsuper or role.rolbypassrls:
            raise RuntimeError(
                "VANTAGE hosted API refuses PostgreSQL superuser or BYPASSRLS roles"
            )
        owned = connection.execute(
            text(
                "SELECT count(*) FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') "
                "AND c.relname = ANY(:tables) "
                "AND pg_get_userbyid(c.relowner) = current_user"
            ),
            {"tables": list(TENANT_TABLES)},
        ).scalar_one()
        if owned:
            raise RuntimeError("VANTAGE runtime role must not own tenant tables")
