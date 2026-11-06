"""Initial multi-tenant control-plane schema with PostgreSQL RLS.

Revision ID: 0001_tenant_control_plane
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_tenant_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(63), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('personal', 'organization')", name="ck_org_kind"),
        sa.CheckConstraint("status IN ('active', 'suspended', 'deleting')", name="ck_org_status"),
    )
    op.create_table(
        "user_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("display_name", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
    )
    op.create_table(
        "memberships",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user_identities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("organization_id", "user_id"),
        sa.CheckConstraint("role IN ('owner', 'admin', 'security_analyst', 'operator', 'viewer')", name="ck_membership_role"),
        sa.CheckConstraint("status IN ('active', 'invited', 'suspended')", name="ck_membership_status"),
    )
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "id", name="uq_projects_org_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
    )
    op.create_index("ix_projects_org_created", "projects", ["organization_id", "created_at"])
    op.create_table(
        "environments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id", "project_id"], ["projects.organization_id", "projects.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "project_id", "id", name="uq_environments_org_project_id"),
        sa.UniqueConstraint("organization_id", "project_id", "name", name="uq_environments_project_name"),
        sa.CheckConstraint("kind IN ('development', 'staging', 'production', 'other')", name="ck_environment_kind"),
    )
    op.create_index("ix_environments_org_project", "environments", ["organization_id", "project_id"])
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True)),
        sa.Column("environment_id", postgresql.UUID(as_uuid=True)),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("canonical_value", sa.String(2048), nullable=False),
        sa.Column("display_name", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "project_id"], ["projects.organization_id", "projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "project_id", "environment_id"], ["environments.organization_id", "environments.project_id", "environments.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "id", name="uq_assets_org_id"),
        sa.UniqueConstraint("organization_id", "environment_id", "kind", "canonical_value", name="uq_assets_environment_identity"),
        sa.CheckConstraint("kind IN ('domain', 'ip_address', 'web_application', 'api', 'cloud_resource', 'repository', 'local_workspace')", name="ck_asset_kind"),
        sa.CheckConstraint("environment_id IS NULL OR project_id IS NOT NULL", name="ck_asset_environment_requires_project"),
    )
    op.create_index("ix_assets_org_kind", "assets", ["organization_id", "kind"])
    op.create_table(
        "approved_scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authorization_reference", sa.String(500), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("allow_active_checks", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed_scanner_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["organization_id", "asset_id"], ["assets.organization_id", "assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "approved_by"], ["memberships.organization_id", "memberships.user_id"], ondelete="RESTRICT"),
        sa.CheckConstraint("status IN ('pending', 'approved', 'revoked', 'expired')", name="ck_scope_status"),
        sa.CheckConstraint("expires_at IS NULL OR expires_at > approved_at", name="ck_scope_expiry_after_approval"),
    )
    op.create_index("ix_scopes_org_asset_status", "approved_scopes", ["organization_id", "asset_id", "status"])
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(128)),
        sa.Column("reason", sa.Text()),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user_identities.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_org_time", "audit_events", ["organization_id", "occurred_at"])

    # Fail closed: tenant-scoped queries see no rows until transaction context is set.
    tenant_tables = ("organizations", "memberships", "projects", "environments", "assets", "approved_scopes", "audit_events")
    for table in tenant_tables:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        tenant_column = "id" if table == "organizations" else "organization_id"
        op.execute(
            f'CREATE POLICY tenant_isolation ON "{table}" '
            f"USING (\"{tenant_column}\" = NULLIF(current_setting('vantage.organization_id', true), '')::uuid) "
            f"WITH CHECK (\"{tenant_column}\" = NULLIF(current_setting('vantage.organization_id', true), '')::uuid)"
        )

    # Audit records are append-only for the application role.
    op.execute("""
        CREATE FUNCTION vantage_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'VANTAGE audit events are append-only';
        END;
        $$;
    """)
    op.execute("""
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION vantage_reject_audit_mutation();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS vantage_reject_audit_mutation()")
    for table in ("audit_events", "approved_scopes", "assets", "environments", "projects", "memberships", "organizations"):
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
    op.drop_table("audit_events")
    op.drop_index("ix_scopes_org_asset_status", table_name="approved_scopes")
    op.drop_table("approved_scopes")
    op.drop_index("ix_assets_org_kind", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_environments_org_project", table_name="environments")
    op.drop_table("environments")
    op.drop_index("ix_projects_org_created", table_name="projects")
    op.drop_table("projects")
    op.drop_table("memberships")
    op.drop_table("user_identities")
    op.drop_table("organizations")
