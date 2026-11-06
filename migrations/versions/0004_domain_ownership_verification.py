"""Add domain ownership verification challenges and verified asset timestamps.

Revision ID: 0004_domain_verify
Revises: 0003_identity_visibility
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_domain_verify"
down_revision = "0003_identity_visibility"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("ownership_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_assets_org_kind_value_unscoped",
        "assets",
        ["organization_id", "kind", "canonical_value"],
        unique=True,
        postgresql_where=sa.text("environment_id IS NULL AND kind = 'domain'"),
    )
    op.create_table(
        "domain_verification_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("method", sa.String(20), nullable=False, server_default="dns_txt"),
        sa.Column("record_name", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "requested_by"],
            ["memberships.organization_id", "memberships.user_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("method IN ('dns_txt')", name="ck_domain_challenge_method"),
        sa.CheckConstraint(
            "status IN ('pending', 'verified', 'expired')",
            name="ck_domain_challenge_status",
        ),
    )
    op.create_index(
        "ix_domain_challenges_org_asset_created",
        "domain_verification_challenges",
        ["organization_id", "asset_id", "created_at"],
    )
    op.execute("ALTER TABLE domain_verification_challenges ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE domain_verification_challenges FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON domain_verification_challenges
        USING (
            organization_id =
                NULLIF(current_setting('vantage.organization_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id =
                NULLIF(current_setting('vantage.organization_id', true), '')::uuid
        )
    """)


def downgrade() -> None:
    op.execute("DROP POLICY tenant_isolation ON domain_verification_challenges")
    op.drop_index(
        "ix_domain_challenges_org_asset_created",
        table_name="domain_verification_challenges",
    )
    op.drop_table("domain_verification_challenges")
    op.drop_index("uq_assets_org_kind_value_unscoped", table_name="assets")
    op.drop_column("assets", "ownership_verified_at")
