"""Allow authenticated actors to enumerate only their own memberships.

Revision ID: 0002_membership_self_listing
Revises: 0001_tenant_control_plane
"""
from alembic import op

revision = "0002_membership_self_listing"
down_revision = "0001_tenant_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP POLICY tenant_isolation ON memberships")
    op.execute("""
        CREATE POLICY tenant_isolation ON memberships
        USING (
            organization_id = NULLIF(current_setting('vantage.organization_id', true), '')::uuid
            OR user_id = NULLIF(current_setting('vantage.actor_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(current_setting('vantage.organization_id', true), '')::uuid
        )
    """)


def downgrade() -> None:
    op.execute("DROP POLICY tenant_isolation ON memberships")
    op.execute("""
        CREATE POLICY tenant_isolation ON memberships
        USING (
            organization_id = NULLIF(current_setting('vantage.organization_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(current_setting('vantage.organization_id', true), '')::uuid
        )
    """)
