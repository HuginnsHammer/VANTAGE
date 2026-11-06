"""Protect identity records with actor/self and organization membership RLS.

Revision ID: 0003_identity_visibility
Revises: 0002_membership_self_listing
"""
from alembic import op

revision = "0003_identity_visibility"
down_revision = "0002_membership_self_listing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE user_identities ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE user_identities FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY identity_visibility ON user_identities
        USING (
            id = NULLIF(current_setting('vantage.actor_id', true), '')::uuid
            OR EXISTS (
                SELECT 1 FROM memberships m
                WHERE m.user_id = user_identities.id
                  AND m.organization_id =
                    NULLIF(current_setting('vantage.organization_id', true), '')::uuid
            )
        )
        WITH CHECK (
            id = NULLIF(current_setting('vantage.actor_id', true), '')::uuid
        )
    """)


def downgrade() -> None:
    op.execute("DROP POLICY identity_visibility ON user_identities")
    op.execute("ALTER TABLE user_identities NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE user_identities DISABLE ROW LEVEL SECURITY")
