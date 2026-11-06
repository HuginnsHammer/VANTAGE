from uuid import uuid4

import pytest
from sqlalchemy import ForeignKeyConstraint

from vantage.persistence.postgres import (
    TENANT_TABLES,
    AssetRecord,
    Base,
    Environment,
    Organization,
    create_postgres_engine,
    set_tenant_context,
    validate_runtime_role,
)


def test_personal_and_organization_accounts_share_one_tenant_model() -> None:
    checks = " ".join(
        str(item.sqltext)
        for item in Organization.__table__.constraints
        if hasattr(item, "sqltext")
    )
    assert "personal" in checks and "organization" in checks


def test_tenant_owned_tables_are_explicit() -> None:
    assert set(TENANT_TABLES) <= set(Base.metadata.tables)
    assert {"organizations", "user_identities"} <= set(Base.metadata.tables)


def test_environment_cannot_reference_a_project_from_another_tenant() -> None:
    constraints = [
        c for c in Environment.__table__.constraints if isinstance(c, ForeignKeyConstraint)
    ]
    assert any(
        [element.parent.name for element in constraint.elements]
        == ["organization_id", "project_id"]
        for constraint in constraints
    )


def test_asset_environment_relationship_is_tenant_and_project_scoped() -> None:
    constraints = [
        c for c in AssetRecord.__table__.constraints if isinstance(c, ForeignKeyConstraint)
    ]
    assert any(
        [element.parent.name for element in constraint.elements]
        == ["organization_id", "project_id", "environment_id"]
        for constraint in constraints
    )


def test_database_factory_rejects_non_postgres_urls() -> None:
    with pytest.raises(ValueError, match="requires a PostgreSQL URL"):
        create_postgres_engine("sqlite:///vantage.db")


def test_rls_context_requires_an_active_transaction() -> None:
    class InactiveSession:
        def in_transaction(self) -> bool:
            return False

    with pytest.raises(RuntimeError, match="active transaction"):
        set_tenant_context(InactiveSession(), uuid4())


def test_runtime_role_guard_rejects_postgres_superuser() -> None:
    admin_url = os.getenv("VANTAGE_DATABASE_URL")
    if not admin_url:
        pytest.skip("PostgreSQL integration URL is not configured")
    engine = create_postgres_engine(admin_url)
    try:
        with pytest.raises(RuntimeError, match="superuser or BYPASSRLS"):
            validate_runtime_role(engine)
    finally:
        engine.dispose()
