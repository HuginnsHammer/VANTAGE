import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from vantage.persistence.postgres import (
    Environment,
    Membership,
    Organization,
    Project,
    UserIdentity,
    create_postgres_engine,
    create_session_factory,
    set_tenant_context,
)

ADMIN_URL = os.getenv("VANTAGE_DATABASE_URL")
APP_URL = os.getenv("VANTAGE_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not ADMIN_URL or not APP_URL,
    reason="PostgreSQL integration URLs are not configured",
)


@pytest.fixture
def tenant_fixture():
    admin_engine = create_postgres_engine(ADMIN_URL)
    org_a = Organization(
        id=uuid4(), slug=f"tenant-a-{uuid4().hex[:8]}",
        name="Tenant A", kind="organization",
    )
    org_b = Organization(
        id=uuid4(), slug=f"tenant-b-{uuid4().hex[:8]}",
        name="Tenant B", kind="organization",
    )
    identity = UserIdentity(
        id=uuid4(), issuer="https://identity.example.test",
        subject=uuid4().hex, email="security@example.test",
    )
    project_b = Project(
        id=uuid4(), organization_id=org_b.id,
        slug="production", name="Production",
    )
    with Session(admin_engine) as session:
        session.add_all([
            org_a, org_b, identity,
            Membership(
                organization_id=org_a.id, user_id=identity.id,
                role="owner", status="active",
            ),
            Membership(
                organization_id=org_b.id, user_id=identity.id,
                role="owner", status="active",
            ),
            project_b,
        ])
        session.commit()
    yield org_a.id, org_b.id, identity.id, project_b.id
    with admin_engine.begin() as connection:
        connection.execute(
            delete(Organization).where(Organization.id.in_([org_a.id, org_b.id]))
        )
        connection.execute(
            delete(UserIdentity).where(UserIdentity.id == identity.id)
        )
    admin_engine.dispose()


def test_row_level_security_hides_other_organizations(tenant_fixture) -> None:
    org_a, org_b, user_id, _ = tenant_fixture
    engine = create_postgres_engine(APP_URL)
    factory = create_session_factory(engine)
    try:
        with factory.begin() as session:
            set_tenant_context(session, org_a)
            organizations = session.scalars(select(Organization)).all()
            memberships = session.scalars(select(Membership)).all()
            assert [item.id for item in organizations] == [org_a]
            assert [(item.organization_id, item.user_id) for item in memberships] == [
                (org_a, user_id)
            ]
            assert org_b not in [item.id for item in organizations]
    finally:
        engine.dispose()


def test_row_level_security_rejects_cross_tenant_insert(tenant_fixture) -> None:
    org_a, org_b, _, _ = tenant_fixture
    engine = create_postgres_engine(APP_URL)
    factory = create_session_factory(engine)
    try:
        with pytest.raises(ProgrammingError):
            with factory.begin() as session:
                set_tenant_context(session, org_a)
                session.add(Project(
                    organization_id=org_b, slug="forbidden",
                    name="Cross-tenant write",
                ))
                session.flush()
    finally:
        engine.dispose()


def test_composite_foreign_key_blocks_cross_tenant_project_reference(tenant_fixture) -> None:
    org_a, _, _, project_b = tenant_fixture
    engine = create_postgres_engine(APP_URL)
    factory = create_session_factory(engine)
    try:
        with pytest.raises(IntegrityError):
            with factory.begin() as session:
                set_tenant_context(session, org_a)
                session.add(Environment(
                    organization_id=org_a, project_id=project_b,
                    name="forbidden", kind="production",
                ))
                session.flush()
    finally:
        engine.dispose()


def test_tenant_context_does_not_leak_between_transactions(tenant_fixture) -> None:
    org_a, _, _, _ = tenant_fixture
    engine = create_postgres_engine(APP_URL)
    factory = create_session_factory(engine)
    try:
        with factory.begin() as session:
            set_tenant_context(session, org_a)
            assert session.scalars(select(Organization)).all()
        with factory.begin() as session:
            assert session.scalars(select(Organization)).all() == []
    finally:
        engine.dispose()
