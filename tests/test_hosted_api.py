import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from vantage.api.hosted import create_app, personal_workspace_id
from vantage.persistence.postgres import create_postgres_engine

ADMIN_URL = os.getenv("VANTAGE_DATABASE_URL")
APP_URL = os.getenv("VANTAGE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not ADMIN_URL or not APP_URL,
    reason="PostgreSQL integration URLs are not configured",
)


def test_hosted_identity_workspaces_and_tenant_isolation():
    issuer = "https://vantage-test-issuer.example"
    alice_sub, bob_sub = uuid4().hex, uuid4().hex
    claims = {
        "alice-token": {
            "iss": issuer, "sub": alice_sub, "email": "alice@example.test",
            "email_verified": True, "name": "Alice Test",
        },
        "bob-token": {
            "iss": issuer, "sub": bob_sub, "email": "bob@example.test",
            "email_verified": True, "name": "Bob Test",
        },
    }
    app = create_app(
        database_url=APP_URL,
        token_verifier=lambda token: claims[token],
    )
    client = TestClient(app)
    alice_headers = {"Authorization": "Bearer alice-token"}
    bob_headers = {"Authorization": "Bearer bob-token"}
    admin_engine = create_postgres_engine(ADMIN_URL)
    cleanup_org_ids = [
        str(personal_workspace_id(issuer, alice_sub)),
        str(personal_workspace_id(issuer, bob_sub)),
    ]
    cleanup_subjects = [alice_sub, bob_sub]
    try:
        assert client.get("/api/v2/me").status_code == 401

        alice = client.get("/api/v2/me", headers=alice_headers)
        assert alice.status_code == 200
        alice_data = alice.json()
        personal_id = alice_data["personal_organization_id"]
        assert personal_id in cleanup_org_ids
        assert any(item["kind"] == "personal" for item in alice_data["workspaces"])

        slug = f"it-org-{uuid4().hex[:10]}"
        created = client.post(
            "/api/v2/organizations",
            headers=alice_headers,
            json={"name": "Integration Test Org", "slug": slug},
        )
        assert created.status_code == 201, created.text
        organization = created.json()
        cleanup_org_ids.append(organization["id"])
        assert organization["role"] == "owner"

        members = client.get(
            f"/api/v2/organizations/{organization['id']}/members",
            headers=alice_headers,
        )
        assert members.status_code == 200
        assert len(members.json()["items"]) == 1
        assert members.json()["items"][0]["role"] == "owner"

        project = client.post(
            f"/api/v2/organizations/{organization['id']}/projects",
            headers=alice_headers,
            json={"name": "Production", "slug": "production"},
        )
        assert project.status_code == 201, project.text
        assert client.get(
            f"/api/v2/organizations/{organization['id']}/projects",
            headers=alice_headers,
        ).json()["items"][0]["slug"] == "production"

        denied = client.get(
            f"/api/v2/organizations/{organization['id']}",
            headers=bob_headers,
        )
        assert denied.status_code == 404
        denied_projects = client.get(
            f"/api/v2/organizations/{organization['id']}/projects",
            headers=bob_headers,
        )
        assert denied_projects.status_code == 404

        bob = client.get("/api/v2/me", headers=bob_headers)
        assert bob.status_code == 200
        assert all(item["id"] != organization["id"] for item in bob.json()["workspaces"])
    finally:
        with admin_engine.begin() as connection:
            if cleanup_org_ids:
                connection.execute(
                    text("DELETE FROM organizations WHERE id::text = ANY(:ids)"),
                    {"ids": cleanup_org_ids},
                )
            connection.execute(
                text(
                    "DELETE FROM user_identities "
                    "WHERE issuer = :issuer AND subject = ANY(:subjects)"
                ),
                {"issuer": issuer, "subjects": cleanup_subjects},
            )
        admin_engine.dispose()
