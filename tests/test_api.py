from fastapi.testclient import TestClient

from vantage.api.app import create_app


def test_health_and_loopback_local_mode(tmp_path):
    app = create_app(data_dir=tmp_path, cloudsentry_executable="missing-cloudsentry")
    client = TestClient(app, client=("127.0.0.1", 12345), headers={"host": "127.0.0.1"})
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "local-single-operator"
    assert response.json()["scanner_available"] is False
    assert response.json()["network_scanning"] is False


def test_workspace_requires_exact_confirmation_and_persists(tmp_path):
    workspace = tmp_path / "owned-project"
    workspace.mkdir()
    (workspace / "Dockerfile").write_text("FROM alpine:latest\n", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "state", cloudsentry_executable="missing-cloudsentry")
    client = TestClient(app, client=("127.0.0.1", 12345), headers={"host": "127.0.0.1"})

    preview = client.post("/api/v1/assets/preview", json={"path": str(workspace)})
    assert preview.status_code == 200
    phrase = preview.json()["confirmation_phrase"]

    rejected = client.post("/api/v1/assets", json={
        "path": str(workspace), "authorization_reference": "SELF-TEST-01",
        "confirmation": "I AUTHORIZE THIS",
    })
    assert rejected.status_code == 422

    created = client.post("/api/v1/assets", json={
        "path": str(workspace), "authorization_reference": "SELF-TEST-01",
        "confirmation": phrase, "display_name": "Owned test project",
    })
    assert created.status_code == 200
    assert created.json()["display_name"] == "Owned test project"
    assert len(client.get("/api/v1/assets").json()["items"]) == 1

    duplicate = client.post("/api/v1/assets", json={
        "path": str(workspace), "authorization_reference": "SELF-TEST-02",
        "confirmation": phrase,
    })
    assert duplicate.status_code == 409


def test_workspace_preview_rejects_missing_path(tmp_path):
    app = create_app(data_dir=tmp_path / "state")
    client = TestClient(app, client=("127.0.0.1", 12345), headers={"host": "127.0.0.1"})
    response = client.post("/api/v1/assets/preview", json={"path": str(tmp_path / "missing")})
    assert response.status_code == 422



def test_api_rejects_non_loopback_clients(tmp_path):
    app = create_app(data_dir=tmp_path / "state")
    client = TestClient(
        app, client=("203.0.113.10", 12345), headers={"host": "127.0.0.1"}
    )
    response = client.get("/api/v1/health")
    assert response.status_code == 403


def test_local_application_serves_frontend_assets():
    from vantage.api.app import ROOT

    if not (ROOT / "app.html").exists():
        return
    app = create_app()
    client = TestClient(app)
    assert client.get("/app").status_code == 200
    assert client.get("/assets/css/console.css").status_code == 200
    assert client.get("/assets/js/console.js").status_code == 200
