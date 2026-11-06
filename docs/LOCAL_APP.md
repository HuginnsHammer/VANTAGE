# Run the VANTAGE local web application

This milestone adds a real local control plane behind the web interface. It is
intended for one operator on their own machine; it is **not** the hosted,
multi-user organization service.

## What works

- Local FastAPI control plane and persistent SQLite state.
- Asset registration for existing local files/directories, with an exact
  resolved-path confirmation and an authorization reference.
- CloudSentry assessment jobs dispatched through the existing scope-enforcing
  scanner coordinator.
- Assessment history and persisted findings using the existing lifecycle ledger.
- Evidence and remediation inspection, analyst disposition, and audit history.
- Dashboard refreshes from the API rather than synthetic sample data.
- API binds to loopback by default and rejects non-loopback API clients.

## What does not work yet

There is no account login, organization membership, cloud-hosted API, PostgreSQL
runtime wiring, distributed worker queue, domain ownership verification, remote
asset discovery, or network scanner. The first working scanner is local static
IaC/container analysis through CloudSentry. The interface must not imply that a
workspace scan checks the public internet or tests exploitability.

## Install

Python 3.12+ is required. Install CloudSentry separately and make its
`cloudsentry` executable available on PATH, or set
`VANTAGE_CLOUDSENTRY_EXECUTABLE` to its absolute path.

From the VANTAGE repository root:

```fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e ".[api,dev]"
uvicorn vantage.api.app:app --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765/app**. API documentation is at
**http://127.0.0.1:8765/api/docs**.

By default, state is stored in `~/.local/share/vantage/` with restrictive
directory/file permissions. Set `VANTAGE_DATA_DIR` to use another location.
Set `VANTAGE_CLOUDSENTRY_EXECUTABLE` if the scanner binary is not named
`cloudsentry`.

## First assessment

1. Choose **Add workspace** and enter the absolute path to a project you own or
   have explicit permission to assess.
2. Enter an authorization reference (for example, a self-assessment ticket).
3. Validate the path and keep the exact generated confirmation phrase.
4. Register the workspace.
5. Select **Run assessment** on that asset.
6. Watch the assessment state update, then inspect evidence-backed findings.
7. Add a reason to accept, suppress, or reopen a finding; the event is retained.

No scan runs during registration. Scans are explicit actions. The service
refuses workspace roots that are symlinks and the CloudSentry adapter refuses
symlinks inside a workspace.

## Safety

Do not bind this development service to `0.0.0.0` or expose it to the internet.
It has no user authentication because it is a local single-operator mode.
Production deployment requires OIDC authentication, tenant membership checks,
PostgreSQL RLS context, durable worker isolation, rate limits, secrets handling,
and an independently reviewed authorization workflow before exposing API access.
