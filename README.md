# VANTAGE

**Evidence-led security exposure management and validation.**

VANTAGE is a hybrid cybersecurity platform built around a secure control plane
and isolated scanner workers. It integrates specialist engines such as
CloudSentry while providing shared asset inventory, authorization, scan
orchestration, evidence, findings, verification and reporting.

> Active development. The local workspace application supports explicitly
> authorized local assessments. A separate hosted API now provides
> OIDC-authenticated personal and organization workspaces on PostgreSQL; it is
> not yet publicly deployed.

## Run the local web application

Python 3.12+ and a separately installed CloudSentry executable are required.

~~~fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e ".[api,dev]"
uvicorn vantage.api.app:app --host 127.0.0.1 --port 8765
~~~

Open **http://127.0.0.1:8765/app**. Register a local workspace you own or are
explicitly authorized to assess, provide an authorization reference, confirm
the resolved path, and then explicitly start an assessment. Findings and
assessment history persist locally under ~/.local/share/vantage/.

See docs/LOCAL_APP.md for the local workflow and safety model.

## Hosted API foundation

The hosted API is separate from the loopback-only local app. It requires
PostgreSQL, a restricted non-owner runtime role and an OIDC provider issuing
RS256 JWT access tokens for the configured API audience.

See docs/HOSTED_API.md and docs/TENANCY.md.

~~~fish
pip install -e ".[api,auth,postgres]"
set -x VANTAGE_DATABASE_URL "postgresql+psycopg://vantage_app:...@db-host/vantage"
set -x VANTAGE_OIDC_ISSUER "https://issuer.example/"
set -x VANTAGE_OIDC_AUDIENCE "https://api.vantage.example"
set -x VANTAGE_OIDC_JWKS_URL "https://issuer.example/.well-known/jwks.json"
uvicorn vantage.api.hosted:create_app --factory --host 127.0.0.1 --port 8765
~~~

The API provisions a personal workspace on first authenticated request,
creates organization workspaces, lists memberships, and manages projects.
It accepts verified OIDC bearer tokens; a browser login flow and public
deployment are not included yet.

## CLI

~~~fish
pip install -e ".[dev]"
vantage scanners list
vantage scan workspace ~/CloudSentry \
  --authorization-reference "ENGAGEMENT-OR-TICKET-ID" \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --output cloudsentry-report.json
~~~

Only local static IaC/container analysis is supported by the first scanner.
It does not perform network reconnaissance or exploit testing. The CLI requires
an exact interactive confirmation of the resolved workspace path.

## Product model

VANTAGE serves two audiences on one security platform:

- **Individuals:** a self-service personal workspace to assess assets they own
  or are explicitly authorized to test, understand evidence-backed findings,
  and follow practical remediation guidance.
- **Organizations:** the primary product audience, with isolated tenants,
  projects, environments, teams, governed scopes, continuous exposure
  management, remediation workflows and enterprise deployment controls.

Personal and organization workspaces share the same security and authorization
model. A personal account is not a shortcut around scope verification.

## Architecture and security

See docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/SCANNER_INTEGRATION.md,
docs/CLI.md, docs/ROADMAP.md and docs/TENANCY.md.

The PostgreSQL schema, row-level-security migrations and OIDC-authenticated
workspace API are implemented foundations, not a deployed service. Browser
login, invitations and membership administration, hosted frontend integration,
distributed workers, external asset verification, network scanning,
verification workflows and enterprise controls remain under development.
