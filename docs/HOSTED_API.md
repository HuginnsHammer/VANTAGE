# Hosted VANTAGE API

This is the hosted multi-tenant API, separate from the loopback-only local
workspace application at vantage.api.app:app.

## Implemented endpoints

All routes below require an OIDC access token in the Authorization: Bearer
header, except the health endpoint.

| Method | Route | Purpose |
|---|---|---|
| GET | /api/v2/health | Database/service health |
| GET | /api/v2/me | Provision identity and personal workspace; list memberships |
| POST | /api/v2/organizations | Create an organization workspace; creator becomes owner |
| GET | /api/v2/organizations/{id} | Read an accessible workspace |
| GET | /api/v2/organizations/{id}/members | List members (owner/admin only) |
| POST | /api/v2/organizations/{id}/projects | Create a project (owner/admin/analyst/operator) |
| GET | /api/v2/organizations/{id}/projects | List projects |

Inaccessible organizations return 404 rather than disclosing whether the
organization exists. User identity is keyed by the exact OIDC issuer and
subject. Email is stored only when the provider marks it verified.

## Database roles and migrations

Use two separate PostgreSQL roles:

- A migration role that owns schema objects and can apply Alembic migrations.
- A runtime role with NOSUPERUSER, NOBYPASSRLS, no ownership of tenant
  tables, and only the required DML grants.

The hosted API checks the runtime role at startup and refuses superusers,
BYPASSRLS roles, and tenant-table owners. Never point the hosted API at the
migration/admin connection string.

Example migration workflow (replace credentials and database host):

~~~fish
set -x VANTAGE_MIGRATION_DATABASE_URL "postgresql+psycopg://vantage_migrator:...@db-host/vantage"
alembic upgrade head
set -e VANTAGE_MIGRATION_DATABASE_URL
~~~

Grant the runtime role access after migration, using the migration/admin role:

~~~sql
CREATE ROLE vantage_app LOGIN PASSWORD 'use-a-secret-manager'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT CONNECT ON DATABASE vantage TO vantage_app;
GRANT USAGE ON SCHEMA public TO vantage_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vantage_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vantage_app;
~~~

Then configure the hosted API with the restricted runtime role:

~~~fish
set -x VANTAGE_DATABASE_URL "postgresql+psycopg://vantage_app:...@db-host/vantage"
set -x VANTAGE_OIDC_ISSUER "https://your-issuer/"
set -x VANTAGE_OIDC_AUDIENCE "https://api.your-domain.example"
set -x VANTAGE_OIDC_JWKS_URL "https://your-issuer/.well-known/jwks.json"
set -x VANTAGE_CORS_ORIGINS "https://app.your-domain.example"
pip install -e ".[api,auth,postgres]"
uvicorn vantage.api.hosted:create_app --factory --host 127.0.0.1 --port 8765
~~~

The API expects RS256-signed JWT access tokens whose issuer, audience, expiry,
issued-at time and subject validate. Use HTTPS for issuer/JWKS URLs and for
all public traffic. When deployed, terminate TLS at a trusted reverse proxy
and bind the service only to the private application network.

## Identity provider setup still required

VANTAGE does not issue credentials or implement a browser authorization-code
callback yet. Configure an OIDC provider to issue access tokens for the VANTAGE
API audience, then integrate its authorization-code + PKCE browser flow with
the future hosted frontend. Do not put an OIDC client secret in browser code.
The API accepts bearer tokens only; it does not accept unsigned development
tokens or trust a user ID supplied by a client.

## Current boundaries

- Personal workspace is provisioned on the first authenticated API request.
- Organization creation grants the creator the owner role.
- Membership enumeration is limited by PostgreSQL RLS to the authenticated
  actor's own memberships; tenant resources require active membership.
- Project operations are role-gated and audit logged.
- Invitations, member role changes, browser login, hosted UI integration,
  asset registration/ownership verification, hosted scans, durable queues,
  and scanner-node enrollment are not implemented in this milestone.
