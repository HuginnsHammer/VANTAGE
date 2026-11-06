# VANTAGE tenancy and PostgreSQL foundation

## Audience model

VANTAGE uses one tenant model for two account kinds:

- \`personal\`: a private workspace for an individual.
- \`organization\`: a workspace for a company, institution or team.

An individual may belong to multiple organizations. Personal workspaces and organizations use the same asset, project, environment, approved-scope and finding concepts. Organization workspaces add team membership and governance; they do not weaken the authorization rules used by personal accounts.

## Identity and authorization

\`user_identities\` stores the stable OpenID Connect issuer/subject pair. Email is profile metadata, never an identity key. Membership roles are constrained to owner, admin, security analyst, operator and viewer. Membership status is explicit.

The schema is not an authentication implementation. A future API must validate OIDC tokens (issuer, audience, signature, expiry and nonce/state as appropriate), resolve the stable issuer/subject identity, and authorize active membership before any tenant operation.

A client-supplied organization ID is an untrusted selector, not proof of membership. Inside a transaction, the API may first set that candidate organization as the RLS row filter, then query membership using both that organization ID and the authenticated user ID. It must reject absent, invited or suspended memberships before performing any other tenant operation. The organization selector cannot authorize access by itself.

## Tenant isolation

Every tenant-owned row carries an \`organization_id\`. Composite foreign keys ensure that a project, environment, asset, approved scope and audit record cannot be attached across organizations even if an application bug supplies mismatched identifiers.

The initial migration enables and forces PostgreSQL row-level security for organizations, memberships, projects, environments, assets, approved scopes and audit events. Tenant queries must run inside a transaction after membership authorization:

\`\`\`python
with session.begin():
    # First validate the authenticated user's membership for this org.
    set_tenant_context(session, organization_id)
    # All subsequent tenant queries in this transaction are RLS-filtered.
\`\`\`

The setting is transaction-local and clears on commit/rollback. If it is absent, the policy returns no tenant rows. The production runtime database role must not be a superuser, must not have BYPASSRLS, and should not own the protected tables. Use a separate migration role for schema changes.

RLS is defense in depth. Service-layer authorization is still required, especially for membership changes, role checks and scope approval. PostgreSQL integration tests are a release gate; schema-level unit tests alone do not prove deployed isolation.

## Assessment authorization

Approved scopes bind an organization, asset and approving membership. Active checks default to disabled. Scanner allowlists, expiry and revocation are stored with the scope. The scan coordinator must continue to enforce scanner capability and explicit approval before dispatch.

A personal account is not blanket authorization to scan arbitrary internet assets. Ownership verification and safe target validation are required before external assessment.

## Audit events

Audit events are tenant-scoped and the migration installs a database trigger rejecting UPDATE and DELETE. The application should insert events for membership changes, scope approval/revocation, scan actions, finding dispositions and administrative changes. Database owners/superusers can bypass application protections; production operations must tightly control those credentials and export audit data to an independently protected destination.

## Migration and dependencies

Install the PostgreSQL extra:

\`\`\`fish
pip install -e ".[postgres,dev]"
\`\`\`

Set the connection URL without committing secrets:

\`\`\`fish
set -x VANTAGE_DATABASE_URL "postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE"
alembic upgrade head
\`\`\`

The initial migration is \`0001_tenant_control_plane\`. Do not run it against a production database until a PostgreSQL integration environment, backup, rollback plan and independent review are in place.

## Explicitly not implemented yet

- OIDC login/callback/token validation.
- User registration and automatic personal-workspace provisioning.
- Organization invitations, membership management and role authorization services.
- API endpoints or frontend.
- PostgreSQL-backed finding lifecycle repository (the existing lifecycle ledger remains local SQLite).
- PostgreSQL integration tests against a real server.
- Durable scan queue, scanner-node enrollment or production deployment hardening.
