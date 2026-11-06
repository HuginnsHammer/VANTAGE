# VANTAGE tenancy and PostgreSQL foundation

## Account model

VANTAGE uses one tenant model for two account kinds:

- Personal workspaces for individuals.
- Organization workspaces for companies, institutions and teams.

Both use the same assets, projects, environments, approved scopes and findings.
Organization workspaces add membership and governance; they do not weaken
authorization requirements for personal users.

## Identity and authentication

The hosted API accepts RS256-signed OIDC JWT access tokens. It validates the
configured issuer, audience, signature, expiry, issued-at time and subject
against the configured JWKS endpoint. The stable identity key is the exact
issuer/subject pair. Email is profile metadata and is stored only when the
provider asserts email_verified=true.

The API does not trust a client-supplied user ID. A personal workspace is
provisioned deterministically on the first authenticated API request. The
browser authorization-code + PKCE login flow and provider-specific client
configuration are not yet implemented; the hosted API currently accepts
bearer tokens from an already configured OIDC provider.

## Tenant authorization and row-level security

Every tenant-owned row carries organization_id. Composite foreign keys prevent
cross-organization project, environment, asset and approved-scope relationships.

PostgreSQL RLS is enabled and forced for user identities, organizations, memberships, projects,
environments, assets, approved scopes and audit events. The API sets
transaction-local organization and actor context. An organization ID supplied
by a client is only a candidate selector: the service must verify that the
authenticated identity has an active membership before accessing workspace
resources. Inaccessible workspaces return 404.

Membership RLS has a narrow additional policy: with actor context but no
organization context, the caller can enumerate only membership rows whose
user_id equals the authenticated identity. This allows the /me endpoint to
list that user's workspaces without granting access to other members or tenant
resources. With organization context, normal organization isolation applies.
The write policy still requires the organization context.

Identity records are visible only to the authenticated identity itself or to members of the same active organization context. Identity IDs are deterministic from the verified issuer/subject pair so the API can establish self-context before reading or provisioning a profile. The hosted API refuses PostgreSQL superuser, BYPASSRLS and tenant-table-owner
runtime roles. Run migrations with a separate owner/migration role. RLS is
defense in depth; service-layer role checks remain mandatory.

## Roles

Membership roles are owner, admin, security_analyst, operator and viewer.
Current project creation is limited to owner, admin, security_analyst and
operator. Member listing is limited to owner and admin. Invitations, role
changes, suspension and SCIM are not yet implemented.

## Domain ownership verification\n\nAuthenticated workspace members can register canonicalized public domain names and request a short-lived DNS TXT challenge at _vantage-challenge.<domain>. VANTAGE stores only a hash of the challenge value, limits challenge creation, verifies the DNS response, records the verification timestamp and writes audit events. DNS verification establishes control of the domain namespace; it does not grant permission for active security testing. No network scanner is dispatched by these endpoints.\n\n## Approved assessment scope

Approved scopes bind an organization, asset and approving membership. Active
checks default to disabled. Scanner allowlists, expiry and revocation are stored
with the scope. The scan coordinator must continue enforcing scanner capability
and explicit approval before dispatch.

A personal account is not blanket authorization to scan arbitrary internet
assets. Ownership verification and safe target validation are required before
external assessment.

## Audit events

Audit events are tenant-scoped and append-only at the database trigger layer.
The current hosted API records personal/organization workspace provisioning,
organization creation and project creation. Membership changes, scope
approval/revocation, scan actions and finding dispositions must be added as
those workflows are implemented. Audit exports and independent retention are
future operational work.

## Migrations and database roles

Migration 0001 creates the tenant schema and initial RLS policies. Migration
0002 allows authenticated actors to enumerate their own memberships. Migration
0003 adds actor/organization-scoped visibility to identity records.

Use VANTAGE_MIGRATION_DATABASE_URL for Alembic and VANTAGE_DATABASE_URL for
the restricted hosted runtime connection. Never use the migration/admin
connection for the public API.

See docs/HOSTED_API.md for exact setup and grant commands.

## Not yet implemented

- Browser OIDC authorization-code + PKCE login/callback.
- Organization invitations and membership role administration.
- Hosted frontend integration and public deployment.
- PostgreSQL-backed finding lifecycle repository (findings remain in the local
  SQLite adapter today).
- Domain ownership verification, hosted assessment orchestration, durable
  scan queue and scanner-node enrollment.
- Production observability, backup/restore, incident response and independent
  security review.
