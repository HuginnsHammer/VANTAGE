# VANTAGE roadmap

## M0 — contracts and architecture (starter)
- Domain contracts for assets, approved scopes, scans, findings and evidence.
- Scanner protocol, registry and scope-enforcing coordinator.
- CloudSentry report normalization.
- Unit tests for authorization gates and partial-scan handling.

## M1 — scanner platform foundations
- PostgreSQL schema and Alembic migrations.
- Durable scan queue, idempotency, retries, cancellation and quotas.
- Authenticated OIDC control-plane API.
- Asset, project, environment and scope management.
- Tenant isolation tests against PostgreSQL.

## M2 — first scanning capabilities
- CloudSentry integration for IaC/container configuration.
- Passive external asset inventory: DNS records, certificate transparency references and safe metadata enrichment.
- Domain ownership verification (DNS TXT / HTTP well-known challenge).
- Strict target canonicalization and public-IP/egress protections.
- Evidence-backed HTTP/TLS posture checks only after scope verification.

## M3 — distributed hybrid nodes
- Outbound-only node enrollment with short-lived credentials and mTLS.
- Signed, expiring scan job envelopes.
- OCI-isolated workers and per-tenant resource budgets.
- Node health, versioning, revocation and audit history.

## M4 — deeper security coverage
- Web/API assessment profiles based on versioned OWASP WSTG and ASVS requirements.
- Dependency and secret exposure integrations.
- Cloud configuration and identity posture.
- Authenticated testing only with customer-scoped credentials and explicit approvals.

## M5 — verification and intelligence
- Reproducible verification steps and confidence levels.
- Finding lifecycle and safe retesting.
- Attack-path graph with evidence links.
- Threat-intelligence correlation and KEV prioritization.
- AI explanations grounded in findings and source evidence.

## M6 — enterprise readiness
- SSO, MFA policy, SCIM, RBAC/ABAC and audit exports.
- Customer-managed encryption keys and retention controls.
- Compliance mapping, reporting and APIs.
- High availability, disaster recovery, backup/restore and observability.
- Independent penetration test and security review.

A milestone is complete only when implementation, tests, documentation, threat model and operational limitations agree.
