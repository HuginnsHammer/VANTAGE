# VANTAGE architecture

## Product boundary
VANTAGE is a new product and control plane. CloudSentry remains an independent IaC/container scanner and becomes an integrated engine. LLMShield remains an independent AI-application security component. Hundred is an optional analyst assistant, not a privileged scanner runtime.

## Hybrid topology
1. **Control plane** — identity, organizations, assets, approved scopes, scan plans, policies, findings, audit history and integrations.
2. **Queue** — durable jobs with tenant quotas, idempotency, cancellation and retry policies.
3. **Scanner nodes** — customer-managed or VANTAGE-managed isolated workers. Nodes establish outbound authenticated connections; the control plane does not open inbound access into customer networks.
4. **Evidence plane** — normalized observations and immutable evidence references, with redaction and retention policies.
5. **Analyst experience** — dashboards, triage, remediation, verification and reports.

## Initial stack
- Python 3.12+, FastAPI, Pydantic
- PostgreSQL + SQLAlchemy + Alembic
- Redis-backed queue (Celery, Dramatiq or ARQ decision deferred pending benchmarks)
- React + TypeScript frontend
- OCI containers for scanner isolation
- OpenTelemetry for traces, metrics and logs
- OIDC for identity; no bespoke password system in the first hosted release

## Scanner contract
Every scanner declares a stable ID, supported asset kinds, capabilities, required permissions, network requirements, resource limits and output schema version. It receives a validated asset and verified scan context, never arbitrary user-controlled shell commands.

The coordinator checks tenant, asset, scope, expiry, scanner allowlist and active-check permission before dispatch. Results are rejected if they claim a different tenant, asset or scanner identity.

## Data model
Organization → Membership → Project → Environment → Asset → ApprovedScope → Scan → Finding → Evidence.

Finding identity is stable across scans. Scan observations record present, absent, not checked, or unobservable. An incomplete scan must never automatically resolve a previously observed finding.

## Deployment modes
- SaaS control plane + managed workers
- SaaS control plane + customer-managed private nodes
- Fully self-hosted control plane and workers
- Hybrid with local evidence retention and optional cloud metadata sync

## Deferred decisions
Queue implementation awaits throughput and delivery-semantics benchmarks. PostgreSQL is sufficient for the first graph model; a graph database is not justified yet. Kubernetes is deferred until worker scale requires it. AI is not in the scanner execution path.
