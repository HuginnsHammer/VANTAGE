# VANTAGE threat model (initial)

## Assets
Tenant data, identity tokens, scanner enrollment credentials, scope approvals, scan results, evidence, customer network access and worker integrity.

## Threats and required controls
| Threat | Required control |
|---|---|
| Cross-tenant access | Tenant-scoped queries, composite database constraints and isolation tests |
| Unauthorized scanning | Verified authority, signed scope, expiry and scanner allowlist |
| Scope escape / SSRF | Canonical target parsing, DNS/IP policy, redirect revalidation and egress firewall |
| Scanner compromise | Ephemeral isolated workers, read-only root FS, dropped capabilities and resource limits |
| Malicious input | Size limits, parser hardening, no execution of target files and bounded output |
| Forged scanner results | Node identity, signed job envelope, authenticated result channel and schema validation |
| Evidence secret leakage | Redaction before persistence, encryption, strict access and retention |
| Queue replay | Job IDs, nonce, expiry, idempotency and replay protection |
| AI prompt injection | Treat findings/pages as untrusted data; no tool or remediation authority from model output |
| Supply-chain compromise | Pinned dependencies, SBOM, signed images, provenance and dependency scanning |

## Current local scanner boundary

The local CloudSentry adapter now streams stdout and stderr under a combined
8 MiB default cap, enforces a configurable timeout, and starts the scanner in a
separate POSIX process group so timeout and output-overflow failures can terminate
ordinary child processes. This reduces unbounded report/diagnostic capture and
prevents a timed-out child process from being left running in the same group.

These controls do not constitute a sandbox. The scanner still runs as the VANTAGE
OS user and can access whatever files and network resources that user can access.
CPU, memory, filesystem and egress isolation, OCI worker hardening and per-tenant
resource budgets remain required before hosted or untrusted scan execution.

## Safe defaults
- No active exploitation in the initial milestone.
- No scanning until scope is explicitly approved.
- No wildcard scope by default.
- No redirect following without destination revalidation.
- No private, loopback, link-local, multicast or metadata-service destinations for external scans.
- No arbitrary shell commands supplied by API callers.
- No automatic remediation without separate approval and rollback.
- Incomplete scans cannot mark missing findings resolved.

## Release gate
A hosted scan endpoint is not production-ready until scope authorization, tenant isolation, scanner isolation, egress controls, quotas, audit records and PostgreSQL integration tests are implemented and independently reviewed.
