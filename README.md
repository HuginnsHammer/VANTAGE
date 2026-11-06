# VANTAGE

**Evidence-led security exposure management and validation.**

VANTAGE is a hybrid cybersecurity platform built around a secure control plane and isolated scanner workers. It integrates specialist engines such as CloudSentry while providing shared asset inventory, authorization, scan orchestration, evidence, findings, verification and reporting.

> Early foundation: this repository is under active development. Network scanning and production multi-tenant operation are not yet enabled.

## Principles

- Evidence before conclusions; AI cannot invent vulnerability facts.
- Every assessment is tied to an explicitly approved scope and rules of engagement.
- Passive and local analysis first; active checks require explicit approval.
- Hybrid deployment: cloud control plane, customer-managed scanner nodes, and self-hosted installations.
- No arbitrary remote filesystem paths or shell commands from API requests.
- Incomplete scans never silently resolve existing findings.

## Architecture

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), [Scanner Integration](docs/SCANNER_INTEGRATION.md), [CLI guide](docs/CLI.md), [Roadmap](docs/ROADMAP.md), and [Architecture Decisions](docs/DECISIONS.md).

## Quick start

Python 3.12+ and a separately installed CloudSentry executable are required for local workspace assessments.

```fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e ".[dev]"
vantage scanners list
```

Run a local assessment only against a workspace you own or are explicitly authorized to assess:

```fish
vantage scan workspace ~/CloudSentry \
  --authorization-reference "ENGAGEMENT-OR-TICKET-ID" \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --output cloudsentry-report.json
```

Review the findings across repeated scans:

```fish
vantage findings list --ledger ~/.local/state/vantage/findings.sqlite3
```

VANTAGE requires an exact interactive confirmation of the resolved workspace path before starting. The first scanner is local static IaC/container analysis; it does not perform network reconnaissance or exploit testing. See the [CLI guide](docs/CLI.md) for lifecycle behavior and limitations.

## Product model

VANTAGE serves two audiences on one security platform:

- **Individuals:** a self-service personal workspace to assess assets they own or are explicitly authorized to test, understand evidence-backed findings, and follow practical remediation guidance.
- **Organizations:** the primary product audience, with isolated tenants, projects, environments, teams, governed scopes, continuous exposure management, remediation workflows and enterprise deployment controls.

Personal and organization workspaces share the same security and authorization model. A personal account is not a shortcut around scope verification: users must still prove or explicitly attest to authority before assessments are enabled.

## Current engineering milestone

- Canonical asset, approved-scope, scan, finding and evidence contracts.
- Scanner plugin protocol, registry and scope-enforcing coordinator.
- CloudSentry report normalization that preserves partial-scan status.
- Operator CLI for explicitly confirmed local workspace assessments.
- Optional SQLite finding ledger with stable identities, deduplication and event history.
- Finding lifecycle states for open, reopened, resolved, accepted risk and suppressed.
- Risk prioritization grounded in severity, confidence and asset criticality.
- PostgreSQL tenant schema foundation for personal and organization workspaces, memberships, projects, environments, assets, approved scopes and audit events.
- Database-enforced tenant row-level security policies and append-only audit-event trigger in the initial migration.
- Incomplete assessments cannot resolve findings merely because they were absent.

This is an early engineering foundation, not yet a production security platform. The PostgreSQL schema and migration are an initial foundation, not a deployed control plane. OIDC authentication, membership authorization services, PostgreSQL integration tests, API endpoints, distributed workers, network scanning, verification workflows and enterprise controls remain under development.
