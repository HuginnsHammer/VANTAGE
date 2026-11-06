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
  --output cloudsentry-report.json
```

VANTAGE requires an exact interactive confirmation of the resolved workspace path before starting. The first CLI is local static IaC/container analysis; it does not perform network reconnaissance or exploit testing. See the [CLI guide](docs/CLI.md) for limitations and exit codes.

## Current engineering milestone

- Canonical asset, approved-scope, scan, finding and evidence contracts.
- Scanner plugin protocol, registry and scope-enforcing coordinator.
- CloudSentry report normalization that preserves partial-scan status.
- Operator CLI for listing scanners and running explicitly confirmed local workspace scans.
- JSON report export and a deliberately vulnerable training fixture.
- Automated tests for authorization gates, report normalization and CLI behavior.

This is an early engineering foundation, not yet a production security platform. Durable storage, authenticated API, distributed workers, network scanning, tenant isolation, verification workflows and enterprise controls remain under development.
