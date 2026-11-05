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

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), [Roadmap](docs/ROADMAP.md), and [Architecture Decisions](docs/DECISIONS.md).

## Development

Python 3.12+.

```fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e ".[dev]"
pytest
ruff check .
```

## Initial milestone

- Canonical asset, approved-scope, scan, finding and evidence contracts.
- Scanner plugin protocol and registry.
- Scope-enforcing scan coordinator.
- CloudSentry report normalization that preserves partial-scan status.
- Tests for authorization gates and report normalization.

See [ROADMAP.md](docs/ROADMAP.md) for planned implementation stages.
