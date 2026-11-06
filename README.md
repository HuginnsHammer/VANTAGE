# VANTAGE

**Evidence-led security exposure management and validation.**

VANTAGE is a hybrid cybersecurity platform built around a secure control plane
and isolated scanner workers. It integrates specialist engines such as
CloudSentry while providing shared asset inventory, authorization, scan
orchestration, evidence, findings, verification and reporting.

> Active development. The local web application currently supports explicitly
> authorized local workspace analysis; production multi-tenant and network
> assessment capabilities are not yet enabled.

## Run the local web application

Python 3.12+ and a separately installed CloudSentry executable are required.

```fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e ".[api,dev]"
uvicorn vantage.api.app:app --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765/app**. Register a local workspace you own or are
explicitly authorized to assess, provide an authorization reference, confirm
the resolved path, and then explicitly start an assessment. Findings and
assessment history persist locally under `~/.local/share/vantage/`.

See [Local web application guide](docs/LOCAL_APP.md) for the full setup,
workflow, boundaries and safety model.

## CLI

```fish
pip install -e ".[dev]"
vantage scanners list
vantage scan workspace ~/CloudSentry \
  --authorization-reference "ENGAGEMENT-OR-TICKET-ID" \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --output cloudsentry-report.json
```

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

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md),
[Scanner Integration](docs/SCANNER_INTEGRATION.md), [CLI guide](docs/CLI.md),
[Roadmap](docs/ROADMAP.md), and [Tenancy](docs/TENANCY.md).

The PostgreSQL schema and row-level-security migration are an initial foundation,
not a deployed control plane. OIDC authentication, membership authorization
services, production API hosting, distributed workers, network scanning,
verification workflows and enterprise controls remain under development.
