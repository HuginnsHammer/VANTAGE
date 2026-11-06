# VANTAGE command-line interface

The local CLI runs the CloudSentry adapter through VANTAGE's authorization coordinator.
An optional SQLite finding ledger adds durable local finding history.

## Install

Install CloudSentry separately and ensure its executable is available to the operator
environment. Then install VANTAGE:

```fish
pip install -e ".[dev]"
vantage scanners list
```

## Run an authorized local workspace assessment

```fish
vantage scan workspace ~/CloudSentry \
  --authorization-reference "ENGAGEMENT-OR-TICKET-ID" \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --output cloudsentry-report.json
```

VANTAGE prints the resolved target and requires the operator to type the exact
`AUTHORIZE <absolute-path>` confirmation. The command performs local static IaC/container
analysis only; it does not probe the network. The output path must be in an existing
directory and must not already exist.

When `--ledger` is supplied, VANTAGE stores normalized finding records and lifecycle events
in SQLite. The local organization identity is derived from the resolved ledger path and
the asset identity from the resolved workspace path, so repeat scans against the same
workspace and ledger correlate across CLI invocations. Moving the ledger creates a different
local profile identity; keep the database path stable and back it up.

## Review findings

List all findings in the local profile:

```fish
vantage findings list --ledger ~/.local/state/vantage/findings.sqlite3
```

Filter to one workspace:

```fish
vantage findings list \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --workspace ~/CloudSentry
```

Record an analyst disposition. A reason is mandatory and retained in the event history:

```fish
vantage findings set-status FINDING-UUID \
  --ledger ~/.local/state/vantage/findings.sqlite3 \
  --status accepted_risk \
  --reason "Compensating control documented in ENG-123"
```

Supported manual dispositions are `open`, `accepted_risk` and `suppressed`.
A finding that reappears after a completed scan resolved it is marked `reopened`.
Inspect the append-only event history for a finding:

```fish
vantage findings history FINDING-UUID \
  --ledger ~/.local/state/vantage/findings.sqlite3
```

## Lifecycle and risk semantics

- Finding identity is scoped by organization, asset, scanner and scanner fingerprint.
- Repeated observations update the same record, increment its occurrence count and append
  an event; they do not create a new finding identity.
- Only a `completed` assessment can resolve previously open findings absent from its
  result. Partial, failed or cancelled assessments never resolve findings by absence.
- Accepted-risk and suppressed dispositions are preserved when the finding is observed again.
- Risk priority is a transparent 0-100 score derived from severity, confidence and an
  optional asset-criticality multiplier (0.5-2.0). It is a prioritization heuristic, not a
  probability of compromise. The CLI currently uses the neutral multiplier of 1.0.
- The SQLite ledger is a local single-operator adapter. It is not yet the multi-tenant
  PostgreSQL control-plane store; production deployments still need authenticated identity,
  tenant-scoped database authorization, migrations, backup/restore and retention controls.

## Exit status

- `0`: scan completed successfully.
- `1`: scan returned partial or failed status.
- `2`: invalid input, missing dependency, denied confirmation or execution error.

## Scope and safety

Only assess workspaces you own or are explicitly authorized to test. The current CLI
supports local workspace scanning through CloudSentry. It does not provide internet-facing
reconnaissance, exploit execution, credential attacks or arbitrary command execution.
