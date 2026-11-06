# VANTAGE command-line interface

The first CLI milestone exposes the local CloudSentry integration without bypassing the
existing authorization coordinator.

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
  --output reports/cloudsentry.json
```

VANTAGE prints the resolved target and requires the operator to type the exact
`AUTHORIZE <absolute-path>` confirmation. The command performs local static IaC/container
analysis only; it does not probe the network. The output path must be in an existing
directory and must not already exist.

The CLI creates ephemeral organization and operator identifiers for this single-process
local workflow. They are not persistent identities and do not constitute enterprise audit
identity. The authorization reference is carried into the in-memory approved-scope object.
Production use requires authenticated principals, durable authorization records and
persistent audit storage.

## Exit status

- `0`: scan completed successfully.
- `1`: scan returned partial or failed status.
- `2`: invalid input, missing dependency, denied confirmation or execution error.

## Scope and safety

Only assess workspaces you own or are explicitly authorized to test. The current CLI
supports local workspace scanning through CloudSentry. It does not provide internet-facing
reconnaissance, exploit execution, credential attacks or arbitrary command execution.
