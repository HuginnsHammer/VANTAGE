# Running the first VANTAGE scanner

VANTAGE currently integrates the CloudSentry local IaC/container scanner. This is a local workspace scan, not an internet-facing network scanner.

## Prerequisites

1. Install CloudSentry from its own repository using its documented development setup.
2. Ensure the \`cloudsentry\` executable is on the scanner worker's PATH, or provide an absolute executable path in the VANTAGE scanner configuration.
3. Run VANTAGE in the same local environment that can access the approved workspace. The current bounded subprocess runner uses POSIX process groups; Linux is the supported local/OCI execution environment.

## Python integration

The caller must first create an asset and an explicit approved scope. The following is a local development example; replace the authorization reference with the real approval record used by your organization.

\`\`\`python
from pathlib import Path
from uuid import uuid4

from vantage.domain.models import Asset, AssetKind, ApprovedScope, ScanRequest
from vantage.scanning.builtins import build_default_registry
from vantage.scanning.coordinator import ScanCoordinator

organization_id = uuid4()
operator_id = uuid4()
workspace = Path("~/CloudSentry/examples").expanduser().resolve()

asset = Asset(
    organization_id=organization_id,
    kind=AssetKind.LOCAL_WORKSPACE,
    canonical_value=str(workspace),
)

scope = ApprovedScope(
    organization_id=organization_id,
    asset_id=asset.id,
    approved_by=operator_id,
    authorization_reference="replace-with-approved-engagement-reference",
    allowed_scanner_ids=frozenset({"cloudsentry"}),
)

request = ScanRequest(
    organization_id=organization_id,
    asset_id=asset.id,
    scope_id=scope.id,
    scanner_id="cloudsentry",
    requested_by=operator_id,
)

coordinator = ScanCoordinator(build_default_registry())
report = coordinator.run(asset, scope, request)

print(report.state)
for finding in report.findings:
    print(finding.severity, finding.rule_id, finding.title)
\`\`\`

## Execution safeguards

- The CloudSentry executable is trusted operator configuration, not user input.
- Workspace paths are passed as separate process arguments; shell execution is disabled.
- The runner enforces a configurable timeout (300 seconds by default) and caps combined stdout/stderr at 8 MiB by default.
- The scanner starts in a separate POSIX process group. Timeout and output-limit failures terminate that group, including ordinary child processes.
- The runner rejects unexpected exit codes and malformed JSON reports.
- Symlinked workspace roots and discovered symlink entries are rejected before execution.
- CloudSentry's exit status and report status are preserved; partial scans are not clean scans.
- Imported findings remain unverified until a separate verification process confirms them.
- Imported evidence, finding descriptions, remediation text, warnings, errors and process diagnostics pass through a best-effort secret sanitizer. It covers common private-key blocks, AWS access-key IDs, GitHub tokens, JWTs, bearer/basic authorization values, URL passwords and literal values assigned to common secret fields.

The sanitizer is defense in depth, not a complete data-loss-prevention guarantee. The output cap bounds captured process output, but the current runner is not an OS sandbox and does not impose CPU, memory, filesystem or network isolation. Protect the local VANTAGE data directory and review reports before sharing them outside the authorized assessment team.

## Current limitations

The current runner is a local process adapter. It is not yet a durable worker, remote scanner node, authenticated API, or multi-tenant scan service. Do not expose it directly to untrusted clients. OCI isolation, resource quotas, egress controls, PostgreSQL-backed scan persistence and durable queueing remain roadmap work.
