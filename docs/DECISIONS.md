# Architecture decision records

## ADR-001: VANTAGE is a new product, not a CloudSentry rename
CloudSentry remains an independent IaC/container scanner. VANTAGE owns orchestration, scope, tenant identity, evidence normalization and cross-engine workflows.

## ADR-002: PostgreSQL first; graph database later if justified
Strong tenant constraints and transactional lifecycle semantics matter more than a specialized graph store at this stage.

## ADR-003: Scanner workers are separate from the API
The API validates intent and queues work. Isolated workers execute bounded jobs; HTTP request processes never run scans.

## ADR-004: Passive-first scanning
Initial external discovery and posture checks are passive or low-impact. Active validation is a distinct capability requiring explicit scope permission.

## ADR-005: AI is advisory
AI may summarize and prioritize evidence. It cannot create confirmed findings, approve scope, execute arbitrary tools or remediate systems.
