## ADR-003: Produce Both JSON and CSV Output Formats

# Status: 
Accepted

# Context:
The toolkit generates audit findings that may be consumed by different audiences: engineers triaging misconfigurations, compliance teams producing evidence packs, and automated pipelines ingesting findings for further processing. A single output format was considered, as was supporting multiple formats.

# Decision:
The reporting module (shared/report.py) generates findings in both JSON and CSV formats, written to a timestamped file in the shared/Results/ directory.

# Reasoning:
JSON and CSV serve fundamentally different consumer needs. JSON preserves the full structured finding schema, supports programmatic ingestion by downstream tooling (dashboards, ticketing systems, automated remediation pipelines), and is the natural format for API-driven workflows. CSV provides flat, human-readable output suitable for compliance evidence packs, spreadsheet review, and non-technical stakeholders. Generating both from a single findings object adds negligible overhead and avoids requiring consumers to transform formats themselves. This dual-output pattern is consistent with how production security tooling (vulnerability scanners, audit platforms) handles reporting.

# Consequences:
Every audit run produces two output files per execution. The findings object serves as the single source of truth; both output formats are derived representations. Adding a new output format (e.g., SARIF for CI/CD pipeline integration) requires only a new serialiser in report.py without changes to audit logic.




