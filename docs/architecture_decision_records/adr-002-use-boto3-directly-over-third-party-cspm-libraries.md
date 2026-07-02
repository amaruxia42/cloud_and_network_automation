## ADR-002: Use Boto3 Directly Over Third-Party CSPM Libraries

## Status
Accepted

## Context:
Several open-source CSPM frameworks exist (Prowler, ScoutSuite, CloudMapper) that provide pre-built AWS audit capabilities. Alternatively, the toolkit could be built directly against the AWS SDK using Boto3.

## Decision:
The toolkit is built directly on Boto3 with no dependency on third-party CSPM frameworks.

## Reasoning:
Third-party CSPM tools are valuable operational tools but provide limited portfolio signal — deploying Prowler demonstrates tool knowledge, not engineering capability. Building directly on Boto3 requires understanding the underlying AWS APIs, response schemas, and error handling at a level that third-party abstractions conceal. This approach also gives full control over compliance mapping logic, finding schema design, output formatting, and execution behaviour. As a portfolio and learning artefact, direct SDK usage demonstrates depth of AWS service knowledge that framework usage does not.

## Consequences:
Each audit module requires explicit knowledge of the relevant AWS APIs and response structures. This is intentional — the implementation effort is the point. The trade-off is that coverage breadth is narrower than mature CSPM tools, which is acceptable given the project's engineering demonstration objectives.