from typing import List
from botocore.exceptions import ClientError, EndpointConnectionError
from shared.logger import get_logger
from shared.aws_clients import get_dynamodb, get_app_autoscaling
from shared.report import AuditFinding, ServicesAuditReport

logger = get_logger(__name__)
autoscaling = get_app_autoscaling()
dynamodb = get_dynamodb()


def list_dynamodb_tables(db_client=None) -> List[str]:
    """List all DynamoDB tables in the current AWS account."""
    db_client = db_client or dynamodb
    tables: List[str] = []

    try:
        paginator = db_client.get_paginator("list_tables")
        for page in paginator.paginate():
            tables.extend(page.get("TableNames", []))
        return tables

    except ClientError as e:
        logger.error(f"Error unable to list DynamoDB tables: {e}")
    except EndpointConnectionError as e:
        logger.error(f"Unable to reach DynamoDB endpoint: {e}")

    return tables


def check_encryption(table: str, db_client=None) -> List[AuditFinding]:
    """
    Check whether DynamoDB table encryption is enabled.
    NIST SC-28 – Protection of Information at Rest
    """
    findings: List[AuditFinding] = []
    db_client = db_client or dynamodb

    try:
        response = db_client.describe_table(TableName=table)
        sse = response["Table"].get("SSEDescription", {})
        status = sse.get("Status")

        if status != "ENABLED":
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Encryption",
                    check_key="encryption_at_rest",
                    resource=table,
                    status="FAIL",
                    severity="High",
                    details=f"DynamoDB table encryption is not enabled for {table}",
                )
            )

    except ClientError as e:
        logger.error(f"Encryption check failed for DynamoDB table {table}: {e}", exc_info=True)
        findings.append (
            AuditFinding(
                service="DynamoDB",
                check="Encryption",
                check_key="encryption_at_rest",
                resource=table,
                status="FAIL",
                severity="High",
                details=f"Unable to determine DynamoDB table encryption status",
            )
        )

    return findings


def check_pitr(table: str, db_client=None) -> List[AuditFinding]:
    """
    Verify Point-in-Time Recovery (PITR) is enabled for DynamoDB table.
    CIS: DynamoDB Backups
    NIST: CP-9 - System Backup
    """
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []

    try:
        response = db_client.describe_continuous_backups(TableName=table)
        pitr = response.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {})
        status = pitr.get("PointInTimeRecoveryStatus")

        if status != "ENABLED":

            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Point-In-Time-Recovery",
                    check_key="point_in_time_recovery",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="Point-In-Time-Recovery (PITR) is not enabled for this table",
                )
            )

    except ClientError as e:
        logger.error(f"PITR check failed for {table}: {e}", exc_info=True)
        findings.append (
            AuditFinding(
                service="DynamoDB",
                check="Point-In-Time-Recovery",
                check_key="point-in-time-recovery",
                resource=table,
                status="FAIL",
                severity="Medium",
                details="Unable to determine PITR status due to an API error "
            )
        )

    return findings


def check_backup(table: str, db_client=None) -> List[AuditFinding]:
    """
    Verify that DynamoDB On-Demand or Scheduled Backups exist.
    CIS: DynamoDB Backups
    NIST: CP-9 - System Backup
    """
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []


    try:
        backups = []
        paginator = db_client.get_paginator("list_backups")

        for page in paginator.paginate(TableName=table):
            backups.extend(page.get("Backups", []))

        if not backups:
            findings.append (
                AuditFinding(
                    service="DynamoDB",
                    check="On Demand Backups",
                    check_key="backups",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="No scheduled or on-demand backups found for this table",
                )
            )

    except ClientError as e:
        logger.error(f"Backups check failed for {table}: {e}", exc_info=True)
        findings.append (
            AuditFinding(
                service="DynamoDB",
                check="On Demand Backups",
                check_key="backups",
                resource=table,
                status="FAIL",
                severity="Medium",
                details="Unable to determine backup configuration due to an API error",
            )
        )

    return findings


def check_autoscaling(table: str, autoscaling_client=None, db_client=None) -> List[AuditFinding]:
    """
    Check if DynamoDB table has Application Auto Scaling enabled
    (Provisioned capacity mode only).

    NIST: SC-5, CP-2, CP-10, SI-13
    """
    autoscaling_client = autoscaling_client or autoscaling
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []

    try:
        # ----- Skip ON_DEMAND tables -----
        table_desc = db_client.describe_table(TableName=table)
        billing_mode = table_desc["Table"].get("BillingModeSummary", {}).get("BillingMode")

        if billing_mode == "PAY_PER_REQUEST":
            return findings

        paginator = autoscaling_client.get_paginator("describe_scalable_targets")
        scalable_targets = []

        for page in paginator.paginate(ServiceNamespace="dynamodb"):
            scalable_targets.extend(page.get("ScalableTargets", []))

        table_targets = [
            t for t in scalable_targets
            if t.get("ResourceId", "").startswith(f"table/{table}")
        ]

        if not table_targets:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Autoscaling",
                    check_key="autoscaling",
                    resource=table,
                    status="FAIL",
                    severity="Low",
                    details="No Application Auto Scaling targets configured for a provisioned table",
                )
            )

    except ClientError as e:
        logger.error(f"Autoscaling check failed for {table}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="DynamoDB",
                check="Autoscaling",
                check_key="autoscaling",
                resource=table,
                status="FAIL",
                severity="Low",
                details="Unable to determine autoscaling configuration due to an API error",
            )
        )

    return findings


def check_deletion_protection(table: str, db_client=None) -> List[AuditFinding]:
    """
    Check whether DynamoDB table deletion protection is enabled.
    Availability / Resilience Control
    """
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []

    try:
        response = db_client.describe_table(TableName=table)
        enabled = response.get("Table", {}).get("DeletionProtectionEnabled", False)

        if not enabled:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Deletion Protection",
                    check_key="deletion_protection",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="Deletion protection is not enabled",
                )
            )

    except ClientError as e:
        logger.error(f"Deletion protection check failed for {table}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="DynamoDB",
                check="Deletion Protection",
                check_key="deletion_protection",
                resource=table,
                status="FAIL",
                severity="Low",
                details="Unable to determine deletion protection configuration due to an API error",
            )
        )

    return findings


def check_public_access_policy(table: str, db_client=None) -> List[AuditFinding]:
    """
    Check whether a DynamoDB table has a resource-based policy that could allow public access.

    DynamoDB tables can have resource policies that grant access to principals
    outside the account. Absence of a policy or inability to retrieve it is treated
    as a potential risk and flagged for review.

    NIST:
      - AC-3 (Access Enforcement)
      - AC-6 (Least Privilege)
    """
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []

    try:
        response = db_client.describe_table(TableName=table)
        table_arn = response.get("Table", {}).get("TableArn")

        if not table_arn:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Public Access Policy",
                    check_key="public_access",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="Unable to determine table ARN; cannot evaluate public access policy",
                )
            )
            return findings

        # MVP behavior: presence-only check
        findings.append(
            AuditFinding(
                service="DynamoDB",
                check="Public Access Policy",
                check_key="public_access",
                resource=table,
                status="FAIL",
                severity="Medium",
                details=(
                    "DynamoDB resource policies were not evaluated. "
                    "Manual review recommended to ensure no public access is permitted."
                ),
            )
        )

    except ClientError as e:
        logger.error(
            f"Error retrieving resource policy for {table}: {e}",
            exc_info=True,
        )

        if e.response["Error"]["Code"] == "PolicyNotFoundException":
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Public Access Policy",
                    check_key="public_access",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="No resource policy attached to the table",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="Public Access Policy",
                    check_key="public_access",
                    resource=table,
                    status="FAIL",
                    severity="Low",
                    details="Unable to determine public access configuration due to API error",
                )
            )

    return findings


def check_kms_cmk_usage(table: str, db_client=None) -> List[AuditFinding]:
    """
    Verify that a DynamoDB table uses a customer-managed KMS CMK.

    Requirements:
      - Encryption must be ENABLED
      - KMSMasterKeyArn must be present
      - Must not use the AWS-managed key (alias/aws/dynamodb)

    CIS: DynamoDB Encryption at Rest
    NIST: SC-28 – Protection of Information at Rest
    """
    db_client = db_client or dynamodb
    findings: List[AuditFinding] = []

    try:
        response = db_client.describe_table(TableName=table)
        sse = response.get("Table", {}).get("SSEDescription", {})

        status = sse.get("Status")
        key_arn = sse.get("KMSMasterKeyArn")

        if status != "ENABLED":
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="KMS CMK Usage",
                    check_key="kms_cmk_usage",
                    resource=table,
                    status="FAIL",
                    severity="High",
                    details="Encryption at rest is not enabled",
                )
            )
            return findings

        if not key_arn:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="KMS CMK Usage",
                    check_key="kms_cmk_usage",
                    resource=table,
                    status="FAIL",
                    severity="High",
                    details="Customer-managed CMK is not configured (AWS-managed key likely in use)",
                )
            )
            return findings

        if "alias/aws/dynamodb" in key_arn:
            findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="KMS CMK Usage",
                    check_key="kms_cmk_usage",
                    resource=table,
                    status="FAIL",
                    severity="Medium",
                    details="AWS-managed KMS key (alias/aws/dynamodb) is in use",
                )
            )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(
            f"KMS CMK usage check failed for {table}: {e}",
            exc_info=True
        )

        findings.append(
            AuditFinding(
                service="DynamoDB",
                check="KMS CMK Usage",
                check_key="kms_cmk_usage",
                resource=table,
                status="FAIL",
                severity="Low",
                details=f"Unable to evaluate CMK usage due to API error: {error_code}",
            )
        )

    return findings


def audit_table(table: str, db_client=None) -> List[AuditFinding]:
    """Run all security checks for a single DynamoDB table."""
    db_client = db_client or dynamodb
    logger.info(f"Auditing DynamoDB table: {table}")

    all_findings: List[AuditFinding] = []

    checks = [
        check_autoscaling,
        check_encryption,
        check_backup,
        check_pitr,
        check_deletion_protection,
        check_public_access_policy,
        check_kms_cmk_usage,
    ]

    for check_func in checks:
        try:
            if "autoscaling_client" in check_func.__code__.co_varnames:
                results = check_func(table)
            else:
                results = check_func(table, db_client=db_client)

            all_findings.extend(results)

        except Exception as e:
            logger.error(
                f"{check_func.__name__} failed for DynamoDB table {table}: {e}",
                exc_info=True,
            )
            all_findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check=check_func.__name__,
                    check_key="execution_error",
                    resource=table,
                    status="FAIL",
                    severity="High",
                    details="Unhandled exception during DynamoDB table audit",
                )
            )

    return all_findings


def run_dynamodb_audit(db_client=None) -> List[AuditFinding]:
    """Audit all DynamoDB tables and write the report to disk."""
    db_client = db_client or dynamodb

    logger.info("Starting DynamoDB audit")
    all_findings: List[AuditFinding] = []

    tables = list_dynamodb_tables(db_client)

    if not tables:
        logger.warning(
            "No DynamoDB tables found in this account/region. "
            "DynamoDB-level checks were skipped."
        )
        return all_findings

    for table in tables:
        all_findings.extend(
            audit_table(table, db_client=db_client)
        )
        # ---- Baseline PASS if no failures ----
        if not any(f.status == "FAIL" for f in all_findings):
            all_findings.append(
                AuditFinding(
                    service="DynamoDB",
                    check="DynamoDB Security Baseline",
                    check_key="baseline",
                    resource="account",
                    status="PASS",
                    severity="Informational",
                    details="No DynamoDB security issues detected.",
                )
            )

        failed = sum(1 for f in all_findings if f.status == "FAIL")
        if failed:
            logger.info(
                "DynamoDB audit completed with %d failed checks, see report for details",
                failed,
            )
        else:
            logger.info("DynamoDB audit completed successfully with no findings")

    return all_findings


# def build_dynamodb_report(service_name: str, db_client=None, output="json"):
#     dynamodb_findings = run_dynamodb_audit(db_client=db_client)
#     report = ServicesAuditReport(findings=dynamodb_findings)
#
#     filename = f"{service_name}_results.{output}"
#     if output == "json":
#         return report.to_json(filename)
#
#     elif output == "csv":
#         return report.to_csv(filename)
#
#     raise ValueError(f"Unknown format: {output}")
#
#
# if __name__ == "__main__":
#     build_dynamodb_report("dynamodb")
