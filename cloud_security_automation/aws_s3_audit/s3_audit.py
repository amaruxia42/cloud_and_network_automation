import json
import argparse
from typing import List
from botocore.exceptions import ClientError
from shared.logger import get_logger
from shared.aws_clients import get_s3
from shared.report import AuditFinding


logger = get_logger(__name__)
s3 = get_s3()


# -----ARGUMENT PARSER-----
def parse_args():
    parser = argparse.ArgumentParser(description="Audit S3 buckets for security misconfigurations")

    parser.add_argument(
        "--buckets",
        nargs="*",
        help="Specific S3 buckets to audit (default: all buckets)"
    )
    parser.add_argument(
        "--output",
        default="s3_audit_results.json",
        help="Output filename (default: audit_results.json)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (json/csv). Default: json"
    )

    return parser.parse_args()


def list_s3_buckets(s3_client=None) -> List[str]:
    """Return a list of bucket names in the account."""

    # ----- Added optional client override to support Mock testing -----
    client = s3_client or s3

    try:
        response = client.list_buckets()
        return [bucket["Name"] for bucket in response.get("Buckets", [])]
    except ClientError as e:
        logger.error(f"Error listing buckets: {e}")
        return []


def check_public_access(bucket: str, s3_client=None) -> List[AuditFinding]:
    """
    Check S3 bucket for public access exposure via ACLs, bucket policies,
    and Public Access Block configuration.

   CIS:
     - 2.1 – Ensure S3 bucket ACLs are not publicly accessible
     - 2.2 – Ensure S3 bucket policies are not publicly accessible
     - 2.3 – Ensure S3 Block Public Access is enabled

   NIST:
     - AC-3, AC-6
       """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    # ----- ACL Checks -----
    try:
        acl = client.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                findings.append(
                    AuditFinding(
                        service="S3",
                        check="S3 Public Access",
                        check_key="public_access",
                        resource=bucket,
                        status="FAIL",
                        severity="Medium",
                        details="Bucket ACL allows public AllUsers group",
                    )
                )

                break

    except ClientError as e:
        logger.warning(f"ACL check failed for {bucket}: {e}")

    # --- Bucket Policy Check ---
    try:
        policy = s3.get_bucket_policy(Bucket=bucket)
        policy_obj = json.loads(policy.get("Policy", "{}"))

        for stmt in policy_obj.get("Statement", []):
            if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                findings.append(
                    AuditFinding(
                        service="S3",
                        check="Policy Check",
                        check_key="policy_check",
                        resource=bucket,
                        status="FAIL",
                        severity="High",
                        details="Bucket Policy allows public access",
                    )
                )

                break

    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            logger.warning(f"Policy check failed for {bucket}: {e}")

    # ----- Public Access Block Exposure Check -----
    try:
        pab = client.get_public_access_block(Bucket=bucket)
        cfg = pab.get("PublicAccessBlockConfiguration", {})

        if not all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False)
        ]):
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Public Access",
                    check_key="public_access",
                    resource=bucket,
                    status="FAIL",
                    severity="Medium",
                    details="Public Access Block is not fully enabled",
                )
            )

    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            logger.warning(f"Public Access Block check failed for {bucket}: {e}")

    return findings


def check_encryption(bucket: str, s3_client=None) -> List[AuditFinding]:
    """
    Check whether S3 bucket has server-side encryption enabled.

    CIS:
      - 2.1 – Ensure S3 bucket encryption is enabled

    NIST:
      - SC-12 (Cryptographic Key Establishment and Management)
      - IA-7 (Cryptographic Module Authentication)
    """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_encryption(Bucket=bucket)
        config = response.get("ServerSideEncryptionConfiguration")
        rules = config.get("Rules", [])

        if not rules:
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Bucket Encryption",
                    check_key="encryption_at_rest",
                    resource=bucket,
                    status="FAIL",
                    severity="High",
                    details="No Server side encryption rules are configured",
                )
            )
            return findings

        for rule in rules:
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            algorithm = sse.get("SSEAlgorithm")
            if algorithm not in ("AES256", "aws:kms"):
                findings.append(
                    AuditFinding(
                        service="S3",
                        check="S3 Bucket Encryption",
                        check_key="encryption_at_rest",
                        resource=bucket,
                        status="FAIL",
                        severity="High",
                        details=f"Unsupported encryption algorithm configured: {algorithm}",
                    )
                )

    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Bucket Encryption",
                    check_key="encryption_at_rest",
                    resource=bucket,
                    status="FAIL",
                    severity="High",
                    details="Server-side encryption is not enabled for this bucket",
                )
            )
        else:
            logger.error(f"Encryption check failed for {bucket}: {e}")
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Bucket Encryption",
                    check_key="encryption_at_rest",
                    resource=bucket,
                    status="FAIL",
                    severity="High",
                    details=f"Unable to retrieve bucket encryption configuration: {e}"
                )
            )

    return findings


def check_logging(bucket: str, s3_client=None) -> List[AuditFinding]:
    """
    Check whether S3 bucket object versioning is enabled.

    CIS:
    - 2.1 – Ensure S3 Bucket Versioning is enabled

    NIST:
     - CP-9 (Information System Backup)
       """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_logging(Bucket=bucket)

        if "LoggingEnabled" not in response:

            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Bucket Access Logging",
                    check_key="access_logging",
                    resource=bucket,
                    status="FAIL",
                    severity="Medium",
                    details="Access logging not enabled",
                )
            )

    except ClientError as e:
        logger.error(f"Logging check failed for {bucket}: {e}")
        findings.append(
            AuditFinding(
                service="S3",
                check="S3 Bucket Access Logging",
                check_key="access_logging",
                resource=bucket,
                status="FAIL",
                severity="Medium",
                details=f"Error retrieving logging configuration: {e}"
            )
        )

    return findings


def check_versioning(bucket:str, s3_client=None) -> List[AuditFinding]:
    """
    Check whether S3 bucket object versioning is enabled.

    CIS:
      - 2.1 – Ensure S3 Bucket Versioning is enabled

    NIST:
      - CP-9 (Information System Backup)
    """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_versioning(Bucket=bucket)
        state = response.get("Status")

        if state != "Enabled":
            if state == "Suspended":
                msg = "S3 bucket versioning is suspended"
            else:
                msg = "S3 bucket versioning is not enabled"
            findings.append (
                AuditFinding(
                    service="S3",
                    check="S3 Bucket Object Versioning",
                    check_key="versioning",
                    resource=bucket,
                    status="FAIL",
                    severity="Medium",
                    details=msg,
                )
            )

    except ClientError as e:
        logger.error(f"Versioning check failed for {bucket}: {e}")
        findings.append(
            AuditFinding(
                service="S3",
                check="S3 Bucket Object Versioning",
                check_key="versioning",
                resource=bucket,
                status="FAIL",
                severity="Medium",
                details=f"Unable to retrieve bucket versioning configuration {e}"
            )
        )

    return findings


def check_cors(bucket: str, s3_client=None) -> List[AuditFinding]:
    """
    Check for overly permissive S3 CORS configurations.

    CIS:
      - 2.6 – Ensure S3 bucket CORS does not allow unrestricted access

    NIST:
      - AC-4 (Information Flow Enforcement)
    """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_cors(Bucket=bucket)

        for rule in response.get("CORSRules", []):
            origins = set(rule.get("AllowedOrigins", []))
            methods = set(rule.get("AllowedMethods", []))

            if "*" not in origins:
                continue

            dangerous_methods = methods & {"PUT", "POST", "DELETE"}

            if dangerous_methods:
                findings.append(
                    AuditFinding(
                        service="S3",
                        check="S3 CORS Configuration",
                        check_key="cors_rules",
                        resource=bucket,
                        status="FAIL",
                        severity="High",
                        details=(
                            f"CORS allows wildcard origin with dangerous methods: "
                            f"{sorted(dangerous_methods)}"
                        ),
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        service="S3",
                        check="S3 CORS Configuration",
                        check_key="cors_rules",
                        resource=bucket,
                        status="FAIL",
                        severity="Medium",
                        details="CORS allows wildcard origin (*)",
                    )
                )

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchCORSConfiguration":
            logger.debug(f"No CORS configuration for bucket {bucket}")
        else:
            logger.error(f"CORS check failed for {bucket}: {e}", exc_info=True)
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 CORS Configuration",
                    check_key="cors_rules",
                    resource=bucket,
                    status="FAIL",
                    severity="Medium",
                    details=f"Unable to retrieve CORS configuration: {e}",
                )
            )

    return findings

def check_mfa_delete(bucket:str, s3_client=None) -> List[AuditFinding]:
    """
    Check whether S3 MFA Delete is enabled.

    CIS:
      - 2.1 – Ensure S3 bucket versioning and MFA Delete are enabled (best practice)

    NIST:
      - IA-2 (Identification and Authentication)
      - CP-9 (Information System Backup)
    """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_versioning(Bucket=bucket)
        mfa = response.get("MfaDelete", "Disabled")

        if mfa != "Enabled":
            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 MFA Delete",
                    check_key="mfa_delete",
                    resource=bucket,
                    status="FAIL",
                    severity="Low",
                    details="MFA Delete not enabled",
                )
            )

    except ClientError as e:
        logger.debug(f"MFA Delete check failed for {bucket}: {e}")
        findings.append(
            AuditFinding(
                service="S3",
                check="S3 MFA Delete",
                check_key="mfa_delete",
                resource=bucket,
                status="FAIL",
                severity="Low",
                details=f"Unable to determine MFA Delete status: {e}"
            )
        )

    return findings


def check_bucket_notifications(bucket:str, s3_client=None) -> List[AuditFinding]:
    """
    Check whether S3 bucket event notifications are configured.

    CIS:
      - 2.x (Best practice – monitoring & alerting)

    NIST:
      - AU-6 (Audit Review, Analysis, and Reporting)
      - IR-5 (Incident Monitoring)
    """
    client = s3_client or s3
    findings: List[AuditFinding] = []

    try:
        response = client.get_bucket_notification_configuration(Bucket=bucket)

        has_notifications = any([
            response.get("TopicConfigurations"),
            response.get("QueueConfigurations"),
            response.get("LambdaConfigurations"),
            response.get("EventBridgeConfiguration")
        ])

        if not has_notifications:

            findings.append(
                AuditFinding(
                    service="S3",
                    check="S3 Notifications Configuration",
                    check_key="notifications",
                    resource=bucket,
                    status="FAIL",
                    severity="Low",
                    details="No event notifications configured",
                )
            )


    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            logger.debug(
                f"Access denied when checking notifications for {bucket} (expected in some accounts)"
            )

            return []

        logger.error(
            f"Notification check failed for {bucket}: {e}",
            exc_info=True
        )
        findings.append(
            AuditFinding(
                service="S3",
                check="S3 Notifications Configuration",
                check_key="notifications",
                resource=bucket,
                status="FAIL",
                severity="Low",
                details=f"Error retrieving event notifications configuration: {e}",
            )
        )

    return findings


def run_s3_audit(s3_client=None) -> List[AuditFinding]:
    """Orchestrates the S3 audit across all buckets."""
    client = s3_client or s3
    logger.info("Starting S3 audit")

    all_findings: List[AuditFinding] = []
    buckets = list_s3_buckets(s3_client=client)

    if not buckets:
        logger.warning("No S3 buckets found in this account/region.\n"
                       "S3-level checks were skipped.")
        return []

    # Simplified list: The check_key should be handled inside the check functions
    checks = [
        check_public_access,
        check_encryption,
        check_logging,
        check_versioning,
        check_cors,
        check_mfa_delete,
        check_bucket_notifications,
    ]

    for bucket in buckets:
        logger.debug(f"Auditing bucket: {bucket}")
        for check_func in checks:
            try:
                # Execute the check
                results = check_func(bucket=bucket, s3_client=client)
                all_findings.extend(results)

            except Exception as e:
                logger.error(f"{check_func.__name__} failed for {bucket}: {e}", exc_info=True)
                all_findings.append(
                    AuditFinding(
                        service="S3",
                        check=check_func.__name__,
                        resource=bucket,
                        status="FAIL",
                        severity="Medium",
                        details=f"Unexpected error during check execution: {str(e)}"
                    )
                )

    # ---- Final Baseline PASS ----
    if not any(f.status == "FAIL" for f in all_findings):
        all_findings.append(
            AuditFinding(
                service="S3",
                check="S3 Security Baseline",
                resource="Account",
                status="PASS",
                severity="Informational",
                details=f"All {len(buckets)} buckets meet the security baseline."
            )
        )

    failed = sum(1 for f in all_findings if f.status == "FAIL")

    if failed:
        logger.info(
            "S3 audit completed with %d findings, see results for details",
            failed,
        )

    else:
        logger.info("S3 audit completed successfully with no findings")


    return all_findings


