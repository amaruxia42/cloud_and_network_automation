from typing import List
from botocore.exceptions import  ClientError
from shared.aws_clients import get_cloudtrail
from shared.report import AuditFinding, ServicesAuditReport
from shared.logger import get_logger


logger = get_logger(__name__)
cloudtrail = get_cloudtrail()


def check_cloudtrail_exists(cloudtrail_client=None) -> List[AuditFinding]:
    """
    Check whether CloudTrail is enabled in the AWS account.

    This control verifies that at least one CloudTrail exists. W

    CIS:
     - 3.1 – Ensure CloudTrail is enabled in all regions

    NIST:
     - AU-2 – Event Logging
     - AU-6 – Audit Review, Analysis, and Reporting
    """
    client = cloudtrail_client or cloudtrail
    findings: List[AuditFinding] = []

    try:
        response = client.describe_trails(includeShadowTrails=True)
        trails = response.get('trailList', [])

        if not trails:
            findings.append(
                AuditFinding(
                    service="CloudTrail",
                    check="CloudTrail Status",
                    check_key="does_trail_exist",
                    resource="account",
                    status="FAIL",
                    severity="High",
                    details="No CloudTrails are configured for this account.",
                )
            )

    except ClientError as e:
        logger.error(f"Failed to describe CloudTrails: {e}", exc_info=True)

        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Status",
                check_key="does_trail_exist",
                resource="account",
                status="FAIL",
                severity="High",
                details=f"Unable to verify CloudTrail status due to AWS API error:"
                        f" {e.response.get('Error', {}).get('Message')}",
            )
        )

    return findings


def check_multi_region_trail(cloudtrail_client=None) -> List[AuditFinding]:
    """
    Ensure CloudTrail is configured as a multi-region trail.

    Single-region trails do not capture activity across all AWS regions,
    creating audit blind spots.

    CIS:
      - 3.1 – Ensure CloudTrail is enabled in all regions

    NIST:
      - AU-2 – Event Logging
    """
    client = cloudtrail_client or cloudtrail
    findings: List[AuditFinding] = []

    try:
        response = client.describe_trails(includeShadowTrails=True)
        trails = response.get('trailList', [])

        # ----- Skip execution if trail list is empty to avoid duplicate findings -----
        if not trails:
            return []

        # ----- Check if any trail has MultiRegion enabled -----
        if not any(t.get("IsMultiRegionTrail") for t in trails):
            findings.append(
                AuditFinding(
                    service="CloudTrail",
                    check="CloudTrail Multi-Region",
                    check_key="multi_region",
                    resource="account",
                    status="FAIL",
                    severity="High",
                    details="No multi-region CloudTrail is enabled"
                )
            )

    except ClientError as e:
        logger.error(f"Error unable to verify if multi-region CloudTrail is enabled: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Multi-Region",
                check_key="multi_region",
                resource="account",
                status="FAIL",
                severity="High",
                details="Unable to verify CloudTrail multi-region is enabled due to AWS API error",
            )
        )

    return findings


def check_management_events(cloudtrail_client=None) -> List[AuditFinding]:

    client = cloudtrail_client or cloudtrail
    findings: List[AuditFinding] = []

    try:
        trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])
        management_logging_enabled = False

        for trail in trails:
            trail_name = trail.get("TrailARN") or trail.get("Name")
            selectors = client.get_event_selectors(TrailName=trail_name)

            # ----- Check Classic Event Selectors -----
            for selector in selectors.get("EventSelectors", []):
                if selector.get("IncludeManagementEvents"):
                    management_logging_enabled = True
                    break

            # ----- Check Advanced Event Selectors (Newer AWS feature) -----
            for adv_selector in selectors.get("AdvancedEventSelectors", []):
                if adv_selector.get("Name"):
                    management_logging_enabled = True
                    break

            if management_logging_enabled:
                return []  # Exit early, requirement met

        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Management Events",
                check_key="management_events",
                resource="account",
                status="FAIL",
                severity="High",
                details="No trails are currently configured to log Management Events.",
            )
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]

        logger.error(
            f"Error auditing CloudTrail Management Events: {error_code} - {error_msg}",
            exc_info=True
        )

        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Management Events",
                check_key="management_events",
                resource="account",
                status="FAIL",
                severity="Medium",
                details=f"Audit Interrupted: Unable to retrieve Event Selectors. AWS Error: {error_code}",
            )
        )

    return findings


def check_log_validation(cloudtrail_client=None) -> List[AuditFinding]:
    """
    Ensure CloudTrail log file integrity validation is enabled.

    This protects against tampering with CloudTrail logs.

    CIS:
      - 3.2 – Ensure log file validation is enabled

    NIST:
      - AU-6 – Audit Review, Analysis, and Reporting
    """
    client = cloudtrail_client or cloudtrail
    findings: List[AuditFinding] = []

    try:
        trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])

        for trail in trails:
            if not trail.get("LogFileValidationEnabled"):
                findings.append(
                    AuditFinding(
                        service="CloudTrail",
                        check="CloudTrail Log Validation",
                        check_key="log_validation",
                        # Use the Trail Name or ARN as the resource for better tracking
                        resource=trail.get("TrailARN"),
                        status="FAIL",
                        severity="Medium",
                        details=f"Log file validation is disabled for trail: {trail.get('Name')}",
                    )
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"CloudTrail Audit Error log validation: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Log File Validation",
                check_key="log_validation",
                resource="account",
                status="FAIL",
                severity="Medium",
                details=f"Unable to verify log file validation: {error_code}",
            )
        )

    return findings


def check_trail_kms_encryption(cloudtrail_client=None) -> List[AuditFinding]:
    """
    Ensure CloudTrail logs are encrypted using AWS KMS.

    KMS encryption provides stronger control over access and key rotation.

    CIS:
      - 3.3 – Ensure CloudTrail logs are encrypted at rest using KMS CMKs

    NIST:
      - SC-12 – Cryptographic Key Establishment and Management
    """
    client = cloudtrail_client or cloudtrail
    findings: List[AuditFinding] = []

    try:
        trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])

        for trail in trails:
            trail_name = trail.get("Name")
            kms_key = trail.get("KmsKeyId")

            if not kms_key:
                findings.append(
                    AuditFinding(
                        service="CloudTrail",
                        check="CloudTrail Encryption",
                        check_key="encryption",
                        resource=trail_name, # Specific resource
                        status="FAIL",
                        severity="Medium",
                        details=f"Trail '{trail_name}' is not encrypted with a KMS Key (using default SSE-S3).",
                    )
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"CloudTrail Audit Error [encryption]: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Encryption",
                check_key="encryption",
                resource="account",
                status="FAIL",
                severity="Medium",
                details=f"Audit Interrupted: Unable to describe trails. AWS Error: {error_code}",
            )
        )

    return findings


def run_cloudtrail_audit(cloudtrail_client=None) -> List[AuditFinding]:
    client = cloudtrail_client or cloudtrail
    logger.info("Starting CloudTrail audit")

    checks = [
        check_cloudtrail_exists,
        check_multi_region_trail,
        check_management_events,
        check_log_validation,
        check_trail_kms_encryption,
    ]

    all_findings: List[AuditFinding] = []

    for check_func in checks:
        try:
            results = check_func(cloudtrail_client=client)
            all_findings.extend(results)

        except Exception as e:
            logger.error(f"{check_func.__name__} execution failed: {e}", exc_info=True)
            all_findings.append(
                AuditFinding(
                    service="CloudTrail",
                    check=check_func.__name__,
                    resource="account",
                    status="FAIL",
                    severity="High",
                    details=f"Unexpected error during audit execution: {str(e)}",
                )
            )

    # ---- Final Baseline PASS ----
    if not any(f.status == "FAIL" for f in all_findings):
        all_findings.append(
            AuditFinding(
                service="CloudTrail",
                check="CloudTrail Security Baseline",
                resource="account",
                status="PASS",
                severity="Informational",
                details="No CloudTrail security issues detected"
            )
        )

    failed = sum(1 for f in all_findings if f.status == "FAIL")

    if failed:
        logger.info("CloudTrail audit completed with %d failed checks", failed)

    else:
        logger.info("CloudTrail audit completed successfully with no findings")

    return all_findings


