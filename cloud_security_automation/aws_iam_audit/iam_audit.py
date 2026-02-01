from datetime import datetime, timezone
from typing import List
from botocore.exceptions import ClientError
from shared.logger import get_logger
from shared.aws_clients import get_iam
from shared.report import AuditFinding

logger = get_logger(__name__)
iam = get_iam()


def check_root_account_mfa(iam_client=None) -> List[AuditFinding]:
    """
    Check whether MFA is enabled on the AWS root account.

    CIS: 1.2 – Ensure MFA is enabled for the root user account
    NIST: IA-2 (Identification and Authentication)
    """
    client = iam_client  or iam
    findings: List[AuditFinding] = []

    try:
        response = client.get_account_summary()
        summary = response.get("SummaryMap", {})

        if summary.get("AccountMFAEnabled") != 1:
            findings.append(AuditFinding(
                service="IAM",
                check="Root Account MFA",
                check_key="root_mfa",
                resource="root",
                status="FAIL",
                severity="Critical",
                details="MFA is not enabled for the Root Account"
            ))

    except ClientError as e:
        logger.error("Failed to evaluate root account MFA", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="Root Account MFA",
                check_key="root_mfa",
                resource="root",
                status="FAIL",
                severity="Critical",
                details=f"Unable to determine root MFA status: {e}"
            )
        )

    return findings


def check_iam_user_mfa(iam_client=None) -> List[AuditFinding]:
    """
    Check that all IAM users with console access have MFA enabled.

    CIS:
      - 1.2 – Ensure multi-factor authentication (MFA) is enabled for all IAM users with console access

    NIST:
      - IA-2 – Identification and Authentication
    """
    client = iam_client  or get_iam()
    findings: List[AuditFinding] = []

    try:
        response = client.list_users()
        users = response.get("Users", [])

        for user in users:
            username = user.get("UserName")

            # ---- Check console access ----
            try:
                client.get_login_profile(UserName=username)
            except ClientError as e:
                # No console access → MFA not required
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue
                raise

            # ---- Check MFA devices ----
            mfa_response = client.list_mfa_devices(UserName=username)
            mfa_devices = mfa_response.get("MFADevices", [])

            if not mfa_devices:
                findings.append(
                    AuditFinding(
                        service="IAM",
                        check="IAM User MFA",
                        check_key="user_mfa",
                        resource=username,
                        status="FAIL",
                        severity="High",
                        details="IAM user has console access but no MFA device enabled",
                    )
                )

    except ClientError as e:
        logger.error("Failed to evaluate IAM user MFA configuration", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="IAM User MFA",
                check_key="user_mfa",
                resource="account",
                status="FAIL",
                severity="High",
                details=f"Unable to evaluate IAM user MFA configuration: {e}",
            )
        )

    return findings


def check_root_mfa(iam_client=None) -> List[AuditFinding]:

    client = iam_client  or iam
    findings: List[AuditFinding] = []

    try:
        response = client.list_mfa_devices(
            UserName="<root_account>"
        )

        mfa_devices = response.get("MFADevices", [])

        if not mfa_devices:
            findings.append(AuditFinding(
                service="IAM",
                check="Root MFA",
                check_key="root_mfa",
                resource="root",
                status="FAIL",
                severity="Critical",
                details="Root account does not have MFA enabled"
            ))

    except ClientError as e:
        logger.error("Error checking root MFA status", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="Root MFA",
                check_key="root_mfa",
                resource="root",
                status="FAIL",
                severity="Critical",
                details=f"Unable to determine root MFA status: {e}"
            ))

    return findings


def check_root_access_keys(iam_client=None) -> List[AuditFinding]:
    """
    Check whether the AWS root account has access keys.

    CIS:
      - 1.4 – Ensure no root user access key exists

    NIST:
      - IA-5 (Authenticator Management)
      - AC-6 (Least Privilege)
    """
    client = iam_client  or iam
    findings: List[AuditFinding] = []

    try:
        response = client.get_account_summary()
        summary = response.get("SummaryMap", {})

        if summary.get("AccountAccessKeysPresent") == 1:
            findings.append(AuditFinding(
                service="IAM",
                check="Root Account Access Keys",
                check_key="root_access_keys",
                resource="root",
                status="FAIL",
                severity="Critical",
                details="Root account has active access keys"

            ))

    except ClientError as e:
        logger.error("Error checking root access keys", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="Root Account Access Keys",
                check_key="root_access_keys",
                resource="root",
                status="FAIL",
                severity="Critical",
                details=f"Unable to determine root access key status: {e}"
            ))

    return findings


def check_iam_password_policy(iam_client=None) -> List[AuditFinding]:
    """
    Check whether IAM password policy exists and meets minimum security requirements.

    CIS:
      - 1.5–1.11 – IAM Password Policy

    NIST:
      - IA-5 – Authenticator Management
    """
    client = iam_client  or get_iam()
    findings: List[AuditFinding] = []

    try:
        response = client.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "NoSuchEntity":
            details = "No IAM password policy is configured for this account"
        elif error_code == "AccessDenied":
            details = "Unable to audit password policy Access Denied"
            print(details)
        else:
            details = f"Unexpected error auditing password policy: {error_code}"

        findings.append(
            AuditFinding(
                service="IAM",
                check="IAM Password Policy",
                check_key="password_policy",
                resource="account",
                status="FAIL",
                severity="High",
                details=details,
            )
        )
        return findings

    PASSWORD_POLICY_RULES = {
        "MinimumPasswordLength": lambda v: v >= 14,
        "RequireUppercaseCharacters": bool,
        "RequireLowercaseCharacters": bool,
        "RequireNumbers": bool,
        "RequireSymbols": bool,
        "PasswordReusePrevention": lambda v: v >= 24,
        "MaxPasswordAge": lambda v: v <= 90,
    }
    # ---- Evaluate policy content ----
    failures = []
    for field, rule in PASSWORD_POLICY_RULES.items():
        value = policy.get(field)

        try:
            compliant = rule(value)

        except Exception:
            compliant = False
        if not compliant:
            failures.append(field)

    if failures:
        findings.append(
            AuditFinding(
                service="IAM",
                check="IAM Password Policy",
                check_key="password_policy",
                resource="account",
                status="FAIL",
                severity="High",
                details="IAM password policy is weak: " + "; ".join(failures),
            )
        )

    return findings


def check_iam_user_access_keys_rotation(
    iam_client=None,
    max_key_age_days: int = 90
) -> List[AuditFinding]:
    """
    Check that IAM user access keys are rotated regularly.

    CIS:
      - 1.3 – Ensure credentials unused for 90 days or greater are disabled

    NIST:
      - IA-5 (Authenticator Management)
    """
    client = iam_client  or get_iam()
    findings: List[AuditFinding] = []
    check_iam_user_access_keys_rotation.check_key = "access_keys_rotation"
    now = datetime.now(timezone.utc)

    try:
        response = client.list_users()
        users = response.get("Users", [])

        for user in users:
            username = user.get("UserName")

            keys_response = client.list_access_keys(UserName=username)
            access_keys = keys_response.get("AccessKeyMetadata", [])

            for key in access_keys:
                # ----- Skip inactive keys -----
                if key.get("Status") != "Active":
                    continue

                create_date = key.get("CreateDate")
                key_age_days = (now - create_date).days

                if key_age_days > max_key_age_days:
                    findings.append(
                        AuditFinding(
                            service="IAM",
                            check="IAM User Access Key Rotation",
                            check_key="access_keys_rotation",
                            resource=username,
                            status="FAIL",
                            severity="High",
                            details=(
                                f"IAM user access key is {key_age_days} days old "
                                f"and exceeds the {max_key_age_days}-day rotation policy"
                            ),
                        )
                    )
                    # One finding per user is enough
                    break

    except ClientError as e:
        logger.error("Failed to evaluate IAM access key rotation", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="IAM User Access Key Rotation",
                check_key="access_keys_rotation",
                resource="account",
                status="FAIL",
                severity="High",
                details=f"Unable to evaluate IAM access key rotation: {e}",
            )
        )

    return findings


def check_iam_wildcard_policies(iam_client=None) -> List[AuditFinding]:
    client = iam_client  or iam
    findings: List[AuditFinding] = []

    try:
        paginator = client.get_paginator("list_policies")

        # ----- check for customer-managed policies only -----
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                default_version = policy["DefaultVersionId"]

                version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version
                )

                document = version["PolicyVersion"]["Document"]
                statements = document.get("Statement", [])

                if not isinstance(statements, list):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue

                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])

                    if actions == "*" or resources == "*":
                        findings.append(
                            AuditFinding(
                                service="IAM",
                                check="IAM Wildcard Policy",
                                check_key="wildcard_policies",
                                resource=policy_name,
                                status="FAIL",
                                severity="High",
                                details="Policy allows wildcard '*' action or resource",
                            )
                        )
                        break  # one finding per policy is enough

    except ClientError as e:
        logger.error("Failed to evaluate IAM wildcard policies", exc_info=True)
        findings.append(
            AuditFinding(
                service="IAM",
                check="IAM Wildcard Policy",
                check_key="wildcard_policies",
                resource="account",
                status="FAIL",
                severity="High",
                details=f"Unable to evaluate IAM policies: {e}",
            )
        )

    return findings



def run_iam_audit(iam_client=None) -> List[AuditFinding]:
    client = iam_client  or iam
    logger.info("Starting IAM audit")

    checks = [
        check_root_account_mfa,
        check_iam_user_mfa,
        check_root_access_keys,
        check_iam_password_policy,
        check_iam_user_access_keys_rotation,
        check_iam_wildcard_policies,
    ]

    all_findings: List[AuditFinding] = []

    for check_func in checks:
        try:
            results = check_func(iam_client=client)
            all_findings.extend(results)

        except Exception as e:
            logger.error(
                f"{check_func.__name__} failed: {e}",
                exc_info=True
            )
            all_findings.append(
                AuditFinding(
                    service="IAM",
                    check=check_func.__name__,
                    resource="account",
                    status="FAIL",
                    severity="High",
                    details=f"Check execution failed: {e}"
            ))

    # ---- Baseline PASS logic ----
    if not any(f.status == "FAIL" for f in all_findings):
        all_findings.append(AuditFinding(
            service="IAM",
            check="IAM Security Baseline",
            resource="account",
            status="PASS",
            severity="Informational",
            details="No IAM security issues detected"
        ))

    failed = sum(1 for f in all_findings if f.status == "FAIL")

    if failed:
        logger.info("IAM audit completed with %d failed checks", failed)
    else:
        logger.info("IAM audit completed successfully with no findings")

    return all_findings











