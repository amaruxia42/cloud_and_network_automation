
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict
from shared.logger import get_logger
from shared.aws_clients import get_ec2, get_iam
from shared.report import AuditFinding


logger = get_logger(__name__)
ec2 = get_ec2()
iam = get_iam()


def list_ec2_instances(ec2_client=None) -> List[Dict]:
    """
    Returns a list of EC2 instance dictionaries.
    Uses pagination to handle large environments.
    """
    client = ec2_client or ec2
    instances: List[Dict] = []

    try:
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            # ----- Filters out terminated instances to reduce noise in security reports -----
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if instance.get("State", {}).get("Name") != "terminated":
                        instances.append(instance)

        return instances

    except (NoCredentialsError, PartialCredentialsError, ProfileNotFound) as e:
        logger.critical(f"FATAL: Authentication failed for EC2 audit: {e}")
        # ----- re-raised to record an error occurred -----
        raise
    except ClientError as e:
        logger.error(f"AWS API error (ClientError) listing EC2 instances: {e}")
    except Exception as e:
        logger.error(f"Unexpected system error during EC2 discovery: {e}", exc_info=True)

    return instances


def check_public_exposure(instance: Dict, **clients) -> List[AuditFinding]:
    """
    Check if a specific EC2 instance has a public IP.
    CIS 4.9, NIST SC-7
    """
    findings: List[AuditFinding] = []

    instance_id = instance.get("InstanceId", "unknown")
    public_ip = instance.get("PublicIpAddress")

    try:
        if public_ip:
            findings.append(
                AuditFinding(
                    service="EC2",
                    check="Public IP Exposure",
                    check_key="public_exposure",
                    resource=instance_id,
                    status="FAIL",
                    severity="High",
                    details=(
                        f"Instance has a public IP address: {public_ip}. "
                        "This increases the attack surface by making the instance "
                        "directly reachable from the internet."
                    )
                )
            )
    except Exception as e:
        logger.error(f"Public exposure check failed for {instance_id}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="EC2",
                check="Public IP Exposure",
                check_key="public_exposure",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details=f"Error during check execution: {str(e)}"
            )
        )

    return findings


def check_imds(instance:Dict, **clients) -> List[AuditFinding]:
    """Check if IMDSv2 is enforced
    Frameworks: CIS 4.29 (Ensure IMDSv2 is required), NIST IA-3 (Device Identification and Authentication)
    """
    ec2_client = clients["ec2"]
    findings: List[AuditFinding] = []
    instance_id = instance.get("InstanceId", "unknown")

    metadata = instance.get("MetadataOptions", {})
    http_tokens = metadata.get("HttpTokens")

    if http_tokens != "required":
        if http_tokens == "optional":
           reason = "IMDSv1 is still allowed (HttpTokens set to 'optional')."
        else:
           reason = f"IMDSv2 is not properly enforced (HttpTokens state: {http_tokens})."

        findings.append(
            AuditFinding(
                service="EC2",
                check="IMDSv2",
                check_key="imds",
                resource=instance_id,
                status="FAIL",
                severity="High",
                details=(
                    f"{reason} IMDSv2 should be 'required' to prevent "
                    "credential theft via SSRF attacks."
                )
            )
        )

    return findings


def check_security_groups(instance: Dict, **clients) -> List[AuditFinding]:
    """
    Check attached security groups for open ingress access.
    CIS 4.1, CIS 4.2 – Security Group Rules
    NIST AC-3 – Access Enforcement
    """
    ec2_client = clients["ec2"]
    findings: List[AuditFinding] = []
    instance_id = instance.get("InstanceId", "unknown")

    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

    if not sg_ids:
        findings.append(
            AuditFinding(
                service="EC2",
                check="Security Groups",
                check_key="security_groups",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details="No security groups attached to instance",
            )
        )

        return findings

    try:
        sgs = ec2_client.describe_security_groups(GroupIds=sg_ids).get("SecurityGroups", [])

        for sg in sgs:
            sg_id = sg.get("GroupId")
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if protocol == "-1":
                    port_range = "ALL"
                elif from_port == to_port:
                    port_range = from_port
                else:
                    port_range = f"Ports {from_port} to {to_port}"

                # ----- Check IPv4 -----
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            AuditFinding(
                                service="EC2",
                                check="Unrestricted Ingress",
                                check_key="security_groups",
                                resource=instance_id,
                                status="FAIL",
                                severity="High",
                                details=f"{port_range} ({protocol}) open to 0.0.0.0/0 in security group {sg_id}"
                            )
                        )

                # ----- Check IPv6 -----
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        findings.append(
                            AuditFinding(
                                service="EC2",
                                check="Unrestricted Ingress",
                                check_key="security_groups",
                                resource=instance_id,
                                status="FAIL",
                                severity="High",
                                details=f"Port {port_range} ({protocol}) open to ::/0 in security group {sg_id}"
                            )
                        )

    except ClientError as e:
        logger.error(f"Security group check failed for {instance_id}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="EC2",
                check="Unrestricted Ingress",
                check_key="security_groups",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details=f"API Error evaluating security groups: {e}"
            )
        )

    return findings


def check_ebs_encryption(instance: Dict, **clients) -> List[AuditFinding]:
    """
    Check if all EBS volumes attached to the instance are encrypted.
    CIS 2.2.1, NIST SC-28
    """
    ec2_client = clients["ec2"]
    findings: List[AuditFinding] = []
    instance_id = instance.get("InstanceId", "unknown")

    # Extract all Volume IDs for this instance at once
    volume_ids = [
        bd["Ebs"]["VolumeId"]
        for bd in instance.get("BlockDeviceMappings", [])
        if "Ebs" in bd
    ]

    if not volume_ids:
        return []  # No EBS volumes (likely an instance-store only type)

    try:
        # Fetch all volumes for this instance in ONE API call
        volumes = ec2_client.describe_volumes(VolumeIds=volume_ids).get("Volumes", [])

        for vol in volumes:
            vol_id = vol.get("VolumeId")
            is_encrypted = vol.get("Encrypted", False)

            if not is_encrypted:
                findings.append(
                    AuditFinding(
                        service="EC2",
                        check="EBS Encryption",
                        check_key="encryption_at_rest",
                        resource=instance_id,
                        status="FAIL",
                        severity="High",
                        details=f"EBS volume {vol_id} is not encrypted. Data at rest is at risk."
                    )
                )

    except ClientError as e:
        logger.error(f"EBS check failed for {instance_id}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="EC2",
                check="EBS Encryption",
                check_key="ebs_encryption",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details=f"API Error retrieving volume info: {e}"
            )
        )

    return findings


def check_ec2_iam_instance_profile(instance: Dict, **clients) -> List[AuditFinding]:
    """
    Check IAM role attached to an EC2 instance for least privilege.

    CIS:
      - 1.16 – IAM instance profiles
    NIST:
      - AC-2 (Account Management)
      - AC-6 (Least Privilege)
    """
    iam_client = clients["iam"]
    findings: List[AuditFinding] = []

    instance_id = instance.get("InstanceId", "unknown")
    profile = instance.get("IamInstanceProfile")

    # ---- No role attached ----
    if not profile:
        findings.append(
            AuditFinding(
                service="EC2",
                check="EC2 IAM Instance Profile",
                check_key="instance_profile",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details="Instance has no IAM role attached",
            )
        )
        return findings

    try:
        profile_name = profile["Arn"].split("/")[-1]
        response = iam_client.get_instance_profile(
            InstanceProfileName=profile_name
        )

        roles = response["InstanceProfile"].get("Roles", [])

        for role in roles:
            role_name = role["RoleName"]
            attached = iam_client.list_attached_role_policies(
                RoleName=role_name
            )

            for policy in attached.get("AttachedPolicies", []):
                policy_name = policy["PolicyName"]

                if policy_name == "AdministratorAccess":
                    severity = "Critical"
                elif policy_name.endswith("FullAccess"):
                    severity = "High"
                else:
                    continue

                findings.append(
                    AuditFinding(
                        service="EC2",
                        check="EC2 IAM Role Least Privilege",
                        check_key="instance_profile",
                        resource=instance_id,
                        status="FAIL",
                        severity=severity,
                        details=(
                            f"Over-privileged managed policy "
                            f"{policy_name} attached to role {role_name}"
                        ),
                    )
                )

    except ClientError as e:
        logger.error(
            f"IAM instance profile check failed for {instance_id}: {e}",
            exc_info=True,
        )
        findings.append(
            AuditFinding(
                service="EC2",
                check="EC2 IAM Role Least Privilege",
                check_key="instance_profile",
                resource=instance_id,
                status="FAIL",
                severity="Low",
                details="Unable to evaluate IAM role configuration",
            )
        )

    return findings


def list_ebs_snapshots(ec2_client=None) -> List[Dict]:
    """Return all EBS snapshots owned by the account."""
    client = ec2_client or ec2
    snapshots = []

    try:
        paginator = client.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            snapshots.extend(page.get("Snapshots", []))

    except ClientError as e:
        logger.error(f"Failed to list EBS snapshots: {e}", exc_info=True)

    return snapshots


def check_ebs_snapshot_exposure(
    snapshot_id: str, ec2_client=None
) -> List[AuditFinding]:
    """
    Check whether EBS snapshots are publicly accessible.

    CIS:
      - 2.2.2 – Ensure EBS snapshots are not publicly accessible

    NIST:
      - AC-3 (Access Enforcement)
      - SC-28 (Protection of Information at Rest)
    """
    client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = client.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission"
        )

        if any(p.get("Group") == "all"
               for p in response.get("CreateVolumePermissions", [])):
            findings.append(
                AuditFinding(
                    service="EC2",
                    check="Public EBS Snapshot",
                    check_key="ebs_snapshot",
                    resource=snapshot_id,
                    status="FAIL",
                    severity="High",
                    details="EBS snapshot is publicly accessible",
                )
            )

    except ClientError as e:
        findings.append(
            AuditFinding(
                service="EC2",
                check="Public EBS Snapshot",
                check_key="ebs_snapshot",
                resource=snapshot_id,
                status="FAIL",
                severity="Low",
                details=f"Unable to determine snapshot permissions: {e}",
            )
        )

    return findings


def check_unrestricted_ssh_rdp_access(
    instance: Dict,  **clients
) -> List[AuditFinding]:
    """
    Check whether EC2 instances allow unrestricted SSH (22) or RDP (3389) access.

    CIS: 4.3 (SSH), 4.4 (RDP)
    NIST: AC-3 (Access Enforcement), SC-7 (Boundary Protection)
    """
    ec2_client = clients["ec2"]
    findings: List[AuditFinding] = []
    instance_id = instance.get("InstanceId", "unknown")

    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    if not sg_ids:
        return findings

    exposed_ports = set()

    try:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)

        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port is None or to_port is None:
                    continue

                ports = range(from_port, to_port + 1)

                if 22 in ports or 3389 in ports:
                    if any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0"
                        for r in rule.get("Ipv6Ranges", [])
                    ):
                        exposed_ports.update(
                            p for p in (22, 3389) if p in ports
                        )

        if exposed_ports:
            findings.append(
                AuditFinding(
                    service="EC2",
                    check="Unrestricted SSH/RDP",
                    check_key="security_groups",
                    resource=instance_id,
                    status="FAIL",
                    severity="High",
                    details=f"Ports {sorted(exposed_ports)} open to the internet",
                )
            )

    except ClientError as e:
        logger.error(
            f"Error checking SSH/RDP exposure for {instance_id}: {e}",
            exc_info=True,
        )
        findings.append(
            AuditFinding(
                service="EC2",
                check="Unrestricted SSH/RDP",
                check_key="security_groups",
                resource=instance_id,
                status="FAIL",
                severity="Medium",
                details="Unable to evaluate security group ingress rules",
            )
        )

    return findings


def audit_instance(instance: Dict,ec2_client,iam_client) -> List[AuditFinding]:
    instance_id = instance.get("InstanceId", "unknown")
    findings: List[AuditFinding] = []

    clients = {
        "ec2": ec2_client,
        "iam": iam_client,
    }

    checks = [
        check_public_exposure,
        check_unrestricted_ssh_rdp_access,
        check_ec2_iam_instance_profile,
        check_imds,
        check_security_groups,
        check_ebs_encryption,
    ]

    for check_func in checks:
        try:
            results = check_func(instance, **clients)
            findings.extend(results)

        except Exception as e:
            logger.error(
                f"{check_func.__name__} failed for {instance_id}: {e}",
                exc_info=True,
            )
            findings.append(
                AuditFinding(
                    service="EC2",
                    check=check_func.__name__,
                    check_key="execution_error",
                    resource=instance_id,
                    status="FAIL",
                    severity="High",
                    details="Unhandled exception during EC2 instance audit",
                )
            )

    return findings


def audit_ebs_snapshots(ec2_client=None) -> List[AuditFinding]:
    """
    Audit EBS snapshots for public exposure.

    CIS:
      - 2.2.2 – Ensure EBS snapshots are not publicly accessible
    NIST:
      - AC-3 (Access Enforcement)
      - SC-28 (Protection of Information at Rest)
    """
    client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        snapshots = client.describe_snapshots(
            OwnerIds=["self"]
        ).get("Snapshots", [])

        for snapshot in snapshots:
            snapshot_id = snapshot.get("SnapshotId")
            if not snapshot_id:
                continue

            findings.extend(
                check_ebs_snapshot_exposure(snapshot_id, client)
            )

    except ClientError as e:
        logger.error(
            f"Failed to audit EBS snapshots: {e}",
            exc_info=True
        )
        findings.append(
            AuditFinding(
                service="EC2",
                check="EBS Snapshot Audit",
                check_key="ebs_snapshot",
                resource="account",
                status="FAIL",
                severity="Medium",
                details="Unable to enumerate EBS snapshots"
            )
        )

    return findings


def run_ec2_audit(ec2_client=None, iam_client=None) -> List[AuditFinding]:
    ec2_client = ec2_client or ec2
    iam_client = iam_client or iam

    logger.info("Starting EC2 audit")
    findings: List[AuditFinding] = []

    instances = list_ec2_instances(ec2_client)
    audited_instances = False

    if not instances:
        logger.warning(
            "No EC2 instances were found in this account/region.\n"
            "Instance-level EC2 checks were skipped."
        )

    for instance in instances:
        audited_instances = True
        findings.extend(
            audit_instance(instance, ec2_client, iam_client)
        )

    # ---- Snapshot checks (account-level, still EC2 service) ----
    snapshots = list_ebs_snapshots(ec2_client)
    for snapshot in snapshots:
        snapshot_id = snapshot.get("SnapshotId")
        if snapshot_id:
            findings.extend(
                check_ebs_snapshot_exposure(snapshot_id, ec2_client)
            )

    if audited_instances:
        logger.info("EC2 audit completed successfully")

    if not any(f.status == "FAIL" for f in findings):
        findings.append(
            AuditFinding(
                service="EC2",
                check="EC2 Security Baseline",
                resource="account",
                status="PASS",
                severity="Informational",
                details="No EC2 or EBS security issues detected.",
            )
        )

    return findings




