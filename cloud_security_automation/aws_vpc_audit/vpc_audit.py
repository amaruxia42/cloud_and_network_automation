from botocore.exceptions import ClientError
from typing import List
from shared.logger import get_logger
from shared.aws_clients import get_ec2
from shared.report import AuditFinding

logger = get_logger(__name__)
ec2 = get_ec2()


def list_vpc_ids(ec2_client=None) -> List[str]:
    """Return a list of all VPC IDs in the account
    Utility function for VPC resource discovery
    """
    ec2_client = ec2_client or ec2
    vpc_ids: List[str] = []

    try:
        paginator = ec2_client.get_paginator("describe_vpcs")

        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                vpc_id = vpc.get("VpcId")
                if vpc_id:
                    vpc_ids.append(vpc_id)

    except ClientError as e:
        logger.error(f"Error listing VPCs: {e}", exc_info=True)

    return vpc_ids


def check_default_security_groups(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    """
    Check whether the default security group in a VPC is overly permissive.

    CIS: 4.3 – Ensure the default security group restricts traffic
    NIST: AC-3, AC-4, SC-7
    """
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )

        for sg in response.get("SecurityGroups", []):
            ingress_rules = sg.get("IpPermissions", [])
            egress_rules = sg.get("IpPermissionsEgress", [])

            if ingress_rules or egress_rules:
                findings.append(
                    AuditFinding(
                        service="VPC",
                        check="Default Security Group",
                        check_key="default_security_groups",
                        resource=vpc_id,
                        status="FAIL",
                        severity="Medium",
                        details=(
                            f"Default security group {sg.get('GroupId')} "
                            "contains ingress or egress rules. "
                            "Best practice is to remove all rules and avoid using the default SG."
                        ),
                    )
                )

    except ClientError as e:
        logger.error(
            f"Error checking default security group for VPC {vpc_id}: {e}",
            exc_info=True,
        )
        findings.append(
            AuditFinding(
                service="VPC",
                check="Default Security Group",
                check_key="default_security_group",
                resource=vpc_id,
                status="FAIL",
                severity="Medium",
                details="Unable to evaluate default security group configuration",
            )
        )

    return findings


def check_vpc_security_groups(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    """
    Check for unrestricted inbound security group rules in a VPC.
    CIS 4.1, 4.2 | NIST AC-3, SC-7
    """
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = ec2_client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for sg in response.get("SecurityGroups", []):
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")

            # ----- Check for unrestricted ingress rules -----
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol")

                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if protocol == "-1":
                    port_desc = "ALL protocols and ports"
                elif from_port == to_port:
                    port_desc = f"Port {from_port}"
                else:
                    port_desc = f"Ports {from_port}-{to_port}"

                # ----- Checking IPv4 and IPv6 for 'Allow All' -----
                ipv4_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                ipv6_ranges = [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]

                if "0.0.0.0/0" in ipv4_ranges or "::/0" in ipv6_ranges:
                    findings.append(
                        AuditFinding(
                            service="VPC",
                            check="Unrestricted Ingress",
                            check_key="security_groups",
                            resource=sg_id,
                            status="FAIL",
                            severity="High",
                            details=(
                                f"Security Group '{sg_name}' ({sg_id}) allows unrestricted "
                                f"inbound access ({port_desc}). This violates the principle "
                                "of least privilege and increases network exposure."
                            ),
                        )
                    )

    except ClientError as e:
        logger.error(f"Error auditing VPC SG {vpc_id}: {e}", exc_info=True)
        findings.append(
            AuditFinding(
                service="VPC",
                check="Unrestricted Ingress",
                check_key="security_groups",
                resource=vpc_id,
                status="FAIL",
                severity="Medium",
                details=f"Audit Interrupted: Failed to describe SGs. Error: {e.response['Error']['Code']}",
            )
        )

    return findings


def check_vpc_flow_logs(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    """
    Check if VPC Flow Logs are enabled and active.

    CIS: 3.9
    NIST: AU-2, AU-12
    """
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )

        flow_logs = response.get("FlowLogs", [])
        is_active = any(log.get("FlowLogStatus") == "ACTIVE" for log in flow_logs)

        if not flow_logs or not is_active:
            findings.append(
                AuditFinding(
                    service="VPC",
                    check="VPC Flow Logs",
                    check_key="flow_logs",
                    resource=vpc_id,
                    status="FAIL",
                    severity="High",
                    details=(
                        f"No ACTIVE VPC Flow Logs detected for VPC {vpc_id}. "
                        "Without flow logs, network traffic cannot be audited or investigated."
                    ),
                )
            )

    except ClientError as e:
        logger.error(
            f"Flow Logs check failed for VPC {vpc_id}: {e}",
            exc_info=True,
        )
        findings.append(
            AuditFinding(
                service="VPC",
                check="VPC Flow Logs",
                check_key="flow_logs",
                resource=vpc_id,
                status="FAIL",
                severity="Low",
                details="Unable to evaluate VPC Flow Logs due to AWS API error",
            )
        )

    return findings


def check_route_tables(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    """
    Check for route tables with default routes (0.0.0.0/0 or ::/0)
    pointing to an Internet Gateway.

    CIS: 4.4
    NIST: AC-4, SC-7
    """
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for rt in response.get("RouteTables", []):
            rt_id = rt.get("RouteTableId", "unknown")
            is_main = any(a.get("Main") for a in rt.get("Associations", []))
            exposures = []

            for route in rt.get("Routes", []):
                if route.get("GatewayId", "").startswith("igw-"):
                    if route.get("DestinationCidrBlock") == "0.0.0.0/0":
                        exposures.append("IPv4 0.0.0.0/0")
                    if route.get("DestinationIpv6CidrBlock") == "::/0":
                        exposures.append("IPv6 ::/0")

            if exposures:
                main_note = " (Main Route Table)" if is_main else ""
                findings.append(
                    AuditFinding(
                        service="VPC",
                        check="Internet Gateway Route",
                        check_key="route_tables",
                        resource=vpc_id,
                        status="FAIL",
                        severity="High",
                        details=(
                            f"Route table {rt_id}{main_note} has internet "
                            f"routes via IGW: {', '.join(exposures)}. "
                            "Subnets associated with this table are public."
                        ),
                    )
                )

    except ClientError as e:
        logger.error(
            f"Route table check failed for VPC {vpc_id}: {e}",
            exc_info=True,
        )
        findings.append(
            AuditFinding(
                service="VPC",
                check="Route Table Audit",
                check_key="route_tables",
                resource=vpc_id,
                status="FAIL",
                severity="Low",
                details="Unable to evaluate route table configuration",
            )
        )

    return findings


def check_network_acls(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    """
    Check Network ACLs for overly permissive inbound rules.

    CIS: 4.1 – Network Security
    NIST: AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection)
    """
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    try:
        response = ec2_client.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for nacl in response.get("NetworkAcls", []):
            nacl_id = nacl.get("NetworkAclId", "unknown")

            for entry in nacl.get("Entries", []):
                # Skip egress rules
                if entry.get("Egress"):
                    continue

                cidr_v4 = entry.get("CidrBlock") == "0.0.0.0/0"
                cidr_v6 = entry.get("Ipv6CidrBlock") == "::/0"

                if (
                    entry.get("RuleAction") == "allow"
                    and entry.get("Protocol") == "-1"
                    and (cidr_v4 or cidr_v6)
                ):
                    findings.append(AuditFinding(
                        service="VPC",
                        check="Network ACL Rules",
                        check_key="nacl_rules",
                        resource=nacl_id,
                        status="FAIL",
                        severity="High",
                        details=(
                            f"Inbound NACL rule {entry.get('RuleNumber')} "
                            f"allows all traffic from 0.0.0.0/0"
                        ),
                    ))

    except ClientError as e:
        logger.error(
            f"Error checking NACLs for VPC {vpc_id}: {e}",
            exc_info=True
        )
        findings.append(AuditFinding(
            service="VPC",
            check="Network ACL Rules",
            check_key="nacl_rules",
            resource=vpc_id,
            status="FAIL",
            severity="High",
            details=f"Unable to evaluate Network ACLs: {e}",
        ))

    return findings


def audit_vpc(vpc_id: str, ec2_client=None) -> List[AuditFinding]:
    ec2_client = ec2_client or ec2
    findings: List[AuditFinding] = []

    checks = [
        check_default_security_groups,
        check_vpc_security_groups,
        check_route_tables,
        check_vpc_flow_logs,
        check_network_acls,
    ]

    for check in checks:
        try:
            results = check(vpc_id, ec2_client=ec2_client)
            findings.extend(results)

        except Exception as e:
            logger.error(
                f"{check.__name__} failed for VPC {vpc_id}: {e}",
                exc_info=True,
            )
            findings.append(
                AuditFinding(
                    service="VPC",
                    check=check.__name__,
                    check_key="execution_error",
                    resource=vpc_id,
                    status="FAIL",
                    severity="High",
                    details="Unhandled exception during VPC audit",
                )
            )

    return findings


def run_vpc_audit(ec2_client=None) -> List[AuditFinding]:
    ec2_client = ec2_client or ec2

    logger.info("Starting VPC audit")
    all_findings: List[AuditFinding] = []

    vpc_ids = list_vpc_ids(ec2_client)

    if not vpc_ids:
        logger.warning(
            "No VPCs found in this account/region.\n"
            "VPC-level checks were skipped."
        )
        return all_findings

    for vpc_id in vpc_ids:
        all_findings.extend(audit_vpc(vpc_id, ec2_client))

    failed = sum(1 for f in all_findings if f.status == "FAIL")

    if failed == 0:
        all_findings.append(
            AuditFinding(
                service="VPC",
                check="VPC Security Baseline",
                check_key="baseline",
                resource="account",
                status="PASS",
                severity="Informational",
                details="No VPC security issues detected.",
            )
        )

    if failed:
        logger.info(
            "VPC audit completed with %d failed checks, see report for further details",
            failed
        )
    else:
        logger.info("VPC audit completed successfully with no findings")

    return all_findings



