
FRAMEWORKS = {
    "s3": {
        "public_access": "CIS 2.1.1, CIS 2.1.2, NIST AC-3, NIST AC-6, NIST SC-28, NIST MP-4",
        "access_logging": "CIS 2.2, NIST AU-2, NIST AU-12, NIST AU-6",
        "versioning": "CIS 2.3, NIST CP-9, NIST CP-10, NIST SI-12",
        "encryption_at_rest": "CIS 2.1, NIST SC-12",
        "cors_rules": "CIS 2.1.1 (related), CIS 2.1.2 (related), NIST AC-3, NIST AC-6, NIST SC-7, NIST SC-28",
        "mfa_delete": "CIS 2.3, NIST CP-9, NIST CP-10, NIST SI-12, NIST AC-3",
        "notifications": "NIST AU-2, NIST AU-6, NIST SI-4, NIST SI-5",
    },
    "ec2": {
        "public_exposure": "CIS 4.9, NIST SC-7",
        "imds": "CIS 4.29, NIST IA-3",
        "instance_profile": "CIS 1.16, NIST AC-2, NIST AC-6",
        "security_groups": "CIS 4.1 , CIS 4.2, NIST AC-3, NIST AC-6",
        "encryption_at_rest": "CIS 2.1, NIST SC-12",
        "ebs_snapshots": "CIS 2.2.2, NIST AC-3, NIST SC-28",
    },
    "dynamodb": {
        "point_in_time_recovery": "CIS 3.11, NIST CP-9, NIST CP-10, NIST SI-12",
        "backups": "NIST CP-9, NIST CP-10",
        "autoscaling": "NIST SC-5, NIST CP-2, NIST CP-10, NIST SI-13",
        "encryption_at_rest": "CIS 2.1, NIST SC-12",
        "deletion_protection": "NIST CP-9, NIST CP-10",
        "public_access": "CIS 4.9, NIST SC-7",
        "kms_cmk_usage":""
    },
    "iam": {
        "root_mfa": "CIS 1.2, NIST IA-2",
        "user_mfa": "CIS 1.2, NIST IA-2, AC-7",
        "root_access_keys": "CIS 1.4, NIST IA-2",
        "access_key_age": "CIS 1.4, NIST IA-5",
        "wildcard_policies": "CIS 1.16, NIST AC-6",
        "password_policy": "CIS 1.5.11, NIST IA-5",
        "access_keys_rotation": "CIS 1.3, NIST IA-5"
    },
    "vpc": {
        "security_groups": "CIS 4.1 , CIS 4.2, NIST AC-3, NIST AC-6",
        "default_security_groups": "CIS 4.3, NIST: AC-3, AC-4, SC-7",
        "nacl_rules": "CIS: 4.1, NIST: AC-4, SC-7",
        "route_tables": "CIS: 4.4, NIST: AC-4, SC-7",
        "flow_logs": "CIS: 3.9, NIST AU-2, NIST AU-12"
    },
    "cloudtrail": {
        "does_trail_exist": "CIS 2.1, NIST AU-2, AU-12",
        "multi_region": "CIS 2.2, NIST AU-2",
        "management_events": "CIS 2.4, NIST AU-12",
        "log_validation": "CIS 2.5, NIST AU-6",
        "encryption": "CIS 2.7, NIST SC-12"
    },
}


def get_framework(service: str, check_key: str) -> str | None:
    """
    Return CIS  and NIST framework mapping for a given AWS service + check key. Returns
    None if no framework applies.
    """
    service = service.lower()
    service_framework = FRAMEWORKS.get(service, {})


    return service_framework.get(check_key)
















