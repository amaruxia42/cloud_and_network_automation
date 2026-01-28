import json
import csv
import uuid
from io import StringIO
from typing import List, Dict, Optional
from pydantic import BaseModel, Field, computed_field, model_validator, field_validator
from collections import Counter
from datetime import datetime, timezone
from shared.frameworks import get_framework


AUDIT_RUN_ID = uuid.uuid4().hex[:5]

AWSService = {
    "ApplicationAutoScaling",
    "CloudTrail",
    "EC2",
    "DynamoDB",
    "IAM",
    "S3",
    "VPC"
}

RESOURCE_MAPPING: Dict[str, str] = {
    "ApplicationAutoScaling": "scaling polices and scalable targets",
    "CloudTrail": "api activity",
    "DynamoDB": "tables",
    "EC2": "instances",
    "IAM": "roles and policies",
    "S3": "buckets",
    "VPC": "networks"
}

SEVERITY_LEVELS = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational"
}

STATUS_VALUES = {
    "PASS",
    "FAIL",
}


class AuditSummary(BaseModel):
    service_type: str
    total_resources: int
    resources_with_issues: int
    critical_severity_issues: int = 0
    high_severity_issues: int = 0
    medium_severity_issues: int = 0
    low_severity_issues: int = 0
    informational_severity_issues: int = 0

    @computed_field
    @property
    def resource_label(self) -> str:
        return RESOURCE_MAPPING.get(self.service_type, "resources")


    @computed_field
    @property
    def total_issues_found(self) -> int:
        return (
                self.critical_severity_issues +
                self.high_severity_issues +
                self.medium_severity_issues +
                self.low_severity_issues
        )


class AuditFinding(BaseModel):
    service: str
    check: str
    resource: str
    status: str
    severity: str
    details: str

    check_key: Optional[str] = None

    @field_validator("service")
    @classmethod
    def validate_service(cls, value: str) -> str:
        if value not in AWSService:
            raise ValueError(
                f"Invalid service value: {value}"
                f"Must be one of {sorted(AWSService)}"
            )

        return value


    @field_validator("check_key")
    @classmethod
    def validate_check_key(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise ValueError("check_key must be a string")

        normalized = value.lower().strip()
        if not normalized:
            raise ValueError("check_key cannot be empty")

        return normalized

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in STATUS_VALUES:
            raise ValueError(
                f"Invalid status value: {value}"
                f"Must be one of {sorted(STATUS_VALUES)}"
            )

        return value


    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity level: {value}"
                f"Must be one of {sorted(SEVERITY_LEVELS)}"
            )

        return value


    # ----- Add Service Check key from get_framework function and use @computed_field to pull the info -----
    @computed_field()
    def framework(self) -> str | None:
        """
        Automatically looks up the compliance framework (NIST, CIS, etc.)
        whenever this object is serialized.
        """
        if self.status != "FAIL" or not self.check_key:
            return None

        return get_framework(self.service, self.check_key)

    # ----- Automatic Metadata (Replaces my audit_metadata function)
    audit_run_id: str = Field(default=AUDIT_RUN_ID)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    def audit_id_formatted(self) -> str:
        return f"{self.audit_run_id}-{self.timestamp.strftime('%d-%m-%Y %H:%M:%S.%f')}"


    @model_validator(mode="after")
    def require_check_key_for_failures(self):
        if self.status == "FAIL" and not self.check_key:
            raise ValueError("check_key is required when status is FAIL")
        return self


class ServicesAuditReport(BaseModel):
    """
     A flat list of findings from ALL services (S3, IAM, DynamoDB, etc.)
    """
    findings: List[AuditFinding]

    @computed_field
    def summary(self) -> Dict:
        """Automatically calculates counts whenever the model is accessed."""
        failed_findings = [f for f in self.findings if f.status == "FAIL"]

        severity_counts = Counter(f.severity for f in failed_findings)
        services_audited = {f.service for f in self.findings}
        failed_resources = {f.resource for f in self.findings if f.status == "FAIL"}

        return {
            "total_findings": len(self.findings),
            "total_failed_checks": sum(severity_counts.values()),
            "services_audited_count": len(services_audited),
            "resources_with_issues": len(failed_resources),
            "severity_breakdown": dict(severity_counts)
        }

    def to_json(self, filepath: str = None) -> str:
        """Serializes the entire report to JSON."""
        data = self.model_dump(mode='json')
        if filepath:
            with open(filepath, 'w') as file:
                json.dump(data, file, indent=2)
        return json.dumps(data)

    def to_csv(self, filepath: str = None) -> str:
        """Flattens findings into a CSV format."""
        output = StringIO()
        if not self.findings:
            return ""

        # Get headers from the first finding's keys
        headers = ["service", "resource", "check", "status", "severity", "details", "audit_id_formatted"]
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()

        for finding in self.findings:
            # ----- model_dump to catch the @computed_field 'audit_id_formatted' -----
            row = finding.model_dump(mode='json')

            # ----- Filter row to only include headers -----
            writer.writerow({k: row.get(k) for k in headers})

        content = output.getvalue()
        if filepath:
            with open(filepath, 'w') as file:
                file.write(content)

        return content

