import pytest
from shared.report import AuditFinding
from aws_iam_audit.iam_audit import check_iam_user_mfa


class MockIAMClient:
    def list_users(self):
        return {
            "Users": [
                {"UserName": "alice"}
            ]
        }

    def get_login_profile(self, UserName):
        # User HAS console access
        return {"LoginProfile": {"UserName": UserName}}

    def list_mfa_devices(self, UserName):
        # User has NO MFA devices
        return {"MFADevices": []}


def test_user_with_console_access_no_mfa():
    iam_client = MockIAMClient()

    findings = check_iam_user_mfa(iam_client=iam_client)

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, AuditFinding)
    assert finding.service == "IAM"
    assert finding.check == "IAM User MFA"
    assert finding.check_key == "user_mfa"
    assert finding.resource == "alice"
    assert finding.status == "FAIL"
    assert finding.severity == "High"
    assert "no mfa" in finding.details.lower()
