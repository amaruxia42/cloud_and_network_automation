import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from aws_iam_audit.iam_audit import check_iam_user_access_keys_rotation
from shared.report import AuditFinding


def days_ago(date: int):
    return datetime.now(timezone.utc) - timedelta(days=date)


def make_client_error(code="AccessDenied", message="Access denied"):
    return ClientError(
        error_response={
            "Error": {"Code": code, "Message": message}
        },
        operation_name="ListAccessKeys",
    )

# ---------------------------------
#           Tests
# ---------------------------------


def test_user_with_no_access_key():
    iam = MagicMock()

    iam.list_users.return_value = {
        "Users": [{"UserName": "john"}]
    }

    iam.list_access_keys.return_value = {
        "AccessKeysMetadata": []
    }

    findings = check_iam_user_access_keys_rotation(iam)

    assert findings == []


def test_user_with_recent_access_key_passes():
    iam = MagicMock()

    iam.list_users.return_value = {
        "Users": [{"UserName": "nicki"}]
    }

    iam.list_access_keys.return_value = {
        "AccessKeysMetadata": [
            {
                "AccessKeyId": "AKIRA123",
                "CreateDate": days_ago(10),
                "Status": "Active"
            }
        ]
    }

    findings = check_iam_user_access_keys_rotation(iam_client=iam)

    assert findings == []


def test_user_with_stale_access_key_passes():
    iam = MagicMock()
    iam.list_users.return_value = {
        "Users": [{"UserName": "sarah"}]
    }

    iam.list_access_keys.return_value = {
        "AccessKeysMetadata": [
            {
                "AccessKeyId": "AKIRA0LD",
                "CreateDate": days_ago(120),
                "Status": "Active"
            }
        ]
    }

    findings = check_iam_user_access_keys_rotation(iam_client=iam)

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, AuditFinding)
    assert finding.status == "FAIL"
    assert finding.severity == "High"
    assert "rotated" in finding.details.lower()
    assert finding.resource == "sarah"


def test_user_with_multiple_keys_one_stale_fails():
    iam = MagicMock()

    iam.list_users.return_value = {
        "Users": [{"UserName": "dave"}]
    }

    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIARECENT",
                "CreateDate": days_ago(5),
                "Status": "Active"
            },
            {
                "AccessKeyId": "AKIASTALE",
                "CreateDate": days_ago(200),
                "Status": "Active"
            }
        ]
    }

    findings = check_iam_user_access_keys_rotation(iam_client=iam)

    assert len(findings) == 1
    assert findings[0].resource == "dave"


def test_api_error_returns_finding():
    iam = MagicMock()

    iam.list_users.side_effect = make_client_error()

    findings = check_iam_user_access_keys_rotation(iam_client=iam)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "High"
    assert "unable" in findings[0].details.lower()