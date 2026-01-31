import pytest
from botocore.exceptions import ClientError
from aws_cloudtrail_audit.cloudtrail_audit import (
    check_cloudtrail_exists,
    check_log_validation,
    check_trail_kms_encryption
)


def test_cloudtrail_missing(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {"trailList": []}
    findings = check_cloudtrail_exists(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].check_key == "cloudtrail_exists"


def test_cloudtrail_exists_api_error(mock_cloudtrail):
    mock_cloudtrail.describe_trails.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDenied", "Message": "Denied"}},
        operation_name="DescribeTrails",
    )

    findings = check_cloudtrail_exists(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].check_key == "cloudtrail_exists"
    assert "Unable to verify" in findings[0].details


def test_log_validation_disabled(mock_cloudtrail):
    # Mocking the trail data
    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [{"Name": "t1", "LogFileValidationEnabled": False}]
    }

    findings = check_log_validation(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].check_key == "log_validation"
    assert "disabled" in findings[0].details.lower()


def test_kms_encryption_missing(mock_cloudtrail):
    """Test when KmsKeyId is missing from the trail configuration"""
    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [{"Name": "t1"}]  # No KmsKeyId key present
    }

    findings = check_trail_kms_encryption(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].check_key == "kms_encryption"
    assert "not encrypted" in findings[0].details.lower()
