import pytest
from botocore.exceptions import ClientError
from aws_cloudtrail_audit.cloudtrail_audit import check_cloudtrail_exists, check_log_validation, check_trail_kms_encryption


def test_cloudtrail_missing(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {
        "trailsList": []
    }

    findings = check_cloudtrail_exists(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].message == "does not exist"


def test_cloudtrail_exists_ok(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {
        "trailsList": [{"Name": "default"}]
    }

    findings = check_cloudtrail_exists(mock_cloudtrail)

    assert findings == []


def test_cloudtrail_exists_api_error(mock_cloudtrail):
    mock_cloudtrail.describe_trails.side_effect = ClientError(
        error_response={
            "Error": {"Code": "AccessDenied", "Message": "Denied"}},
        operation_name="DescribeTrails",
    )

    findings = check_cloudtrail_exists(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert "Unable to verify" in findings[0].details


def test_multi_region_enabled(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {
        "trailsList": [{"Name": "t1", "IsMultiRegionTrail": True}]
    }

    assert check_cloudtrail_exists(mock_cloudtrail) == []


def test_log_validation_disabled(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {
        "trailsList": [{"Name": "t1", "LogFileValidationEnabled": False}]
    }

    mock_cloudtrail.get_trails_status.return_value = {"IsLogging": True}

    findings = check_log_validation(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].check_key == "log_validation"


def test_kms_not_enabled(mock_cloudtrail):
    mock_cloudtrail.describe_trails.return_value = {
        "trailsList": [{"Name": "t1"}]
    }

    findings = check_trail_kms_encryption(mock_cloudtrail)

    assert len(findings) == 1
    assert findings[0].check_key == "kms_encryption"