import pytest
from aws_iam_audit.iam_audit import check_iam_password_policy
from botocore.exceptions import ClientError


def test_check_iam_password_policy(mocker):
    iam_client = mocker.Mock()

    iam_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 14,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "PasswordReusePrevention": 24,
            "MaxPasswordAge": 90
        }
    }

    findings = check_iam_password_policy(iam_client=iam_client)

    assert findings == []


def test_password_policy_non_compliant(mocker):
    iam_client = mocker.Mock()

    iam_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 8,  # too short
            "RequireUppercaseCharacters": False,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": False,
            "PasswordReusePrevention": 5,
            "MaxPasswordAge": 365,
        }
    }

    findings = check_iam_password_policy(iam_client=iam_client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status == "FAIL"
    assert finding.severity == "High"
    assert "password policy" in finding.details.lower()


def test_password_policy_missing(mocker):
    iam_client = mocker.Mock()

    iam_client.get_account_password_policy.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "NoSuchEntity",
                "Message": "The password policy does not exist."
            }
        },
        operation_name="GetAccountPasswordPolicy"
    )

    findings = check_iam_password_policy(iam_client=iam_client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status == "FAIL"
    assert finding.severity == "High"
    assert "no iam password policy" in finding.details.lower()


def test_password_policy_api_error(mocker):
    iam_client = mocker.Mock()

    iam_client.get_account_password_policy.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "AccessDenied",
                "Message": "Not authorized"
            }
        },
        operation_name="GetAccountPasswordPolicy"
    )

    findings = check_iam_password_policy(iam_client=iam_client)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert "Unable to audit" in findings[0].details
    assert "Access Denied" in findings[0].details
