import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from shared.aws_clients import get_iam, BaseFinding
from aws_iam_audit.iam_audit import check_root_access_keys


def test_root_no_access_keys():
    iam_client = get_iam()
    stubber = Stubber(iam_client)

    stubber.add_response(
        "get_account_summary",
        {
            "SummaryMap": {
                "AccountAccessKeysPresent": 0
            }
        }
    )

    with stubber:
        findings = check_root_access_keys(iam_client)

    assert findings == []


def test_root_access_keys_present():
    iam_client = get_iam()
    stubber = Stubber(iam_client)

    stubber.add_response(
        "get_account_summary",
        {
            "SummaryMap": {
                "AccountAccessKeysPresent": 1
            }
        }
    )

    with stubber:
        findings = check_root_access_keys(iam_client)

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, BaseFinding)
    assert finding.status == "FAIL"
    assert finding.severity == "Critical"
    assert finding.resource == "root"
    assert "access key" in finding.details.lower()


def test_root_access_keys_client_error():
    iam_client = get_iam()
    stubber = Stubber(iam_client)

    iam_client.add_client_error(
        "get_account_summary",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    with stubber:
        findings = check_root_access_keys(iam_client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status == "FAIL"
    assert finding.severity == "Critical"
    assert "unable to determine" in finding.details.lower()