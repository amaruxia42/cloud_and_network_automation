from aws_iam_audit.iam_audit import check_root_account_mfa

def test_root_mfa_disabled(mock_iam_client):
    mock_iam_client.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 0}
    }

    findings = check_root_account_mfa(iam_client=mock_iam_client)

    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert findings[0].check_key == "root_mfa"
    assert findings[0].resource == "root"