import pytest
from unittest.mock import MagicMock
from unittest.mock import Mock
# from moto import mock_iam  # Professional alternative

@pytest.fixture
def mock_iam_client():
    """Provides a mocked IAM client for testing."""
    return MagicMock()

# If you wanted to use Moto for real AWS behaviour simulation:
# @pytest.fixture
# def iam_moto():
#     with mock_iam():
#         yield boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def mocker():
    return Mock()


@pytest.fixture
def iam_client_mock():
    return Mock()