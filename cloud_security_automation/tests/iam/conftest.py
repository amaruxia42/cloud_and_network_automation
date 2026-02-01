import pytest
from unittest.mock import MagicMock
from unittest.mock import Mock


@pytest.fixture
def mock_iam_client():
    """Provides a mocked IAM client for testing."""
    return MagicMock()


@pytest.fixture
def mocker():
    return Mock()


@pytest.fixture
def iam_client_mock():
    return Mock()
