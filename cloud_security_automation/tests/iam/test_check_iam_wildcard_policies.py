import pytest


def test_policy_with_wildcard_action_fails(iam_client_mock):
    ...


def test_policy_with_wildcard_resource_fails(iam_client_mock):
    ...


def test_policy_without_wildcards_passes(iam_client_mock):
    ...


def test_aws_managed_policy_ignored(iam_client_mock):
    ...


def test_wildcard_policy_client_error_returns_finding(iam_client_mock):
    ...