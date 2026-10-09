import boto3
import pytest
from moto import mock_aws

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    """A moto-mocked AWS session; no real credentials are ever used."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def ids(findings):
    return {f.check_id for f in findings}


def resources(findings):
    return {f.resource for f in findings}
