import json

from cloudaudit.checks import iam as iam_checks
from cloudaudit.findings import Severity
from tests.conftest import REGION, ids, resources


def test_days_since_handles_missing_values():
    assert iam_checks._days_since("N/A") is None
    assert iam_checks._days_since("no_information") is None
    assert iam_checks._days_since("") is None
    assert iam_checks._days_since("2020-01-01T00:00:00+00:00") > 1000


def test_console_user_without_mfa_flagged(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="console-no-mfa")
    iam.create_login_profile(UserName="console-no-mfa", Password="Xx14characters!!")
    iam.create_user(UserName="api-only")  # no console password: out of scope

    found = resources(iam_checks.users_without_mfa(aws, REGION))
    assert "console-no-mfa" in found
    assert "api-only" not in found


def test_fresh_access_key_not_flagged(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="dev")
    iam.create_access_key(UserName="dev")

    assert iam_checks.stale_access_keys(aws, REGION) == []


def test_stale_access_key_flagged(aws, monkeypatch):
    iam = aws.client("iam")
    iam.create_user(UserName="dev")
    key = iam.create_access_key(UserName="dev")["AccessKey"]["AccessKeyId"]

    monkeypatch.setattr(iam_checks, "KEY_ROTATION_DAYS", -1)
    found = resources(iam_checks.stale_access_keys(aws, REGION))
    assert f"dev/{key}" in found


def test_unused_credentials_runs_cleanly(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="dormant")
    iam.create_login_profile(UserName="dormant", Password="Xx14characters!!")
    # moto's credential report has no usable last-used timestamps; the check
    # must still parse the report without raising.
    assert isinstance(iam_checks.unused_credentials(aws, REGION), list)


def test_full_admin_policy_flagged(aws):
    iam = aws.client("iam")
    iam.create_policy(PolicyName="god-mode", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    iam.create_policy(PolicyName="scoped", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::data/*"}]}))

    found = resources(iam_checks.full_admin_policies(aws, REGION))
    assert "god-mode" in found
    assert "scoped" not in found


def test_full_admin_finding_is_high(aws):
    iam = aws.client("iam")
    iam.create_policy(PolicyName="god-mode", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}))
    findings = iam_checks.full_admin_policies(aws, REGION)
    assert findings and findings[0].severity is Severity.HIGH


def test_policy_attached_to_user_flagged(aws):
    iam = aws.client("iam")
    arn = iam.create_policy(PolicyName="direct", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                       "Resource": "*"}]}))["Policy"]["Arn"]
    iam.create_user(UserName="direct-user")
    iam.attach_user_policy(UserName="direct-user", PolicyArn=arn)
    iam.create_user(UserName="clean-user")

    found = resources(iam_checks.policies_on_users(aws, REGION))
    assert "direct-user" in found
    assert "clean-user" not in found


def test_missing_password_policy_flagged(aws):
    assert ids(iam_checks.password_policy(aws, REGION)) == {"IAM_008"}


def test_weak_password_policy_flagged(aws):
    aws.client("iam").update_account_password_policy(MinimumPasswordLength=8)
    findings = iam_checks.password_policy(aws, REGION)
    assert findings and "minimum length below 14" in findings[0].description


def test_strong_password_policy_passes(aws):
    aws.client("iam").update_account_password_policy(
        MinimumPasswordLength=16, PasswordReusePrevention=24)
    assert iam_checks.password_policy(aws, REGION) == []
