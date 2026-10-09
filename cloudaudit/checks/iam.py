"""IAM checks: root account hygiene, MFA, key rotation, over-permissive policies."""

import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudaudit.findings import Finding, Severity
from cloudaudit.registry import check

KEY_ROTATION_DAYS = 90
UNUSED_CREDENTIAL_DAYS = 45


def _credential_report(iam) -> list:
    """Return the account credential report as a list of dict rows."""
    for _ in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(1)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def _days_since(iso: str):
    if not iso or iso in ("N/A", "no_information", "not_supported"):
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


@check("IAM_001", "Root account MFA not enabled", "iam", "global", "1.5")
def root_mfa(session, region):
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        return [Finding(
            check_id="IAM_001", title="Root account MFA not enabled",
            severity=Severity.CRITICAL, service="iam",
            resource="root", region="global",
            description="The root account does not have MFA enabled.",
            cis="1.5")]
    return []


@check("IAM_002", "Root account access keys exist", "iam", "global", "1.4")
def root_access_keys(session, region):
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) != 0:
        return [Finding(
            check_id="IAM_002", title="Root account access keys exist",
            severity=Severity.CRITICAL, service="iam",
            resource="root", region="global",
            description="Long-lived access keys exist for the root account.",
            cis="1.4")]
    return []


@check("IAM_003", "Console user without MFA", "iam", "global", "1.10")
def users_without_mfa(session, region):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)  # raises if no console password
            except ClientError:
                continue
            mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
            if not mfa:
                findings.append(Finding(
                    check_id="IAM_003", title="Console user without MFA",
                    severity=Severity.HIGH, service="iam",
                    resource=name, region="global",
                    description="User has a console password but no MFA device.",
                    cis="1.10"))
    return findings


@check("IAM_004", "Access key not rotated within 90 days", "iam", "global", "1.14")
def stale_access_keys(session, region):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age > KEY_ROTATION_DAYS:
                    findings.append(Finding(
                        check_id="IAM_004", title="Access key not rotated within 90 days",
                        severity=Severity.MEDIUM, service="iam",
                        resource=f"{name}/{key['AccessKeyId']}", region="global",
                        description=f"Active access key is {age} days old "
                                    f"(limit {KEY_ROTATION_DAYS}).",
                        cis="1.14"))
    return findings


@check("IAM_005", "Credentials unused for 45+ days", "iam", "global", "1.12")
def unused_credentials(session, region):
    iam = session.client("iam")
    findings = []
    try:
        rows = _credential_report(iam)
    except ClientError:
        return findings
    for row in rows:
        if row.get("user") == "<root_account>":
            continue
        if row.get("password_enabled") == "true":
            days = _days_since(row.get("password_last_used", ""))
            if days is not None and days > UNUSED_CREDENTIAL_DAYS:
                findings.append(Finding(
                    check_id="IAM_005", title="Credentials unused for 45+ days",
                    severity=Severity.MEDIUM, service="iam",
                    resource=row["user"], region="global",
                    description=f"Console password unused for {days} days.",
                    cis="1.12"))
    return findings


@check("IAM_006", "Customer-managed policy allows full admin", "iam", "global", "1.16")
def full_admin_policies(session, region):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for pol in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
            doc = version["PolicyVersion"]["Document"]
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                if (stmt.get("Effect") == "Allow"
                        and "*" in actions and "*" in resources):
                    findings.append(Finding(
                        check_id="IAM_006",
                        title="Customer-managed policy allows full admin",
                        severity=Severity.HIGH, service="iam",
                        resource=pol["PolicyName"], region="global",
                        description="Policy allows Action \"*\" on Resource \"*\", violating "
                                    "least privilege.",
                        cis="1.16"))
                    break
    return findings


@check("IAM_007", "Policy attached directly to user", "iam", "global", "1.15")
def policies_on_users(session, region):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            inline = iam.list_user_policies(UserName=name)["PolicyNames"]
            if attached or inline:
                findings.append(Finding(
                    check_id="IAM_007", title="Policy attached directly to user",
                    severity=Severity.LOW, service="iam",
                    resource=name, region="global",
                    description=f"{len(attached)} attached and {len(inline)} inline policies "
                                "on the user; permissions should flow through groups or roles.",
                    cis="1.15"))
    return findings


@check("IAM_008", "Weak or missing account password policy", "iam", "global", "1.8")
def password_policy(session, region):
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        return [Finding(
            check_id="IAM_008", title="Weak or missing account password policy",
            severity=Severity.MEDIUM, service="iam",
            resource="account-password-policy", region="global",
            description="No account password policy is set.",
            cis="1.8")]
    problems = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        problems.append("minimum length below 14")
    if not policy.get("PasswordReusePrevention"):
        problems.append("password reuse not prevented")
    if problems:
        return [Finding(
            check_id="IAM_008", title="Weak or missing account password policy",
            severity=Severity.MEDIUM, service="iam",
            resource="account-password-policy", region="global",
            description="Password policy issues: " + ", ".join(problems) + ".",
            cis="1.8")]
    return []
