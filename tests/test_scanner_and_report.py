import csv
import json

from cloudaudit.registry import all_checks
from cloudaudit.report import write_csv, write_html, write_json
from cloudaudit.scanner import run_scan
from tests.conftest import REGION


def seed_bad_account(aws):
    """A deliberately misconfigured account: at least one finding per service."""
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="exposed-data")
    s3.put_bucket_acl(Bucket="exposed-data", ACL="public-read")

    iam = aws.client("iam")
    iam.create_user(UserName="no-mfa-user")
    iam.create_login_profile(UserName="no-mfa-user", Password="Xx14characters!!")

    ec2 = aws.client("ec2", region_name=REGION)
    gid = ec2.create_security_group(GroupName="open-ssh",
                                    Description="x")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    # no CloudTrail at all -> CT_001


def test_registry_has_24_unique_checks():
    checks = all_checks()
    assert len(checks) == 24
    assert len({c.check_id for c in checks}) == 24
    assert all(c.scope in ("global", "regional") for c in checks)


def test_full_scan_finds_seeded_issues(aws):
    seed_bad_account(aws)
    result = run_scan(session=aws, regions=[REGION])

    found = {f.check_id for f in result.findings}
    for expected in ("S3_001", "IAM_003", "EC2_001", "CT_001"):
        assert expected in found
    assert result.checks_run == 24
    assert result.account_id
    assert sum(result.severity_counts.values()) == len(result.findings)


def test_findings_sorted_most_severe_first(aws):
    seed_bad_account(aws)
    result = run_scan(session=aws, regions=[REGION])
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks)


def test_reports_written(aws, tmp_path):
    seed_bad_account(aws)
    result = run_scan(session=aws, regions=[REGION])

    csv_path = write_csv(result, tmp_path / "findings.csv")
    json_path = write_json(result, tmp_path / "findings.json")
    html_path = write_html(result, tmp_path / "report.html")

    with open(csv_path) as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(result.findings)
    assert {"check_id", "severity", "resource", "cis", "runbook"} <= set(rows[0])

    payload = json.loads(json_path.read_text())
    assert payload["checks_run"] == 24
    assert len(payload["findings"]) == len(result.findings)

    html = html_path.read_text()
    assert "S3_001" in html and "CloudAudit" in html


def test_every_check_has_a_runbook():
    from pathlib import Path
    runbooks = Path(__file__).resolve().parents[1] / "runbooks"
    for meta in all_checks():
        assert (runbooks / f"{meta.check_id}.md").is_file(), meta.check_id
