#!/usr/bin/env python3
"""Generate the sample report in examples/ against a mocked, deliberately
misconfigured AWS account. Needs the dev dependencies (moto) but no
credentials and no real AWS account:

    python scripts/generate_sample_report.py
"""

import json
from pathlib import Path

import boto3
from moto import mock_aws

from cloudaudit.report import write_csv, write_html, write_json
from cloudaudit.scanner import run_scan

REGION = "us-east-1"
OUT = Path(__file__).resolve().parents[1] / "examples"


def seed(session):
    """Build a small account with realistic mistakes in every service."""
    s3 = session.client("s3")
    s3.create_bucket(Bucket="customer-exports")
    s3.put_bucket_acl(Bucket="customer-exports", ACL="public-read")
    s3.create_bucket(Bucket="app-assets")
    s3.put_bucket_policy(Bucket="app-assets", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*",
                       "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::app-assets/*"}]}))
    s3.create_bucket(Bucket="terraform-state")  # merely missing hardening

    iam = session.client("iam")
    iam.create_user(UserName="deploy-bot")
    iam.create_user(UserName="akarshika.admin")
    iam.create_login_profile(UserName="akarshika.admin",
                             Password="Xx14characters!!")
    iam.create_access_key(UserName="deploy-bot")
    policy = iam.create_policy(PolicyName="quick-fix-admin",
                               PolicyDocument=json.dumps({
                                   "Version": "2012-10-17",
                                   "Statement": [{"Effect": "Allow",
                                                  "Action": "*",
                                                  "Resource": "*"}]}))
    iam.attach_user_policy(UserName="deploy-bot",
                           PolicyArn=policy["Policy"]["Arn"])

    ec2 = session.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="web-debug",
                                   Description="temporary debug access")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=20)
    ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                      MetadataOptions={"HttpTokens": "optional"})
    # No CloudTrail trail at all.


def main():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        seed(session)
        result = run_scan(session=session, regions=[REGION])

        OUT.mkdir(exist_ok=True)
        write_html(result, OUT / "sample_report.html")
        write_csv(result, OUT / "sample_findings.csv")
        write_json(result, OUT / "sample_findings.json")

        counts = result.severity_counts
        print(f"{result.checks_run} checks, {len(result.findings)} findings "
              f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
              f"{counts['MEDIUM']}M/{counts['LOW']}L] -> {OUT}")


if __name__ == "__main__":
    main()
