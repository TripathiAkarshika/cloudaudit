import json

from cloudaudit.checks import s3 as s3_checks
from tests.conftest import REGION, resources


def make_bucket(aws, name):
    aws.client("s3").create_bucket(Bucket=name)
    return name


def test_public_acl_flagged(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "open-bucket")
    s3.put_bucket_acl(Bucket="open-bucket", ACL="public-read")
    make_bucket(aws, "private-bucket")

    found = resources(s3_checks.bucket_acl_public(aws, REGION))
    assert "open-bucket" in found
    assert "private-bucket" not in found


def test_public_policy_flagged(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "policy-bucket")
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*",
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::policy-bucket/*"}]}
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=json.dumps(policy))

    found = resources(s3_checks.bucket_policy_public(aws, REGION))
    assert "policy-bucket" in found


def test_conditioned_policy_not_flagged(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "vpc-bucket")
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*",
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::vpc-bucket/*",
        "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}}}]}
    s3.put_bucket_policy(Bucket="vpc-bucket", Policy=json.dumps(policy))

    assert resources(s3_checks.bucket_policy_public(aws, REGION)) == set()


def test_public_access_block(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "unblocked")
    make_bucket(aws, "blocked")
    s3.put_public_access_block(
        Bucket="blocked",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    found = resources(s3_checks.public_access_block(aws, REGION))
    assert "unblocked" in found
    assert "blocked" not in found


def test_default_encryption(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "enc-bucket")
    s3.put_bucket_encryption(
        Bucket="enc-bucket",
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    make_bucket(aws, "plain-bucket")
    s3.delete_bucket_encryption(Bucket="plain-bucket")

    found = resources(s3_checks.default_encryption(aws, REGION))
    assert "plain-bucket" in found
    assert "enc-bucket" not in found


def test_versioning(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "versioned")
    s3.put_bucket_versioning(Bucket="versioned",
                             VersioningConfiguration={"Status": "Enabled"})
    make_bucket(aws, "unversioned")

    found = resources(s3_checks.versioning(aws, REGION))
    assert "unversioned" in found
    assert "versioned" not in found


def test_access_logging(aws):
    s3 = aws.client("s3")
    make_bucket(aws, "logs-target")
    s3.put_bucket_acl(Bucket="logs-target", GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
                      GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery")
    make_bucket(aws, "logged")
    s3.put_bucket_logging(Bucket="logged", BucketLoggingStatus={
        "LoggingEnabled": {"TargetBucket": "logs-target", "TargetPrefix": "logged/"}})
    make_bucket(aws, "unlogged")

    found = resources(s3_checks.access_logging(aws, REGION))
    assert "unlogged" in found
    assert "logged" not in found
