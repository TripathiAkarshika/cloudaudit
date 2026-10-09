"""S3 checks: public exposure, encryption, versioning, access logging."""

from botocore.exceptions import ClientError

from cloudaudit.findings import Finding, Severity
from cloudaudit.registry import check

PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _buckets(s3):
    return [b["Name"] for b in s3.list_buckets().get("Buckets", [])]


@check("S3_001", "S3 bucket ACL grants public access", "s3", "global", "2.1.5")
def bucket_acl_public(session, region):
    s3 = session.client("s3")
    findings = []
    for name in _buckets(s3):
        try:
            acl = s3.get_bucket_acl(Bucket=name)
        except ClientError:
            continue
        grantees = [g.get("Grantee", {}).get("URI", "") for g in acl.get("Grants", [])]
        public = [u for u in grantees if u in PUBLIC_GRANTEES]
        if public:
            findings.append(Finding(
                check_id="S3_001",
                title="S3 bucket ACL grants public access",
                severity=Severity.HIGH, service="s3",
                resource=name, region="global",
                description=f"Bucket ACL grants access to {len(public)} public group(s) "
                            "(AllUsers/AuthenticatedUsers).",
                cis="2.1.5"))
    return findings


@check("S3_002", "S3 bucket policy allows public access", "s3", "global", "2.1.5")
def bucket_policy_public(session, region):
    import json
    s3 = session.client("s3")
    findings = []
    for name in _buckets(s3):
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError:
            continue  # no policy attached
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal")
            is_public = principal == "*" or (
                isinstance(principal, dict) and principal.get("AWS") == "*")
            if stmt.get("Effect") == "Allow" and is_public and not stmt.get("Condition"):
                findings.append(Finding(
                    check_id="S3_002",
                    title="S3 bucket policy allows public access",
                    severity=Severity.HIGH, service="s3",
                    resource=name, region="global",
                    description="Bucket policy contains an unconditional Allow statement "
                                "with Principal \"*\".",
                    cis="2.1.5"))
                break
    return findings


@check("S3_003", "S3 Block Public Access not fully enabled", "s3", "global", "2.1.5")
def public_access_block(session, region):
    s3 = session.client("s3")
    findings = []
    flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    for name in _buckets(s3):
        try:
            conf = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            missing = [f for f in flags if not conf.get(f)]
        except ClientError:
            missing = list(flags)  # no configuration at all
        if missing:
            findings.append(Finding(
                check_id="S3_003",
                title="S3 Block Public Access not fully enabled",
                severity=Severity.HIGH, service="s3",
                resource=name, region="global",
                description=f"Block Public Access settings disabled: {', '.join(missing)}.",
                cis="2.1.5"))
    return findings


@check("S3_004", "S3 bucket default encryption disabled", "s3", "global", "best practice")
def default_encryption(session, region):
    s3 = session.client("s3")
    findings = []
    for name in _buckets(s3):
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            findings.append(Finding(
                check_id="S3_004",
                title="S3 bucket default encryption disabled",
                severity=Severity.MEDIUM, service="s3",
                resource=name, region="global",
                description="Bucket has no default server-side encryption configuration.",
                cis="best practice"))
    return findings


@check("S3_005", "S3 bucket versioning disabled", "s3", "global", "best practice")
def versioning(session, region):
    s3 = session.client("s3")
    findings = []
    for name in _buckets(s3):
        try:
            status = s3.get_bucket_versioning(Bucket=name).get("Status")
        except ClientError:
            continue
        if status != "Enabled":
            findings.append(Finding(
                check_id="S3_005",
                title="S3 bucket versioning disabled",
                severity=Severity.LOW, service="s3",
                resource=name, region="global",
                description="Versioning is not enabled, so deleted or overwritten objects "
                            "cannot be recovered.",
                cis="best practice"))
    return findings


@check("S3_006", "S3 server access logging disabled", "s3", "global", "best practice")
def access_logging(session, region):
    s3 = session.client("s3")
    findings = []
    for name in _buckets(s3):
        try:
            conf = s3.get_bucket_logging(Bucket=name)
        except ClientError:
            continue
        if "LoggingEnabled" not in conf:
            findings.append(Finding(
                check_id="S3_006",
                title="S3 server access logging disabled",
                severity=Severity.LOW, service="s3",
                resource=name, region="global",
                description="Server access logging is off; bucket-level request history "
                            "is not being recorded.",
                cis="best practice"))
    return findings
