"""CloudTrail checks: the audit log that the Splunk detections depend on."""

from botocore.exceptions import ClientError

from cloudaudit.findings import Finding, Severity
from cloudaudit.registry import check


def _trails(ct):
    return ct.describe_trails(includeShadowTrails=False).get("trailList", [])


@check("CT_001", "No multi-region CloudTrail", "cloudtrail", "global", "3.1")
def multi_region_trail(session, region):
    ct = session.client("cloudtrail")
    trails = _trails(ct)
    if not any(t.get("IsMultiRegionTrail") for t in trails):
        return [Finding(
            check_id="CT_001", title="No multi-region CloudTrail",
            severity=Severity.HIGH, service="cloudtrail",
            resource="account", region="global",
            description="No trail records management events across all regions, so "
                        "API activity outside the home region is invisible.",
            cis="3.1")]
    return []


@check("CT_002", "CloudTrail log file validation disabled", "cloudtrail", "global", "3.2")
def log_file_validation(session, region):
    ct = session.client("cloudtrail")
    findings = []
    for trail in _trails(ct):
        if not trail.get("LogFileValidationEnabled"):
            findings.append(Finding(
                check_id="CT_002", title="CloudTrail log file validation disabled",
                severity=Severity.MEDIUM, service="cloudtrail",
                resource=trail.get("Name", "unknown"), region="global",
                description="Log file integrity validation is off, so tampering with "
                            "delivered logs cannot be detected.",
                cis="3.2"))
    return findings


@check("CT_003", "CloudTrail trail is not logging", "cloudtrail", "global", "3.1")
def trail_logging(session, region):
    ct = session.client("cloudtrail")
    findings = []
    for trail in _trails(ct):
        arn = trail.get("TrailARN") or trail.get("Name")
        try:
            status = ct.get_trail_status(Name=arn)
        except ClientError:
            continue
        if not status.get("IsLogging"):
            findings.append(Finding(
                check_id="CT_003", title="CloudTrail trail is not logging",
                severity=Severity.HIGH, service="cloudtrail",
                resource=trail.get("Name", "unknown"), region="global",
                description="The trail exists but logging is stopped.",
                cis="3.1"))
    return findings
