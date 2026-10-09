# Detection runbook: CloudTrail tampering

**Severity:** CRITICAL · **Search:** `detections/splunk/cloudtrail_tampering.spl`

## Triage steps

1. Restart logging immediately: aws cloudtrail start-logging --name TRAIL.
2. Treat the caller identity as compromised until proven otherwise; review every action it took before and after the tampering event.
3. Check S3 for deleted or modified log objects and use log file validation digests to verify integrity (CloudAudit CT_002).
4. Preserve evidence before cleanup: copy the relevant log files to a separate, locked-down bucket.
