# Detection runbook: Root account activity

**Severity:** CRITICAL · **Search:** `detections/splunk/root_account_usage.spl`

## Triage steps

1. Confirm whether a planned break-glass action explains the activity (check with whoever holds root).
2. If unexplained: treat as account takeover. From a trusted session, rotate the root password, verify root MFA is intact, and review IAM for new users, keys, or policy changes created around the event time.
3. Search the same source IP across all CloudTrail events to scope what else it touched.
4. Afterwards, re-check CloudAudit findings IAM_001/IAM_002 to make sure root hygiene is clean.
