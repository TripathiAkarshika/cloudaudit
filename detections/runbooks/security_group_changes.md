# Detection runbook: Security group modified

**Severity:** MEDIUM · **Search:** `detections/splunk/security_group_changes.spl`

## Triage steps

1. Check the world_open column first: a YES on AuthorizeSecurityGroupIngress is a live exposure.
2. Confirm with the caller (userIdentity.arn) whether the change was intentional and ticketed.
3. If not intentional, revoke the rule immediately (see runbooks/EC2_001.md for the CLI) and review what the group is attached to.
4. Re-run cloudaudit scan to confirm no EC2_001/EC2_002/EC2_003 findings remain.
