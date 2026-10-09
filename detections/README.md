# Detection lab: CloudTrail → Splunk

The scanner finds misconfigurations at rest. This folder is the second half
of CloudAudit: watching the account's audit log live and catching the moment
something risky happens. Four SPL searches are included, each with a triage
runbook in `runbooks/`.

## Architecture

```
AWS account
  └── CloudTrail (multi-region trail, management events)
        └── S3 log bucket
              └── Splunk Add-on for AWS (SQS-based S3 input or Generic S3 input)
                    └── index=aws, sourcetype=aws:cloudtrail
                          └── saved searches in splunk/ run on a schedule
```

## Setup (local, $0)

1. **Trail**: create a multi-region CloudTrail delivering management events to
   a private S3 bucket (see `../runbooks/CT_001.md` for the exact commands).
2. **Splunk**: run Splunk Enterprise locally with Docker. The free license
   indexes 500MB/day, far more than a lab account produces.

   ```bash
   docker run -d --name splunk -p 8000:8000 -p 8088:8088 \
     -e SPLUNK_START_ARGS=--accept-license \
     -e SPLUNK_PASSWORD=ChangeMe-Locally1 \
     splunk/splunk:latest
   ```

3. **Ingest**: install the *Splunk Add-on for AWS* from Splunkbase inside the
   container. Create an IAM user for Splunk with the add-on's documented
   read-only policy (S3 read on the log bucket + SQS if you use SQS-based
   ingestion; never admin). Configure a CloudTrail input targeting the log
   bucket, writing to an index named `aws`.
4. **Searches**: create each `.spl` file as a saved search (Settings →
   Searches, reports, and alerts), scheduled every 15 minutes, alerting when
   results > 0.
5. **Test it**: generate a benign trigger, e.g. create then revoke a
   throwaway security group rule, and watch `security_group_changes.spl`
   fire. CloudTrail delivers to S3 within ~5-15 minutes.

## The four detections

| Search | Catches | Severity |
|---|---|---|
| `root_account_usage.spl` | Any root API call or console login | CRITICAL |
| `console_login_no_mfa.spl` | Successful console sign-in without MFA | HIGH |
| `security_group_changes.spl` | Security group created/changed, flags 0.0.0.0/0 | MEDIUM |
| `cloudtrail_tampering.spl` | StopLogging / DeleteTrail / UpdateTrail | CRITICAL |

Each detection pairs with a scanner check: the scanner finds the state
(a user without MFA), the detection catches the event (that user logging in).
