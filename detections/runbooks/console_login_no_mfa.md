# Detection runbook: Console sign-in without MFA

**Severity:** HIGH · **Search:** `detections/splunk/console_login_no_mfa.spl`

## Triage steps

1. Identify the user from userIdentity.arn and check whether the login matches their normal hours, IP range, and user agent.
2. If the user simply has no MFA device, enroll one now (CloudAudit finding IAM_003 will list them).
3. If the user claims they did not log in, disable the login profile, rotate the password, and review their session's CloudTrail activity.
4. Consider an IAM policy that denies everything except MFA enrollment when MFA is absent.
