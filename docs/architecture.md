# Architecture

```
cloudaudit/
  cli.py        argparse entry point: scan | list-checks
  scanner.py    orchestrator: session, region fan-out, error isolation
  registry.py   @check decorator + global check registry
  findings.py   Finding dataclass, Severity enum, sorting
  report.py     HTML / CSV / JSON writers
  checks/
    s3.py         6 checks (global scope)
    iam.py        8 checks (global scope)
    ec2.py        7 checks (regional scope)
    cloudtrail.py 3 checks (global scope)
runbooks/       one remediation runbook per check id
detections/     CloudTrail -> Splunk pipeline + 4 SPL searches + triage runbooks
tests/          pytest suite against moto-mocked AWS, no credentials needed
```

## How a scan runs

1. `cli.py` builds a boto3 Session (profile/region from flags or environment)
   and calls `run_scan`.
2. `run_scan` resolves the account id via STS, then iterates the registry.
   Checks declare `scope="global"` (IAM, S3, CloudTrail: their APIs are not
   regional) or `scope="regional"` (EC2: run once per requested region).
3. Each check returns `list[Finding]`; an API error (AccessDenied, throttle)
   is caught per check, logged into `ScanResult.errors`, and the scan
   continues. One missing permission never costs the rest of the report.
4. Findings are sorted most-severe-first and written as HTML, CSV, and JSON.
   The process exit code is 1 when critical/high findings exist, so a
   pipeline can fail a deploy on a bad posture.

## Adding a check

```python
@check("RDS_001", "RDS instance publicly accessible", "rds", "regional", "best practice")
def rds_public(session, region):
    rds = session.client("rds", region_name=region)
    return [Finding(...) for db in ... if db["PubliclyAccessible"]]
```

Write `runbooks/RDS_001.md`, add a moto test, done. The registry picks it up
through the decorator import side effect.

## Design decisions

- **Read-only**: only List/Get/Describe calls, runnable under the AWS-managed
  `SecurityAudit` policy. An auditor that can mutate is a liability.
- **No framework**: checks are flat functions, not classes, because a check
  is one question asked of one API. The decorator carries the metadata.
- **CIS v1.5.0 as the reference**: findings cite a control where one exists
  and say "best practice" where it does not, instead of stretching mappings.
- **moto for tests**: every check is tested against a mocked account seeded
  with both compliant and non-compliant resources, asserting on exact
  check ids and flagged resource names.
