# CloudAudit

AWS security posture scanner and detection lab. One command scans an AWS
account for 24 common misconfigurations, maps every finding to the CIS AWS
Foundations Benchmark, and writes an HTML/CSV/JSON report with a
step-by-step remediation runbook per finding. A companion detection lab
ships CloudTrail into Splunk with four scheduled threat detections.

Built with Python, boto3, Splunk, Docker, and pytest.

## Why

Most real cloud breaches start with the boring stuff: a public bucket, an
over-permissive IAM policy, a security group open to the world. CloudAudit
automates finding that stuff (posture), and pairs each static check with the
live detection that catches the same problem the moment it is introduced
(telemetry). Scanner says "user X has no MFA"; detection fires when user X
logs in without it.

## Quickstart

```bash
git clone https://github.com/TripathiAkarshika/cloudaudit
cd cloudaudit
pip install -e .

# Read-only credentials are enough (the SecurityAudit managed policy covers it)
cloudaudit scan --profile audit --regions us-east-1
```

Output:

```
Scanned account 123456789012 (us-east-1): 24 checks, 17 findings [2 critical / 6 high / 7 medium / 2 low]
Report: reports/report.html
```

`cloudaudit scan` exits non-zero when critical or high findings exist, so it
can gate a CI pipeline. `cloudaudit list-checks` prints the full catalog.

A sample report generated against a deliberately misconfigured mock account
is in [`examples/`](examples/).

## What it checks

24 checks across four services, each mapped to CIS AWS Foundations
Benchmark v1.5.0 where a control exists ("best practice" otherwise), with a
runbook in [`runbooks/`](runbooks/):

| Area | Checks |
|---|---|
| **S3** (6) | public ACLs, public bucket policies, Block Public Access, default encryption, versioning, access logging |
| **IAM** (8) | root MFA, root access keys, console users without MFA, key rotation (90d), unused credentials (45d), full-admin policies, policies attached to users, password policy |
| **EC2/VPC** (7) | SSH/RDP/all-traffic open to 0.0.0.0/0, default security group rules, unencrypted EBS volumes, EBS encryption-by-default, IMDSv2 enforcement |
| **CloudTrail** (3) | multi-region trail exists, log file validation, trail actually logging |

## Detection lab

[`detections/`](detections/) contains the CloudTrail → Splunk pipeline and
four scheduled SPL searches (root account usage, console login without MFA,
security group changes, CloudTrail tampering), each with a triage runbook
and MITRE ATT&CK mapping. Setup instructions, including a $0 local Splunk
in Docker, are in [`detections/README.md`](detections/README.md).

## Design

- **Checks are plain functions** registered with a decorator
  (`cloudaudit/registry.py`); adding a check means writing one function and
  one runbook, nothing else.
- **Failures never kill a scan**: a check that hits AccessDenied is recorded
  in the report's error list and the scan continues. Partial results beat
  none.
- **Read-only by design**: the scanner only calls List/Get/Describe APIs.
  Run it with the AWS-managed `SecurityAudit` policy.
- **Reports are self-contained**: the HTML report is a single file with no
  external assets, safe to attach to a ticket.

More in [`docs/architecture.md`](docs/architecture.md).

## Development

```bash
pip install -r requirements-dev.txt
pytest            # 30+ tests against a mocked AWS account (moto), no credentials needed
ruff check .
```

CI runs both on every push (`.github/workflows/ci.yml`).

## Roadmap

- RDS and Lambda check packs
- `--format junit` for CI dashboards
- Auto-remediation dry-run mode (print the exact fix commands per finding)

## License

MIT · built by [Akarshika Tripathi](https://www.linkedin.com/in/akarshika-tripathi/)
