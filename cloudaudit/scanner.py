"""Scan orchestrator: runs every registered check and aggregates findings."""

import logging
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloudaudit.findings import sort_findings
from cloudaudit.registry import all_checks

log = logging.getLogger("cloudaudit")


@dataclass
class ScanResult:
    account_id: str
    regions: list
    checks_run: int
    findings: list
    errors: list = field(default_factory=list)   # (check_id, region, message)

    @property
    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


def run_scan(session: boto3.Session | None = None,
             regions: list | None = None) -> ScanResult:
    """Run all checks. Global checks run once; regional checks run per region.

    A check that fails with AccessDenied (or any API error) is recorded in
    ScanResult.errors and never aborts the scan: partial results beat none.
    """
    session = session or boto3.Session()
    regions = regions or [session.region_name or "us-east-1"]

    sts = session.client("sts", region_name=regions[0])
    account_id = sts.get_caller_identity()["Account"]

    findings, errors, executed = [], [], 0
    for meta in all_checks():
        targets = ["global"] if meta.scope == "global" else regions
        for target in targets:
            region = regions[0] if target == "global" else target
            try:
                findings.extend(meta.func(session, region))
            except (ClientError, BotoCoreError) as exc:
                log.warning("%s failed in %s: %s", meta.check_id, target, exc)
                errors.append((meta.check_id, target, str(exc)))
        executed += 1

    return ScanResult(account_id=account_id, regions=regions,
                      checks_run=executed, findings=sort_findings(findings),
                      errors=errors)
