"""Finding model and severity levels for CloudAudit."""

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return order[self.value]


@dataclass
class Finding:
    """A single failed check against a single resource."""

    check_id: str          # e.g. "S3_003"
    title: str             # short human-readable name of the check
    severity: Severity
    service: str           # s3 | iam | ec2 | cloudtrail
    resource: str          # ARN, bucket name, user name, sg id ...
    region: str            # region or "global"
    description: str       # what is wrong with THIS resource
    cis: str               # CIS AWS Foundations Benchmark v1.5.0 control, or "best practice"
    runbook: str = field(default="")  # relative path to the remediation runbook

    def __post_init__(self):
        if not self.runbook:
            self.runbook = f"runbooks/{self.check_id}.md"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def sort_findings(findings: list) -> list:
    """Most severe first, then by check id and resource for stable output."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.check_id, f.resource))
