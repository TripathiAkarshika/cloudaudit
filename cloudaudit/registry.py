"""Check registry.

Each check is a plain function decorated with @check(...). The decorator
attaches metadata and adds the function to the global REGISTRY, so the
scanner can discover every check without hard-coding a list.

A check receives a boto3 Session and a region name and returns a list of
Finding objects (empty list = the check passed everywhere it looked).
Checks for global services (IAM, S3 listing, CloudTrail trail inventory)
declare scope="global" and run exactly once per scan.
"""

from collections.abc import Callable
from dataclasses import dataclass

REGISTRY: list = []


@dataclass(frozen=True)
class CheckMeta:
    check_id: str
    title: str
    service: str
    scope: str          # "global" or "regional"
    cis: str
    func: Callable


def check(check_id: str, title: str, service: str, scope: str, cis: str):
    def wrap(func: Callable):
        meta = CheckMeta(check_id=check_id, title=title, service=service,
                         scope=scope, cis=cis, func=func)
        REGISTRY.append(meta)
        func.meta = meta
        return func
    return wrap


def all_checks() -> list:
    # Import check modules for their registration side effects.
    from cloudaudit.checks import cloudtrail, ec2, iam, s3  # noqa: F401
    return sorted(REGISTRY, key=lambda m: m.check_id)
