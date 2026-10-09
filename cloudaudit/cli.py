"""CloudAudit command line interface.

Usage:
    cloudaudit scan [--profile NAME] [--regions us-east-1,us-west-2] [--output DIR]
    cloudaudit list-checks
"""

import argparse
import logging
import sys
from pathlib import Path

import boto3

from cloudaudit import __version__
from cloudaudit.registry import all_checks
from cloudaudit.report import write_csv, write_html, write_json
from cloudaudit.scanner import run_scan


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloudaudit",
                                description="AWS security posture scanner")
    p.add_argument("--version", action="version", version=f"cloudaudit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an AWS account")
    scan.add_argument("--profile", help="AWS profile name (default: environment)")
    scan.add_argument("--regions", help="comma-separated regions "
                                        "(default: the session region)")
    scan.add_argument("--output", default="reports",
                      help="directory for report files (default: ./reports)")

    sub.add_parser("list-checks", help="list every registered check")
    return p


def _cmd_list_checks() -> int:
    for meta in all_checks():
        print(f"{meta.check_id:8} {meta.scope:8} CIS {meta.cis:13} {meta.title}")
    print(f"\n{len(all_checks())} checks registered")
    return 0


def _cmd_scan(args) -> int:
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    regions = args.regions.split(",") if args.regions else None

    result = run_scan(session=session, regions=regions)

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    html_path = write_html(result, outdir / "report.html")
    write_csv(result, outdir / "findings.csv")
    write_json(result, outdir / "findings.json")

    counts = result.severity_counts
    print(f"Scanned account {result.account_id} "
          f"({', '.join(result.regions)}): {result.checks_run} checks, "
          f"{len(result.findings)} findings "
          f"[{counts['CRITICAL']} critical / {counts['HIGH']} high / "
          f"{counts['MEDIUM']} medium / {counts['LOW']} low]")
    if result.errors:
        print(f"{len(result.errors)} check(s) could not run "
              "(missing permissions?) - see findings.json")
    print(f"Report: {html_path}")

    # Non-zero exit when critical or high findings exist, so CI jobs can gate.
    return 1 if counts["CRITICAL"] or counts["HIGH"] else 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    args = _parser().parse_args(argv)
    if args.command == "list-checks":
        return _cmd_list_checks()
    return _cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
