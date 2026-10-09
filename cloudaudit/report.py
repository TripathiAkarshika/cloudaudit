"""Report writers: CSV, JSON, and a self-contained HTML report."""

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ["check_id", "title", "severity", "service", "resource", "region",
          "description", "cis", "runbook"]

SEVERITY_COLORS = {
    "CRITICAL": "#b3261e",
    "HIGH": "#c4451c",
    "MEDIUM": "#b07d10",
    "LOW": "#4f6f52",
}

RUNBOOK_BASE = "https://github.com/TripathiAkarshika/cloudaudit/blob/main/"


def write_csv(result, path: Path) -> Path:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for f in result.findings:
            writer.writerow(f.to_dict())
    return path


def write_json(result, path: Path) -> Path:
    payload = {
        "account_id": result.account_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "regions": result.regions,
        "checks_run": result.checks_run,
        "severity_counts": result.severity_counts,
        "findings": [f.to_dict() for f in result.findings],
        "errors": [{"check_id": c, "region": r, "message": m} for c, r, m in result.errors],
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def write_html(result, path: Path) -> Path:
    counts = result.severity_counts
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = " · ".join(f"{counts[s]} {s.lower()}" for s in
                         ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    rows = []
    for f in result.findings:
        color = SEVERITY_COLORS[f.severity.value]
        runbook_url = RUNBOOK_BASE + f.runbook
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>"
            f"{f.severity.value}</span></td>"
            f"<td class='mono'>{html.escape(f.check_id)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td class='mono'>{html.escape(f.resource)}</td>"
            f"<td>{html.escape(f.region)}</td>"
            f"<td>{html.escape(f.description)}</td>"
            f"<td class='mono'>{html.escape(f.cis)}</td>"
            f"<td><a href='{html.escape(runbook_url)}'>fix</a></td>"
            "</tr>")

    body_rows = "\n".join(rows) or (
        "<tr><td colspan='8' style='text-align:center;padding:2rem'>"
        "No findings. Every check passed.</td></tr>")

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudAudit Report</title>
<style>
  :root {{ --ink:#1c1b1f; --paper:#ffffff; --line:#e3e1e7; --dim:#5f5d66; }}
  body {{ margin:0; padding:24px 16px; background:var(--paper); color:var(--ink);
         font:14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .meta {{ color:var(--dim); margin-bottom:20px; }}
  table {{ border-collapse:collapse; width:100%; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
           vertical-align:top; }}
  th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--dim); }}
  .badge {{ color:#fff; font-size:11px; font-weight:600; padding:2px 8px;
           border-radius:10px; white-space:nowrap; }}
  .mono {{ font-family:ui-monospace, "SF Mono", Menlo, monospace; font-size:12.5px; }}
  a {{ color:#1a5fb4; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>CloudAudit report</h1>
  <p class="meta">Account {html.escape(result.account_id)} ·
     regions {html.escape(", ".join(result.regions))} ·
     {result.checks_run} checks run · {len(result.findings)} findings
     ({summary}) · generated {generated}</p>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Resource</th>
    <th>Region</th><th>Detail</th><th>CIS v1.5</th><th>Runbook</th></tr></thead>
    <tbody>
{body_rows}
    </tbody>
  </table>
</div>
</body>
</html>
"""
    path.write_text(doc)
    return path
