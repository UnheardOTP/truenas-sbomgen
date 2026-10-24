"""Turns Grype results into a summary: CISA KEV tags, new-since-last-run diff, Markdown and CSV."""
import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}


def load_kev(path: Path) -> set[str]:
    try:
        return {v["cveID"] for v in json.loads(path.read_text())["vulnerabilities"]}
    except (OSError, ValueError, KeyError):
        return set()


def _key(f: dict) -> str:
    return f"{f['target']}|{f['package']}|{f['version']}|{f['id']}"


def summarize(run_dir: Path, kev: set[str], prev_dir: Path | None) -> dict:
    findings: dict[str, dict] = {}
    for vf in sorted((run_dir / "vulns").glob("*.json")):
        target = vf.stem
        for m in json.loads(vf.read_text()).get("matches", []):
            v = m["vulnerability"]
            ids = [v["id"]] + [r["id"] for r in m.get("relatedVulnerabilities", [])]
            cve = next((i for i in ids if i.startswith("CVE-")), v["id"])
            f = {
                "target": target,
                "id": cve,
                "severity": v.get("severity", "Unknown"),
                "package": m["artifact"]["name"],
                "version": m["artifact"]["version"],
                "fixed_in": ", ".join(v.get("fix", {}).get("versions", [])),
                "kev": cve in kev,
                "new": True,
            }
            findings.setdefault(_key(f), f)

    baseline = None
    if prev_dir and (prev_dir / "summary.json").is_file():
        baseline = prev_dir.name
        prev = {_key(p) for p in json.loads((prev_dir / "summary.json").read_text())["findings"]}
        for k, f in findings.items():
            f["new"] = k not in prev

    items = sorted(findings.values(),
                   key=lambda f: (not f["kev"], not f["new"], RANK.get(f["severity"], 9), f["target"], f["id"]))
    stats = {
        "new": sum(f["new"] for f in items),
        "new_kev": sum(f["new"] and f["kev"] for f in items),
        "new_crit": sum(f["new"] and f["severity"] == "Critical" for f in items),
        "critical": sum(f["severity"] == "Critical" for f in items),
        "high": sum(f["severity"] == "High" for f in items),
        "kev": sum(f["kev"] for f in items),
        "total": len(items),
    }
    summary = {"generated": datetime.now(timezone.utc).isoformat(), "baseline": baseline,
               "stats": stats, "findings": items}
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1))
    (run_dir / "summary.md").write_text(to_markdown(run_dir.name, summary))
    return stats


def to_markdown(run_name: str, summary: dict) -> str:
    s, items = summary["stats"], summary["findings"]
    out = [f"# SBOM scan {run_name}\n",
           f"Compared with {summary['baseline']}.\n" if summary["baseline"]
           else "First run, so everything counts as new.\n",
           f"New: {s['new']} (KEV {s['new_kev']}, critical {s['new_crit']}). "
           f"Totals: {s['total']} findings, {s['critical']} critical, {s['high']} high, {s['kev']} in CISA KEV.\n"]
    sections = [
        ("Known exploited (CISA KEV)", lambda f: f["kev"]),
        ("New since last run", lambda f: f["new"] and not f["kev"]),
        ("All critical and high", lambda f: not f["new"] and not f["kev"] and f["severity"] in ("Critical", "High")),
    ]
    for title, pred in sections:
        rows = [f for f in items if pred(f)]
        out.append(f"## {title} ({len(rows)})\n")
        if not rows:
            out.append("None.\n")
            continue
        out.append("| | Severity | ID | Package | Fixed in | Target |\n|---|---|---|---|---|---|")
        out += [f"| {'**KEV**' if f['kev'] else ''} | {f['severity']} | {f['id']} | {f['package']} {f['version']} "
                f"| {f['fixed_in'] or '-'} | {f['target']} |" for f in rows]
        out.append("")
    return "\n".join(out) + "\n"


def to_csv(summary_path: Path) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["kev", "new", "severity", "id", "package", "version", "fixed_in", "target"])
    for f in json.loads(summary_path.read_text())["findings"]:
        w.writerow(["yes" if f["kev"] else "", "yes" if f["new"] else "", f["severity"], f["id"],
                    f["package"], f["version"], f["fixed_in"], f["target"]])
    return buf.getvalue().encode()
