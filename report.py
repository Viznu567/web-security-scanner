import html
from datetime import datetime
from urllib.parse import urlparse

ORDER = {"High": 0, "Medium": 1, "Low": 2}
COLORS = {"High": "#d32f2f", "Medium": "#f57c00", "Low": "#388e3c"}

def sort_findings(findings):
    return sorted(findings, key=lambda f: ORDER.get(f["severity"], 3))

def summary(findings):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts

def save_reports(target, findings):
    findings = sort_findings(findings)
    counts = summary(findings)
    now = datetime.now()
    when = now.strftime("%Y-%m-%d %H:%M:%S")
    host = urlparse(target).netloc.replace(":", "_") or "target"
    base = f"report_{host}_{now.strftime('%Y%m%d_%H%M%S')}"
    total_line = (f"{len(findings)} (High: {counts['High']}, "
                  f"Medium: {counts['Medium']}, Low: {counts['Low']})")

    # ---------- Markdown ----------
    md = ["# Web Security Assessment Report", "",
          f"- **Target:** {target}",
          f"- **Date:** {when}",
          f"- **Total findings:** {total_line}", ""]
    for i, f in enumerate(findings, 1):
        md += [f"## {i}. [{f['severity']}] {f['title']}",
               f"- **Impact:** {f['impact']}",
               f"- **Remediation:** {f['fix']}", ""]
    md.append("*Automated passive checks only. Findings should be verified manually.*")
    md_path = base + ".md"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    # ---------- HTML ----------
    rows = ""
    for i, f in enumerate(findings, 1):
        color = COLORS.get(f["severity"], "#555")
        rows += (
            f"<tr><td>{i}</td>"
            f"<td style='color:{color};font-weight:bold'>{html.escape(f['severity'])}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f['impact'])}</td>"
            f"<td>{html.escape(f['fix'])}</td></tr>\n"
        )
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Assessment Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 30px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f0f0f0; }}
</style></head><body>
<h1>Web Security Assessment Report</h1>
<p><b>Target:</b> {html.escape(target)}<br>
<b>Date:</b> {when}<br>
<b>Total findings:</b> {total_line}</p>
<table>
<tr><th>#</th><th>Severity</th><th>Finding</th><th>Impact</th><th>Remediation</th></tr>
{rows}</table>
<p><i>Automated passive checks only. Findings should be verified manually.</i></p>
</body></html>"""
    html_path = base + ".html"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)

    return md_path, html_path