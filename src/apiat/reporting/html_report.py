import html
from pathlib import Path


def write_html(result, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for finding in result.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.id)}</td>"
            f"<td>{html.escape(finding.kind)}</td>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.confidence)}</td>"
            f"<td>{html.escape(finding.endpoint)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            "</tr>"
        )

    path_items = []
    for path_data in result.attack_paths:
        steps = " → ".join(
            f"{step['kind']} {step['endpoint']}" for step in path_data["steps"]
        )
        path_items.append(
            f"<li><b>{html.escape(path_data['entry_role'])}</b>: {html.escape(steps)}</li>"
        )

    details = []
    for finding in result.findings:
        details.append(
            f"<section><h3>{html.escape(finding.id)} — {html.escape(finding.title)}</h3>"
            f"<p>{html.escape(finding.summary)}</p>"
            f"<h4>Evidence</h4><pre>{html.escape(str(finding.evidence))}</pre>"
            f"<h4>Remediation</h4><p>{html.escape(' '.join(finding.remediation))}</p></section>"
        )

    document = f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>APIAT Security Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px;line-height:1.5}}
code,pre{{background:#f5f5f5;border-radius:6px;padding:2px 5px}}
pre{{padding:14px;overflow:auto}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
.badge{{display:inline-block;padding:4px 8px;border-radius:999px;background:#eee}}
section{{margin-top:24px}}
</style>
</head>
<body>
<h1>API Attack-Path &amp; Authorization Tester</h1>
<p>Target: <code>{html.escape(result.target)}</code> · Endpoints: {result.scanned_endpoints} · Requests: {result.requests_sent}</p>
<p><span class='badge'>{len(result.findings)} verified findings</span> <span class='badge'>{len(result.attack_paths)} attack paths</span></p>
<h2>Confirmed Findings</h2>
<table><tr><th>ID</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Endpoint</th><th>Title</th></tr>{''.join(rows) or '<tr><td colspan=6>No verified findings</td></tr>'}</table>
<h2>Attack Paths</h2>
<ul>{''.join(path_items) or '<li>No correlated attack paths.</li>'}</ul>
<h2>Evidence &amp; Remediation</h2>
{''.join(details) or '<p>No findings.</p>'}
</body>
</html>
"""
    target.write_text(document, encoding="utf-8")
