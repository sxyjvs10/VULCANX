def generate_html_report(findings, traffic, dom_sinks):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VulcanX Engagement Report</title>
    <style>
        body {{ font-family: monospace; background: #111; color: #eee; padding: 20px; }}
        h1 {{ color: #ff0055; }}
        h2 {{ color: #ffcc00; margin-top: 30px; border-bottom: 1px solid #333; padding-bottom: 5px; }}
        .finding {{ background: #1a1a24; border-left: 3px solid #ff0055; padding: 10px; margin-bottom: 10px; }}
        .severity-CRITICAL {{ border-left-color: #ff0055; }}
        .severity-HIGH {{ border-left-color: #ff5500; }}
        .severity-MEDIUM {{ border-left-color: #ffcc00; }}
        .severity-LOW {{ border-left-color: #00aaff; }}
        .url {{ color: #00ff55; word-break: break-all; }}
        .sink {{ background: #1a0a0a; border: 1px solid #660000; padding: 8px; margin-bottom: 5px; font-size: 11px; }}
    </style>
</head>
<body>
    <h1>VulcanX Engagement Report</h1>
    
    <h2>Vulnerabilities ({len(findings)})</h2>
"""
    for f in findings:
        sev = str(f.get('severity', 'INFO')).upper()
        html += f"""
    <div class="finding severity-{sev}">
        <strong>[{sev}] {f.get('type', 'Unknown')}</strong><br>
        <span class="url">{f.get('url', '')}</span><br>
        <p>Match: {str(f.get('match', ''))[:200]}...</p>
    </div>
"""

    html += f"""
    <h2>DOM Sinks Triggered ({len(dom_sinks)})</h2>
"""
    for s in dom_sinks:
        html += f"""
    <div class="sink">
        <strong>[{s.get('sink', 'UNKNOWN')}]</strong><br>
        <span class="url">{s.get('url', '')}</span><br>
        <pre>{str(s.get('value', ''))[:200]}</pre>
    </div>
"""

    html += """
</body>
</html>
"""
    return html
