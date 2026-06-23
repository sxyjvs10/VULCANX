import json
import datetime
import sys

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GREY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BRIGHT_CYAN = "\033[96;1m"
BRIGHT_MAGENTA = "\033[95;1m"
BRIGHT_GREEN = "\033[92;1m"

class Reporter:
    def __init__(self, findings, verbose=False):
        self.findings = findings
        self.verbose = verbose
        self.severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.sensitive_keywords = ['api', 'public', 'secret', 'key', 'token', 'auth', 'password', 'admin', 'login', 'crypto', 'encrypt', 'decrypt']

    def _highlight_sensitive(self, text):
        if not text: return ""
        import re
        highlighted = str(text)
        for kw in self.sensitive_keywords:
            # Case insensitive replacement with BOLD MAGENTA
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            highlighted = pattern.sub(lambda m: f"{BRIGHT_MAGENTA}{m.group(0)}{RESET}", highlighted)
        return highlighted

    def _get_color(self, severity):
        if severity == 'CRITICAL': return RED + BOLD
        if severity == 'HIGH': return RED
        if severity == 'MEDIUM': return YELLOW
        if severity == 'LOW': return BLUE
        if severity == 'INFO': return GREEN
        return RESET

    def print_summary(self):
        # Sort findings by severity
        self.findings.sort(key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5))

        print(f"\n{BOLD}{CYAN}╔{'═'*58}╗{RESET}")
        print(f"{BOLD}{CYAN}║{'SCAN SUMMARY':^58}║{RESET}")
        print(f"{BOLD}{CYAN}╠{'═'*58}╣{RESET}")
        print(f"║ {BOLD}{'SEVERITY':<12}{RESET} │ {BOLD}{'COUNT':<43}{RESET}║")
        print(f"{CYAN}╟{'─'*13}┼{'─'*44}╢{RESET}")
        
        # Count by severity
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            counts[sev] = counts.get(sev, 0) + 1
        
        total_count = 0
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = counts.get(sev, 0)
            total_count += count
            if count > 0:
                color = self._get_color(sev)
                print(f"║ {color}{sev:<12}{RESET} │ {count:<43}║")
        
        print(f"{CYAN}╠{'═'*58}╣{RESET}")
        print(f"║ {BOLD}{'TOTAL':<12}{RESET} │ {BOLD}{total_count:<43}{RESET}║")
        print(f"{CYAN}╚{'═'*58}╝{RESET}")
        
        # New section for specifically decoded sensitive URLs
        decoded_urls = [f for f in self.findings if f['type'] == 'DEOBFUSCATED_SENSITIVE_URL']
        if decoded_urls:
            print(f"\n{BG_RED}{WHITE}{BOLD} 🔥 CRITICAL: HIDDEN ENDPOINTS DETECTED 🔥 {RESET}")
            for f in decoded_urls:
                print(f"  {YELLOW}»{RESET} {f['context']} {GREY}(via {f['url']}){RESET}")

        if not self.findings:
            print(f"\n{GREEN}[+] No vulnerabilities found.{RESET}")
            return

        print(f"\n{BOLD}{UNDERLINE}DETAILED FINDINGS{RESET}")

        # Group by type for display
        grouped = {}
        for f in self.findings:
            t = f['type']
            if t not in grouped: grouped[t] = []
            grouped[t].append(f)
        
        # Sort grouped keys by severity of the first item
        sorted_types = sorted(grouped.keys(), key=lambda t: self.severity_order.get(grouped[t][0].get('severity', 'INFO'), 5))

        for t in sorted_types:
            items = grouped[t]
            first_item = items[0]
            sev = first_item.get('severity', 'INFO')
            color = self._get_color(sev)
            
            title = f"[{sev}] {t} ({len(items)} found)"
            padding = " " * max(0, 78 - len(title))
            print(f"\n{color}┌{'─'*80}┐{RESET}")
            print(f"{color}│ {BOLD}{title}{RESET}{padding} {color}│{RESET}")
            print(f"{color}└{'─'*80}┘{RESET}")
            print(f"  {BOLD}Description:{RESET} {first_item.get('description', 'N/A')}")
            print(f"  {BOLD}Remediation:{RESET} {first_item.get('remediation', 'N/A')}")
            print()
            
            # Decide on slice
            display_items = items if self.verbose else items[:3]
            
            for i, item in enumerate(display_items):
                source_tag = f"{BRIGHT_MAGENTA}[DYNAMIC]{RESET} " if item.get('source') in ['DYNAMIC_PROBE', 'DYNAMIC', 'DYNAMIC_INTERCEPTION'] else ""
                
                print(f"    {BRIGHT_CYAN}Target {i+1}:{RESET} {source_tag}{item.get('url', 'Unknown')}")
                
                line_num = item.get('line', 0)
                if line_num:
                    print(f"      {BOLD}Line:{RESET}    {YELLOW}{line_num}{RESET}")
                
                match_val = item.get('match', 'N/A')
                # Truncate match if too long
                if len(str(match_val)) > 150:
                    match_val = str(match_val)[:147] + "..."
                print(f"      {BOLD}Match:{RESET}   {RED}{self._highlight_sensitive(match_val)}{RESET}")
                
                if item.get('decoded_value'):
                    # Use a highlighted background for decoded values to make them pop
                    print(f"      {BRIGHT_GREEN}{BOLD}Decoded:{RESET} {BG_YELLOW}{WHITE}{BOLD} {item['decoded_value']} {RESET}")
                
                context = item.get('context', '')
                if context:
                    # Clean up newlines/tabs for display
                    context = context.replace('\n', ' ').replace('\r', '').strip()
                    if len(context) > 150:
                        context = context[:147] + "..."
                    print(f"      {BOLD}Context:{RESET} {GREY}{self._highlight_sensitive(context)}{RESET}")
                print()
            
            if not self.verbose and len(items) > 3:
                print(f"    {YELLOW}... and {len(items)-3} more instances (use -v to see all).{RESET}\n")

    def save(self, filepath):
        print(f"[*] Saving report to {filepath}...")
        
        if filepath.endswith('.html'):
            self.save_html(filepath)
        else:
            self.save_json(filepath)

    def save_json(self, filepath):
        report_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'details': self.findings
        }
        try:
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=4)
            print(f"[+] JSON Report saved successfully.")
        except Exception as e:
            print(f"[-] Failed to save JSON report: {e}")

    def save_html(self, filepath):
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VulcanX Interactive Scan Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                :root {
                    --bg-dark: #0f172a;
                    --bg-panel: #1e293b;
                    --text-main: #f8fafc;
                    --text-muted: #94a3b8;
                    --accent: #38bdf8;
                    --critical: #ef4444;
                    --high: #f97316;
                    --medium: #eab308;
                    --low: #3b82f6;
                    --info: #22c55e;
                }
                body { 
                    font-family: 'Inter', -apple-system, sans-serif; 
                    margin: 0; 
                    background-color: var(--bg-dark); 
                    color: var(--text-main); 
                }
                .navbar {
                    background: var(--bg-panel);
                    padding: 1rem 2rem;
                    border-bottom: 1px solid #334155;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .navbar h1 { margin: 0; font-size: 1.5rem; color: var(--accent); letter-spacing: 1px; }
                .container { padding: 2rem; max-width: 1400px; margin: 0 auto; }
                
                .dashboard-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }
                .panel {
                    background: var(--bg-panel);
                    border-radius: 12px;
                    padding: 1.5rem;
                    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
                    border: 1px solid #334155;
                }
                .panel h3 { margin-top: 0; color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
                
                .stat-hero { font-size: 3rem; font-weight: bold; margin: 0.5rem 0; }
                
                .chart-container { position: relative; height: 300px; width: 100%; }
                
                table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 0.95rem; }
                th, td { border-bottom: 1px solid #334155; padding: 12px; text-align: left; }
                th { color: var(--text-muted); font-weight: 600; }
                tr:hover { background-color: #334155; }
                
                .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
                .badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
                .badge.high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
                .badge.medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
                .badge.low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
                .badge.info { background: rgba(34, 197, 94, 0.2); color: var(--info); border: 1px solid var(--info); }
                
                .finding-block { 
                    background: var(--bg-panel); 
                    padding: 1.5rem; 
                    border-radius: 8px; 
                    margin-bottom: 1.5rem; 
                    border-left: 4px solid var(--text-muted);
                    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
                }
                .finding-block.critical { border-left-color: var(--critical); }
                .finding-block.high { border-left-color: var(--high); }
                .finding-block.medium { border-left-color: var(--medium); }
                .finding-block.low { border-left-color: var(--low); }
                .finding-block.info { border-left-color: var(--info); }
                
                .finding-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 15px; }
                .finding-header h4 { margin: 0; font-size: 1.2rem; }
                
                pre { background-color: #0f172a; color: #e2e8f0; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 0.9rem; border: 1px solid #334155; }
                code { background-color: #0f172a; padding: 3px 6px; border-radius: 4px; color: #f472b6; border: 1px solid #334155; }
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1>VulcanX Analysis Graph</h1>
                <span style="color: var(--text-muted);">{{TIMESTAMP}}</span>
            </div>
            
            <div class="container">
                <div class="dashboard-grid">
                    <div class="panel">
                        <h3>Total Findings</h3>
                        <div class="stat-hero" id="totalCount">{{TOTAL}}</div>
                        <p style="color: var(--text-muted); margin:0;">Identified across the scanned application.</p>
                    </div>
                    <div class="panel">
                        <h3>Severity Distribution</h3>
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                    <div class="panel">
                        <h3>Vulnerability Types</h3>
                        <div class="chart-container">
                            <canvas id="typeChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="panel" style="margin-bottom: 2rem;">
                    <h3>Findings Summary</h3>
                    {{SUMMARY_TABLE}}
                </div>

                <h2 style="border-bottom: 1px solid #334155; padding-bottom: 10px; margin-top: 2rem;">Detailed Trace Logs</h2>
                {{FINDINGS_LIST}}
            </div>

            <script>
                const sevData = {{SEVERITY_DATA_JSON}};
                const typeData = {{TYPE_DATA_JSON}};

                // Severity Chart
                new Chart(document.getElementById('severityChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [sevData.CRITICAL, sevData.HIGH, sevData.MEDIUM, sevData.LOW, sevData.INFO],
                            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e'],
                            borderWidth: 0,
                            hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { position: 'right', labels: { color: '#f8fafc' } } }
                    }
                });

                // Type Chart
                new Chart(document.getElementById('typeChart'), {
                    type: 'bar',
                    data: {
                        labels: Object.keys(typeData),
                        datasets: [{
                            label: 'Count',
                            data: Object.values(typeData),
                            backgroundColor: '#38bdf8',
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8', stepSize: 1 } },
                            x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                        }
                    }
                });
            </script>
        </body>
        </html>
        """
        
        # Aggregate Data
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        type_counts = {}
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            if sev in counts: counts[sev] += 1
            
            t = f.get('type', 'Unknown')
            type_counts[t] = type_counts.get(t, 0) + 1
            
        # Summary Table
        summary_rows = ""
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if counts[sev] > 0:
                summary_rows += f"<tr><td><span class='badge {sev.lower()}'>{sev}</span></td><td>{counts[sev]}</td></tr>"
        
        summary_table = f"<table><tr><th>Severity Risk Level</th><th>Identified Instances</th></tr>{summary_rows}</table>"

        # Findings List
        findings_html = ""
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            sev_class = sev.lower()
            
            findings_html += f'<div class="finding-block {sev_class}">\n'
            findings_html += f'<div class="finding-header"><h4>{f.get("type", "Unknown")}</h4><span class="badge {sev_class}">{sev}</span></div>\n'
            findings_html += f'<p><strong>Endpoint/URL:</strong> <a href="{f.get("url", "#")}" style="color: var(--accent);">{f.get("url", "N/A")}</a></p>\n'
            
            if f.get("confidence") and f.get("confidence") != 'N/A':
                findings_html += f'<p><strong>Confidence Score:</strong> <span style="color: var(--accent); font-weight: bold;">{f["confidence"]}</span></p>\n'
            if f.get("compliance") and f.get("compliance") != 'N/A':
                findings_html += f'<p><strong>Compliance Mapping:</strong> {f["compliance"]}</p>\n'
                
            findings_html += f'<p><strong>Description:</strong> {f.get("description","")}</p>\n'
            findings_html += f'<p><strong>Remediation:</strong> {f.get("remediation","")}</p>\n'
            findings_html += f'<p><strong>Target Match:</strong> <code>{f.get("match","")}</code></p>\n'
            if f.get("decoded_value"):
                findings_html += f'<p><strong>Decoded Payload:</strong> <code style="background: rgba(234, 179, 8, 0.2); color: var(--medium); border-color: var(--medium);">{f["decoded_value"]}</code></p>\n'
            findings_html += f'<pre><code>{f.get("context","")}</code></pre>\n'
            findings_html += '</div>\n'
        
        # Inject Variables
        html = html_template.replace("{{TIMESTAMP}}", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        html = html.replace("{{TOTAL}}", str(len(self.findings)))
        html = html.replace("{{SUMMARY_TABLE}}", summary_table)
        html = html.replace("{{FINDINGS_LIST}}", findings_html)
        html = html.replace("{{SEVERITY_DATA_JSON}}", json.dumps(counts))
        html = html.replace("{{TYPE_DATA_JSON}}", json.dumps(type_counts))
        
        try:
            with open(filepath, 'w') as f:
                f.write(html)
            print(f"[+] Advanced Graphical HTML Report saved to {filepath}")
        except Exception as e:
            print(f"[-] Failed to save Graphical HTML report: {e}")