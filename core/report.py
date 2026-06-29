import json
import datetime
import sys
import re

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
        self.sensitive_keywords = [
            'api', 'public', 'secret', 'key', 'token', 'auth',
            'password', 'admin', 'login', 'crypto', 'encrypt', 'decrypt'
        ]

    def _highlight_sensitive(self, text):
        if not text:
            return ""
        highlighted = str(text)
        for kw in self.sensitive_keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            highlighted = pattern.sub(
                lambda m: f"{BRIGHT_MAGENTA}{m.group(0)}{RESET}", highlighted
            )
        return highlighted

    def _get_color(self, severity):
        if severity == 'CRITICAL': return RED + BOLD
        if severity == 'HIGH':     return RED
        if severity == 'MEDIUM':   return YELLOW
        if severity == 'LOW':      return BLUE
        if severity == 'INFO':     return GREEN
        return RESET

    # -------------------------------------------------------------------------
    # Terminal Summary
    # -------------------------------------------------------------------------
    def print_summary(self):
        # Sort findings by severity
        self.findings.sort(key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5))

        print(f"\n{BOLD}{CYAN}\u2554{'=' * 58}\u2557{RESET}")
        print(f"{BOLD}{CYAN}\u2551{'SCAN SUMMARY':^58}\u2551{RESET}")
        print(f"{BOLD}{CYAN}\u2560{'=' * 58}\u2563{RESET}")
        print(f"\u2551 {BOLD}{'SEVERITY':<12}{RESET} \u2502 {BOLD}{'COUNT':<43}{RESET}\u2551")
        print(f"{CYAN}\u255f{'-' * 13}\u253c{'-' * 44}\u2562{RESET}")

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
                print(f"\u2551 {color}{sev:<12}{RESET} \u2502 {count:<43}\u2551")

        print(f"{CYAN}\u2560{'=' * 58}\u2563{RESET}")
        print(f"\u2551 {BOLD}{'TOTAL':<12}{RESET} \u2502 {BOLD}{total_count:<43}{RESET}\u2551")
        print(f"{CYAN}\u255a{'=' * 58}\u255d{RESET}")

        # Section for decoded sensitive URLs
        decoded_urls = [f for f in self.findings if f['type'] == 'DEOBFUSCATED_SENSITIVE_URL']
        if decoded_urls:
            print(f"\n{BG_RED}{WHITE}{BOLD} \U0001f525 CRITICAL: HIDDEN ENDPOINTS DETECTED \U0001f525 {RESET}")
            for f in decoded_urls:
                print(f"  {YELLOW}\u00bb{RESET} {f['context']} {GREY}(via {f['url']}){RESET}")

        if not self.findings:
            print(f"\n{GREEN}[+] No vulnerabilities found.{RESET}")
            return

        print(f"\n{BOLD}{UNDERLINE}DETAILED FINDINGS{RESET}")

        # Group by type for display
        grouped = {}
        for f in self.findings:
            t = f['type']
            if t not in grouped:
                grouped[t] = []
            grouped[t].append(f)

        # Sort grouped keys by severity of the first item
        sorted_types = sorted(
            grouped.keys(),
            key=lambda t: self.severity_order.get(grouped[t][0].get('severity', 'INFO'), 5)
        )

        for t in sorted_types:
            items = grouped[t]
            first_item = items[0]
            sev = first_item.get('severity', 'INFO')
            color = self._get_color(sev)

            title = f"[{sev}] {t} ({len(items)} found)"
            padding = " " * max(0, 78 - len(title))
            print(f"\n{color}\u250c{'-' * 80}\u2510{RESET}")
            print(f"{color}\u2502 {BOLD}{title}{RESET}{padding} {color}\u2502{RESET}")
            print(f"{color}\u2514{'-' * 80}\u2518{RESET}")
            print(f"  {BOLD}Description:{RESET} {first_item.get('description', 'N/A')}")
            print(f"  {BOLD}Remediation:{RESET} {first_item.get('remediation', 'N/A')}")
            print()

            display_items = items if self.verbose else items[:3]

            for i, item in enumerate(display_items):
                source_tag = (
                    f"{BRIGHT_MAGENTA}[DYNAMIC]{RESET} "
                    if item.get('source') in ['DYNAMIC_PROBE', 'DYNAMIC', 'DYNAMIC_INTERCEPTION']
                    else ""
                )
                print(f"    {BRIGHT_CYAN}Target {i+1}:{RESET} {source_tag}{item.get('url', 'Unknown')}")

                line_num = item.get('line', 0)
                if line_num:
                    print(f"      {BOLD}Line:{RESET}    {YELLOW}{line_num}{RESET}")

                match_val = item.get('match', 'N/A')
                if len(str(match_val)) > 150:
                    match_val = str(match_val)[:147] + "..."
                print(f"      {BOLD}Match:{RESET}   {RED}{self._highlight_sensitive(match_val)}{RESET}")

                if item.get('decoded_value'):
                    print(
                        f"      {BRIGHT_GREEN}{BOLD}Decoded:{RESET} "
                        f"{BG_YELLOW}{WHITE}{BOLD} {item['decoded_value']} {RESET}"
                    )

                context = item.get('context', '')
                if context:
                    context = context.replace('\n', ' ').replace('\r', '').strip()
                    if len(context) > 150:
                        context = context[:147] + "..."
                    print(f"      {BOLD}Context:{RESET} {GREY}{self._highlight_sensitive(context)}{RESET}")
                print()

            if not self.verbose and len(items) > 3:
                print(f"    {YELLOW}... and {len(items)-3} more instances (use -v to see all).{RESET}\n")

    # -------------------------------------------------------------------------
    # Save dispatcher — honours report_format
    # -------------------------------------------------------------------------
    def save(self, filepath, report_format='html'):
        """
        Save report to filepath in the requested format.

        Supported formats: html, json, markdown, pdf, burp
        Format is inferred from the extension when report_format='html' (default).
        """
        print(f"[*] Saving report to {filepath}...")

        ext = filepath.rsplit('.', 1)[-1].lower() if '.' in filepath else ''

        if report_format == 'markdown' or ext == 'md':
            self.save_markdown(filepath)
        elif report_format == 'pdf' or ext == 'pdf':
            self.save_pdf(filepath)
        elif report_format == 'burp' or ext == 'xml':
            self.save_burp_xml(filepath)
        elif report_format == 'json' or ext == 'json':
            self.save_json(filepath)
        else:
            # Default: html
            self.save_html(filepath)

    # -------------------------------------------------------------------------
    # JSON Export
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # CVSS Estimation
    # -------------------------------------------------------------------------
    def estimate_cvss(self, finding):
        """
        Estimate a CVSS 3.1 score and vector for a finding.

        Returns
        -------
        (score_float, vector_string)
        """
        vuln_type = finding.get('type', '').upper()

        cvss_map = {
            'XSS':              (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
            'SQLI':             (8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
            'SQL':              (8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
            'RCE':              (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
            'COMMAND_INJECTION':(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
            'SSRF':             (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            'LFI':              (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            'XXE':              (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            'IDOR':             (6.5, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'),
            'INFO':             (2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
        }

        for key, value in cvss_map.items():
            if key in vuln_type:
                return value

        # Fallback based on severity label
        severity = finding.get('severity', 'INFO').upper()
        severity_defaults = {
            'CRITICAL': (9.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
            'HIGH':     (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            'MEDIUM':   (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
            'LOW':      (3.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
            'INFO':     (2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
        }
        return severity_defaults.get(severity, (0.0, 'N/A'))

    # -------------------------------------------------------------------------
    # Executive Summary
    # -------------------------------------------------------------------------
    def generate_executive_summary(self):
        """Return a 2-paragraph executive summary string."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            counts[sev] = counts.get(sev, 0) + 1

        total = sum(counts.values())
        critical_high = counts['CRITICAL'] + counts['HIGH']

        # Derive target from first finding
        target = 'the target application'
        if self.findings:
            first_url = self.findings[0].get('url', '')
            if first_url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(first_url)
                    target = parsed.netloc or target
                except Exception:
                    pass

        risk_level = (
            'Critical'      if counts['CRITICAL'] > 0 else
            'High'          if counts['HIGH'] > 0 else
            'Medium'        if counts['MEDIUM'] > 0 else
            'Low'           if counts['LOW'] > 0 else
            'Informational'
        )

        para1 = (
            f"A comprehensive security assessment was conducted against {target} using the VulcanX "
            f"automated vulnerability scanner. The assessment identified a total of {total} security "
            f"finding(s) across all severity categories: {counts['CRITICAL']} Critical, {counts['HIGH']} High, "
            f"{counts['MEDIUM']} Medium, {counts['LOW']} Low, and {counts['INFO']} Informational. "
            f"The overall risk posture of the application is assessed as **{risk_level}**."
        )

        if critical_high > 0:
            para2 = (
                f"Immediate remediation is recommended for the {critical_high} Critical/High severity "
                f"finding(s), which pose a direct risk to data confidentiality, integrity, and system "
                f"availability. Medium and lower findings should be addressed in subsequent development "
                f"cycles as part of a structured security improvement programme. All findings include "
                f"detailed reproduction steps, CVSS scores, and remediation guidance to facilitate "
                f"efficient triage and resolution by the development team."
            )
        else:
            para2 = (
                f"No Critical or High severity vulnerabilities were identified during this assessment. "
                f"The {total} lower-severity finding(s) should be reviewed and addressed as part of "
                f"ongoing security hygiene. Continued security testing and code review practices are "
                f"recommended to maintain this security posture. All findings include detailed "
                f"reproduction steps and remediation guidance."
            )

        return para1 + "\n\n" + para2

    # -------------------------------------------------------------------------
    # Markdown Report
    # -------------------------------------------------------------------------
    def save_markdown(self, filepath):
        """Save a professional bug-bounty style Markdown report."""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            counts[sev] = counts.get(sev, 0) + 1

        sorted_findings = sorted(
            self.findings,
            key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5)
        )

        lines = []
        lines.append('# VulcanX Security Assessment Report')
        lines.append('')
        lines.append(f'**Generated:** {timestamp}')
        lines.append('**Tool:** VulcanX Automated Web Application Scanner')
        lines.append(f'**Total Findings:** {len(self.findings)}')
        lines.append('')
        lines.append('---')
        lines.append('')

        # Executive Summary
        lines.append('## Executive Summary')
        lines.append('')
        lines.append(self.generate_executive_summary())
        lines.append('')

        # Severity Table
        lines.append('### Severity Breakdown')
        lines.append('')
        lines.append('| Severity | Count |')
        lines.append('|----------|-------|')
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            lines.append(f'| {sev} | {counts[sev]} |')
        lines.append('')
        lines.append('---')
        lines.append('')

        # Findings
        lines.append('## Findings')
        lines.append('')

        for idx, f in enumerate(sorted_findings, 1):
            sev = f.get('severity', 'INFO').upper()
            ftype = f.get('type', 'Unknown')
            url = f.get('url', 'N/A')
            desc = f.get('description', 'N/A')
            remediation = f.get('remediation', 'N/A')
            match = f.get('match', 'N/A')
            context = f.get('context', '')
            decoded = f.get('decoded_value', '')
            line_no = f.get('line', 0)

            cvss_score, cvss_vector = self.estimate_cvss(f)

            lines.append(f'### Finding {idx}: {ftype}')
            lines.append('')
            lines.append('| Field | Value |')
            lines.append('|-------|-------|')
            lines.append(f'| **Severity** | {sev} |')
            lines.append(f'| **URL** | {url} |')
            if line_no:
                lines.append(f'| **Line** | {line_no} |')
            lines.append(f'| **CVSS Score** | {cvss_score} |')
            lines.append(f'| **CVSS Vector** | `{cvss_vector}` |')
            lines.append('')

            lines.append('**Description**')
            lines.append('')
            lines.append(desc)
            lines.append('')

            lines.append('**Steps to Reproduce**')
            lines.append('')
            lines.append(f'1. Navigate to: `{url}`')
            if line_no:
                lines.append(f'2. Inspect source code at line {line_no}.')
            lines.append(f'3. Observe the following pattern: `{str(match)[:200]}`')
            lines.append('')

            lines.append('**Impact**')
            lines.append('')
            lines.append(
                f'This finding has a CVSS base score of **{cvss_score}** ({sev}). '
                f'Exploitation could lead to unauthorized data access, application compromise, '
                f'or other security impacts depending on the attack context.'
            )
            lines.append('')

            if context or match:
                lines.append('**Evidence**')
                lines.append('')
                evidence = context if context else str(match)
                lines.append('```')
                lines.append(str(evidence)[:1000])
                lines.append('```')
                lines.append('')

            if decoded:
                lines.append('**Decoded Payload**')
                lines.append('')
                lines.append('```')
                lines.append(str(decoded))
                lines.append('```')
                lines.append('')

            lines.append('**Recommendation**')
            lines.append('')
            lines.append(remediation)
            lines.append('')
            lines.append('---')
            lines.append('')

        # Footer
        lines.append('## Report Footer')
        lines.append('')
        lines.append(f'*This report was generated automatically by VulcanX on {timestamp}.*')
        lines.append('*All findings should be validated manually before disclosure.*')
        lines.append('')

        content = '\n'.join(lines)
        try:
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(content)
            print(f'[+] Markdown Report saved to {filepath}')
        except Exception as e:
            print(f'[-] Failed to save Markdown report: {e}')

    # -------------------------------------------------------------------------
    # PDF Report
    # -------------------------------------------------------------------------
    def save_pdf(self, filepath):
        """
        Save PDF report.

        Attempts weasyprint first, then reportlab, then falls back to Markdown.
        """
        html_content = self._build_html_string()

        # Attempt 1: weasyprint
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(filepath)
            print(f'[+] PDF Report saved to {filepath} (via weasyprint)')
            return
        except ImportError:
            pass
        except Exception as e:
            print(f'[!] weasyprint failed: {e}. Trying reportlab...')

        # Attempt 2: reportlab
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Preformatted
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch

            doc = SimpleDocTemplate(
                filepath, pagesize=letter,
                rightMargin=inch, leftMargin=inch,
                topMargin=inch, bottomMargin=inch
            )
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                'Title2', parent=styles['Title'], fontSize=20, spaceAfter=12
            )
            h2_style = ParagraphStyle(
                'H2', parent=styles['Heading2'], fontSize=14, spaceAfter=6
            )
            h3_style = ParagraphStyle(
                'H3', parent=styles['Heading3'], fontSize=11, spaceAfter=4
            )
            body_style = styles['BodyText']
            code_style = ParagraphStyle(
                'Code', parent=styles['Code'], fontSize=8, backColor=colors.lightgrey
            )

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            story.append(Paragraph('VulcanX Security Assessment Report', title_style))
            story.append(Paragraph(f'Generated: {timestamp}', body_style))
            story.append(Spacer(1, 0.3 * inch))

            story.append(Paragraph('Executive Summary', h2_style))
            summary_text = self.generate_executive_summary().replace('\n\n', '<br/><br/>')
            story.append(Paragraph(summary_text, body_style))
            story.append(Spacer(1, 0.2 * inch))

            story.append(Paragraph('Findings', h2_style))

            sev_colors = {
                'CRITICAL': colors.red,
                'HIGH':     colors.orangered,
                'MEDIUM':   colors.orange,
                'LOW':      colors.blue,
                'INFO':     colors.green,
            }

            sorted_findings = sorted(
                self.findings,
                key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5)
            )

            for idx, f in enumerate(sorted_findings, 1):
                sev = f.get('severity', 'INFO').upper()
                ftype = f.get('type', 'Unknown')
                url = f.get('url', 'N/A')
                desc = f.get('description', 'N/A')
                remediation = f.get('remediation', 'N/A')
                context = f.get('context', '')
                cvss_score, cvss_vector = self.estimate_cvss(f)

                sev_color = sev_colors.get(sev, colors.black)
                heading = ParagraphStyle(
                    f'FindH{idx}', parent=h3_style, textColor=sev_color
                )
                story.append(Paragraph(f'Finding {idx}: {ftype} [{sev}]', heading))
                story.append(Paragraph(f'<b>URL:</b> {url}', body_style))
                story.append(Paragraph(
                    f'<b>CVSS Score:</b> {cvss_score} \u2014 {cvss_vector}', body_style
                ))
                story.append(Paragraph(f'<b>Description:</b> {desc}', body_style))
                if context:
                    story.append(Paragraph('<b>Evidence:</b>', body_style))
                    story.append(Preformatted(str(context)[:500], code_style))
                story.append(Paragraph(
                    f'<b>Recommendation:</b> {remediation}', body_style
                ))
                story.append(Spacer(1, 0.15 * inch))

            doc.build(story)
            print(f'[+] PDF Report saved to {filepath} (via reportlab)')
            return
        except ImportError:
            pass
        except Exception as e:
            print(f'[!] reportlab failed: {e}')

        # Fallback: save as Markdown
        md_path = filepath.rsplit('.', 1)[0] + '.md'
        print(
            f'[!] Neither weasyprint nor reportlab is available. '
            f'Saving as Markdown instead: {md_path}'
        )
        print(
            '[!] Install weasyprint (pip install weasyprint) or '
            'reportlab (pip install reportlab) for PDF support.'
        )
        self.save_markdown(md_path)

    # -------------------------------------------------------------------------
    # Burp Suite XML Export
    # -------------------------------------------------------------------------
    def save_burp_xml(self, filepath):
        """Save Burp Suite compatible XML report."""
        import xml.etree.ElementTree as ET

        severity_map = {
            'CRITICAL': 'High',
            'HIGH':     'High',
            'MEDIUM':   'Medium',
            'LOW':      'Low',
            'INFO':     'Information',
        }
        confidence_map = {
            'CRITICAL': 'Certain',
            'HIGH':     'Firm',
            'MEDIUM':   'Firm',
            'LOW':      'Tentative',
            'INFO':     'Tentative',
        }

        export_time = datetime.datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')
        root = ET.Element('issues', burpVersion='2023.1', exportTime=export_time)

        for idx, f in enumerate(self.findings, 1):
            issue = ET.SubElement(root, 'issue')

            sev = f.get('severity', 'INFO').upper()
            ftype = f.get('type', 'Unknown')
            url = f.get('url', 'http://unknown/')
            desc = f.get('description', '')
            remediation = f.get('remediation', '')
            context = f.get('context', '')
            match = f.get('match', '')
            cvss_score, cvss_vector = self.estimate_cvss(f)

            # Parse host and path
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host_val = f'{parsed.scheme}://{parsed.netloc}'
                path_val = parsed.path or '/'
                if parsed.query:
                    path_val += '?' + parsed.query
            except Exception:
                host_val = url
                path_val = '/'

            ET.SubElement(issue, 'serialNumber').text = str(idx * 100000)
            ET.SubElement(issue, 'type').text = str(abs(hash(ftype)) % (10 ** 8))
            ET.SubElement(issue, 'name').text = ftype
            host_el = ET.SubElement(issue, 'host')
            host_el.set('ip', '')
            host_el.text = host_val
            ET.SubElement(issue, 'path').text = path_val
            ET.SubElement(issue, 'location').text = url
            ET.SubElement(issue, 'severity').text = severity_map.get(sev, 'Information')
            ET.SubElement(issue, 'confidence').text = confidence_map.get(sev, 'Tentative')
            ET.SubElement(issue, 'issueBackground').text = desc
            ET.SubElement(issue, 'remediationBackground').text = remediation
            ET.SubElement(issue, 'cvssScore').text = str(cvss_score)
            ET.SubElement(issue, 'cvssVector').text = cvss_vector
            if context or match:
                evidence_text = context if context else str(match)
                ET.SubElement(issue, 'issueDetail').text = evidence_text[:2000]

        # Build XML string with DOCTYPE
        xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_str += '<!DOCTYPE issues [<!ELEMENT issues ANY>]>\n'
        xml_str += ET.tostring(root, encoding='unicode', xml_declaration=False)

        try:
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(xml_str)
            print(f'[+] Burp Suite XML Report saved to {filepath}')
        except Exception as e:
            print(f'[-] Failed to save Burp XML report: {e}')

    # -------------------------------------------------------------------------
    # Internal HTML builder (used by save_html and save_pdf)
    # -------------------------------------------------------------------------
    def _build_html_string(self):
        """Build and return the HTML report as a string."""
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
            if sev in counts:
                counts[sev] += 1
            t = f.get('type', 'Unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        # Summary Table
        summary_rows = ''
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if counts[sev] > 0:
                summary_rows += (
                    f"<tr><td><span class='badge {sev.lower()}'>{sev}</span></td>"
                    f"<td>{counts[sev]}</td></tr>"
                )

        summary_table = (
            f"<table><tr><th>Severity Risk Level</th><th>Identified Instances</th></tr>"
            f"{summary_rows}</table>"
        )

        # Findings List
        findings_html = ''
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            sev_class = sev.lower()

            findings_html += f'<div class="finding-block {sev_class}">\n'
            findings_html += (
                f'<div class="finding-header"><h4>{f.get("type", "Unknown")}</h4>'
                f'<span class="badge {sev_class}">{sev}</span></div>\n'
            )
            findings_html += (
                f'<p><strong>Endpoint/URL:</strong> '
                f'<a href="{f.get("url", "#")}" style="color: var(--accent);">'
                f'{f.get("url", "N/A")}</a></p>\n'
            )

            if f.get('confidence') and f.get('confidence') != 'N/A':
                findings_html += (
                    f'<p><strong>Confidence Score:</strong> '
                    f'<span style="color: var(--accent); font-weight: bold;">'
                    f'{f["confidence"]}</span></p>\n'
                )
            if f.get('compliance') and f.get('compliance') != 'N/A':
                findings_html += f'<p><strong>Compliance Mapping:</strong> {f["compliance"]}</p>\n'

            findings_html += f'<p><strong>Description:</strong> {f.get("description", "")}</p>\n'
            findings_html += f'<p><strong>Remediation:</strong> {f.get("remediation", "")}</p>\n'
            findings_html += f'<p><strong>Target Match:</strong> <code>{f.get("match", "")}</code></p>\n'
            if f.get('decoded_value'):
                findings_html += (
                    f'<p><strong>Decoded Payload:</strong> '
                    f'<code style="background: rgba(234, 179, 8, 0.2); color: var(--medium); '
                    f'border-color: var(--medium);">{f["decoded_value"]}</code></p>\n'
                )
            findings_html += f'<pre><code>{f.get("context", "")}</code></pre>\n'
            findings_html += '</div>\n'

        # Inject Variables
        html = html_template.replace('{{TIMESTAMP}}', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))
        html = html.replace('{{TOTAL}}', str(len(self.findings)))
        html = html.replace('{{SUMMARY_TABLE}}', summary_table)
        html = html.replace('{{FINDINGS_LIST}}', findings_html)
        html = html.replace('{{SEVERITY_DATA_JSON}}', json.dumps(counts))
        html = html.replace('{{TYPE_DATA_JSON}}', json.dumps(type_counts))
        return html

    def save_html(self, filepath):
        html = self._build_html_string()
        try:
            with open(filepath, 'w') as f:
                f.write(html)
            print(f'[+] Advanced Graphical HTML Report saved to {filepath}')
        except Exception as e:
            print(f'[-] Failed to save Graphical HTML report: {e}')