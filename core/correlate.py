import json

class Correlator:
    """
    The Correlator module takes raw findings from the engine and analyzes them 
    collectively to identify chained exploit vectors, escalate severity scores, 
    and provide deep explainability for the risk profile of the application.
    """
    def __init__(self, findings):
        self.raw_findings = findings
        self.correlated_findings = []
        self.endpoint_risk_profiles = {}

    def correlate(self):
        print("\n[*] Initializing Correlation Engine...")
        # Deep copy to avoid mutating the original raw list uncontrollably
        self.correlated_findings = [f.copy() for f in self.raw_findings]

        self._build_endpoint_profiles()
        
        self._correlate_xss_and_csp()
        self._correlate_cors_and_xss()
        self._correlate_info_disclosure_and_components()
        self._correlate_endpoint_risk()
        self.build_attack_graph()

        return self.correlated_findings

    def _build_endpoint_profiles(self):
        """Groups findings by endpoint/URL to determine localized risk."""
        for finding in self.correlated_findings:
            url = finding.get('url', 'UNKNOWN')
            # Strip query params for profiling the base endpoint
            base_url = url.split('?')[0]
            
            if base_url not in self.endpoint_risk_profiles:
                self.endpoint_risk_profiles[base_url] = []
            self.endpoint_risk_profiles[base_url].append(finding)

    def _correlate_xss_and_csp(self):
        """
        If Reflected or DOM XSS is found, we check if the CSP on that endpoint 
        mitigates it or allows it. If CSP is missing or allows unsafe-inline, 
        the XSS is fully weaponizable and confidence/severity is escalated.
        """
        for url, findings in self.endpoint_risk_profiles.items():
            xss_findings = [f for f in findings if 'XSS' in f.get('type', '')]
            csp_findings = [f for f in findings if 'CSP' in f.get('type', '')]
            
            if xss_findings and csp_findings:
                # XSS exists and CSP is broken
                for xss in xss_findings:
                    xss['severity'] = 'CRITICAL'
                    xss['confidence'] = '100%'
                    xss['description'] += " \n\n[CORRELATED RISK]: This XSS is fully exploitable because the endpoint also suffers from a weak or missing Content-Security-Policy (CSP) that allows inline execution. This defeats defense-in-depth mechanisms."
                    
            elif xss_findings and not csp_findings:
                # XSS exists but no CSP weakness was found (meaning CSP might be strong)
                # However, our scanner might not have checked CSP thoroughly if it wasn't triggered
                pass

    def _correlate_cors_and_xss(self):
        """
        If CORS is misconfigured and XSS exists on the same domain, an attacker 
        can use the XSS to bypass CORS restrictions entirely or use CORS to leak 
        data extracted via XSS.
        """
        for url, findings in self.endpoint_risk_profiles.items():
            xss_findings = [f for f in findings if 'XSS' in f.get('type', '')]
            cors_findings = [f for f in findings if 'CORS' in f.get('type', '')]
            
            if xss_findings and cors_findings:
                for cors in cors_findings:
                    cors['severity'] = 'CRITICAL'
                    cors['description'] += " \n\n[CORRELATED RISK]: This CORS misconfiguration is highly critical because an active XSS vulnerability exists on the same endpoint. An attacker can pivot through the XSS to bypass SOP and leverage this CORS weakness for full account takeover."

    def _correlate_info_disclosure_and_components(self):
        """
        If a Known Vulnerability (CVE) is found in a component, and we also have 
        Information Disclosure (e.g. leaking server paths or sensitive endpoints), 
        the CVE becomes much easier to exploit.
        """
        cves = [f for f in self.correlated_findings if f.get('type') == 'KNOWN_VULNERABILITY']
        info_leaks = [f for f in self.correlated_findings if f.get('type') in ['SENSITIVE_API_PATH', 'SENSITIVE_FILE_EXPOSURE', 'ERROR_MESSAGE_LEAK']]
        
        if cves and info_leaks:
            for cve in cves:
                if cve.get('severity') in ['MEDIUM', 'HIGH']:
                    # Escalate
                    old_sev = cve['severity']
                    cve['severity'] = 'HIGH' if old_sev == 'MEDIUM' else 'CRITICAL'
                    cve['description'] += f" \n\n[CORRELATED RISK]: Exploitation is highly probable. Information disclosure vulnerabilities were found on the server, which typically aids attackers in mapping out the environment to successfully deploy exploits for this CVE."

    def _correlate_endpoint_risk(self):
        """
        If a single endpoint has more than 3 distinct vulnerabilities, flag the 
        endpoint itself as critically unstable/insecure.
        """
        for url, findings in self.endpoint_risk_profiles.items():
            unique_types = set(f.get('type') for f in findings)
            
            if len(unique_types) >= 3:
                # Generate a meta-finding
                meta_finding = {
                    'url': url,
                    'type': 'CRITICAL_ENDPOINT_DEGRADATION',
                    'severity': 'CRITICAL',
                    'confidence': '100%',
                    'compliance': 'OWASP A04:2021-Insecure Design',
                    'description': f"Endpoint '{url}' suffers from {len(unique_types)} distinct classes of vulnerabilities ({', '.join(list(unique_types)[:3])}...). This indicates a systemic failure in input validation, output encoding, and secure design at this specific boundary.",
                    'remediation': 'A complete security rewrite and code review of this endpoint is strongly recommended.',
                    'match': f"{len(findings)} total findings on this endpoint.",
                    'context': 'Cross-Vulnerability Correlation',
                    'line': 0,
                    'source': 'CORRELATION_ENGINE'
                }
                
                # Check if we already added it to prevent duplicates if called multiple times
                if not any(f.get('type') == 'CRITICAL_ENDPOINT_DEGRADATION' and f.get('url') == url for f in self.correlated_findings):
                    self.correlated_findings.append(meta_finding)

    def build_attack_graph(self):
        """
        Maps findings to MITRE ATT&CK techniques and correlates across 4 kill-chain stages:
        Reconnaissance, Initial Access, Execution, and Exfiltration.
        """
        attack_graph = {
            'reconnaissance': [],
            'initial_access': [],
            'execution': [],
            'exfiltration': []
        }
        
        for f in self.correlated_findings:
            f_type = f.get('type', '')
            
            # Mapping logic
            if 'INFO' in f_type or 'LEAK' in f_type:
                f['mitre_mapping'] = 'T1592 (Gather Victim Org Information)'
                attack_graph['reconnaissance'].append(f)
            elif 'XSS' in f_type or 'INJECTION' in f_type:
                f['mitre_mapping'] = 'T1190 (Exploit Public-Facing Application)'
                attack_graph['initial_access'].append(f)
            elif 'VULNERABILITY' in f_type:
                f['mitre_mapping'] = 'T1059 (Command and Scripting Interpreter)'
                attack_graph['execution'].append(f)
            elif 'CORS' in f_type or 'AUTH' in f_type:
                f['mitre_mapping'] = 'T1537 (Transfer Data to Cloud Account)'
                attack_graph['exfiltration'].append(f)
        
        # Tag correlated findings with graph context
        for stage, findings in attack_graph.items():
            for f in findings:
                f['attack_stage'] = stage.upper()
