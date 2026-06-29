import re

class ComponentChecker:
    """
    Identifies third-party libraries and their versions from source code and URLs.
    """
    def __init__(self, vuln_db):
        self.db = vuln_db
        
        # Regex patterns to detect library and version from comments or inline code
        self.lib_patterns = [
            (r'jQuery\s+v?(\d+\.\d+\.\d+(-\w+)?)', 'jquery'),
            (r'Bootstrap\s+v?(\d+\.\d+\.\d+)', 'bootstrap'),
            (r'AngularJS\s+v?(\d+\.\d+\.\d+)', 'angularjs'),
            (r'Vue\.js\s+v?(\d+\.\d+\.\d+)', 'vue'),
            (r'React\s+v?(\d+\.\d+\.\d+)', 'react'),
            (r'CryptoJS\s+v?(\d+\.\d+\.\d+)', 'crypto-js'),
            (r'Moment\.js\s+v?(\d+\.\d+\.\d+)', 'moment'),
            (r'Lodash\s+v?(\d+\.\d+\.\d+)', 'lodash'),
            (r'TinyMCE\s+v?(\d+\.\d+\.\d+)', 'tinymce'),
            (r'CKEditor\s+v?(\d+\.\d+\.\d+)', 'ckeditor'),
            (r'WordPress\s+v?(\d+\.\d+(\.\d+)?)', 'wordpress')
        ]
        
        # Generator meta tags
        self.meta_generator_pattern = r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']'

    def _check_url_for_version(self, url):
        found = []
        # Match patterns like jquery-3.5.1.js, bootstrap@5.1.3, vue@2.6.14, bootstrap/4.1.1
        url_patterns = [
            (r'jquery[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'jquery'),
            (r'bootstrap[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'bootstrap'),
            (r'angular[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'angularjs'),
            (r'vue[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'vue'),
            (r'react[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'react'),
            (r'moment[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'moment'),
            (r'lodash[-@v/]*(\d+\.\d+\.\d+(-\w+)?)', 'lodash')
        ]
        
        for pattern, name in url_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                found.append((name, match.group(1)))
        return found

    def check(self, url, content, headers=None):
        findings = []
        identified_components = set()
        
        # 1. Check URL for versions (e.g. CDNs)
        url_components = self._check_url_for_version(url)
        for name, version in url_components:
            identified_components.add((name, version))
            
        # 2. Check Content (Comments/Variables)
        for pattern, name in self.lib_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                identified_components.add((name, version))
                
        # 3. Check Meta Generator (e.g. WordPress, Joomla, Drupal)
        generator_matches = re.finditer(self.meta_generator_pattern, content, re.IGNORECASE)
        for match in generator_matches:
            generator_string = match.group(1)
            # Example: "WordPress 5.8.1"
            gen_match = re.search(r'([A-Za-z\-]+)\s+v?(\d+\.\d+(\.\d+)?)', generator_string, re.IGNORECASE)
            if gen_match:
                name = gen_match.group(1).lower()
                version = gen_match.group(2)
                identified_components.add((name, version))
                
        # 3.5 Check script/link tags in the HTML for CDNs/versions
        src_matches = re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for match in src_matches:
            extracted_url = match.group(1)
            url_components = self._check_url_for_version(extracted_url)
            for name, version in url_components:
                identified_components.add((name, version))
                
        # 4. Check Response Headers (e.g., Server, X-Powered-By)
        if headers:
            for k, v in headers.items():
                if k.lower() in ('server', 'x-powered-by'):
                    # Match standard patterns like "nginx/1.18.0", "Apache/2.4.41", "PHP/7.4.3"
                    server_matches = re.finditer(r'([A-Za-z0-9\-]+)/(\d+\.\d+(\.\d+)?(-\w+)?)', str(v))
                    for sm in server_matches:
                        name = sm.group(1).lower()
                        version = sm.group(2)
                        identified_components.add((name, version))

        # Look up vulnerabilities for all identified components
        for name, version in identified_components:
            vulns = self.db.get_vulnerabilities(name, version)
            
            # If no CVEs but we detected it, emit an INFO finding for component mapping
            if not vulns:
                finding = {
                    'url': url,
                    'type': 'COMPONENT_DISCOVERED',
                    'severity': 'INFO',
                    'description': f"Detected software component '{name}' version '{version}'. No known vulnerabilities found in local DB.",
                    'remediation': 'Ensure the component is kept up to date.',
                    'match': f"{name}@{version}",
                    'context': f"Detected via: {url}",
                    'line': 0
                }
                findings.append(finding)
                continue
                
            for v in vulns:
                finding = {
                    'url': url,
                    'type': 'KNOWN_VULNERABILITY',
                    'severity': v['severity'],
                    'description': f"Known vulnerability in {name} {version}: {v['cve_id']}",
                    'remediation': f"Update {name} to a secure version. Details: {v['description'][:150]}...",
                    'match': f"{name} {version}",
                    'context': v['cve_id'],
                    'line': 0
                }
                findings.append(finding)
                
        return findings
