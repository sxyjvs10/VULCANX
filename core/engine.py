import re
import urllib.parse
import base64
import json
import math
from utils.component_checker import ComponentChecker
from utils.decryption.manager import DecryptionManager
from utils.ast_deobfuscator import ASTDeobfuscator

class Analyzer:
    def __init__(self, vuln_db=None):
        self.findings = []
        self.vuln_db = vuln_db
        self.component_checker = None
        self.vuln_db = vuln_db
        self.component_checker = None
        if vuln_db:
            self.component_checker = ComponentChecker(vuln_db)
        
        self.decryption_manager = DecryptionManager()
        self.ast_deobfuscator = ASTDeobfuscator()
        
        self.patterns = {
            'API_KEY_AWS': {
                'pattern': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', # Simplified, usually AKIA...
                'regex': r'AKIA[0-9A-Z]{16}',
                'severity': 'HIGH',
                'description': 'AWS Access Key ID detected.',
                'remediation': 'Revoke the key and use IAM roles.'
            },
            'API_KEY_GOOGLE': {
                'regex': r'AIza[0-9A-Za-z-_]{35}',
                'severity': 'HIGH',
                'description': 'Google API Key detected.',
                'remediation': 'Restrict the key or use backend proxy.'
            },
            'PRIVATE_KEY': {
                'regex': r'-----BEGIN PRIVATE KEY-----',
                'severity': 'CRITICAL',
                'description': 'Private Key detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'DANGEROUS_JS_EVAL': {
                'regex': r'\beval\(',
                'severity': 'HIGH',
                'description': 'Use of eval() detected.',
                'remediation': 'Avoid eval(); use JSON.parse() or safer alternatives.'
            },
            'DANGEROUS_JS_DOCWRITE': {
                'regex': r'document\.write\(',
                'severity': 'MEDIUM',
                'description': 'Use of document.write() detected.',
                'remediation': 'Use DOM manipulation methods like appendChild().'
            },
            'DANGEROUS_JS_INNERHTML': {
                'regex': r'\.innerHTML\s*=',
                'severity': 'MEDIUM',
                'description': 'Unsafe innerHTML assignment.',
                'remediation': 'Use textContent or sanitize input.'
            },
            'SENSITIVE_COMMENT': {
                'regex': r'(TODO|FIXME|HACK|XXX):',
                'severity': 'INFO',
                'description': 'Developer comment detected.',
                'remediation': 'Review comments for sensitive info before deployment.'
            },
            'USER_REQUESTED_KEY': {
                'regex': r'[367]x![\w@#$%^&*!.-]{5,100}',
                'severity': 'CRITICAL',
                'description': 'User-specified key pattern (starting with 3x!, 6x!, or 7x!) detected.',
                'remediation': 'Rotate this key immediately.'
            },
            'JS_ATOB_DECODE': {
                'regex': r'atob\s*\(\s*["\']([A-Za-z0-9+/=_ -]{10,})["\']\s*\)',
                'severity': 'HIGH',
                'description': 'JavaScript atob() call with Base64 string detected.',
                'remediation': 'Investigate the decoded content for secrets.'
            },
            'PASSWORD_FIELD': {
                'regex': r'type=["\']password["\']',
                'severity': 'LOW',
                'description': 'Password field detected (Info).',
                'remediation': 'Ensure forms are served over HTTPS.'
            },
            'POTENTIAL_XSS_SINK': {
                'regex': r'location\.hash|location\.search|document\.cookie',
                'severity': 'MEDIUM',
                'description': 'Potential XSS sink detected.',
                'remediation': 'Validate and sanitize data from these sources.'
            },
            'CUSTOM_KEY_SYMBOLS': {
                'regex': r'\$785%\$#\*\*5#@!7\^#',
                'severity': 'HIGH',
                'description': 'Custom Pattern Symbols detected.',
                'remediation': 'Investigate this custom secret format.'
            },
            'CUSTOM_HARDCODED_SECRETS': {
                'regex': r'([37]x!A%[DS]\*[IG]-[\w@#$%^&*!]{6,8})|(&a!@0\(l%\+0YU\*\^4g)|(LD@8RG#3SEZ)|(3337373832353434326134373264346236313530363435333637353632343430)',
                'severity': 'CRITICAL',
                'description': 'Known custom hardcoded secret detected.',
                'remediation': 'These patterns match known secret keys. Rotate immediately.'
            },
            'AES_OBFUSCATION_LOOP': {
                'regex': r'while\s*\(\s*!!\[\]\s*\)\s*\{.*?push.*shift',
                'severity': 'HIGH',
                'description': 'Obfuscated array rotation loop detected (common in malware/packers).',
                'remediation': 'Deobfuscate and analyze the code logic.'
            },
            'HARDCODED_KEK': {
                'regex': r'UlVGbk1tbHVkR0kyYm5wUFZYVXlTMEk9',
                'severity': 'HIGH',
                'description': 'Hardcoded Key Encryption Key (KEK) detected.',
                'remediation': 'Do not hardcode keys in client-side code.'
            },
            'AES_AUTO_INCREMENT': {
                'regex': r'encryptedAutoIncrement',
                'severity': 'MEDIUM',
                'description': 'Suspicious encrypted variable name detected.',
                'remediation': 'Verify the purpose of this encrypted data.'
            },
            'JWT_TOKEN': {
                'regex': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'severity': 'HIGH',
                'description': 'Potential JWT Token detected.',
                'remediation': 'Ensure tokens are not hardcoded or leaked.'
            },
            'SLACK_TOKEN': {
                'regex': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                'severity': 'HIGH',
                'description': 'Slack Token detected.',
                'remediation': 'Revoke token and use environment variables.'
            },
            'GOOGLE_OAUTH_ID': {
                'regex': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'severity': 'LOW',
                'description': 'Google OAuth Client ID detected.',
                'remediation': 'Verify if this ID is intended to be public.'
            },
            'SENSITIVE_PUBLIC_API': {
                'regex': r'["\'][\w\-./:]*(api/Public|PublicApi|/api/Public)[\w\-./?&=%]*["\']',
                'severity': 'HIGH',
                'description': 'Potential sensitive public API endpoint or variable detected.',
                'remediation': 'Verify if this endpoint or variable name exposes internal API structures.'
            },
            'SENSITIVE_CONSTRUCTED_PATH': {
                'regex': r'\b\w*URL\b\s*\+\s*["\']/?api/[\w/]+["\']',
                'severity': 'MEDIUM',
                'description': 'URL path being constructed dynamically with /api/.',
                'remediation': 'Review dynamic URL construction for potential exposure.'
            },
            'SENSITIVE_API_PATH': {
                'regex': r'/(api|v1|v2|graphql|swagger|admin)/',
                'severity': 'INFO',
                'confidence': '95%',
                'description': 'Sensitive API or Admin path detected.',
                'remediation': 'Ensure endpoints are secured.'
            },
            'SUSPICIOUS_CRYPTO_KEYWORD': {
                'regex': r'\b(crypto|encrypt|decrypt|decode|encode|cipher|key)\b',
                'severity': 'INFO',
                'confidence': '60%',
                'description': 'Cryptography keyword detected.',
                'remediation': 'Verify strong cryptography usage.'
            },
            'HARDCODED_ENCRYPT_KEY': {
                'regex': r'\b(encryptkey|secret|token|auth_key|api_key|access_key|private_key|secret_key)\b\s*[:=]\s*["\'][\w-]{5,}["\']',
                'severity': 'HIGH',
                'confidence': '90%',
                'description': 'Potential hardcoded secret key.',
                'remediation': 'Store secrets in environment variables.'
            },
            'GENERIC_KEY_ASSIGNMENT': {
                'regex': r'\b(k|kek|key)\b\s*[:=]\s*["\']?([\w\-]{6,})["\']?',
                'severity': 'MEDIUM',
                'confidence': '70%',
                'description': 'Short-name key/secret assignment detected.',
                'remediation': 'Verify if this value is sensitive.'
            },
            'CRYPTOJS_AES_ENCRYPT': {
                'regex': r'CryptoJS\.AES\.encrypt\([^,]+,\s*["\']([^"\']+)["\']',
                'severity': 'CRITICAL',
                'confidence': '99%',
                'description': 'Hardcoded AES Key in CryptoJS detected.',
                'remediation': 'Do not hardcode keys in client-side code.'
            },
            'SUSPICIOUS_FUNC_ARG_KEY': {
                'regex': r'\(\s*[^,]+,\s*["\']([a-zA-Z0-9]{16}|[a-zA-Z0-9]{24}|[a-zA-Z0-9]{32})["\']\s*\)',
                'severity': 'HIGH',
                'confidence': '50%',
                'description': 'Suspicious function argument (potential hardcoded key/IV).',
                'remediation': 'Verify if this string is a secret.'
            },
            'NUMERIC_PARTS_KEY_GEN': {
                'regex': r'numericParts\s*=\s*\[(\d+,\s*)+\d+\]',
                'severity': 'CRITICAL',
                'confidence': '95%',
                'description': 'Dynamic key generation via numericParts array detected.',
                'remediation': 'Do not use predictable client-side key generation.'
            },
            'HARDCODED_KEY_VAR': {
                'regex': r'\b(aesValu|aesiv|juKu|iv)\b\s*=',
                'severity': 'HIGH',
                'confidence': '80%',
                'description': 'Potential hardcoded/dynamic key variable assignment.',
                'remediation': 'Verify the source of this key variable.'
            },
            'BASE64_POTENTIAL_KEY': {
                'regex': r'["\'](N3[A-Za-z0-9+/]{20,60}={0,2})["\']',
                'severity': 'HIGH',
                'confidence': '85%',
                'description': 'Suspicious Base64 string (potential encoded key starting with 7x...).',
                'remediation': 'Decode and verify if this is a hardcoded secret.'
            },
            'SENSITIVE_FILE_EXPOSURE': {
                'regex': r'([\w\-./]*\.(env|bak|bkp|old|tmp|sql|dump|db|pem|crt|key|git|svn|ds_store|zip|tar|gz|rar|7z))|\b(config\.php|wp-config\.php|settings\.py|database\.yml|appsettings\.json|web\.config|httpd\.conf|nginx\.conf|php\.ini)\b|(/etc/(passwd|shadow))',
                'severity': 'MEDIUM',
                'confidence': '90%',
                'description': 'Reference to a potentially sensitive file/path detected.',
                'remediation': 'Ensure these files are not publicly accessible.'
            },
            'STRIPE_API_KEY': {
                'regex': r'(?i)stripe(.{0,20})?["\']?(sk_live_[0-9a-zA-Z]{24})',
                'severity': 'CRITICAL',
                'confidence': '99%',
                'description': 'Stripe Live Secret Key detected.',
                'remediation': 'Revoke the Stripe key immediately and rotate.'
            },
            'GITHUB_PAT_TOKEN': {
                'regex': r'ghp_[0-9a-zA-Z]{36}',
                'severity': 'CRITICAL',
                'confidence': '99%',
                'description': 'GitHub Personal Access Token detected.',
                'remediation': 'Revoke token in GitHub Developer Settings.'
            },
            'SSRF_URL_PARAM': {
                'regex': r'[\?&](url|uri|target|dest|destination|proxy|redirect|webhook)=http[s]?://',
                'severity': 'MEDIUM',
                'confidence': '60%',
                'description': 'Potential SSRF or Open Redirect parameter in URL.',
                'remediation': 'Validate all URLs passed as parameters on the backend.'
            },
            'S3_BUCKET_EXPOSURE': {
                'regex': r'[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|[a-zA-Z0-9-\.\_]+\.s3-[a-z0-9-]+\.amazonaws\.com',
                'severity': 'INFO',
                'confidence': '90%',
                'description': 'AWS S3 Bucket URL detected.',
                'remediation': 'Verify the S3 bucket permissions do not allow public write/read if sensitive.'
            },
            'AUTHORIZATION_BEARER': {
                'regex': r'["\']?Authorization["\']?\s*:\s*["\']?Bearer\s+([A-Za-z0-9-._~+/]+=*)["\']?',
                'severity': 'HIGH',
                'confidence': '95%',
                'description': 'Hardcoded Bearer Token in authorization header.',
                'remediation': 'Never hardcode active session or API bearer tokens in client-side code.'
            },
            'FIREBASE_DATABASE_URL': {
                'regex': r'https://[a-z0-9-]+\.firebaseio\.com',
                'severity': 'MEDIUM',
                'confidence': '90%',
                'description': 'Firebase Realtime Database URL detected.',
                'remediation': 'Ensure Firebase Security Rules are properly configured.'
            }
        }

    def _shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan(self, response_data, network_urls=None):
        """
        Main analysis method.
        Analyzes the given response dictionary ({url: body_content}) for vulnerabilities.
        Returns a list of finding dictionaries.
        """
        new_findings = []
        network_urls = network_urls or set()
        
        for url, content in response_data.items():
            print(f"[*] Scanning {url}...")
            source = 'NETWORK' if url in network_urls else 'STATIC'
            
            # 1. Check for reflected inputs from the URL itself
            self._check_reflection(url, content, source)
            
            # 2. Check for IDOR candidates in URL parameters
            self._check_idor(url, source)

            # 2.5 Check for sensitive parameters (Open Redirect, SSRF, LFI)
            self._check_sensitive_params(url, source)
            
            # 2.6 Extract API Parameter maps
            self._extract_api_map(url, content, source)
            
            # 2.7 Static Taint Analysis for DOM XSS
            self._check_dom_xss_taint(url, content, source)

            # 2.8 Decode Base64/Hex and find sensitive URLs
            self._decode_and_find_sensitive(url, content, source)

            # 3. Check for known vulnerabilities in components
            if self.component_checker:
                comp_findings = self.component_checker.check(url, content)
                for f in comp_findings:
                    f['source'] = source
                    if f not in self.findings:
                        self.findings.append(f)
                        new_findings.append(f)

            # 3. Dynamic Decryption & Deobfuscation (Catch packed payloads)
            decryption_findings = self.decryption_manager.run(content, url)
            if decryption_findings:
                for f in decryption_findings:
                    finding = {
                        'url': url,
                        'type': 'DECRYPTED_PAYLOAD',
                        'severity': 'HIGH',
                        'description': 'Advanced Deobfuscation/Decryption Successful',
                        'remediation': 'Review exposed logic.',
                        'match': f,
                        'context': 'Dynamically decrypted payload',
                        'line': 0,
                        'source': source
                    }
                    if finding not in self.findings:
                        self.findings.append(finding)
                        new_findings.append(finding)

            # 3.5 AST Deobfuscation
            deobfuscated_code = self.ast_deobfuscator.deobfuscate(content)
            if deobfuscated_code:
                contents_to_scan = [(content, source), (deobfuscated_code, f"{source} (AST Deobfuscated)")]
            else:
                contents_to_scan = [(content, source)]

            # 4. Check each pattern against content
            for scan_content, scan_source in contents_to_scan:
                for name, data in self.patterns.items():
                    pattern = data['regex']
                    matches = re.finditer(pattern, scan_content)
                    for match in matches:
                        match_str = match.group(0)
                        
                        # Apply Advanced Entropy Validation for generic keys
                        if name in ['API_KEY_AWS', 'GENERIC_KEY_ASSIGNMENT', 'BASE64_POTENTIAL_KEY', 'HARDCODED_ENCRYPT_KEY', 'HARDCODED_KEY_VAR', 'SUSPICIOUS_FUNC_ARG_KEY']:
                            # Extract just the value part if it's an assignment (e.g., key="VALUE")
                            val_match = re.search(r'["\']([^"\']+)["\']', match_str)
                            check_val = val_match.group(1) if val_match else match_str
                            
                            # Filter out low entropy strings (e.g., "0000000000", "aaaaabbbbb")
                            if len(check_val) > 10 and self._shannon_entropy(check_val) < 3.5:
                                continue
                                
                        # JWT Offline Analysis
                        jwt_details = ""
                        if name == 'JWT_TOKEN':
                            try:
                                parts = match_str.split('.')
                                if len(parts) == 3:
                                    # Fix padding
                                    header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
                                    payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
                                    
                                    header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                                    payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                                    
                                    jwt_details = f"\n[+] Extracted Payload: {json.dumps(payload)[:100]}...\n"
                                    if header.get('alg', '').lower() == 'none':
                                        jwt_details += "[!] CRITICAL: JWT accepts 'none' signing algorithm!"
                                        data['severity'] = 'CRITICAL'
                                        data['confidence'] = '99%'
                            except Exception:
                                pass

                        snippet = scan_content[max(0, match.start() - 50):min(len(scan_content), match.end() + 50)]
                        
                        # Add compliance mapping based on the vulnerability type
                        compliance = "N/A"
                        if name in ['HARDCODED_ENCRYPT_KEY', 'GENERIC_KEY_ASSIGNMENT', 'CRYPTOJS_AES_ENCRYPT', 'BASE64_POTENTIAL_KEY', 'HARDCODED_KEY_VAR', 'SUSPICIOUS_FUNC_ARG_KEY']:
                            compliance = "OWASP A02:2021-Cryptographic Failures, PCI-DSS Req 3.5/3.6"
                        elif name in ['STRIPE_API_KEY', 'GITHUB_PAT_TOKEN', 'AUTHORIZATION_BEARER']:
                            compliance = "OWASP A07:2021-Identification and Authentication Failures, NIST SP 800-63B"
                        elif name in ['SSRF_URL_PARAM']:
                            compliance = "OWASP A10:2021-Server-Side Request Forgery (SSRF)"
                        elif name in ['SENSITIVE_API_PATH', 'SENSITIVE_FILE_EXPOSURE', 'S3_BUCKET_EXPOSURE', 'FIREBASE_DATABASE_URL']:
                            compliance = "OWASP A01:2021-Broken Access Control, ISO 27001 A.14.1.2"

                        finding = {
                            'url': url,
                            'type': name,
                            'severity': data['severity'],
                            'confidence': data.get('confidence', 'N/A'),
                            'compliance': compliance,
                            'description': data['description'] + jwt_details,
                            'remediation': data['remediation'],
                            'match': match_str,
                            'context': snippet.strip(),
                            'line': scan_content[:match.start()].count('\n') + 1,
                            'source': scan_source
                        }
                        
                        # Only add if it's uniquely new to prevent exponential bloat
                        if finding not in self.findings:
                            self.findings.append(finding)
                            new_findings.append(finding)
        
        return new_findings

    def _decode_and_find_sensitive(self, url, content, source='STATIC'):
        """
        Decodes Base64, Hex, URL-encoded, and Hex-escaped strings found in the content.
        Checks if they contain sensitive paths like '/api/Public'.
        """
        import base64
        import binascii
        import urllib.parse
        
        # 1. Patterns for obfuscated strings
        # - Strings in quotes (Base64, Hex, URL-encoded)
        # - atob('...'), unescape('...'), etc.
        # - Hex escape sequences: \x61\x70\x69
        # - fromCharCode(97, 112, 105)
        
        # Combined regex for potential encoded strings
        obf_regex = r'(?:atob|decodeURIComponent|decodeURI|unescape)\s*\(\s*["\']([A-Za-z0-9+/=%]{4,})["\']\s*\)|["\']([A-Za-z0-9+/=]{16,}|[A-Fa-f0-9]{16,}|%[A-Fa-f0-9]{2}[A-Za-z0-9%_.+-]*)["\']'
        matches = set(re.findall(obf_regex, content))
        
        # Hex escape sequences pattern: \xHH\xHH...
        hex_escape_regex = r'((?:\\x[0-9a-fA-F]{2}){4,})'
        hex_escapes = re.findall(hex_escape_regex, content)
        
        # fromCharCode pattern: fromCharCode(97, 112, ...)
        char_code_regex = r'fromCharCode\s*\(([\d\s,]+)\)'
        char_codes = re.findall(char_code_regex, content)
        
        # Comma-separated binary-like numbers: "1010100,1101010,..."
        binary_csv_regex = r'["\']((?:[01]{7,8},)+[01]{7,8})["\']'
        binary_csvs = re.findall(binary_csv_regex, content)
        
        sensitive_keywords = ['/api/public', '/api/', 'http://', 'https://']
        found_decoded = []

        # Helper to flag findings
        def flag_finding(original, decoded, enc_type):
            severity = 'HIGH' if '/api/public' in decoded.lower() else 'MEDIUM'
            line_idx = content.find(original)
            line_num = content[:line_idx].count('\n') + 1 if line_idx != -1 else 0
            
            self.findings.append({
                'url': url,
                'type': 'DEOBFUSCATED_SENSITIVE_URL',
                'severity': severity,
                'description': f'Found deobfuscated ({enc_type}) sensitive URL or path.',
                'remediation': 'Review the decoded path to ensure it does not expose sensitive endpoints.',
                'match': original[:50] + "..." if len(original) > 50 else original,
                'context': f"Decoded: {decoded}",
                'line': line_num,
                'source': source
            })

        # Process matches from first regex
        for m in matches:
            val = m[0] if m[0] else m[1]
            if not val: continue
            
            # Try URL Decoding
            if '%' in val:
                try:
                    decoded = urllib.parse.unquote(val)
                    if any(kw in decoded.lower() for kw in sensitive_keywords):
                        flag_finding(val, f"URL-Decoded: {decoded}", "URL")
                        continue
                except: pass

            # Try Base64
            try:
                # Basic check for Base64 validity
                if re.match(r'^[A-Za-z0-9+/=]+$', val):
                    b64_val = val + '=' * ((4 - len(val) % 4) % 4)
                    decoded = base64.b64decode(b64_val).decode('utf-8', errors='ignore')
                    if any(kw in decoded.lower() for kw in sensitive_keywords):
                        flag_finding(val, f"Base64: {decoded}", "Base64")
                        continue
            except: pass
            
            # Try Hex
            try:
                if re.match(r'^[0-9a-fA-F]{16,}$', val):
                    decoded = binascii.unhexlify(val).decode('utf-8', errors='ignore')
                    if any(kw in decoded.lower() for kw in sensitive_keywords):
                        flag_finding(val, f"Hex: {decoded}", "Hex")
                        continue
            except: pass

        # Process Hex Escapes
        for val in hex_escapes:
            try:
                decoded = "".join([chr(int(h[2:], 16)) for h in re.findall(r'\\x[0-9a-fA-F]{2}', val)])
                if any(kw in decoded.lower() for kw in sensitive_keywords):
                    flag_finding(val, f"Hex-Escape: {decoded}", "Hex-Escape")
            except: pass

        # Process fromCharCode
        for val in char_codes:
            try:
                codes = [int(c.strip()) for c in val.split(',')]
                decoded = "".join([chr(c) for c in codes])
                if any(kw in decoded.lower() for kw in sensitive_keywords):
                    flag_finding(val, f"CharCode: {decoded}", "fromCharCode")
            except: pass

        # Process Binary CSV
        for val in binary_csvs:
            try:
                parts = val.split(',')
                decoded = "".join([chr(int(p, 2)) for p in parts])
                if any(kw in decoded.lower() for kw in sensitive_keywords):
                    flag_finding(val, f"Binary-CSV: {decoded}", "Binary-CSV")
            except: pass

    def _check_sensitive_params(self, url, source='STATIC'):
        """
        Analyzes URL parameters for potential sensitive links like Open Redirect, SSRF, or LFI.
        """
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # Common parameters that accept URLs or paths
        redirect_params = ['returnurl', 'redirect', 'next', 'url', 'target', 'goto', 'return_url', 'redirect_url', 'forward', 'destination']
        ssrf_lfi_params = ['file', 'path', 'dir', 'document', 'folder', 'root', 'page', 'doc', 'load', 'read']
        
        for param, values in params.items():
            param_lower = param.lower()
            
            for value in values:
                # 1. Open Redirect
                if any(s in param_lower for s in redirect_params):
                    self.findings.append({
                        'url': url,
                        'type': 'OPEN_REDIRECT_PARAM',
                        'severity': 'MEDIUM',
                        'description': f'Potential Open Redirect parameter "{param}" detected.',
                        'remediation': 'Ensure the redirect destination is validated against an allowlist.',
                        'match': f"{param}={value}",
                        'context': url,
                        'line': 0,
                        'source': source
                    })
                
                # 2. SSRF / LFI
                if any(s == param_lower for s in ssrf_lfi_params):
                    if '/' in value or '\\' in value or value.startswith('http'):
                        self.findings.append({
                            'url': url,
                            'type': 'POTENTIAL_SSRF_LFI',
                            'severity': 'HIGH',
                            'description': f'Potential SSRF/LFI parameter "{param}" detected.',
                            'remediation': 'Validate and sanitize file paths or URLs provided in parameters.',
                            'match': f"{param}={value}",
                            'context': url,
                            'line': 0,
                            'source': source
                        })

    def _check_idor(self, url, source='STATIC'):
        """
        Analyzes URL parameters AND path for potential IDOR candidates.
        Advanced checks: Path IDs, JWTs, Base64 encoded IDs.
        """
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        suspicious_params = ['id', 'user', 'account', 'profile', 'order', 'invoice', 'report', 'doc', 'file', 'key', 'token', 'uid', 'uuid', 'pid', 'item', 'customer', 'transaction', 'member', 'group']
        
        # --- 1. Query Parameter Analysis ---
        for param, values in params.items():
            param_lower = param.lower()
            is_suspicious_name = any(s in param_lower for s in suspicious_params) or param_lower.endswith('id')
            
            for value in values:
                # A. Numeric ID
                if is_suspicious_name and value.isdigit():
                    self.findings.append({
                        'url': url,
                        'type': 'POTENTIAL_IDOR_NUMERIC',
                        'severity': 'MEDIUM',
                        'description': f'Potential IDOR (Numeric) in parameter "{param}".',
                        'remediation': 'Ensure access controls are in place. Numeric IDs are easily enumerated.',
                        'match': f"{param}={value}",
                        'context': url,
                        'line': 0,
                        'source': source
                    })
                
                # B. UUID/GUID
                elif is_suspicious_name and re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', value):
                    self.findings.append({
                        'url': url,
                        'type': 'POTENTIAL_IDOR_UUID',
                        'severity': 'LOW',
                        'description': f'Potential IDOR (UUID) in parameter "{param}".',
                        'remediation': 'Verify access controls. UUIDs prevent enumeration but not unauthorized access.',
                        'match': f"{param}={value}",
                        'context': url,
                        'line': 0,
                        'source': source
                    })

                # C. JWT Detection
                if value.startswith('eyJ') and value.count('.') == 2:
                    try:
                        # Decode payload (middle part)
                        payload = value.split('.')[1]
                        # Fix padding
                        padding = len(payload) % 4
                        if padding: payload += '=' * (4 - padding)
                        
                        decoded_bytes = base64.urlsafe_b64decode(payload)
                        decoded_json = json.loads(decoded_bytes)
                        
                        # Check for ID-like fields in JWT
                        jwt_suspicious = ['sub', 'uid', 'user_id', 'id', 'email', 'account']
                        found_claims = [k for k in decoded_json.keys() if any(s in k.lower() for s in jwt_suspicious)]
                        
                        if found_claims:
                            self.findings.append({
                                'url': url,
                                'type': 'POTENTIAL_IDOR_JWT',
                                'severity': 'HIGH',
                                'description': f'JWT token found in parameter "{param}" containing user identifiers: {found_claims}.',
                                'remediation': 'Ensure the token signature is verified and not just decoded.',
                                'match': f"{param}=JWT(...)",
                                'context': f"Claims: {found_claims}",
                                'line': 0,
                                'source': source
                            })
                    except Exception:
                        pass # Not a valid JWT or JSON

                # D. Base64 Encoded ID
                elif re.match(r'^[a-zA-Z0-9+/]+={0,2}$', value) and len(value) > 1:
                    try:
                        decoded_bytes = base64.b64decode(value, validate=True)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        
                        if decoded_str.isdigit():
                             self.findings.append({
                                'url': url,
                                'type': 'POTENTIAL_IDOR_BASE64',
                                'severity': 'MEDIUM',
                                'description': f'Base64 encoded numeric ID found in parameter "{param}".',
                                'remediation': 'Encoding is not encryption. Ensure access controls.',
                                'match': f"{param}={value} -> {decoded_str}",
                                'context': url,
                                'line': 0,
                                'source': source
                            })
                        elif decoded_str.strip().startswith('{') and decoded_str.strip().endswith('}'):
                             # JSON object?
                             try:
                                 json_obj = json.loads(decoded_str)
                                 # Check keys
                                 if any(s in k.lower() for k in json_obj.keys() for s in suspicious_params):
                                     self.findings.append({
                                        'url': url,
                                        'type': 'POTENTIAL_IDOR_BASE64_JSON',
                                        'severity': 'HIGH',
                                        'description': f'Base64 encoded JSON object with ID fields found in parameter "{param}".',
                                        'remediation': 'Do not pass access control objects via client-side parameters.',
                                        'match': f"{param}={value} -> {decoded_str}",
                                        'context': url,
                                        'line': 0,
                                        'source': source
                                    })
                             except:
                                 pass
                    except Exception:
                        pass

        # --- 2. Path-based Analysis ---
        path_segments = parsed_url.path.strip('/').split('/')
        for i, segment in enumerate(path_segments):
            # Context comes from previous segment (e.g., /users/123)
            context = path_segments[i-1].lower() if i > 0 else ""
            
            # Numeric ID in path
            if segment.isdigit() and len(segment) < 20: 
                # Heuristic: Only interesting if context is meaningful
                if context and any(s in context for s in suspicious_params):
                    self.findings.append({
                        'url': url,
                        'type': 'POTENTIAL_IDOR_PATH',
                        'severity': 'MEDIUM',
                        'description': f'Potential Path-based IDOR: Numeric ID "{segment}" found after "{context}".',
                        'remediation': 'Ensure proper access controls for RESTful resources.',
                        'match': f".../{context}/{segment}/...",
                        'context': url,
                        'line': 0,
                        'source': source
                    })
            
            # UUID in path
            elif re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', segment):
                 if context and any(s in context for s in suspicious_params):
                    self.findings.append({
                        'url': url,
                        'type': 'POTENTIAL_IDOR_PATH_UUID',
                        'severity': 'LOW',
                        'description': f'Potential Path-based IDOR: UUID "{segment}" found after "{context}".',
                        'remediation': 'Verify access controls.',
                        'match': f".../{context}/{segment}/...",
                        'context': url,
                        'line': 0,
                        'source': source
                    })

    def _check_reflection(self, url, content, source='STATIC'):
        """
        Checks if any query parameters from the URL are reflected in the content.
        """
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        for param, values in params.items():
            for value in values:
                if len(value) > 3:
                    # Escape value for regex if it contains special characters
                    escaped_value = re.escape(value)
                    matches = re.finditer(escaped_value, content)
                    for match in matches:
                        snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                        finding = {
                            'url': url,
                            'type': 'REFLECTED_INPUT',
                            'severity': 'MEDIUM',
                            'description': f'Input parameter "{param}" reflected in response.',
                            'remediation': 'Sanitize and encode user inputs.',
                            'match': value,
                            'context': snippet.strip(),
                            'line': content[:match.start()].count('\n') + 1,
                            'param': param,
                        }
                        self.findings.append(finding)

    def _extract_api_map(self, url, content, source='STATIC'):
        """
        Statically parses JS content to find backend API routes and their expected parameters.
        Builds a map for the pentester.
        """
        # Look for fetch('/api/...') or axios.post('/api/...', { param: 'val' })
        api_pattern = r'(?:fetch|axios(?:\.post|\.get|\.put)?|ajax)\s*\(\s*["\']([^"\']*/api/[^"\']*)["\'](.*?\})?'
        matches = re.finditer(api_pattern, content, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            api_route = match.group(1)
            options_block = match.group(2)
            
            params = []
            if options_block:
                # Naively extract JSON keys from the options block
                key_pattern = r'["\']?([a-zA-Z0-9_]+)["\']?\s*:'
                keys = re.findall(key_pattern, options_block)
                params = list(set(keys))
            
            self.findings.append({
                'url': url,
                'type': 'API_ROUTE_DISCOVERED',
                'severity': 'INFO',
                'description': f'API Route Extracted: {api_route}',
                'remediation': 'Manual review of endpoints and parameters for IDOR/Mass Assignment.',
                'match': f"{api_route} -> Params: {params if params else 'Unknown'}",
                'context': content[max(0, match.start() - 20):min(len(content), match.start() + 100)].strip().replace('\n', ' '),
                'line': content[:match.start()].count('\n') + 1,
                'source': source
            })

    def _check_dom_xss_taint(self, url, content, source='STATIC'):
        """
        Performs a basic static taint analysis tracking sources to sinks in JS.
        """
        # Sources: location, document.cookie, window.name
        # Sinks: innerHTML, document.write, eval, setTimeout
        
        # Regex to catch assigning a source to a variable
        source_pattern = r'(var|let|const)\s+([a-zA-Z0-9_]+)\s*=\s*.*?(location\.hash|location\.search|document\.cookie|window\.name)'
        sources_matches = re.finditer(source_pattern, content)
        
        tainted_vars = set()
        for match in sources_matches:
            tainted_vars.add(match.group(2))
            
        if not tainted_vars:
            return
            
        # Regex to catch sinks
        sink_pattern = r'(innerHTML\s*=|document\.write\s*\(|eval\s*\()'
        sinks_matches = re.finditer(sink_pattern, content)
        
        for match in sinks_matches:
            # Look backwards slightly to see what's going into the sink
            context_block = content[max(0, match.start() - 10):min(len(content), match.end() + 50)]
            for tainted in tainted_vars:
                if tainted in context_block:
                    self.findings.append({
                        'url': url,
                        'type': 'DOM_XSS_STATIC_TAINT',
                        'severity': 'HIGH',
                        'description': f'Static Taint Analysis: Tainted variable "{tainted}" flows into a dangerous sink.',
                        'remediation': 'Ensure user input is properly sanitized before reaching DOM sinks.',
                        'match': f'Variable {tainted} -> Sink',
                        'context': content[max(0, match.start() - 50):min(len(content), match.end() + 100)].strip(),
                        'line': content[:match.start()].count('\n') + 1,
                        'source': source
                    })

