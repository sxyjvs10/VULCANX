import re

with open('core/engine.py', 'r') as f:
    content = f.read()

new_patterns = """            'DOM_XSS_INNERHTML': {
                'regex': r'\.innerHTML\s*=\s*[^\'"][^;]*',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via innerHTML assignment.',
                'remediation': 'Use textContent instead of innerHTML, or sanitize the input using a library like DOMPurify.'
            },
            'DOM_XSS_OUTERHTML': {
                'regex': r'\.outerHTML\s*=\s*[^\'"][^;]*',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via outerHTML assignment.',
                'remediation': 'Avoid using outerHTML with untrusted data.'
            },
            'DOM_XSS_DOC_WRITE': {
                'regex': r'document\.write(?:ln)?\s*\(\s*[^\'"][^)]*\)',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via document.write().',
                'remediation': 'Avoid document.write() for dynamic content.'
            },
            'DOM_XSS_EVAL': {
                'regex': r'\beval\s*\(\s*[^)]+\)',
                'severity': 'CRITICAL',
                'description': 'Potential DOM XSS or Code Injection via eval().',
                'remediation': 'Do not use eval() with untrusted data.'
            },
            'DOM_XSS_SETTIMEOUT': {
                'regex': r'setTimeout\s*\(\s*[^\'"][^,]*\s*,',
                'severity': 'HIGH',
                'description': 'Potential DOM XSS via setTimeout() taking a string instead of a function.',
                'remediation': 'Pass a function reference to setTimeout, not a string.'
            },
            'DOM_XSS_SETINTERVAL': {
                'regex': r'setInterval\s*\(\s*[^\'"][^,]*\s*,',
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
            },"""

insert_pos = content.find("            'AWS_ACCESS_KEY': {")
if insert_pos != -1:
    new_content = content[:insert_pos] + new_patterns + '\n' + content[insert_pos:]
    with open('core/engine.py', 'w') as f:
        f.write(new_content)
    print("Patterns added successfully.")
else:
    print("Could not find insertion point.")
