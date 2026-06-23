import re
from .base import DecryptionStrategy

class GenericKeyPatternStrategy(DecryptionStrategy):
    """
    A decryption strategy that uses regular expressions to identify common key patterns
    (e.g., API keys, secret keys, tokens) within content.
    """

    def __init__(self):
        # Define a dictionary of common key patterns and their descriptions/severity
        self.key_patterns = {
            "AWS_ACCESS_KEY": {
                "regex": r"(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16,}",
                "description": "Potential AWS Access Key ID found.",
                "severity": "CRITICAL"
            },
            "AWS_SECRET_KEY": {
                "regex": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
                "description": "Potential AWS Secret Access Key found.",
                "severity": "CRITICAL"
            },
            "GOOGLE_API_KEY": {
                "regex": r"AIza[0-9A-Za-z-_]{35}",
                "description": "Potential Google API Key found.",
                "severity": "HIGH"
            },
            "GENERIC_API_KEY": {
                "regex": r"(?i)(api_key|apikey|client_secret|secret|token)[\s\"\'\`=:]*[A-Za-z0-9_-]{10,}",
                "description": "Potential generic API key or secret found.",
                "severity": "MEDIUM"
            },
            "JWT": {
                "regex": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+",
                "description": "Potential JSON Web Token (JWT) found.",
                "severity": "MEDIUM"
            },
            "PRIVATE_KEY_START": {
                "regex": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
                "description": "Potential Private Key header found.",
                "severity": "CRITICAL"
            },
            "GITHUB_TOKEN": {
                "regex": r"(ghp|gho|ghu|ghs|ssr)[_][0-9a-zA-Z]{36}",
                "description": "Potential GitHub Personal Access Token found.",
                "severity": "CRITICAL"
            }
            # Add more patterns as needed
        }

    def detect_and_decrypt(self, content, url):
        findings = []
        for key_type, pattern_info in self.key_patterns.items():
            regex = re.compile(pattern_info["regex"])
            for match in regex.finditer(content):
                start_line = content.count('\n', 0, match.start()) + 1
                findings.append({
                    'url': url,
                    'type': f'DETECTED_{key_type}',
                    'severity': pattern_info["severity"],
                    'description': pattern_info["description"],
                    'remediation': 'Hardcoding sensitive keys in client-side code is highly discouraged. Use secure environment variables or a secrets management service.',
                    'match': match.group(0),
                    'context': content[max(0, match.start() - 100):min(len(content), match.end() + 100)], # Provide some context around the match
                    'line': start_line,
                    'decoded_value': match.group(0) # In this case, the detected key is the decoded value
                })
        return findings
