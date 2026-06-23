import json
import re
from .base import DecryptionStrategy

class NetworkStrategy(DecryptionStrategy):
    """
    Strategy to inspect data fetched from network endpoints (like JSON responses)
    to find potential keys or sensitive data.
    """
    def detect_and_decrypt(self, content, url):
        findings = []

        # 1. Check if the content is JSON (typical for API endpoint responses)
        try:
            data = json.loads(content)
            findings.extend(self._search_dict(data, url, content))
        except (json.JSONDecodeError, TypeError):
            pass

        # 2. Check for endpoints in JS files (fetch/XHR) that might leak keys or endpoints
        fetch_pattern = r'''fetch\s*\(\s*["']([^"']+)["']\s*\)'''
        xhr_pattern = r'''\.open\s*\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']'''
        
        endpoints = re.findall(fetch_pattern, content) + re.findall(xhr_pattern, content)
        for endpoint in endpoints:
            if any(kw in endpoint.lower() for kw in ['key', 'config', 'api', 'secret', 'token', 'credential']):
                line_idx = content.find(endpoint)
                line_num = content[:line_idx].count('\n') + 1 if line_idx != -1 else 0
                findings.append({
                    'url': url,
                    'type': 'NETWORK_ENDPOINT_DISCOVERED',
                    'severity': 'INFO',
                    'description': f'Discovered potential API endpoint in source code: {endpoint}',
                    'remediation': 'Review the endpoint to ensure it does not expose sensitive data.',
                    'match': endpoint,
                    'context': f"Found endpoint call: {endpoint}",
                    'line': line_num
                })

        return findings

    def _search_dict(self, d, url, original_content, path=""):
        findings = []
        if isinstance(d, dict):
            for k, v in d.items():
                new_path = f"{path}.{k}" if path else k
                # If key name suggests a secret
                if any(x in k.lower() for x in ['key', 'secret', 'token', 'iv', 'password', 'credential', 'auth']):
                    if isinstance(v, str) and len(v) >= 8:
                        # Extract line number using regex to find the key in the original content
                        line_num = 0
                        # simple heuristic to find the line
                        idx = original_content.find(f'"{k}"')
                        if idx != -1:
                            line_num = original_content[:idx].count('\n') + 1

                        findings.append({
                            'url': url,
                            'type': 'NETWORK_JSON_KEY_EXPOSURE',
                            'severity': 'HIGH',
                            'description': f'Found sensitive key in JSON data from endpoint at JSON path {new_path}.',
                            'remediation': 'Ensure endpoints do not expose sensitive keys.',
                            'match': v,
                            'context': f'"{k}": "{v}"',
                            'line': line_num
                        })
                
                # Recursively search nested dictionaries
                findings.extend(self._search_dict(v, url, original_content, new_path))
        elif isinstance(d, list):
            for i, item in enumerate(d):
                findings.extend(self._search_dict(item, url, original_content, f"{path}[{i}]"))
        return findings
