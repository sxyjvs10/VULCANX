import sys
import re
from packaging import version

content = """
    <!-- Test Vulnerable Components -->
    <script src="https://code.jquery.com/jquery-3.4.0.min.js"></script>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css">
    <meta name="generator" content="WordPress 5.8.1">
"""
src_matches = re.finditer(r"(?:src|href)=[\"']([^\"']+)[\"']", content, re.IGNORECASE)
for match in src_matches:
    extracted_url = match.group(1)
    print("Found url:", extracted_url)
    
    url_patterns = [
        (r"jquery[-@v]*(\d+\.\d+\.\d+(-\w+)?)", "jquery"),
        (r"bootstrap[-@v]*(\d+\.\d+\.\d+(-\w+)?)", "bootstrap")
    ]
    for pattern, name in url_patterns:
        m = re.search(pattern, extracted_url, re.IGNORECASE)
        if m:
            print("  Matched component:", name, "v", m.group(1))

