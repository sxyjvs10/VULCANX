import re

with open('core/live_browser.py', 'r') as f:
    content = f.read()

# Fix unescaped single quote in SQLi payload
content = content.replace(
    """'text': '- <strong>Vulnerability:</strong> Untrusted data concatenated into WebSQL/SQLite queries.<br>- <strong>Impact:</strong> Local data leakage or modification.<br>- <strong>Payloads:</strong><br><code style="color:#ffaa66; background:#111; padding:2px; display:block; margin:4px 0;">' OR 1=1--<br>" UNION SELECT * FROM sensitive_table--</code>'""",
    """'text': '- <strong>Vulnerability:</strong> Untrusted data concatenated into WebSQL/SQLite queries.<br>- <strong>Impact:</strong> Local data leakage or modification.<br>- <strong>Payloads:</strong><br><code style="color:#ffaa66; background:#111; padding:2px; display:block; margin:4px 0;">\\' OR 1=1--<br>" UNION SELECT * FROM sensitive_table--</code>'"""
)

with open('core/live_browser.py', 'w') as f:
    f.write(content)
