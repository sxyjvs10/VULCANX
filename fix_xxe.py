import re

with open('core/live_browser.py', 'r') as f:
    content = f.read()

# Fix multiline string for XXE payload
content = re.sub(
    r"'text': '- <strong>Vulnerability:</strong> Insecure XML parser allows external entities.<br>- <strong>Impact:</strong> Read local files, SSRF, or denial of service.<br>- <strong>Payload:</strong><br><pre style=\"color:#ffaa66; background:#111; padding:6px; margin:4px 0; font-size:10px;\">&lt;\?xml version=\"1.0\"\?&gt;\n&lt;!DOCTYPE foo \[ &lt;!ENTITY xxe SYSTEM \"file:///etc/passwd\"&gt; \]&gt;\n&lt;foo&gt;&amp;xxe;&lt;/foo&gt;</pre>'",
    r"""'text': '- <strong>Vulnerability:</strong> Insecure XML parser allows external entities.<br>- <strong>Impact:</strong> Read local files, SSRF, or denial of service.<br>- <strong>Payload:</strong><br><pre style="color:#ffaa66; background:#111; padding:6px; margin:4px 0; font-size:10px;">&lt;?xml version="1.0"?&gt;\\n&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;\\n&lt;foo&gt;&amp;xxe;&lt;/foo&gt;</pre>'""",
    content
)

with open('core/live_browser.py', 'w') as f:
    f.write(content)
