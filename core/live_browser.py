import time
import json
import threading
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from core.correlate import CorrelationEngine

class LiveBrowserInterceptor:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.driver = None
        self.running = False
        self.processed_requests = set()
        self.live_findings = []
        self.current_url = ""
        # Correlation engine: chains raw findings (added below, one call per
        # finding) into ranked vulnerability hypotheses. Kept separate from
        # live_findings so the HUD can render "raw findings" and "suggested
        # vuln chains" as two distinct lists/tabs instead of mixing them.
        self.correlator = CorrelationEngine()
        self.live_hypotheses = []  # list of dicts (VulnHypothesis.to_finding_dict()), newest-relevant first
        
    def start(self, start_url):
        print("[*] Launching Live Browser Mode (using Firefox)...")
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        from selenium.webdriver.firefox.service import Service as FirefoxService
        from webdriver_manager.firefox import GeckoDriverManager
        
        opts = FirefoxOptions()
        # We don't use headless because this is the manual browse mode
        opts.set_preference("devtools.netmonitor.enabled", True)
        opts.set_preference("devtools.netmonitor.persistlog", True)
        opts.set_preference("network.http.phishy-userpass-length", 255)
        
        try:
            service = FirefoxService(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=opts)
        except Exception as e:
            print(f"[-] Could not find or install GeckoDriver. Error: {e}")
            return
            
        print("[+] Live Browser launched! Please log in and browse the application naturally.")
        print("[*] VulcanX is actively intercepting and analyzing traffic in the background...")
        self.driver.get(start_url)
        self.running = True
        
        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            print("\n[*] Live Browsing Session Ended by User.")
        finally:
            self.stop()
            
    def _monitor_loop(self):
        while self.running:
            try:
                for request in self.driver.requests:
                    if not request.response:
                        continue
                        
                    url = request.url
                    if url in self.processed_requests:
                        continue
                        
                    # Filter out images, fonts, css
                    if any(ext in url.lower() for ext in ['.jpg', '.png', '.gif', '.woff', '.ttf', '.css', '.svg']):
                        self.processed_requests.add(url)
                        continue
                        
                    self.processed_requests.add(url)
                    
                    # Check Security Headers Dynamically
                    headers = dict(request.response.headers)
                    ctype = headers.get('Content-Type', headers.get('content-type', '')).lower()
                    headers_lower = {k.lower(): v for k, v in headers.items()}

                    if 'text/html' in ctype:
                        missing = []
                        if 'content-security-policy' not in headers_lower:
                            missing.append("Content-Security-Policy (CSP)")
                        if 'strict-transport-security' not in headers_lower and url.startswith('https'):
                            missing.append("Strict-Transport-Security (HSTS)")
                        if 'x-frame-options' not in headers_lower:
                            missing.append("X-Frame-Options (XFO)")
                        if 'x-content-type-options' not in headers_lower:
                            missing.append("X-Content-Type-Options")
                            
                        for m_header in missing:
                            f_header = {
                                'url': url,
                                'type': 'MISSING_SECURITY_HEADER',
                                'severity': 'LOW',
                                'match': f'Missing: {m_header}'
                            }
                            self._inject_ui_alert(f_header)

                    # CORS wildcard / reflected-origin check. Not restricted to
                    # text/html since this matters most on JSON API responses.
                    # NOTE: a wildcard origin is only dangerous when paired with
                    # credentialed requests (cookies/Authorization) — the
                    # correlation engine (R-CORS-COOKIE-CHAIN) is what actually
                    # decides exploitability; this check just records the fact.
                    acao = headers_lower.get('access-control-allow-origin')
                    acac = headers_lower.get('access-control-allow-credentials', '').lower() == 'true'
                    if acao and (acao == '*' or acao not in ('', None)):
                        is_wildcard_or_reflected = (acao == '*') or (acao.rstrip('/') != self._origin_of(url))
                        if is_wildcard_or_reflected:
                            f_cors = {
                                'url': url,
                                'type': 'CORS_WILDCARD_ORIGIN',
                                'severity': 'MEDIUM' if not acac else 'HIGH',
                                'match': f'Access-Control-Allow-Origin: {acao}' + (' (with credentials)' if acac else ''),
                                'context': f'ACAO={acao}, ACAC={acac}',
                                'source': 'NETWORK',
                            }
                            self._inject_ui_alert(f_cors)

                    # Insecure cookie flag check. selenium-wire collapses
                    # multiple Set-Cookie headers when read via dict(headers);
                    # use get_all() when available to not silently drop cookies
                    # past the first one on responses that set several at once.
                    set_cookie_values = self._get_all_set_cookie(request.response.headers)
                    for raw_cookie in set_cookie_values:
                        cookie_name = raw_cookie.split('=', 1)[0].strip()
                        lc = raw_cookie.lower()
                        missing_flags = []
                        if 'httponly' not in lc:
                            missing_flags.append('HttpOnly')
                        if 'secure' not in lc and url.startswith('https'):
                            missing_flags.append('Secure')
                        if 'samesite' not in lc:
                            missing_flags.append('SameSite')
                        if missing_flags:
                            f_cookie = {
                                'url': url,
                                'type': 'INSECURE_COOKIE',
                                'severity': 'HIGH' if 'SameSite' in missing_flags else 'MEDIUM',
                                'match': f"{cookie_name}: missing {', '.join(missing_flags)}",
                                'context': raw_cookie[:120],
                                'source': 'NETWORK',
                            }
                            self._inject_ui_alert(f_cookie)
                    
                    # Try to get response body via selenium-wire
                    try:
                        import gzip
                        from io import BytesIO
                        body_bytes = request.response.body
                        
                        # Handle gzip decoding if necessary
                        if request.response.headers.get('Content-Encoding') == 'gzip':
                            body_bytes = gzip.GzipFile(fileobj=BytesIO(body_bytes)).read()
                            
                        body = body_bytes.decode('utf-8', errors='ignore')
                        
                        # Run analyzer dynamically
                        if body:
                            print(f"    [Intercepted] {url}")
                            findings = self.analyzer.scan({url: body}, set())
                            
                            # Print real-time alerts if High/Critical
                            for f in findings:
                                if f['severity'] in ['CRITICAL', 'HIGH']:
                                    print(f"\n[!!!] {f['severity']} FINDING DYNAMICALLY DISCOVERED!")
                                    print(f"      Type: {f['type']}")
                                    print(f"      URL: {f['url']}")
                                    print(f"      Match: {f['match'][:100]}...\n")
                                    
                                # Inject ALL findings into the live browser UI (not just High/Critical)
                                self._inject_ui_alert(f)
                                    
                    except Exception as e:
                        # Body decoding might fail on binary files not caught by filter
                        pass
                
                # Unconditionally inject/update the UI every second to ensure it survives page loads
                # and dynamically updates as the user navigates
                self._inject_ui_alert(None)
                
                time.sleep(1) # Prevent CPU thrashing
            except Exception as e:
                # Browser might be closed by user
                if "connection refused" in str(e).lower() or "disconnected" in str(e).lower() or "not reachable" in str(e).lower():
                    print("\n[*] Browser closed. Stopping interception.")
                    break
                time.sleep(1)
                
    def _inject_ui_alert(self, finding=None):
        if finding and finding not in self.live_findings:
            self.live_findings.append(finding)

            # Feed the correlation engine. This is the single choke point
            # every finding passes through before reaching the HUD, so it's
            # the right place to also surface chained hypotheses without
            # touching the dozen call sites above that produce findings.
            try:
                new_hyps = self.correlator.ingest(finding)
                for h in new_hyps:
                    self.live_hypotheses.append(h.to_finding_dict())
            except Exception as e:
                # A correlation bug must never break the live HUD/monitor loop.
                print(f"[correlate] suppressed error: {e}")
            
        # Group findings by type
        grouped_findings = {}
        for f in self.live_findings:
            ftype = f['type'].replace("'", "\\'")
            if ftype not in grouped_findings:
                grouped_findings[ftype] = []
            grouped_findings[ftype].append(f)
            
        list_html = ""
        for ftype, findings in grouped_findings.items():
            # Get severity from the first finding in the group
            first_finding = findings[0]
            severity = first_finding['severity'].replace("'", "\\'")
            
            # Determine contextual suggestion based on type
            suggestion = "Investigate the finding."
            if "MISSING_SECURITY_HEADER" in ftype:
                if "Content-Security-Policy" in first_finding.get('match', ''):
                    suggestion = "Missing CSP! There is a high chance of Cross-Site Scripting (XSS) here. You can likely execute arbitrary JavaScript if you find a reflection."
                elif "Strict-Transport-Security" in first_finding.get('match', ''):
                    suggestion = "Missing HSTS! The application might be vulnerable to Man-in-the-Middle (MitM) attacks or SSL stripping."
                elif "X-Frame-Options" in first_finding.get('match', ''):
                    suggestion = "Missing XFO! The application is vulnerable to Clickjacking. Try loading this page in an iframe."
                else:
                    suggestion = first_finding.get('remediation', "Investigate the missing header.")
            elif "DOM_XSS" in ftype:
                suggestion = "DOM XSS Taint flow detected! Look for ways to control the source (e.g., URL parameters, hash) to execute JS."
            elif "JWT_TOKEN" in ftype:
                suggestion = "JWT Token Found! Try decoding it, changing the 'alg' to 'none', or bruteforcing the signing key."
            elif "KEY" in ftype or "SECRET" in ftype:
                suggestion = "Sensitive Secret found! Try using this key to access backend APIs or third-party services."
            
            safe_suggestion = suggestion.replace("`", "\\`").replace("$", "\\$")
            
            # Determine severity color
            sev_color = "red"
            if severity == "MEDIUM": sev_color = "#ff9900"
            elif severity == "LOW": sev_color = "#ffff00"
            elif severity == "INFO": sev_color = "#00ccff"
            
            # Build the list of URLs for this type
            urls_html = ""
            for f in findings:
                url = f['url'].replace("'", "\\'")
                safe_url = url.replace("`", "\\`").replace("$", "\\$")
                match_info = f.get('match', '').replace("'", "\\'").replace("`", "\\`").replace("$", "\\$")
                if len(match_info) > 100: match_info = match_info[:100] + "..."
                urls_html += f"""
                <div style="margin-bottom: 5px;">
                    <strong style="color:#aaa;">URL:</strong> <span style="color:#4da6ff;word-break:break-all;">{safe_url}</span><br>
                    <strong style="color:#aaa;">Match:</strong> <span style="color:#ccc;">{match_info}</span>
                </div>
                """
            
            # Create a collapsible group
            count = len(findings)
            list_html += f"""
            <details style="margin-bottom:8px; padding-bottom:8px; border-bottom:1px dotted #444;">
                <summary style="cursor:pointer; outline:none; font-weight:bold;">
                    <strong style="color:{sev_color};">[{severity}]</strong> <span style="color:#fff;">{ftype}</span> <span style="color:#888;font-size:10px;">({count} instances)</span>
                </summary>
                <div style="margin-top:8px; padding-left:15px; border-left:2px solid #555;">
                    <span style="color:#ffcc00;font-size:11px;">💡 {safe_suggestion}</span><br><br>
                    {urls_html}
                </div>
            </details>
            """

        # --- Correlation engine output: rendered as its own section, visually
        # distinct (purple accent) from raw pattern-match findings above, since
        # these are inferred chains, not direct scanner hits. Sorted by
        # severity so the highest-confidence chain is always visible without
        # scrolling, even as live_findings grows during a long session.
        sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_hyps = sorted(self.live_hypotheses, key=lambda h: sev_rank.get(h.get('severity', 'INFO'), 9))

        suggestions_html = ""
        if sorted_hyps:
            for h in sorted_hyps:
                severity = h['severity'].replace("'", "\\'")
                sev_color = "red"
                if severity == "MEDIUM": sev_color = "#ff9900"
                elif severity == "LOW": sev_color = "#ffff00"
                elif severity == "HIGH": sev_color = "#ff3333"

                title = h.get('description', '').replace("'", "\\'").replace("`", "\\`").replace("$", "\\$")
                cwe = h.get('context', '').replace("'", "\\'")
                conf = h.get('confidence', 'N/A')
                url_s = h.get('url', '').replace("'", "\\'").replace("`", "\\`")
                if len(url_s) > 70: url_s = url_s[:70] + "..."
                remediation = h.get('remediation', '').replace("'", "\\'").replace("`", "\\`").replace("$", "\\$")

                suggestions_html += f"""
                <details style="margin-bottom:8px; padding-bottom:8px; border-bottom:1px dotted #553366;">
                    <summary style="cursor:pointer; outline:none; font-weight:bold;">
                        <strong style="color:{sev_color};">[{severity}]</strong>
                        <span style="color:#e0b3ff;">{title}</span>
                        <span style="color:#888;font-size:10px;">({cwe}, conf {conf})</span>
                    </summary>
                    <div style="margin-top:8px; padding-left:15px; border-left:2px solid #663377;">
                        <strong style="color:#aaa;">URL:</strong> <span style="color:#4da6ff;word-break:break-all;">{url_s}</span><br>
                        <strong style="color:#aaa;">Next steps:</strong><br>
                        <span style="color:#ccc;font-size:11px;">{remediation}</span>
                    </div>
                </details>
                """

        import base64
        list_html_b64 = base64.b64encode(list_html.encode('utf-8')).decode('utf-8')
        suggestions_html_b64 = base64.b64encode(suggestions_html.encode('utf-8')).decode('utf-8')
            
        js_code = f"""
        try {{
            var w = document.getElementById('vulcanx-widget');
            if (!w) {{
                w = document.createElement('div');
                w.id = 'vulcanx-widget';
                w.style.position = 'fixed';
                w.style.bottom = '20px';
                w.style.right = '20px';
                w.style.width = '450px';
                w.style.height = '400px';
                w.style.resize = 'both';
                w.style.overflow = 'hidden';
                w.style.backgroundColor = 'rgba(10, 10, 10, 0.95)';
                w.style.color = '#00ff00';
                w.style.border = '2px solid #ff0000';
                w.style.borderRadius = '8px';
                w.style.zIndex = '2147483647';
                w.style.fontFamily = 'monospace';
                w.style.fontSize = '12px';
                w.style.pointerEvents = 'auto';
                w.style.boxShadow = '0 0 20px rgba(255,0,0,0.4)';
                w.style.display = 'flex';
                w.style.flexDirection = 'column';
                
                var header = document.createElement('div');
                header.style.display = 'flex';
                header.style.justifyContent = 'space-between';
                header.style.alignItems = 'center';
                header.style.padding = '10px';
                header.style.borderBottom = '1px solid #333';
                header.style.backgroundColor = '#1a1a1a';
                header.style.borderTopLeftRadius = '6px';
                header.style.borderTopRightRadius = '6px';
                
                var title = document.createElement('strong');
                title.innerText = 'VULCANX LIVE FEED';
                title.style.color = '#ff0000';
                header.appendChild(title);
                
                var btnGroup = document.createElement('div');
                
                var scanBtn = document.createElement('button');
                scanBtn.innerText = 'Scan Site';
                scanBtn.style.background = '#800000';
                scanBtn.style.color = '#fff';
                scanBtn.style.border = '1px solid #ff0000';
                scanBtn.style.padding = '4px 8px';
                scanBtn.style.marginRight = '5px';
                scanBtn.style.borderRadius = '4px';
                scanBtn.style.cursor = 'pointer';
                scanBtn.onclick = async function() {{
                    var links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                    var internalLinks = links.filter(href => href.startsWith(window.location.origin));
                    var uniqueLinks = [...new Set(internalLinks)];
                    
                    if (uniqueLinks.length === 0) {{
                        alert("No internal links found to scan.");
                        return;
                    }}
                    
                    var confirmScan = confirm("Start background scan of " + uniqueLinks.length + " internal links?");
                    if (confirmScan) {{
                        scanBtn.style.background = '#4CAF50';
                        scanBtn.style.border = '1px solid #4CAF50';
                        scanBtn.disabled = true;
                        
                        let completed = 0;
                        const total = uniqueLinks.length;
                        
                        scanBtn.innerText = `Scanning: 0 / ${{total}}`;
                        
                        const fetchPromises = uniqueLinks.map(link => 
                            fetch(link, {{ credentials: 'same-origin' }})
                            .catch(e => {{}})
                            .finally(() => {{
                                completed++;
                                scanBtn.innerText = `Scanning: ${{completed}} / ${{total}}`;
                            }})
                        );
                        
                        await Promise.allSettled(fetchPromises);
                        
                        scanBtn.innerText = 'Scan Complete!';
                        setTimeout(() => {{
                            scanBtn.innerText = 'Scan Site';
                            scanBtn.style.background = '#800000';
                            scanBtn.style.border = '1px solid #ff0000';
                            scanBtn.disabled = false;
                        }}, 2000);
                    }}
                }};
                
                var clearBtn = document.createElement('button');
                clearBtn.innerText = 'Clear';
                clearBtn.style.background = '#333';
                clearBtn.style.color = '#fff';
                clearBtn.style.border = 'none';
                clearBtn.style.padding = '4px 8px';
                clearBtn.style.borderRadius = '4px';
                clearBtn.style.cursor = 'pointer';
                clearBtn.onclick = function() {{ document.getElementById('vulcanx-list').innerHTML = ''; }};
                
                var minBtn = document.createElement('button');
                minBtn.innerText = '_';
                minBtn.style.background = '#333';
                minBtn.style.color = '#fff';
                minBtn.style.border = 'none';
                minBtn.style.padding = '4px 8px';
                minBtn.style.marginLeft = '5px';
                minBtn.style.borderRadius = '4px';
                minBtn.style.cursor = 'pointer';
                minBtn.onclick = function() {{
                    var l = document.getElementById('vulcanx-list');
                    l.style.display = (l.style.display === 'none') ? 'block' : 'none';
                    w.style.height = (l.style.display === 'none') ? 'auto' : '400px';
                }};
                
                btnGroup.appendChild(scanBtn);
                btnGroup.appendChild(clearBtn);
                btnGroup.appendChild(minBtn);
                header.appendChild(btnGroup);
                w.appendChild(header);

                // Tab bar: Findings (raw scanner hits) vs Suggestions (correlated
                // vuln-chain hypotheses from core/correlate.py). Two separate lists
                // kept in the DOM at all times; tab click just toggles display so
                // re-render logic below doesn't need to know which tab is active.
                var tabBar = document.createElement('div');
                tabBar.style.display = 'flex';
                tabBar.style.borderBottom = '1px solid #333';
                tabBar.style.backgroundColor = '#141414';

                var tabFindings = document.createElement('div');
                tabFindings.innerText = 'FINDINGS';
                tabFindings.id = 'vulcanx-tab-findings';
                tabFindings.style.padding = '6px 12px';
                tabFindings.style.cursor = 'pointer';
                tabFindings.style.color = '#ff5555';
                tabFindings.style.borderBottom = '2px solid #ff0000';
                tabFindings.style.fontWeight = 'bold';

                var tabSuggest = document.createElement('div');
                tabSuggest.innerText = 'SUGGESTIONS';
                tabSuggest.id = 'vulcanx-tab-suggest';
                tabSuggest.style.padding = '6px 12px';
                tabSuggest.style.cursor = 'pointer';
                tabSuggest.style.color = '#888';
                tabSuggest.style.borderBottom = '2px solid transparent';

                function activateTab(which) {{
                    var f = document.getElementById('vulcanx-list');
                    var s = document.getElementById('vulcanx-suggest-list');
                    var tf = document.getElementById('vulcanx-tab-findings');
                    var ts = document.getElementById('vulcanx-tab-suggest');
                    if (which === 'findings') {{
                        f.style.display = 'block'; s.style.display = 'none';
                        tf.style.color = '#ff5555'; tf.style.borderBottom = '2px solid #ff0000';
                        ts.style.color = '#888'; ts.style.borderBottom = '2px solid transparent';
                    }} else {{
                        f.style.display = 'none'; s.style.display = 'block';
                        ts.style.color = '#e0b3ff'; ts.style.borderBottom = '2px solid #aa55ff';
                        tf.style.color = '#888'; tf.style.borderBottom = '2px solid transparent';
                    }}
                }}
                tabFindings.onclick = function() {{ activateTab('findings'); }};
                tabSuggest.onclick = function() {{ activateTab('suggest'); }};

                tabBar.appendChild(tabFindings);
                tabBar.appendChild(tabSuggest);
                w.appendChild(tabBar);
                
                var list = document.createElement('div');
                list.id = 'vulcanx-list';
                list.style.flex = '1';
                list.style.overflowY = 'auto';
                list.style.padding = '10px';
                w.appendChild(list);

                var suggestList = document.createElement('div');
                suggestList.id = 'vulcanx-suggest-list';
                suggestList.style.flex = '1';
                suggestList.style.overflowY = 'auto';
                suggestList.style.padding = '10px';
                suggestList.style.display = 'none';
                w.appendChild(suggestList);
                
                if (document.body) {{
                    document.body.appendChild(w);
                }} else {{
                    document.documentElement.appendChild(w);
                }}
            }}
            
            // Re-render each list independently from python state, base64-safe.
            var listEl = document.getElementById('vulcanx-list');
            if (listEl) {{
                var newB64 = '{list_html_b64}';
                if (listEl.getAttribute('data-b64') !== newB64) {{
                    listEl.innerHTML = decodeURIComponent(escape(window.atob(newB64)));
                    listEl.setAttribute('data-b64', newB64);
                }}
            }}

            var suggestEl = document.getElementById('vulcanx-suggest-list');
            if (suggestEl) {{
                var newSuggestB64 = '{suggestions_html_b64}';
                if (suggestEl.getAttribute('data-b64') !== newSuggestB64) {{
                    suggestEl.innerHTML = newSuggestB64 ? decodeURIComponent(escape(window.atob(newSuggestB64))) : '<div style="color:#666;padding:10px;">No correlated suggestions yet.</div>';
                    suggestEl.setAttribute('data-b64', newSuggestB64);
                }}
            }}

            // Badge the Suggestions tab with a count so it's visible even
            // while the Findings tab is active (matches how a real HUD
            // signals "something needs your attention over here").
            var tabSuggestBadge = document.getElementById('vulcanx-tab-suggest');
            if (tabSuggestBadge) {{
                tabSuggestBadge.innerText = 'SUGGESTIONS ({len(sorted_hyps)})';
            }}
            
        }} catch(e) {{}}
        """
        try:
            self.driver.execute_script(js_code)
        except:
            pass
                
    def stop(self):
        self.running = False
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

    @staticmethod
    def _origin_of(url):
        """scheme://host[:port] of a URL, for comparing against Access-Control-Allow-Origin."""
        import urllib.parse
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _get_all_set_cookie(headers):
        """
        dict(headers) in the existing code collapses repeated Set-Cookie
        headers into one (last-value-wins or comma-joined depending on the
        underlying multidict implementation). Pull all Set-Cookie values
        explicitly so a response setting 3 cookies doesn't only get checked
        on 1 of them.
        """
        try:
            if hasattr(headers, 'get_all'):
                return list(headers.get_all('Set-Cookie') or [])
        except Exception:
            pass
        val = headers.get('Set-Cookie') or headers.get('set-cookie')
        if not val:
            return []
        # Fallback: some implementations comma-join multiple Set-Cookie
        # values. This is lossy (a cookie value itself can contain commas
        # for e.g. Expires=...GMT), so only split on the comma-then-space
        # pattern that precedes a new cookie-name=value pair, not blindly
        # on every comma.
        import re
        parts = re.split(r',(?=\s*[\w!#$%&\'*+\-.^_`|~]+=)', val)
        return [p.strip() for p in parts if p.strip()]
