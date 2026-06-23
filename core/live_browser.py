import time
import json
import threading
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

class LiveBrowserInterceptor:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.driver = None
        self.running = False
        self.processed_requests = set()
        self.live_findings = []
        self.current_url = ""
        
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
                    
                    if 'text/html' in ctype:
                        headers_lower = {k.lower(): v for k, v in headers.items()}
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
            
        import base64
        list_html_b64 = base64.b64encode(list_html.encode('utf-8')).decode('utf-8')
            
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
                
                var list = document.createElement('div');
                list.id = 'vulcanx-list';
                list.style.flex = '1';
                list.style.overflowY = 'auto';
                list.style.padding = '10px';
                w.appendChild(list);
                
                if (document.body) {{
                    document.body.appendChild(w);
                }} else {{
                    document.documentElement.appendChild(w);
                }}
            }}
            
            // Re-render the entire list from the python state safely using base64
            var listEl = document.getElementById('vulcanx-list');
            if (listEl) {{
                var newB64 = '{list_html_b64}';
                if (listEl.getAttribute('data-b64') !== newB64) {{
                    listEl.innerHTML = decodeURIComponent(escape(window.atob(newB64)));
                    listEl.setAttribute('data-b64', newB64);
                }}
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
