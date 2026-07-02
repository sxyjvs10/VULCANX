VULNERABILITIES_TAB_JS = r"""
                container.innerHTML = '';
                var findings = window.__vulcanx_state.findings || [];
                
                var topRow = document.createElement('div');
                topRow.style.display = 'flex';
                topRow.style.justifyContent = 'flex-end';
                topRow.style.marginBottom = '10px';
                
                var clearBtn = document.createElement('button');
                clearBtn.innerText = '🗑️ Clear Findings';
                clearBtn.style.background = '#aa0000';
                clearBtn.style.color = '#fff';
                clearBtn.style.border = '1px solid #ff0055';
                clearBtn.style.padding = '5px 10px';
                clearBtn.style.borderRadius = '3px';
                clearBtn.style.cursor = 'pointer';
                clearBtn.onclick = function() {
                    window.__vulcanx_cmd = {action: 'clear_findings'};
                    window.__vulcanx_state.findings = [];
                    window.__vulcanx_render();
                };
                topRow.appendChild(clearBtn);
                container.appendChild(topRow);

                if (findings.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '50px';
                    emptyDiv.innerText = 'No vulnerabilities detected yet.';
                    container.appendChild(emptyDiv);
                    return;
                }

                // Helper to extract domain from URL
                function getDomain(urlStr) {
                    try {
                        // Handle relative URLs or just paths just in case
                        if (!urlStr.startsWith('http')) {
                            // If there's no http/https, try to prepend it or just return 'Unknown'
                            // Usually f.url is absolute in the scanner.
                            urlStr = 'http://' + urlStr;
                        }
                        var url = new URL(urlStr);
                        return url.hostname;
                    } catch(e) {
                        return 'Unknown Domain';
                    }
                }

                // Group by domain, then by type
                var domainGroups = {};
                findings.forEach(f => {
                    var domain = getDomain(f.url);
                    var type = f.type || 'UNKNOWN';
                    
                    if (!domainGroups[domain]) domainGroups[domain] = {};
                    if (!domainGroups[domain][type]) domainGroups[domain][type] = [];
                    
                    domainGroups[domain][type].push(f);
                });

                Object.keys(domainGroups).forEach(domain => {
                    var domainDetails = document.createElement('details');
                    domainDetails.style.marginBottom = '15px';
                    domainDetails.style.border = '1px solid #335577';
                    domainDetails.style.borderRadius = '5px';
                    domainDetails.style.background = 'rgba(10,20,30,0.5)';
                    domainDetails.open = true;

                    var domainTotal = 0;
                    Object.values(domainGroups[domain]).forEach(list => { domainTotal += list.length; });

                    var domainSummary = document.createElement('summary');
                    domainSummary.style.cursor = 'pointer';
                    domainSummary.style.padding = '8px';
                    domainSummary.style.fontWeight = 'bold';
                    domainSummary.style.outline = 'none';
                    domainSummary.style.backgroundColor = '#112233';
                    domainSummary.style.borderBottom = '1px solid #335577';
                    domainSummary.innerHTML = `🌍 <span style="color:#4da6ff; font-size:13px;">${domain}</span> <span style="color:#aaa; font-size:11px;">(${domainTotal} findings)</span>`;
                    domainDetails.appendChild(domainSummary);

                    var domainContent = document.createElement('div');
                    domainContent.style.padding = '10px';

                    var groups = domainGroups[domain];
                    Object.keys(groups).forEach(type => {
                        var list = groups[type];
                        var first = list[0];
                        var severity = first.severity || 'INFO';
                        var badgeClass = 'vx-badge vx-badge-' + severity.toLowerCase();
                        
                        var details = document.createElement('details');
                        details.style.marginBottom = '10px';
                        details.style.borderBottom = '1px solid #222';
                        details.style.paddingBottom = '8px';

                        var stateKey = domain + '_' + type;
                        if (window.__vx_open_details && window.__vx_open_details[stateKey]) {
                            details.open = true;
                        }
                        details.addEventListener('toggle', function() {
                            window.__vx_open_details = window.__vx_open_details || {};
                            window.__vx_open_details[stateKey] = details.open;
                        });

                        var summary = document.createElement('summary');
                        summary.style.cursor = 'pointer';
                        summary.style.fontWeight = 'bold';
                        summary.style.outline = 'none';
                        summary.innerHTML = `<span class="${badgeClass}">${severity}</span> <span style="margin-left:5px; color:#fff;">${type}</span> <span style="color:#666;font-size:10px;">(${list.length})</span>`;
                        details.appendChild(summary);

                        var descDiv = document.createElement('div');
                        descDiv.className = 'vx-finding-details';
                        
                        var remediation = first.remediation || 'Review and secure this resource.';
                        var description = first.description || 'Vulnerability detected.';
                        
                        var exploitSteps = "Manual exploitation steps not explicitly defined for this vulnerability class. Review documentation for standard attack vectors.";
                        var t = type.toUpperCase();
                        if (t.includes('XSS') || t.includes('DOM_XSS')) {
                            exploitSteps = "1. Identify the exact reflection point in the DOM or Response.\\n2. Inject a benign HTML payload (e.g., `<u>test</u>`).\\n3. Verify if the payload is rendered without HTML encoding.\\n4. Inject an active execution payload (e.g., `<script>alert(document.domain)</script>`).\\n5. If blocked, attempt standard WAF bypasses (e.g., `<img src=x onerror=alert(1)>`).";
                        } else if (t.includes('SQL') || t.includes('INJECTION')) {
                            exploitSteps = "1. Identify the susceptible input parameter.\\n2. Inject standard syntax breakers (e.g., `'`, `\"`, `;`).\\n3. Monitor the response for raw database errors.\\n4. Proceed with Boolean logic testing (e.g., `' OR 1=1--`).\\n5. Attempt Time-Based inference (e.g., `WAITFOR DELAY '0:0:5'`).";
                        } else if (t.includes('CORS')) {
                            exploitSteps = "1. Confirm if the server reflects an arbitrary `Origin` header.\\n2. Verify if `Access-Control-Allow-Credentials` is set to `true`.\\n3. Craft an exploit page with JavaScript to send cross-origin requests.\\n4. Phish an authenticated victim to visit the exploit page to exfiltrate their data.";
                        } else if (t.includes('SINK') || t.includes('RUNTIME')) {
                            exploitSteps = "1. Trace the input source (URL, hash, storage) reaching the sink.\\n2. Determine the execution context (e.g., inside a JS string, HTML context).\\n3. Craft a payload to break out of the context (e.g., `\");alert(1);//`).\\n4. Deliver the payload to execute arbitrary code.";
                        } else if (t.includes('SECRET') || t.includes('KEY') || t.includes('TOKEN')) {
                            exploitSteps = "1. Extract the disclosed secret from the application response.\\n2. Identify the target service (AWS, Stripe, Internal API).\\n3. Utilize the secret to attempt unauthorized API access or privilege escalation.";
                        } else if (t.includes('COOKIE') || t.includes('INSECURE')) {
                            exploitSteps = "1. (Missing HttpOnly) Attempt to steal the session cookie via XSS using `document.cookie`.\\n2. (Missing Secure) Attempt a Man-in-the-Middle (MitM) attack to capture the cookie over cleartext HTTP.\\n3. (Missing SameSite) Attempt Cross-Site Request Forgery (CSRF).";
                        }

                        var exploitHTML = `<div style="color:#aa55ff;margin-bottom:10px;font-size:11px;"><strong>🛡️ Exploitation Steps:</strong><br>${exploitSteps.replace(/\\n/g, '<br>')}</div>`;

                        descDiv.innerHTML = `<div style="color:#ffcc00;margin-bottom:6px;">💡 ${description}</div>
                                             <div style="color:#aaa;margin-bottom:10px;font-style:italic;">Remediation: ${remediation}</div>
                                             ${exploitHTML}`;

                        list.forEach(f => {
                            var item = document.createElement('div');
                            item.style.marginBottom = '6px';
                            var method = f.method || '';
                            var status = f.status_code || '';
                            var meta = (method || status) ? `[${method} ${status}] ` : '';
                            var match = f.match || '';
                            if (match.length > 1500) match = match.substring(0, 1500) + '... [TRUNCATED]';
                            
                            var safeMatch = match.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                            var matchHTML = match ? `<br><span style="color:#888;">Match: <code style="color:#ccc;white-space:pre-wrap;display:block;padding:4px;background:#222;border:1px solid #333;margin-top:2px;">${safeMatch}</code></span>` : '';
                            
                            // Highlight the path instead of full URL for cleaner display
                            var displayUrl = f.url;
                            try {
                                var u = new URL(f.url);
                                displayUrl = u.pathname + u.search + u.hash;
                                if (displayUrl === '') displayUrl = '/';
                            } catch(e) {}

                            item.innerHTML = `<strong style="color:#ff0055;font-size:10px;">${meta}</strong><span style="color:#4da6ff;word-break:break-all;">${displayUrl}</span>${matchHTML}`;
                            descDiv.appendChild(item);
                        });

                        details.appendChild(descDiv);
                        domainContent.appendChild(details);
                    });
                    
                    domainDetails.appendChild(domainContent);
                    container.appendChild(domainDetails);
                });
"""
