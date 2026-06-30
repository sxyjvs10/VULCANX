TRAFFIC_TAB_JS = r"""
container.innerHTML = '';
                var traffic = window.__vulcanx_state.traffic || [];
                
                var topRow = document.createElement('div');
                topRow.style.display = 'flex';
                topRow.style.justifyContent = 'flex-end';
                topRow.style.marginBottom = '10px';
                
                var clearBtn = document.createElement('button');
                clearBtn.innerText = '🗑️ Clear History';
                clearBtn.style.background = '#aa0000';
                clearBtn.style.color = '#fff';
                clearBtn.style.border = '1px solid #ff0055';
                clearBtn.style.padding = '5px 10px';
                clearBtn.style.borderRadius = '3px';
                clearBtn.style.cursor = 'pointer';
                clearBtn.onclick = async function() {
                    try { await fetch('/api/clear_traffic', {method: 'POST'}); } catch(e) {}
                    window.__vulcanx_state.traffic = [];
                    window.__vulcanx_render();
                };
                topRow.appendChild(clearBtn);
                container.appendChild(topRow);

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
                        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";", "' or \"", "-- or #", 
                        "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '",
                        "admin' --", "admin' #", "' OR 'x'='x",
                        "<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[5*5]]",
                        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
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
"""
