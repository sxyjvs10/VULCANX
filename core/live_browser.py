import time
import json
import base64
import hashlib
import urllib.parse
import datetime

try:
    from seleniumwire import webdriver
    _SELENIUM_WIRE_AVAILABLE = True
except ImportError:
    _SELENIUM_WIRE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Runtime DOM-sink instrumentation
#
# Static taint analysis (core/engine.py _check_dom_xss_taint) can only prove a
# sink is *reachable*. In manual-browse mode we have a live DOM, so we hook
# the actual sink APIs and log calls that really fire, with a best-effort
# caller stack. This catches dynamically-constructed sinks static analysis
# cannot see (e.g. sinks built via string concatenation/computed member access)
# and confirms which statically-flagged sinks are live.
# ---------------------------------------------------------------------------
DOM_SINK_HOOK_JS = r"""
(function() {
    if (window.__vulcanx_hooked) return;
    window.__vulcanx_hooked = true;
    window.__vulcanx_sink_log = window.__vulcanx_sink_log || [];

    function record(kind, detail) {
        try {
            var stack = (new Error()).stack || '';
            window.__vulcanx_sink_log.push({
                kind: kind,
                detail: String(detail).slice(0, 500),
                url: window.location.href,
                stack: stack.split('\n').slice(1, 5).join(' | ').slice(0, 400),
                t: Date.now()
            });
        } catch (e) {}
    }

    // 1. innerHTML / outerHTML setter hook
    ['innerHTML', 'outerHTML'].forEach(function(prop) {
        try {
            var desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
            if (!desc || !desc.set) return;
            Object.defineProperty(Element.prototype, prop, {
                get: desc.get,
                set: function(val) {
                    if (typeof val === 'string' && val.length > 0) {
                        record('DOM_SINK_' + prop.toUpperCase(), val);
                    }
                    return desc.set.call(this, val);
                },
                configurable: true
            });
        } catch (e) {}
    });

    // 2. document.write / writeln
    ['write', 'writeln'].forEach(function(fn) {
        try {
            var orig = document[fn];
            document[fn] = function() {
                record('DOM_SINK_DOCUMENT_' + fn.toUpperCase(), Array.prototype.join.call(arguments, ' '));
                return orig.apply(document, arguments);
            };
        } catch (e) {}
    });

    // 3. eval
    try {
        var origEval = window.eval;
        window.eval = function(src) {
            record('DOM_SINK_EVAL', src);
            return origEval(src);
        };
    } catch (e) {}

    // 4. Function constructor (dynamic code gen)
    try {
        var OrigFunction = window.Function;
        window.Function = function() {
            record('DOM_SINK_FUNCTION_CTOR', Array.prototype.join.call(arguments, ' | '));
            return OrigFunction.apply(this, arguments);
        };
        window.Function.prototype = OrigFunction.prototype;
    } catch (e) {}

    // 5. setTimeout/setInterval with string argument (implicit eval)
    ['setTimeout', 'setInterval'].forEach(function(fn) {
        try {
            var orig = window[fn];
            window[fn] = function(handler) {
                if (typeof handler === 'string') {
                    record('DOM_SINK_' + fn.toUpperCase() + '_STRING', handler);
                }
                return orig.apply(window, arguments);
            };
        } catch (e) {}
    });

    // 6. postMessage listeners receiving untrusted-origin data with no origin check
    try {
        var origAdd = window.addEventListener;
        window.addEventListener = function(type, listener, opts) {
            if (type === 'message') {
                var src = String(listener).slice(0, 300);
                if (src.indexOf('event.origin') === -1 && src.indexOf('e.origin') === -1) {
                    record('POSTMESSAGE_NO_ORIGIN_CHECK', src);
                }
            }
            return origAdd.call(window, type, listener, opts);
        };
    } catch (e) {}
})();
"""


WIDGET_INIT_JS = r"""
(function() {
    try {
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
            
            var tabs = ['vulnerabilities', 'traffic', 'forms', 'storage', 'map'];
            var tabLabels = ['Findings', 'Traffic', 'Forms', 'Storage', 'LinkMap'];
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
                
                var sendBtn = document.createElement('button');
                sendBtn.innerText = 'Send Request';
                sendBtn.style.background = '#004488';
                sendBtn.style.color = '#fff';
                sendBtn.style.border = '1px solid #0088ff';
                sendBtn.style.padding = '4px 8px';
                sendBtn.style.borderRadius = '3px';
                sendBtn.style.cursor = 'pointer';
                sendBtn.style.marginBottom = '8px';
                repeaterDiv.appendChild(sendBtn);
                
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

                if (items.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '20px';
                    emptyDiv.innerText = 'No cookies or storage keys found.';
                    container.appendChild(emptyDiv);
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
                                        <th>Source</th>
                                        <th>Key</th>
                                        <th>Value</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                
                var sensitiveKeys = /token|session|secret|jwt|password|key|admin|auth|role/i;
                items.forEach(item => {
                    var tr = document.createElement('tr');
                    var isSensitive = sensitiveKeys.test(item.key) || sensitiveKeys.test(item.value);
                    if (isSensitive) {
                        tr.style.background = 'rgba(255, 0, 85, 0.15)';
                    }
                    tr.innerHTML = `<td style="color:#00ff55;font-weight:bold;">${item.source}</td>
                                    <td style="color:#ffcc00;font-weight:bold;">${item.key}</td>
                                    <td style="color:#aaa;word-break:break-all;">${item.value}</td>`;
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);
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
"""

DOM_SINK_DRAIN_JS = """
if (window.__vulcanx_sink_log && window.__vulcanx_sink_log.length > 0) {
    var out = window.__vulcanx_sink_log;
    window.__vulcanx_sink_log = [];
    return out;
}
return [];
"""


class ScopeFilter:
    """
    Restricts analysis to the target's registrable domain (+ optional extra
    hosts the user explicitly adds, e.g. an API subdomain or CDN that's
    actually in scope). Out-of-scope traffic (analytics, ad tech, unrelated
    third parties) is never decoded or scanned, which keeps findings clean
    and avoids wasting cycles on noise.
    """

    def __init__(self, start_url, extra_hosts=None):
        self.root_host = self._registrable(urllib.parse.urlparse(start_url).hostname or '')
        self.extra_hosts = set()
        for h in (extra_hosts or []):
            h = h.strip().lower()
            if h:
                self.extra_hosts.add(h)

    @staticmethod
    def _registrable(hostname):
        """Best-effort eTLD+1 without external deps: last two labels, with a
        small list of common multi-part public suffixes handled explicitly."""
        if not hostname:
            return ''
        hostname = hostname.lower()
        multi_part_suffixes = ('co.uk', 'org.uk', 'gov.uk', 'co.in', 'com.au',
                                'co.jp', 'com.br', 'co.nz')
        for suf in multi_part_suffixes:
            if hostname.endswith('.' + suf):
                parts = hostname.split('.')
                return '.'.join(parts[-3:]) if len(parts) >= 3 else hostname
        parts = hostname.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    def in_scope(self, url):
        try:
            host = (urllib.parse.urlparse(url).hostname or '').lower()
        except Exception:
            return False
        if not host:
            return False
        if host in self.extra_hosts:
            return True
        return self._registrable(host) == self.root_host


class HARBuilder:
    """Accumulates request/response pairs and emits a HAR 1.2 document so a
    manual-browse session can be replayed via --har or imported into Burp."""

    def __init__(self, page_url):
        self.entries = []
        self.page_url = page_url
        self.start_time = datetime.datetime.utcnow()

    def add(self, request):
        try:
            req_headers = [{'name': k, 'value': v} for k, v in dict(request.headers).items()]
            resp = request.response
            resp_headers = [{'name': k, 'value': v} for k, v in dict(resp.headers).items()] if resp else []
            body_text = ''
            if resp is not None and resp.body:
                try:
                    body_text = resp.body.decode('utf-8', errors='ignore')
                except Exception:
                    body_text = ''
            req_body_text = ''
            if request.body:
                try:
                    req_body_text = request.body.decode('utf-8', errors='ignore')
                except Exception:
                    req_body_text = ''

            entry = {
                'startedDateTime': self.start_time.isoformat() + 'Z',
                'time': 0,
                'request': {
                    'method': request.method,
                    'url': request.url,
                    'httpVersion': 'HTTP/1.1',
                    'headers': req_headers,
                    'queryString': [],
                    'cookies': [],
                    'headersSize': -1,
                    'bodySize': len(req_body_text),
                    'postData': {'mimeType': dict(request.headers).get('Content-Type', ''),
                                 'text': req_body_text} if req_body_text else {}
                },
                'response': {
                    'status': resp.status_code if resp else 0,
                    'statusText': resp.reason if resp else '',
                    'httpVersion': 'HTTP/1.1',
                    'headers': resp_headers,
                    'cookies': [],
                    'content': {
                        'size': len(body_text),
                        'mimeType': dict(resp.headers).get('Content-Type', '') if resp else '',
                        'text': body_text
                    },
                    'redirectURL': '',
                    'headersSize': -1,
                    'bodySize': len(body_text)
                },
                'cache': {},
                'timings': {'send': 0, 'wait': 0, 'receive': 0}
            }
            self.entries.append(entry)
        except Exception:
            pass

    def save(self, filepath):
        har = {
            'log': {
                'version': '1.2',
                'creator': {'name': 'VulcanX', 'version': '2.0'},
                'pages': [{
                    'startedDateTime': self.start_time.isoformat() + 'Z',
                    'id': 'page_1',
                    'title': self.page_url,
                    'pageTimings': {}
                }],
                'entries': self.entries
            }
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(har, f, indent=2)


class LiveBrowserInterceptor:
    def __init__(self, analyzer, scope_extra=None, har_out=None, dom_sinks=True):
        self.tls_checked_hosts = set()
        self.analyzer = analyzer
        self.driver = None
        self.running = False
        self.processed_requests = set()
        self.processed_request_bodies = set()
        self.live_findings = []
        self.live_traffic = []
        self.current_url = ""
        self.last_seen_url = ""
        self.scope = None
        self.scope_extra = scope_extra or []
        self.har = None
        self.har_out = har_out
        self.dom_sinks_enabled = dom_sinks

    def start(self, start_url):
        if not _SELENIUM_WIRE_AVAILABLE:
            print("[-] selenium-wire is not installed. Run: pip install selenium-wire --break-system-packages")
            return

        print("[*] Launching Live Browser Mode (using Firefox)...")
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        from selenium.webdriver.firefox.service import Service as FirefoxService
        from webdriver_manager.firefox import GeckoDriverManager

        self.scope = ScopeFilter(start_url, extra_hosts=self.scope_extra)
        self.har = HARBuilder(start_url) if self.har_out else None

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
        print(f"[*] Scope: *.{self.scope.root_host}" + (f" + {len(self.scope_extra)} extra host(s)" if self.scope_extra else ""))
        if self.dom_sinks_enabled:
            print("[*] Runtime DOM-sink instrumentation: ENABLED (innerHTML/eval/document.write/Function/setTimeout/postMessage)")
        if self.har_out:
            print(f"[*] HAR export on stop: {self.har_out}")
        print("[*] VulcanX is actively intercepting and analyzing traffic in the background...")

        self.driver.get(start_url)
        self.last_seen_url = start_url
        if self.dom_sinks_enabled:
            self._inject_dom_hooks()
        self.running = True

        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            print("\n[*] Live Browsing Session Ended by User.")
        finally:
            self.stop()

    # -- DOM sink instrumentation -------------------------------------------------

    def _inject_dom_hooks(self):
        try:
            self.driver.execute_script(DOM_SINK_HOOK_JS)
        except Exception:
            pass

    def _drain_dom_sinks(self):
        try:
            results = self.driver.execute_script(DOM_SINK_DRAIN_JS)
        except Exception:
            return
        if not results:
            return
        for entry in results:
            kind = entry.get('kind', 'DOM_SINK_UNKNOWN')
            detail = str(entry.get('detail', ''))
            url = entry.get('url', self.current_url)
            stack = entry.get('stack', '')

            severity = 'HIGH' if 'EVAL' in kind or 'FUNCTION' in kind or 'INNERHTML' in kind else 'MEDIUM'
            if kind == 'POSTMESSAGE_NO_ORIGIN_CHECK':
                severity = 'MEDIUM'

            is_dom_xss = False
            reflected_param = ""
            try:
                parsed_url = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed_url.query)
                for param, values in params.items():
                    for v in values:
                        if len(v) > 3 and v in detail:
                            is_dom_xss = True
                            reflected_param = param
                            break
                    if is_dom_xss: break
                
                if not is_dom_xss and parsed_url.fragment and len(parsed_url.fragment) > 3:
                    if parsed_url.fragment in detail:
                        is_dom_xss = True
                        reflected_param = "location.hash"
            except Exception:
                pass

            if is_dom_xss:
                finding = {
                    'url': url,
                    'type': f'CONFIRMED_DOM_XSS_{kind}',
                    'severity': 'CRITICAL',
                    'confidence': '100%',
                    'description': f'DOM XSS CONFIRMED! User input from "{reflected_param}" flows directly into dangerous sink "{kind}".',
                    'remediation': 'Sanitize user input before passing it to DOM sinks like innerHTML or eval().',
                    'match': detail[:200],
                    'context': stack or url,
                    'line': 0,
                    'source': 'RUNTIME_DOM'
                }
            else:
                finding = {
                    'url': url,
                    'type': f'CONFIRMED_RUNTIME_{kind}',
                    'severity': severity,
                    'confidence': '95%',
                    'description': f'Live DOM sink "{kind}" actually fired during manual browsing (not just statically reachable).',
                    'remediation': 'Trace the caller stack to its data source; sanitize/encode before reaching this sink.',
                    'match': detail,
                    'context': stack or url,
                    'line': 0,
                    'source': 'RUNTIME_DOM'
                }

            if finding not in self.analyzer.findings:
                self.analyzer.findings.append(finding)
            self._inject_ui_alert(finding)

    # -- Traffic monitoring --------------------------------------------------------

    def _monitor_loop(self):
        while self.running:
            try:
                # (Tab state and hook injection moved to the end of the loop)

                for request in self.driver.requests:
                    url = request.url

                    if self.har is not None and request.response:
                        req_key = (request.method, url, id(request))
                        if req_key not in self.processed_request_bodies:
                            self.har.add(request)

                    if not self.scope.in_scope(url):
                        continue

                    # --- Request-side analysis (runs once per request, regardless of response) ---
                    req_sig = (request.method, url, hashlib.sha1((request.body or b'')).hexdigest())
                    if req_sig not in self.processed_request_bodies:
                        self.processed_request_bodies.add(req_sig)
                        self._analyze_request(request)

                    if not request.response:
                        continue

                    if url in self.processed_requests:
                        continue

                    # Filter out images, fonts, css
                    if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.woff', '.woff2', '.ttf', '.css', '.svg', '.ico']):
                        self.processed_requests.add(url)
                        continue

                    # Add to live traffic log if in scope
                    if self.scope.in_scope(url):
                        req_id = id(request)
                        if not any(t.get('id') == req_id for t in getattr(self, 'live_traffic', [])):
                            try:
                                status_code = request.response.status_code if request.response else 0
                            except Exception:
                                status_code = 0
                            
                            display_url = url
                            if len(display_url) > 150:
                                display_url = display_url[:150] + "..."

                            # Try to get raw body if it exists
                            req_body_text = ''
                            if request.body:
                                try:
                                    req_body_text = request.body.decode('utf-8', errors='ignore')
                                except Exception:
                                    req_body_text = '<binary/un-decodable data>'

                            self.live_traffic.append({
                                'id': req_id,
                                'method': request.method,
                                'url': url,  # store full url for repeater
                                'display_url': display_url,
                                'status_code': status_code,
                                'time': datetime.datetime.now().strftime('%H:%M:%S'),
                                'req_headers': dict(request.headers),
                                'req_body': req_body_text
                            })
                            if len(self.live_traffic) > 100:
                                self.live_traffic.pop(0)

                    self.processed_requests.add(url)
                    self._analyze_response(request)

                # Unconditionally inject/update the UI every second to ensure it survives page loads
                # and dynamically updates as the user navigates
                try:
                    try:
                        current = self.driver.current_window_handle
                    except Exception:
                        current = None

                    handles = self.driver.window_handles
                    if not hasattr(self, 'known_handles'):
                        self.known_handles = set(handles)

                    new_handles = set(handles) - self.known_handles
                    
                    if new_handles:
                        # User opened a new tab, switch Selenium's context to it
                        current = list(new_handles)[-1]
                        self.driver.switch_to.window(current)
                        self.known_handles = set(handles)
                    elif current not in handles and handles:
                        # Active window was closed, fallback to last available
                        current = handles[-1]
                        self.driver.switch_to.window(current)
                        self.known_handles = set(handles)
                    elif set(handles) != self.known_handles:
                        # A tab was closed, just update the known set
                        self.known_handles = set(handles)

                    # Re-inject hooks if the page navigated
                    if self.dom_sinks_enabled:
                        try:
                            cur = self.driver.current_url
                        except Exception:
                            cur = self.last_seen_url
                        if cur != self.last_seen_url:
                            self.last_seen_url = cur
                            self.current_url = cur
                            self._inject_dom_hooks()
                        self._drain_dom_sinks()

                    self._inject_ui_alert(None)
                except Exception:
                    pass

                time.sleep(1)  # Prevent CPU thrashing
            except Exception as e:
                # Browser might be closed by user
                if "connection refused" in str(e).lower() or "disconnected" in str(e).lower() or "not reachable" in str(e).lower():
                    print("\n[*] Browser closed. Stopping interception.")
                    break
                time.sleep(1)

    def _check_tls_vulnerabilities(self, url):
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            return
            
        host = parsed.hostname
        port = parsed.port or 443
        host_key = f"{host}:{port}"
        
        if host_key in self.tls_checked_hosts:
            return
        self.tls_checked_hosts.add(host_key)
        
        try:
            import ssl
            import socket
            # Check for SSLv2/SSLv3 (POODLE)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Use threading to prevent blocking the main interception loop
            import threading
            def do_tls_check():
                try:
                    # In newer Python versions, SSLv2/3 are disabled by default or entirely removed.
                    # We can check the negotiated TLS version and ciphers.
                    with socket.create_connection((host, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            version = ssock.version()
                            cipher = ssock.cipher()
                            
                            if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                f_tls = {
                                    'url': url,
                                    'method': 'TLS_CHECK',
                                    'status_code': 0,
                                    'type': 'WEAK_TLS_VERSION',
                                    'severity': 'HIGH' if version in ['SSLv2', 'SSLv3'] else 'MEDIUM',
                                    'match': f'Negotiated: {version}',
                                    'description': f'Server supports deprecated/weak protocol {version}. May be vulnerable to POODLE or BEAST.',
                                    'remediation': 'Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Require TLSv1.2 or TLSv1.3.',
                                    'context': f"Host: {host}"
                                }
                                self._inject_ui_alert(f_tls)
                                
                            # Check for weak ciphers (RC4, DES, CBC mode for Lucky13)
                            if cipher:
                                cipher_name = cipher[0]
                                if 'RC4' in cipher_name or 'DES' in cipher_name:
                                    f_cipher = {
                                        'url': url,
                                        'method': 'TLS_CHECK',
                                        'status_code': 0,
                                        'type': 'WEAK_CIPHER_SUITE',
                                        'severity': 'HIGH',
                                        'match': f'Cipher: {cipher_name}',
                                        'description': f'Server negotiated a weak cipher ({cipher_name}). Vulnerable to SWEET32/RC4 biases.',
                                        'remediation': 'Configure server to use strong AEAD ciphers (e.g., AES-GCM, CHACHA20).',
                                        'context': f"Host: {host}"
                                    }
                                    self._inject_ui_alert(f_cipher)
                                elif 'CBC' in cipher_name and version in ['TLSv1.1', 'TLSv1.2']:
                                    f_cbc = {
                                        'url': url,
                                        'method': 'TLS_CHECK',
                                        'status_code': 0,
                                        'type': 'CBC_MAC_VULNERABILITY',
                                        'severity': 'LOW',
                                        'match': f'Cipher: {cipher_name} ({version})',
                                        'description': f'Server negotiated a CBC-mode cipher ({cipher_name}) in TLS. May be vulnerable to Lucky13 or padding oracle attacks if not patched.',
                                        'remediation': 'Prioritize AEAD ciphers (GCM/CCM/CHACHA20) over CBC-mode ciphers.',
                                        'context': f"Host: {host}"
                                    }
                                    self._inject_ui_alert(f_cbc)
                except Exception:
                    pass
                    
            threading.Thread(target=do_tls_check, daemon=True).start()
        except Exception:
            pass

    def _analyze_request(self, request):
        self._check_tls_vulnerabilities(request.url)
        """Runs Analyzer.scan_request against an outgoing request's headers/body."""
        try:
            headers = dict(request.headers)
            body_text = ''
            if request.body:
                try:
                    body_text = request.body.decode('utf-8', errors='ignore')
                except Exception:
                    body_text = ''

            findings = self.analyzer.scan_request(
                request.url, method=request.method, headers=headers, body=body_text or None
            )

            # Also run the generic secret/JWT/entropy pattern set against the body itself —
            # scan() already knows how to find AWS keys, JWTs, etc. in arbitrary text.
            if body_text:
                findings += self.analyzer.scan({f"{request.url} [REQUEST BODY]": body_text}, set())

            for f in findings:
                f.setdefault('method', request.method)
                if f['severity'] in ['CRITICAL', 'HIGH']:
                    print(f"\n[!!!] {f['severity']} REQUEST-SIDE FINDING!")
                    print(f"      Type: {f['type']}")
                    print(f"      {request.method} {request.url}")
                    print(f"      Match: {str(f.get('match',''))[:100]}...\n")
                self._inject_ui_alert(f)
        except Exception:
            pass

    def _analyze_response(self, request):
        url = request.url
        headers = dict(request.response.headers)
        ctype = headers.get('Content-Type', headers.get('content-type', '')).lower()
        status_code = request.response.status_code

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check Security Headers Dynamically
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
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'LOW',
                    'match': f'Missing: {m_header}'
                }
                self._inject_ui_alert(f_header)

        # Check for HTTP Compression (Potential BREACH/CRIME vulnerability)
        if 'content-encoding' in headers_lower:
            encoding = headers_lower['content-encoding'].lower()
            if encoding in ['gzip', 'deflate', 'br']:
                # BREACH targets HTTP compression on responses reflecting user input
                f_compression = {
                    'url': url,
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'HTTP_COMPRESSION_ENABLED',
                    'severity': 'INFO',
                    'match': f'Content-Encoding: {encoding}',
                    'description': f'HTTP compression ({encoding}) is enabled. If this endpoint reflects user input and contains secrets (like CSRF tokens), it may be vulnerable to BREACH/CRIME attacks.',
                    'remediation': 'Disable HTTP compression for endpoints that reflect user data and contain sensitive secrets, or use length-hiding techniques (e.g., XOR masking CSRF tokens).',
                    'context': f"Status: {status_code}"
                }
                self._inject_ui_alert(f_compression)

        # Check Set-Cookie Headers for Vulnerabilities
        if 'set-cookie' in headers_lower:
            cookie_headers = []
            if hasattr(request.response.headers, 'get_all'):
                cookie_headers = request.response.headers.get_all('set-cookie', [])
            else:
                # Fallback to get_list or manually parsing
                raw_headers = getattr(request.response.headers, '_headers', [])
                cookie_headers = [v for k, v in raw_headers if k.lower() == 'set-cookie']
                if not cookie_headers:
                    # Final fallback if _headers isn't available
                    cookie_headers = [headers_lower['set-cookie']]
                
            for cookie_str in cookie_headers:
                # Don't split by comma here as Set-Cookie strings contain commas in dates (e.g., Expires=Wed, 21 Oct 2015 07:28:00 GMT)
                # Instead, parse each string individually
                cookie_lower = cookie_str.lower()
                cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else "Unknown"
                missing_flags = []
                
                # We usually don't care if a tracking cookie lacks HttpOnly, but let's flag it anyway with LOW severity if it doesn't look sensitive
                is_sensitive = any(s in cookie_lower for s in ['session', 'token', 'auth', 'sess', 'id', 'user'])
                severity = 'MEDIUM' if is_sensitive else 'LOW'

                # HttpOnly Check
                if 'httponly' not in cookie_lower:
                    missing_flags.append('HttpOnly')
                
                # Secure Check
                if 'secure' not in cookie_lower and url.startswith('https'):
                    missing_flags.append('Secure')
                
                # SameSite Check
                if 'samesite' not in cookie_lower:
                    missing_flags.append('SameSite (Missing)')
                elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                    missing_flags.append('SameSite=None without Secure')
                    
                if missing_flags:
                    f_cookie = {
                        'url': url,
                        'method': request.method,
                        'status_code': status_code,
                        'type': 'INSECURE_COOKIE',
                        'severity': severity,
                        'match': f'Cookie: {cookie_name}',
                        'description': f'Cookie "{cookie_name}" is missing security flags: {", ".join(missing_flags)}.',
                        'remediation': 'Set HttpOnly, Secure, and SameSite attributes on sensitive cookies.',
                        'context': cookie_str[:100]
                    }
                    self._inject_ui_alert(f_cookie)

        # CORS Misconfiguration Check
        if 'access-control-allow-origin' in headers_lower:
            acao = headers_lower['access-control-allow-origin']
            if acao == '*':
                f_cors = {
                    'url': url,
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'CORS_WILDCARD_ORIGIN',
                    'severity': 'LOW', # Wildcard with credentials=true would be HIGH, but we can't always know without the acac header
                    'match': 'Access-Control-Allow-Origin: *',
                    'description': 'CORS policy allows access from any origin (*). This could be dangerous if combined with Access-Control-Allow-Credentials: true or if the endpoint exposes sensitive data.',
                    'remediation': 'Restrict Access-Control-Allow-Origin to trusted domains only.',
                    'context': f"Status: {status_code}"
                }
                self._inject_ui_alert(f_cors)
            elif 'access-control-allow-credentials' in headers_lower and headers_lower['access-control-allow-credentials'].lower() == 'true':
                # Check if it reflected a domain
                if acao != '*' and 'http' in acao:
                     f_cors = {
                        'url': url,
                        'method': request.method,
                        'status_code': status_code,
                        'type': 'POTENTIAL_CORS_MISCONFIG',
                        'severity': 'MEDIUM',
                        'match': f'ACAO: {acao} | ACAC: true',
                        'description': 'CORS allows credentials and specifies an origin. Verify if the origin is dynamically reflected from the request Origin header without validation.',
                        'remediation': 'Ensure the reflected origin is validated against a strict allowlist before granting access.',
                        'context': f"Status: {status_code}"
                    }
                     self._inject_ui_alert(f_cors)


        # Try to get response body via selenium-wire
        try:
            import gzip
            from io import BytesIO
            body_bytes = request.response.body

            # Handle gzip decoding if necessary
            if request.response.headers.get('Content-Encoding') == 'gzip':
                body_bytes = gzip.GzipFile(fileobj=BytesIO(body_bytes)).read()

            body = body_bytes.decode('utf-8', errors='ignore')

            if body:
                print(f"    [Intercepted] {request.method} {url} -> {status_code}")
                # We need to pass headers to scan so it can pass them to component_checker
                findings = self.analyzer.scan({url: body}, set(), headers=headers)

                for f in findings:
                    f.setdefault('method', request.method)
                    f.setdefault('status_code', status_code)
                    if f['severity'] in ['CRITICAL', 'HIGH']:
                        print(f"\n[!!!] {f['severity']} FINDING DYNAMICALLY DISCOVERED!")
                        print(f"      Type: {f['type']}")
                        print(f"      URL: {f['url']}")
                        print(f"      Match: {f['match'][:100]}...\n")

                    self._inject_ui_alert(f)

        except Exception:
            # Body decoding might fail on binary files not caught by filter
            pass

    def _inject_ui_alert(self, finding=None):
        if finding and finding not in self.live_findings:
            self.live_findings.append(finding)

        findings_json = json.dumps(self.live_findings)
        findings_b64 = base64.b64encode(findings_json.encode('utf-8')).decode('utf-8')

        traffic_json = json.dumps(getattr(self, 'live_traffic', []))
        traffic_b64 = base64.b64encode(traffic_json.encode('utf-8')).decode('utf-8')

        js_inject_state = f"""
        (function() {{
            try {{
                var findings = JSON.parse(window.atob('{findings_b64}'));
                var traffic = JSON.parse(window.atob('{traffic_b64}'));
                
                if (window.__vulcanx_state) {{
                    var old_f = JSON.stringify(window.__vulcanx_state.findings);
                    var old_t = JSON.stringify(window.__vulcanx_state.traffic);
                    var new_f = JSON.stringify(findings);
                    var new_t = JSON.stringify(traffic);
                    
                    window.__vulcanx_state.findings = findings;
                    window.__vulcanx_state.traffic = traffic;
                    
                    if (window.__vulcanx_state.activeTab === 'vulnerabilities' && old_f !== new_f) {{
                        window.__vulcanx_render();
                    }} else if (window.__vulcanx_state.activeTab === 'traffic' && old_t !== new_t) {{
                        window.__vulcanx_render();
                    }} else if (window.__vulcanx_state.activeTab !== 'vulnerabilities' && window.__vulcanx_state.activeTab !== 'traffic') {{
                        // Do not re-render forms or storage just because traffic changed
                    }}
                }}
            }} catch(e) {{}}
        }})();
        """

        try:
            self.driver.execute_script(WIDGET_INIT_JS)
            self.driver.execute_script(js_inject_state)
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.har_out and self.har is not None:
            try:
                self.har.save(self.har_out)
                print(f"[+] HAR traffic export saved to {self.har_out} ({len(self.har.entries)} entries)")
            except Exception as e:
                print(f"[-] Failed to save HAR export: {e}")
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
