VPN_TAB_JS = r"""
container.innerHTML = '';

                var title = document.createElement('h3');
                title.innerText = 'Proxy / VPN Manager';
                title.style.color = '#ffcc00';
                title.style.borderBottom = '1px solid #333';
                title.style.paddingBottom = '8px';
                container.appendChild(title);

                var info = document.createElement('div');
                info.style.color = '#aaa';
                info.style.marginBottom = '15px';
                info.style.fontSize = '11px';
                info.innerHTML = 'Route Chrome traffic through <strong>Tor</strong> or a <strong>custom proxy</strong> without restarting the browser. Powered by the VulcanX Proxy Extension.<br><br><span style="color:#ffcc00;">⚠ Tor requires Tor Browser (or Tor service) running on 127.0.0.1:9050.</span>';
                container.appendChild(info);

                var resultDiv = document.createElement('div');
                resultDiv.style.background = '#111';
                resultDiv.style.border = '1px solid #333';
                resultDiv.style.padding = '10px';
                resultDiv.style.fontFamily = 'monospace';
                resultDiv.style.whiteSpace = 'pre-wrap';
                resultDiv.style.borderRadius = '4px';
                resultDiv.style.marginTop = '10px';
                resultDiv.style.fontSize = '11px';
                resultDiv.style.color = '#00ffcc';
                resultDiv.innerText = 'Proxy Status: Direct (no proxy)';
                container.appendChild(resultDiv);

                // ── Button Row 1: Tor ──────────────────────────────────────────
                var row1 = document.createElement('div');
                row1.style.display = 'flex';
                row1.style.gap = '6px';
                row1.style.marginTop = '12px';

                function apiBase() {
                    return 'http://127.0.0.1:' + (window.__vulcanx_api_port || 0);
                }

                var torBtn = document.createElement('button');
                torBtn.innerText = '🧅 Enable Tor (SOCKS5 :9050)';
                torBtn.style.flex = '1';
                torBtn.style.padding = '8px';
                torBtn.style.background = '#4CAF50';
                torBtn.style.color = '#fff';
                torBtn.style.border = 'none';
                torBtn.style.cursor = 'pointer';
                torBtn.style.borderRadius = '4px';
                torBtn.style.fontWeight = 'bold';
                torBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = 'Enabling Tor... Chrome will switch within ~2 seconds.';
                    fetch(apiBase() + '/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'enable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.style.color = '#00ffcc';
                            resultDiv.innerText = '✅ ' + data.message;
                        } else {
                            resultDiv.style.color = '#ff4444';
                            resultDiv.innerText = '❌ Error: ' + data.error;
                        }
                    }).catch(e => {
                        resultDiv.style.color = '#ff4444';
                        resultDiv.innerText = '❌ Error: ' + e;
                    });
                };

                var disableBtn = document.createElement('button');
                disableBtn.innerText = '⛔ Disable Proxy';
                disableBtn.style.flex = '1';
                disableBtn.style.padding = '8px';
                disableBtn.style.background = '#f44336';
                disableBtn.style.color = '#fff';
                disableBtn.style.border = 'none';
                disableBtn.style.cursor = 'pointer';
                disableBtn.style.borderRadius = '4px';
                disableBtn.style.fontWeight = 'bold';
                disableBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = 'Disabling proxy...';
                    fetch(apiBase() + '/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'disable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.style.color = '#00ffcc';
                            resultDiv.innerText = '✅ ' + data.message;
                        } else {
                            resultDiv.style.color = '#ff4444';
                            resultDiv.innerText = '❌ Error: ' + data.error;
                        }
                    }).catch(e => {
                        resultDiv.style.color = '#ff4444';
                        resultDiv.innerText = '❌ Error: ' + e;
                    });
                };

                var checkIpBtn = document.createElement('button');
                checkIpBtn.innerText = '🌐 Check My IP';
                checkIpBtn.style.flex = '1';
                checkIpBtn.style.padding = '8px';
                checkIpBtn.style.background = '#2196F3';
                checkIpBtn.style.color = '#fff';
                checkIpBtn.style.border = 'none';
                checkIpBtn.style.cursor = 'pointer';
                checkIpBtn.style.borderRadius = '4px';
                checkIpBtn.style.fontWeight = 'bold';
                checkIpBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = 'Checking IP address...';
                    fetch(apiBase() + '/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'check_ip'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.style.color = '#00ffcc';
                            resultDiv.innerText = `🌐 Current IP: ${data.ip}\nProxy Mode: ${data.mode || 'direct'}`;
                        } else {
                            resultDiv.style.color = '#ff4444';
                            resultDiv.innerText = '❌ Error: ' + data.error;
                        }
                    }).catch(e => {
                        resultDiv.style.color = '#ff4444';
                        resultDiv.innerText = '❌ Error: ' + e;
                    });
                };

                row1.appendChild(torBtn);
                row1.appendChild(disableBtn);
                row1.appendChild(checkIpBtn);
                container.appendChild(row1);

                // ── Custom Proxy Section ────────────────────────────────────────
                var customSection = document.createElement('div');
                customSection.style.marginTop = '16px';
                customSection.style.border = '1px solid #333';
                customSection.style.padding = '10px';
                customSection.style.borderRadius = '4px';
                customSection.style.background = '#0d0d15';

                var customTitle = document.createElement('div');
                customTitle.innerText = '🔧 Custom Proxy / Burp Suite Integration';
                customTitle.style.color = '#ffcc00';
                customTitle.style.fontWeight = 'bold';
                customTitle.style.marginBottom = '8px';
                customTitle.style.fontSize = '11px';
                customSection.appendChild(customTitle);

                var customInfo = document.createElement('div');
                customInfo.innerHTML = 'Route Chrome through <strong>Burp Suite</strong>, <strong>mitmproxy</strong>, or any other proxy.<br>Default: <code>http://127.0.0.1:8080</code>';
                customInfo.style.color = '#888';
                customInfo.style.fontSize = '10px';
                customInfo.style.marginBottom = '8px';
                customSection.appendChild(customInfo);

                var fieldRow = document.createElement('div');
                fieldRow.style.display = 'flex';
                fieldRow.style.gap = '6px';
                fieldRow.style.alignItems = 'center';

                var schemeSelect = document.createElement('select');
                ['http', 'https', 'socks5', 'socks4'].forEach(function(s) {
                    var opt = document.createElement('option');
                    opt.value = s; opt.text = s;
                    schemeSelect.appendChild(opt);
                });
                schemeSelect.style.background = '#1a1a24';
                schemeSelect.style.color = '#fff';
                schemeSelect.style.border = '1px solid #444';
                schemeSelect.style.padding = '5px';
                schemeSelect.style.borderRadius = '3px';

                var hostInput = document.createElement('input');
                hostInput.type = 'text'; hostInput.value = '127.0.0.1';
                hostInput.placeholder = 'Host';
                hostInput.style.flex = '1';
                hostInput.style.background = '#1a1a24';
                hostInput.style.color = '#fff';
                hostInput.style.border = '1px solid #444';
                hostInput.style.padding = '5px';
                hostInput.style.borderRadius = '3px';

                var portInput = document.createElement('input');
                portInput.type = 'number'; portInput.value = '8080';
                portInput.placeholder = 'Port';
                portInput.style.width = '70px';
                portInput.style.background = '#1a1a24';
                portInput.style.color = '#fff';
                portInput.style.border = '1px solid #444';
                portInput.style.padding = '5px';
                portInput.style.borderRadius = '3px';

                var applyCustomBtn = document.createElement('button');
                applyCustomBtn.innerText = 'Apply';
                applyCustomBtn.style.padding = '5px 12px';
                applyCustomBtn.style.background = '#7c4dff';
                applyCustomBtn.style.color = '#fff';
                applyCustomBtn.style.border = 'none';
                applyCustomBtn.style.cursor = 'pointer';
                applyCustomBtn.style.borderRadius = '3px';
                applyCustomBtn.style.fontWeight = 'bold';
                applyCustomBtn.onclick = function() {
                    var scheme = schemeSelect.value;
                    var host = hostInput.value.trim();
                    var port = parseInt(portInput.value);
                    if (!host || !port) { resultDiv.innerText = 'Enter a valid host and port.'; return; }
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = `Setting custom proxy to ${scheme}://${host}:${port}...`;
                    fetch(apiBase() + '/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'enable_custom', scheme, host, port}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.style.color = '#00ffcc';
                            resultDiv.innerText = '✅ ' + data.message;
                        } else {
                            resultDiv.style.color = '#ff4444';
                            resultDiv.innerText = '❌ ' + data.error;
                        }
                    }).catch(e => {
                        resultDiv.style.color = '#ff4444';
                        resultDiv.innerText = '❌ Error: ' + e;
                    });
                };

                fieldRow.appendChild(schemeSelect);
                fieldRow.appendChild(hostInput);
                fieldRow.appendChild(portInput);
                fieldRow.appendChild(applyCustomBtn);
                customSection.appendChild(fieldRow);
                container.appendChild(customSection);
"""
