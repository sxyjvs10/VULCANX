VPN_TAB_JS = r"""
container.innerHTML = '';

                // Command bus helper — no fetch(), no CORS, no PNA issues
                function sendCmd(cmd, onResult) {
                    window.__vulcanx_cmd = cmd;
                    window.__vulcanx_cmd_result = null;
                    if (onResult) {
                        var tries = 0;
                        var t = setInterval(function() {
                            tries++;
                            var r = window.__vulcanx_cmd_result;
                            if (r !== null && r !== undefined) {
                                clearInterval(t);
                                onResult(r);
                            } else if (tries > 20) {   // 2s timeout
                                clearInterval(t);
                                onResult({status:'error', error:'Timeout — no response from Python backend.'});
                            }
                        }, 100);
                    }
                }

                var title = document.createElement('h3');
                title.innerText = 'Proxy / VPN Manager';
                title.style.cssText = 'color:#ffcc00;border-bottom:1px solid #333;padding-bottom:8px;margin:0 0 12px;';
                container.appendChild(title);

                var info = document.createElement('div');
                info.style.cssText = 'color:#888;margin-bottom:14px;font-size:11px;line-height:1.5;';
                info.innerHTML = 'Route Chrome traffic through <strong>Tor</strong> or a <strong>custom proxy</strong> mid-session.' +
                    ' The VulcanX proxy extension updates Chrome within ~2s.<br>' +
                    '<span style="color:#ffcc00;">⚠ Tor requires Tor Browser (or Tor service) running on 127.0.0.1:9050.</span>';
                container.appendChild(info);

                var resultDiv = document.createElement('div');
                resultDiv.style.cssText = 'background:#0d0d15;border:1px solid #333;padding:10px;font-family:monospace;' +
                    'white-space:pre-wrap;border-radius:4px;margin-bottom:12px;font-size:11px;color:#00ffcc;min-height:36px;';
                resultDiv.innerText = '— Proxy Status: Direct (no proxy) —';
                container.appendChild(resultDiv);

                function showResult(data) {
                    if (data.status === 'ok') {
                        resultDiv.style.color = '#00ffcc';
                        resultDiv.innerText = '✅ ' + (data.message || data.ip || 'Done');
                        if (data.ip) resultDiv.innerText = '🌐 Your IP: ' + data.ip + (data.mode ? '\nProxy Mode: ' + data.mode : '');
                    } else {
                        resultDiv.style.color = '#ff4444';
                        resultDiv.innerText = '❌ ' + (data.error || 'Error');
                    }
                }

                // ── Row 1: Tor + Disable + Check IP ─────────────────────────
                var row1 = document.createElement('div');
                row1.style.cssText = 'display:flex;gap:6px;margin-bottom:10px;';

                function mkBtn(text, bg, border) {
                    var b = document.createElement('button');
                    b.innerText = text;
                    b.style.cssText = 'flex:1;padding:8px;background:' + bg + ';color:#fff;border:' +
                        (border ? '1px solid ' + border : 'none') + ';border-radius:4px;cursor:pointer;font-weight:bold;font-size:11px;';
                    return b;
                }

                var torBtn = mkBtn('🧅 Enable Tor (SOCKS5 :9050)', '#2e7d32', '');
                torBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = '⏳ Enabling Tor…';
                    sendCmd({action: 'enable_tor'}, showResult);
                };

                var disBtn = mkBtn('⛔ Disable Proxy', '#c62828', '');
                disBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = '⏳ Disabling proxy…';
                    sendCmd({action: 'disable_proxy'}, showResult);
                };

                var ipBtn = mkBtn('🌐 Check IP', '#1565c0', '');
                ipBtn.onclick = function() {
                    resultDiv.style.color = '#ffcc00';
                    resultDiv.innerText = '⏳ Fetching IP address…';
                    sendCmd({action: 'check_ip'}, showResult);
                };

                row1.appendChild(torBtn); row1.appendChild(disBtn); row1.appendChild(ipBtn);
                container.appendChild(row1);

                // ── Custom Proxy Section ─────────────────────────────────────
                var customBox = document.createElement('div');
                customBox.style.cssText = 'background:#0d0d15;border:1px solid #333;border-radius:4px;padding:10px;';

                var cTitle = document.createElement('div');
                cTitle.style.cssText = 'color:#ffcc00;font-weight:bold;font-size:11px;margin-bottom:8px;';
                cTitle.innerText = '🔧 Custom Proxy — Burp Suite / mitmproxy';
                customBox.appendChild(cTitle);

                var cInfo = document.createElement('div');
                cInfo.style.cssText = 'color:#666;font-size:10px;margin-bottom:8px;';
                cInfo.innerHTML = 'Route Chrome through any proxy. Default: <code>http://127.0.0.1:8080</code> (Burp Suite)';
                customBox.appendChild(cInfo);

                var cRow = document.createElement('div');
                cRow.style.cssText = 'display:flex;gap:6px;align-items:center;';

                var schSel = document.createElement('select');
                ['http','https','socks5','socks4'].forEach(function(s){
                    var o=document.createElement('option'); o.value=s; o.text=s; schSel.appendChild(o);
                });
                schSel.style.cssText = 'background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:3px;';

                var hostInp = document.createElement('input');
                hostInp.type='text'; hostInp.value='127.0.0.1'; hostInp.placeholder='Host';
                hostInp.style.cssText='flex:1;background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:3px;';

                var portInp = document.createElement('input');
                portInp.type='number'; portInp.value='8080'; portInp.placeholder='Port';
                portInp.style.cssText='width:70px;background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:3px;';

                var applyBtn = document.createElement('button');
                applyBtn.innerText = 'Apply';
                applyBtn.style.cssText = 'padding:5px 12px;background:#6a1b9a;color:#fff;border:none;border-radius:3px;cursor:pointer;font-weight:bold;';
                applyBtn.onclick = function() {
                    var s=schSel.value, h=hostInp.value.trim(), p=parseInt(portInp.value);
                    if(!h||!p){ resultDiv.innerText='Enter a valid host and port.'; return; }
                    resultDiv.style.color='#ffcc00';
                    resultDiv.innerText='⏳ Setting proxy to ' + s + '://' + h + ':' + p + '…';
                    sendCmd({action:'enable_custom_proxy', scheme:s, host:h, port:p}, showResult);
                };

                cRow.appendChild(schSel); cRow.appendChild(hostInp);
                cRow.appendChild(portInp); cRow.appendChild(applyBtn);
                customBox.appendChild(cRow);
                container.appendChild(customBox);
"""
