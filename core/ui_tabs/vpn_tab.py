VPN_TAB_JS = r"""
container.innerHTML = '';
                
                var title = document.createElement('h3');
                title.innerText = 'Tor Proxy Manager';
                title.style.color = '#ffcc00';
                title.style.borderBottom = '1px solid #333';
                title.style.paddingBottom = '8px';
                container.appendChild(title);
                
                var info = document.createElement('div');
                info.style.color = '#aaa';
                info.style.marginBottom = '15px';
                info.style.fontSize = '11px';
                info.innerText = 'Route all browser traffic through local Tor proxy to bypass blocks.';
                container.appendChild(info);
                
                var resultDiv = document.createElement('div');
                resultDiv.style.background = '#111';
                resultDiv.style.border = '1px solid #333';
                resultDiv.style.padding = '10px';
                resultDiv.style.fontFamily = 'monospace';
                resultDiv.style.whiteSpace = 'pre-wrap';
                resultDiv.style.display = 'none';
                
                resultDiv.style.display = 'block';
                resultDiv.style.marginTop = '10px';
                
                var torBtn = document.createElement('button');
                torBtn.innerText = 'Enable Tor Proxy (SOCKS5 127.0.0.1:9050)';
                torBtn.style.padding = '8px';
                torBtn.style.background = '#4CAF50';
                torBtn.style.color = '#fff';
                torBtn.style.border = 'none';
                torBtn.style.cursor = 'pointer';
                torBtn.style.borderRadius = '4px';
                torBtn.onclick = function() {
                    resultDiv.innerText = 'Routing traffic through Tor...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'enable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Success!\n\nTor proxy enabled.`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                var checkIpBtn = document.createElement('button');
                checkIpBtn.innerText = 'Check Current IP';
                checkIpBtn.style.padding = '8px';
                checkIpBtn.style.background = '#2196F3';
                checkIpBtn.style.color = '#fff';
                checkIpBtn.style.border = 'none';
                checkIpBtn.style.cursor = 'pointer';
                checkIpBtn.style.borderRadius = '4px';
                checkIpBtn.style.marginLeft = '10px';
                checkIpBtn.onclick = function() {
                    resultDiv.innerText = 'Checking IP address...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'check_ip'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Current IP: ${data.ip}`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                var disableTorBtn = document.createElement('button');
                disableTorBtn.innerText = 'Disable Tor Proxy';
                disableTorBtn.style.padding = '8px';
                disableTorBtn.style.marginTop = '10px';
                disableTorBtn.style.background = '#f44336';
                disableTorBtn.style.color = '#fff';
                disableTorBtn.style.border = 'none';
                disableTorBtn.style.cursor = 'pointer';
                disableTorBtn.style.borderRadius = '4px';
                disableTorBtn.style.marginLeft = '10px';
                disableTorBtn.onclick = function() {
                    resultDiv.innerText = 'Disabling Tor proxy...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'disable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Success!\n\nTor proxy disabled.`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                container.appendChild(torBtn);
                container.appendChild(disableTorBtn);
                container.appendChild(checkIpBtn);
                container.appendChild(resultDiv);
"""
