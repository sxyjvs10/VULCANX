STORAGE_TAB_JS = r"""
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
                
                // Cookies (Frontend + Backend)
                var cookieMap = {};
                try {
                    if (document.cookie) {
                        document.cookie.split(';').forEach(c => {
                            var parts = c.split('=');
                            var key = parts[0] ? parts[0].trim() : '';
                            var val = parts.slice(1).join('=');
                            if (key) {
                                cookieMap[key] = { source: 'Cookie', key: key, value: val };
                            }
                        });
                    }
                } catch(e) {
                    items.push({source: 'Cookie', key: 'Error', value: 'Frontend access denied: ' + e.message});
                }
                
                // Merge HttpOnly cookies from backend
                if (window.__vulcanx_state && window.__vulcanx_state.backendCookies) {
                    window.__vulcanx_state.backendCookies.forEach(c => {
                        var sourceLabel = c.httpOnly ? 'Cookie (HttpOnly)' : 'Cookie';
                        cookieMap[c.name] = { source: sourceLabel, key: c.name, value: c.value };
                    });
                }
                
                Object.values(cookieMap).forEach(c => items.push(c));
                
                // LocalStorage
                try {
                    if (window.localStorage) {
                        for (var i = 0; i < localStorage.length; i++) {
                            var k = localStorage.key(i);
                            items.push({
                                source: 'Local',
                                key: k,
                                value: localStorage.getItem(k)
                            });
                        }
                    }
                } catch(e) {
                    items.push({source: 'Local', key: 'Error', value: 'Access denied: ' + e.message});
                }

                // SessionStorage
                try {
                    if (window.sessionStorage) {
                        for (var i = 0; i < sessionStorage.length; i++) {
                            var k = sessionStorage.key(i);
                            items.push({
                                source: 'Session',
                                key: k,
                                value: sessionStorage.getItem(k)
                            });
                        }
                    }
                } catch(e) {
                    items.push({source: 'Session', key: 'Error', value: 'Access denied: ' + e.message});
                }
                
                if (items.length === 0) {
                    var noStorage = document.createElement('div');
                    noStorage.style.color = '#666';
                    noStorage.style.textAlign = 'center';
                    noStorage.style.marginTop = '20px';
                    noStorage.innerText = 'No storage items found.';
                    container.appendChild(noStorage);
                } else {
                    var table = document.createElement('table');
                    table.className = 'vx-table';
                    table.innerHTML = `<thead>
                                        <tr>
                                            <th style="width:60px;">Source</th>
                                            <th style="width:120px;">Key</th>
                                            <th>Value</th>
                                        </tr>
                                       </thead><tbody></tbody>`;
                    var tbody = table.querySelector('tbody');
                    items.forEach(function(item) {
                        var tr = document.createElement('tr');
                        tr.innerHTML = `<td><span class="vx-badge" style="background:#333;">${item.source}</span></td>
                                        <td style="font-weight:bold;color:#ccc;">${item.key}</td>
                                        <td style="color:#aaa;">${item.value}</td>`;
                        tbody.appendChild(tr);
                    });
                    container.appendChild(table);
                }
"""
