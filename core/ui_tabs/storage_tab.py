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
