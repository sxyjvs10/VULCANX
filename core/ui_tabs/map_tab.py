MAP_TAB_JS = r"""
container.innerHTML = '';

                // ── Header ─────────────────────────────────────────────────────
                var hdr = document.createElement('div');
                hdr.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;';

                var title = document.createElement('div');
                title.innerText = '🗺 Site Linkmap';
                title.style.cssText = 'font-weight:bold;color:#ffcc00;font-size:13px;';
                hdr.appendChild(title);

                var traffic = window.__vulcanx_state ? (window.__vulcanx_state.traffic || []) : [];

                var badge = document.createElement('span');
                badge.style.cssText = 'background:#222;border:1px solid #444;color:#aaa;border-radius:10px;padding:2px 8px;font-size:10px;';
                badge.innerText = traffic.length + ' URLs total';
                hdr.appendChild(badge);
                container.appendChild(hdr);

                // ── Filter bar ──────────────────────────────────────────────────
                var filterRow = document.createElement('div');
                filterRow.style.cssText = 'display:flex;gap:6px;margin-bottom:10px;align-items:center;';

                var filterInput = document.createElement('input');
                filterInput.type = 'text';
                filterInput.placeholder = 'Filter URLs…';
                filterInput.style.cssText = 'flex:1;background:#111;color:#fff;border:1px solid #444;padding:5px 8px;border-radius:4px;font-size:11px;';

                var methodFilter = document.createElement('select');
                ['ALL','GET','POST','DISCOVERED'].forEach(function(m) {
                    var o = document.createElement('option');
                    o.value = m; o.text = m;
                    methodFilter.appendChild(o);
                });
                methodFilter.style.cssText = 'background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:4px;font-size:11px;';

                var scanAllBtn = document.createElement('button');
                scanAllBtn.innerText = '⚡ Scan All';
                scanAllBtn.title = 'Open every discovered URL in a background tab to trigger VulcanX analysis';
                scanAllBtn.style.cssText = 'padding:5px 10px;background:#800000;color:#fff;border:1px solid #ff0055;border-radius:4px;cursor:pointer;font-size:11px;font-weight:bold;white-space:nowrap;';

                filterRow.appendChild(filterInput);
                filterRow.appendChild(methodFilter);
                filterRow.appendChild(scanAllBtn);
                container.appendChild(filterRow);

                // ── Status bar ──────────────────────────────────────────────────
                var statusBar = document.createElement('div');
                statusBar.style.cssText = 'font-size:10px;color:#888;margin-bottom:8px;';
                statusBar.innerText = 'Showing all intercepted + discovered URLs. DISCOVERED = crawled by VulcanX (not manually browsed).';
                container.appendChild(statusBar);

                // ── Table ───────────────────────────────────────────────────────
                var tableWrapper = document.createElement('div');
                tableWrapper.style.cssText = 'overflow-y:auto;max-height:340px;';

                var table = document.createElement('table');
                table.style.cssText = 'width:100%;border-collapse:collapse;font-size:10px;';
                table.innerHTML = `<thead style="position:sticky;top:0;background:#151520;z-index:1;">
                    <tr>
                        <th style="text-align:left;padding:5px;color:#aaa;border-bottom:1px solid #333;width:70px;">Method</th>
                        <th style="text-align:left;padding:5px;color:#aaa;border-bottom:1px solid #333;width:45px;">Status</th>
                        <th style="text-align:left;padding:5px;color:#aaa;border-bottom:1px solid #333;">URL</th>
                    </tr>
                </thead>`;
                var tbody = document.createElement('tbody');

                function statusColor(code) {
                    if (code === 0)   return '#888';
                    if (code === -1)  return '#ff4444';
                    if (code < 300)   return '#00ff55';
                    if (code < 400)   return '#ffcc00';
                    if (code < 500)   return '#ff9900';
                    return '#ff4444';
                }

                function methodColor(m) {
                    if (m === 'POST')       return '#ff9900';
                    if (m === 'PUT')        return '#ff5500';
                    if (m === 'DELETE')     return '#ff0055';
                    if (m === 'DISCOVERED') return '#7c4dff';
                    return '#00ccff';
                }

                function renderRows(items) {
                    tbody.innerHTML = '';
                    var shown = 0;
                    items.forEach(function(entry) {
                        var tr = document.createElement('tr');
                        tr.style.borderBottom = '1px solid #1a1a24';
                        tr.style.cursor = 'pointer';
                        tr.onmouseenter = function() { tr.style.background = 'rgba(255,255,255,0.04)'; };
                        tr.onmouseleave = function() { tr.style.background = ''; };

                        var tdM = document.createElement('td');
                        tdM.style.cssText = 'padding:4px 5px;font-weight:bold;';
                        tdM.style.color = methodColor(entry.method);
                        tdM.innerText = entry.method || 'GET';

                        var tdS = document.createElement('td');
                        tdS.style.cssText = 'padding:4px 5px;font-weight:bold;';
                        tdS.style.color = statusColor(entry.status_code);
                        tdS.innerText = entry.status_code > 0 ? entry.status_code : (entry.status_code === -1 ? 'ERR' : '…');

                        var tdU = document.createElement('td');
                        tdU.style.cssText = 'padding:4px 5px;word-break:break-all;color:#ccc;';
                        var dispUrl = entry.display_url || entry.url || '';
                        tdU.innerText = dispUrl;
                        tdU.title = entry.url || '';

                        // Click → open in new tab
                        tr.onclick = function() {
                            if (entry.url) window.open(entry.url, '_blank');
                        };

                        tr.appendChild(tdM);
                        tr.appendChild(tdS);
                        tr.appendChild(tdU);
                        tbody.appendChild(tr);
                        shown++;
                    });
                    badge.innerText = shown + ' / ' + traffic.length + ' URLs';
                }

                function applyFilter() {
                    var q = filterInput.value.toLowerCase();
                    var m = methodFilter.value;
                    var filtered = traffic.filter(function(e) {
                        var urlMatch = !q || (e.url || '').toLowerCase().includes(q);
                        var methodMatch = m === 'ALL' || (e.method || 'GET') === m;
                        return urlMatch && methodMatch;
                    });
                    renderRows(filtered);
                }

                filterInput.oninput = applyFilter;
                methodFilter.onchange = applyFilter;

                // ── Scan-All button ─────────────────────────────────────────────
                scanAllBtn.onclick = async function() {
                    var toScan = traffic.filter(function(e) {
                        return e.method === 'DISCOVERED' || e.method === 'GET';
                    });
                    if (toScan.length === 0) {
                        statusBar.innerText = 'No URLs to scan. Browse the app first!';
                        return;
                    }
                    scanAllBtn.disabled = true;
                    scanAllBtn.style.opacity = '0.5';
                    for (var i = 0; i < toScan.length; i++) {
                        var entry = toScan[i];
                        statusBar.innerText = 'Opening: ' + (entry.display_url || entry.url) + ' (' + (i+1) + '/' + toScan.length + ')';
                        var w = window.open(entry.url, '_blank');
                        await new Promise(function(r) { setTimeout(r, 2000); });
                        if (w && !w.closed) w.close();
                    }
                    statusBar.innerText = 'Scan complete! Check the Findings and Traffic tabs.';
                    scanAllBtn.disabled = false;
                    scanAllBtn.style.opacity = '1';
                };

                // Initial render
                table.appendChild(tbody);
                tableWrapper.appendChild(table);
                container.appendChild(tableWrapper);
                renderRows(traffic);

                // ── Stats panel ─────────────────────────────────────────────────
                var stats = document.createElement('div');
                stats.style.cssText = 'margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;';

                var disc = traffic.filter(function(e){return e.method==='DISCOVERED';}).length;
                var post = traffic.filter(function(e){return e.method==='POST';}).length;
                var err  = traffic.filter(function(e){return e.status_code >= 400;}).length;

                [{label:'Total', val: traffic.length,  color:'#00ccff'},
                 {label:'Discovered', val: disc,         color:'#7c4dff'},
                 {label:'POST', val: post,               color:'#ff9900'},
                 {label:'Errors 4xx/5xx', val: err,      color:'#ff4444'}
                ].forEach(function(s) {
                    var chip = document.createElement('div');
                    chip.style.cssText = 'background:#111;border:1px solid #333;border-radius:4px;padding:4px 10px;font-size:10px;';
                    chip.innerHTML = '<span style="color:' + s.color + ';font-weight:bold;">' + s.val + '</span> <span style="color:#666;">' + s.label + '</span>';
                    stats.appendChild(chip);
                });
                container.appendChild(stats);
"""
