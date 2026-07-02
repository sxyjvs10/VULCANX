MAP_TAB_JS = r"""
container.innerHTML = '';

                function apiBase() { return 'http://127.0.0.1:' + (window.__vulcanx_api_port || 0); }
                var traffic = window.__vulcanx_state ? (window.__vulcanx_state.traffic || []) : [];

                // ══════════════════════════════════════════════════════════════
                // SPIDER CONTROL PANEL
                // ══════════════════════════════════════════════════════════════
                var spiderPanel = document.createElement('div');
                spiderPanel.style.cssText = 'background:#0d0d18;border:1px solid #7c4dff;border-radius:6px;padding:12px;margin-bottom:12px;';

                var spiderTitle = document.createElement('div');
                spiderTitle.style.cssText = 'color:#7c4dff;font-weight:bold;font-size:12px;margin-bottom:10px;';
                spiderTitle.innerHTML = '🕷️ Active Spider — Recursive Link Crawler';
                spiderPanel.appendChild(spiderTitle);

                // URL row
                var urlRow = document.createElement('div');
                urlRow.style.cssText = 'display:flex;gap:6px;margin-bottom:8px;';

                var urlInput = document.createElement('input');
                urlInput.type = 'text';
                urlInput.placeholder = 'Seed URL (leave blank to use current page)';
                urlInput.value = location.href;
                urlInput.style.cssText = 'flex:1;background:#111;color:#fff;border:1px solid #444;padding:6px 8px;border-radius:4px;font-size:11px;';
                urlRow.appendChild(urlInput);
                spiderPanel.appendChild(urlRow);

                // Settings row
                var settingsRow = document.createElement('div');
                settingsRow.style.cssText = 'display:flex;gap:8px;margin-bottom:10px;align-items:center;font-size:11px;';

                function labeledInput(labelText, defaultVal, type, width) {
                    var wrap = document.createElement('div');
                    wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
                    var lbl = document.createElement('label');
                    lbl.style.cssText = 'color:#888;font-size:9px;';
                    lbl.innerText = labelText;
                    var inp = document.createElement('input');
                    inp.type = type || 'number';
                    inp.value = defaultVal;
                    inp.style.cssText = 'width:' + (width||55) + 'px;background:#111;color:#ffcc00;border:1px solid #333;padding:4px;border-radius:3px;font-size:11px;text-align:center;';
                    wrap.appendChild(lbl);
                    wrap.appendChild(inp);
                    return {wrap, inp};
                }

                var {wrap: dWrap, inp: depthInp}   = labeledInput('Max Depth', 4);
                var {wrap: uWrap, inp: urlsInp}     = labeledInput('Max URLs', 400);
                var {wrap: tWrap, inp: threadsInp}  = labeledInput('Threads', 5);
                var {wrap: delWrap, inp: delayInp}  = labeledInput('Delay (s)', 0.3, 'number', 60);

                settingsRow.appendChild(dWrap);
                settingsRow.appendChild(uWrap);
                settingsRow.appendChild(tWrap);
                settingsRow.appendChild(delWrap);
                spiderPanel.appendChild(settingsRow);

                // Button row
                var btnRow = document.createElement('div');
                btnRow.style.cssText = 'display:flex;gap:8px;margin-bottom:10px;';

                var startBtn = document.createElement('button');
                startBtn.innerText = '▶ Start Spider';
                startBtn.style.cssText = 'flex:1;padding:8px;background:linear-gradient(135deg,#7c4dff,#3f00cc);color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px;';

                var stopBtn = document.createElement('button');
                stopBtn.innerText = '⏹ Stop';
                stopBtn.style.cssText = 'padding:8px 16px;background:#333;color:#fff;border:1px solid #555;border-radius:4px;cursor:pointer;font-size:12px;';
                stopBtn.disabled = true;

                btnRow.appendChild(startBtn);
                btnRow.appendChild(stopBtn);
                spiderPanel.appendChild(btnRow);

                // Progress bar
                var progressWrap = document.createElement('div');
                progressWrap.style.cssText = 'background:#111;border-radius:4px;height:8px;margin-bottom:8px;overflow:hidden;display:none;';
                var progressBar = document.createElement('div');
                progressBar.style.cssText = 'height:100%;background:linear-gradient(90deg,#7c4dff,#00ffcc);width:0%;transition:width 0.5s;border-radius:4px;';
                progressWrap.appendChild(progressBar);
                spiderPanel.appendChild(progressWrap);

                // Status line
                var spiderStatus = document.createElement('div');
                spiderStatus.style.cssText = 'font-size:10px;color:#aaa;font-family:monospace;min-height:16px;';
                spiderStatus.innerText = 'Spider idle. Click ▶ Start Spider to begin crawling.';
                spiderPanel.appendChild(spiderStatus);

                // Stats chips
                var statsRow = document.createElement('div');
                statsRow.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;';
                spiderPanel.appendChild(statsRow);

                function makeChip(id, label, color) {
                    var chip = document.createElement('div');
                    chip.style.cssText = 'background:#111;border:1px solid #333;border-radius:4px;padding:3px 8px;font-size:10px;';
                    chip.id = id;
                    chip.innerHTML = '<span style="color:' + color + ';font-weight:bold;" id="' + id + '_val">0</span> <span style="color:#555;">' + label + '</span>';
                    statsRow.appendChild(chip);
                    return chip;
                }
                makeChip('vx_sp_visited',  'Visited',  '#00ff55');
                makeChip('vx_sp_queued',   'Queued',   '#ffcc00');
                makeChip('vx_sp_total',    'Found',    '#7c4dff');
                makeChip('vx_sp_errors',   'Errors',   '#ff4444');

                container.appendChild(spiderPanel);

                // ── Spider poll loop ────────────────────────────────────────
                var _spiderPoll = null;

                function updateSpiderStats(stats) {
                    var v = stats.visited  || 0;
                    var q = stats.queued   || 0;
                    var t = stats.total_found || 0;
                    var e = stats.errors   || 0;

                    var vEl = document.getElementById('vx_sp_visited_val');
                    var qEl = document.getElementById('vx_sp_queued_val');
                    var tEl = document.getElementById('vx_sp_total_val');
                    var eEl = document.getElementById('vx_sp_errors_val');
                    if(vEl) vEl.innerText = v;
                    if(qEl) qEl.innerText = q;
                    if(tEl) tEl.innerText = t;
                    if(eEl) eEl.innerText = e;

                    var pct = t > 0 ? Math.min(100, Math.round(v / t * 100)) : 0;
                    progressBar.style.width = pct + '%';
                    progressWrap.style.display = 'block';

                    var cur = (stats.current_urls || []).join(', ');
                    if (cur.length > 80) cur = cur.substring(0, 77) + '…';

                    if (stats.running) {
                        spiderStatus.innerHTML = '<span style="color:#7c4dff;">🕷️ Crawling…</span>  ' +
                            'Visited <b style="color:#00ff55;">' + v + '</b> / Found <b style="color:#ffcc00;">' + t + '</b>' +
                            (cur ? '<br><span style="color:#555;">→ ' + cur + '</span>' : '');
                    } else {
                        spiderStatus.innerHTML = '<span style="color:#00ff55;">✅ Spider finished.</span>  ' +
                            'Visited <b>' + v + '</b> URLs, found <b>' + t + '</b> total, <b style="color:#ff4444;">' + e + '</b> errors.';
                        clearInterval(_spiderPoll);
                        startBtn.disabled = false;
                        stopBtn.disabled = true;
                    }
                }

                startBtn.onclick = async function() {
                    var url = urlInput.value.trim() || location.href;
                    var payload = {
                        action: 'start',
                        url: url,
                        max_depth: parseInt(depthInp.value) || 4,
                        max_urls:  parseInt(urlsInp.value)  || 400,
                        threads:   parseInt(threadsInp.value)||5,
                        delay:     parseFloat(delayInp.value)||0.4
                    };
                    startBtn.disabled = true;
                    stopBtn.disabled  = false;
                    progressWrap.style.display = 'block';
                    spiderStatus.innerHTML = '<span style="color:#ffcc00;">⏳ Starting spider…</span>';

                    try {
                        var r = await fetch(apiBase() + '/api/spider', {
                            method: 'POST',
                            body: JSON.stringify(payload),
                            headers: {'Content-Type': 'application/json'}
                        });
                        var d = await r.json();
                        if (d.status !== 'ok') {
                            spiderStatus.innerHTML = '<span style="color:#ff4444;">❌ ' + (d.error || 'Failed') + '</span>';
                            startBtn.disabled = false; stopBtn.disabled = true;
                            return;
                        }
                        // Poll status every 2 seconds
                        _spiderPoll = setInterval(async function() {
                            try {
                                var sr = await fetch(apiBase() + '/api/spider', {
                                    method: 'POST',
                                    body: JSON.stringify({action: 'status'}),
                                    headers: {'Content-Type': 'application/json'}
                                });
                                var sd = await sr.json();
                                if (sd.stats) updateSpiderStats(sd.stats);
                            } catch(e) {}
                        }, 2000);
                    } catch(e) {
                        spiderStatus.innerHTML = '<span style="color:#ff4444;">❌ ' + e + '</span>';
                        startBtn.disabled = false; stopBtn.disabled = true;
                    }
                };

                stopBtn.onclick = async function() {
                    clearInterval(_spiderPoll);
                    try {
                        await fetch(apiBase() + '/api/spider', {
                            method: 'POST',
                            body: JSON.stringify({action: 'stop'}),
                            headers: {'Content-Type': 'application/json'}
                        });
                    } catch(e) {}
                    spiderStatus.innerHTML = '<span style="color:#ffcc00;">🛑 Stopping spider…</span>';
                    stopBtn.disabled = true;
                    startBtn.disabled = false;
                };

                // ══════════════════════════════════════════════════════════════
                // LINKMAP TABLE
                // ══════════════════════════════════════════════════════════════
                var mapHeader = document.createElement('div');
                mapHeader.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;';
                var mapTitle = document.createElement('div');
                mapTitle.style.cssText = 'color:#ffcc00;font-weight:bold;font-size:12px;';
                mapTitle.innerText = '🗺 Linkmap';
                var mapBadge = document.createElement('span');
                mapBadge.style.cssText = 'background:#222;border:1px solid #444;color:#aaa;border-radius:10px;padding:2px 8px;font-size:10px;';
                mapBadge.innerText = traffic.length + ' URLs';
                mapHeader.appendChild(mapTitle);
                mapHeader.appendChild(mapBadge);
                container.appendChild(mapHeader);

                // Filter bar
                var filterRow = document.createElement('div');
                filterRow.style.cssText = 'display:flex;gap:6px;margin-bottom:8px;';

                var filterInput = document.createElement('input');
                filterInput.type = 'text';
                filterInput.placeholder = 'Filter URLs…';
                filterInput.style.cssText = 'flex:1;background:#111;color:#fff;border:1px solid #444;padding:5px 8px;border-radius:4px;font-size:11px;';

                var methodSel = document.createElement('select');
                ['ALL','GET','POST','SPIDER','DISCOVERED'].forEach(function(m){
                    var o = document.createElement('option'); o.value=m; o.text=m;
                    methodSel.appendChild(o);
                });
                methodSel.style.cssText = 'background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:4px;font-size:11px;';

                filterRow.appendChild(filterInput);
                filterRow.appendChild(methodSel);
                container.appendChild(filterRow);

                // Table
                var tableWrap = document.createElement('div');
                tableWrap.style.cssText = 'overflow-y:auto;max-height:280px;border:1px solid #222;border-radius:4px;';

                var table = document.createElement('table');
                table.style.cssText = 'width:100%;border-collapse:collapse;font-size:10px;';
                table.innerHTML = `<thead style="position:sticky;top:0;background:#12121e;z-index:1;">
                    <tr>
                      <th style="text-align:left;padding:5px;color:#666;width:60px;">Method</th>
                      <th style="text-align:left;padding:5px;color:#666;width:40px;">Code</th>
                      <th style="text-align:left;padding:5px;color:#666;width:30px;">Dep</th>
                      <th style="text-align:left;padding:5px;color:#666;">URL</th>
                    </tr>
                </thead>`;
                var tbody = document.createElement('tbody');

                function statusColor(c){ return c===0?'#555':c===-1?'#ff4444':c<300?'#00ff55':c<400?'#ffcc00':c<500?'#ff9900':'#ff4444'; }
                function methodColor(m){ return m==='POST'?'#ff9900':m==='PUT'?'#ff5500':m==='DELETE'?'#ff0055':m==='SPIDER'?'#00ccff':m==='DISCOVERED'?'#7c4dff':'#aaa'; }

                function renderTable(items) {
                    tbody.innerHTML = '';
                    items.forEach(function(e) {
                        var tr = document.createElement('tr');
                        tr.style.borderBottom = '1px solid #1a1a24';
                        tr.style.cursor = 'pointer';
                        tr.onmouseenter = function(){ tr.style.background='rgba(255,255,255,0.04)'; };
                        tr.onmouseleave = function(){ tr.style.background=''; };
                        tr.onclick = function(){ if(e.url) window.open(e.url,'_blank'); };

                        var tdM = document.createElement('td');
                        tdM.style.cssText = 'padding:4px 5px;font-weight:bold;color:' + methodColor(e.method) + ';';
                        tdM.innerText = e.method || 'GET';

                        var tdS = document.createElement('td');
                        tdS.style.cssText = 'padding:4px 5px;font-weight:bold;color:' + statusColor(e.status_code) + ';';
                        tdS.innerText = e.status_code > 0 ? e.status_code : (e.status_code===-1?'ERR':'—');

                        var tdD = document.createElement('td');
                        tdD.style.cssText = 'padding:4px 5px;color:#555;text-align:center;';
                        tdD.innerText = e.depth !== undefined ? e.depth : '—';

                        var tdU = document.createElement('td');
                        tdU.style.cssText = 'padding:4px 5px;word-break:break-all;color:#ccc;';
                        tdU.innerText = e.display_url || e.url || '';
                        tdU.title = e.url || '';

                        tr.appendChild(tdM); tr.appendChild(tdS); tr.appendChild(tdD); tr.appendChild(tdU);
                        tbody.appendChild(tr);
                    });
                    mapBadge.innerText = items.length + ' / ' + traffic.length + ' URLs';
                }

                function applyFilter() {
                    var q = filterInput.value.toLowerCase();
                    var m = methodSel.value;
                    renderTable(traffic.filter(function(e){
                        return (!q || (e.url||'').toLowerCase().includes(q)) &&
                               (m==='ALL' || (e.method||'GET')===m);
                    }));
                }
                filterInput.oninput = applyFilter;
                methodSel.onchange  = applyFilter;

                table.appendChild(tbody);
                tableWrap.appendChild(table);
                container.appendChild(tableWrap);
                renderTable(traffic);

                // Bottom stats
                var bStats = document.createElement('div');
                bStats.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;';
                var byMethod = {};
                traffic.forEach(function(e){ var m=e.method||'GET'; byMethod[m]=(byMethod[m]||0)+1; });
                Object.keys(byMethod).forEach(function(m){
                    var chip = document.createElement('div');
                    chip.style.cssText = 'background:#111;border:1px solid #333;border-radius:4px;padding:3px 8px;font-size:10px;';
                    chip.innerHTML = '<span style="color:' + methodColor(m) + ';font-weight:bold;">' + byMethod[m] + '</span> <span style="color:#555;">' + m + '</span>';
                    bStats.appendChild(chip);
                });
                container.appendChild(bStats);
"""
