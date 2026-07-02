MAP_TAB_JS = r"""
container.innerHTML = '';

                function sendCmd(cmd) {
                    // Command bus: writes to window.__vulcanx_cmd, Python reads+executes it
                    window.__vulcanx_cmd = cmd;
                    window.__vulcanx_cmd_result = null;
                }

                var traffic = window.__vulcanx_state ? (window.__vulcanx_state.traffic || []) : [];

                // ══════════════════════════════════════════════════════════════
                // SPIDER CONTROL PANEL
                // ══════════════════════════════════════════════════════════════
                var spiderPanel = document.createElement('div');
                spiderPanel.style.cssText = 'background:#0d0d18;border:1px solid #7c4dff;border-radius:6px;padding:12px;margin-bottom:12px;';

                var spiderTitle = document.createElement('div');
                spiderTitle.style.cssText = 'color:#7c4dff;font-weight:bold;font-size:12px;margin-bottom:10px;';
                spiderTitle.innerHTML = '🕷️ Active Spider — Recursive Crawler';
                spiderPanel.appendChild(spiderTitle);

                // URL input
                var urlRow = document.createElement('div');
                urlRow.style.cssText = 'display:flex;gap:6px;margin-bottom:8px;';
                var urlInput = document.createElement('input');
                urlInput.type = 'text';
                urlInput.placeholder = 'Seed URL (leave blank = current page)';
                urlInput.value = location.href.split('#')[0];
                urlInput.style.cssText = 'flex:1;background:#111;color:#fff;border:1px solid #444;padding:6px 8px;border-radius:4px;font-size:11px;';
                urlRow.appendChild(urlInput);
                spiderPanel.appendChild(urlRow);

                // Settings
                var settingsRow = document.createElement('div');
                settingsRow.style.cssText = 'display:flex;gap:8px;margin-bottom:10px;';

                function numField(label, val, w) {
                    var wrap = document.createElement('div');
                    wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
                    var lbl = document.createElement('label');
                    lbl.style.cssText = 'color:#666;font-size:9px;';
                    lbl.innerText = label;
                    var inp = document.createElement('input');
                    inp.type = 'number'; inp.value = val;
                    inp.style.cssText = 'width:' + (w||55) + 'px;background:#111;color:#ffcc00;border:1px solid #333;padding:4px;border-radius:3px;font-size:11px;text-align:center;';
                    wrap.appendChild(lbl); wrap.appendChild(inp);
                    return {wrap, inp};
                }
                var {wrap: dW, inp: depthInp}  = numField('Depth', 4);
                var {wrap: uW, inp: urlsInp}   = numField('Max URLs', 400, 65);
                var {wrap: tW, inp: thrdInp}   = numField('Threads', 5);
                var {wrap: dlW, inp: delayInp} = numField('Delay(s)', 0.3, 60);
                settingsRow.appendChild(dW); settingsRow.appendChild(uW);
                settingsRow.appendChild(tW); settingsRow.appendChild(dlW);
                spiderPanel.appendChild(settingsRow);

                // Buttons
                var btnRow = document.createElement('div');
                btnRow.style.cssText = 'display:flex;gap:8px;margin-bottom:10px;';

                var startBtn = document.createElement('button');
                startBtn.innerText = '▶ Start Spider';
                startBtn.style.cssText = 'flex:1;padding:8px;background:linear-gradient(135deg,#7c4dff,#3f00cc);color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px;';

                var stopBtn = document.createElement('button');
                stopBtn.innerText = '⏹ Stop';
                stopBtn.disabled = true;
                stopBtn.style.cssText = 'padding:8px 16px;background:#333;color:#aaa;border:1px solid #555;border-radius:4px;cursor:pointer;font-size:12px;';

                btnRow.appendChild(startBtn); btnRow.appendChild(stopBtn);
                spiderPanel.appendChild(btnRow);

                // Progress bar
                var pWrap = document.createElement('div');
                pWrap.style.cssText = 'background:#111;border-radius:4px;height:8px;margin-bottom:8px;overflow:hidden;';
                var pBar = document.createElement('div');
                pBar.style.cssText = 'height:100%;background:linear-gradient(90deg,#7c4dff,#00ffcc);width:0%;transition:width 0.8s;border-radius:4px;';
                pWrap.appendChild(pBar);
                spiderPanel.appendChild(pWrap);

                // Status
                var spiderStatus = document.createElement('div');
                spiderStatus.style.cssText = 'font-size:10px;color:#888;font-family:monospace;min-height:16px;';
                spiderStatus.innerText = 'Spider idle — click ▶ Start Spider to begin recursive crawl.';
                spiderPanel.appendChild(spiderStatus);

                // Stats chips
                var statsRow = document.createElement('div');
                statsRow.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;';

                function statChip(id, label, color) {
                    var c = document.createElement('div');
                    c.style.cssText = 'background:#111;border:1px solid #2a2a3a;border-radius:4px;padding:3px 8px;font-size:10px;';
                    c.innerHTML = '<b id="' + id + '" style="color:' + color + '">0</b> <span style="color:#555">' + label + '</span>';
                    statsRow.appendChild(c);
                }
                statChip('vx_sp_v', 'Visited',  '#00ff55');
                statChip('vx_sp_q', 'Queued',   '#ffcc00');
                statChip('vx_sp_t', 'Found',    '#7c4dff');
                statChip('vx_sp_e', 'Errors',   '#ff4444');
                spiderPanel.appendChild(statsRow);

                container.appendChild(spiderPanel);

                // ── Spider stat updater (reads from window.__vulcanx_state) ─
                function refreshSpiderStats() {
                    var st = (window.__vulcanx_state && window.__vulcanx_state.spider_stats) || {};
                    var v = st.visited || 0, q = st.queued || 0,
                        t = st.total_found || 0, e = st.errors || 0;
                    var vE=document.getElementById('vx_sp_v'),
                        qE=document.getElementById('vx_sp_q'),
                        tE=document.getElementById('vx_sp_t'),
                        eE=document.getElementById('vx_sp_e');
                    if(vE) vE.innerText=v;
                    if(qE) qE.innerText=q;
                    if(tE) tE.innerText=t;
                    if(eE) eE.innerText=e;

                    var pct = t>0 ? Math.min(100, Math.round(v/t*100)) : 0;
                    pBar.style.width = pct + '%';

                    if (st.running) {
                        spiderStatus.innerHTML = '<span style="color:#7c4dff">🕷️ Crawling…</span> ' +
                            'Visited <b style="color:#00ff55">' + v + '</b> / Found <b style="color:#ffcc00">' + t + '</b>';
                    } else if (v > 0) {
                        spiderStatus.innerHTML = '<span style="color:#00ff55">✅ Done.</span> Visited <b>' + v +
                            '</b> URLs · <b style="color:#7c4dff">' + t + '</b> found · <b style="color:#ff4444">' + e + '</b> errors';
                        stopBtn.disabled = true;
                        startBtn.disabled = false;
                        startBtn.style.opacity = '1';
                    }
                }
                // Poll spider stats every 1.5s from the injected state
                var _spSt = setInterval(refreshSpiderStats, 1500);

                // ── Button handlers ─────────────────────────────────────────
                startBtn.onclick = function() {
                    var url = urlInput.value.trim() || location.href;
                    startBtn.disabled = true;
                    startBtn.style.opacity = '0.6';
                    stopBtn.disabled = false;
                    spiderStatus.innerHTML = '<span style="color:#ffcc00">⏳ Starting spider from ' + url + ' …</span>';
                    sendCmd({
                        action:    'spider_start',
                        url:       url,
                        max_depth: parseInt(depthInp.value) || 4,
                        max_urls:  parseInt(urlsInp.value)  || 400,
                        threads:   parseInt(thrdInp.value)  || 5,
                        delay:     parseFloat(delayInp.value) || 0.4
                    });
                };

                stopBtn.onclick = function() {
                    sendCmd({action: 'spider_stop'});
                    spiderStatus.innerHTML = '<span style="color:#ff9900">🛑 Stop requested…</span>';
                    stopBtn.disabled = true;
                    startBtn.disabled = false;
                    startBtn.style.opacity = '1';
                    clearInterval(_spSt);
                };

                // ══════════════════════════════════════════════════════════════
                // LINKMAP TABLE
                // ══════════════════════════════════════════════════════════════
                var mapHdr = document.createElement('div');
                mapHdr.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;';

                var mapTitle = document.createElement('div');
                mapTitle.style.cssText = 'color:#ffcc00;font-weight:bold;font-size:12px;';
                mapTitle.innerText = '🗺 Linkmap';

                var mapBadge = document.createElement('span');
                mapBadge.id = 'vx_map_badge';
                mapBadge.style.cssText = 'background:#222;border:1px solid #444;color:#aaa;border-radius:10px;padding:2px 8px;font-size:10px;';
                mapBadge.innerText = traffic.length + ' URLs';

                mapHdr.appendChild(mapTitle); mapHdr.appendChild(mapBadge);
                container.appendChild(mapHdr);

                // Filter bar
                var fRow = document.createElement('div');
                fRow.style.cssText = 'display:flex;gap:6px;margin-bottom:8px;';

                var fInp = document.createElement('input');
                fInp.type = 'text'; fInp.placeholder = 'Filter URLs…';
                fInp.style.cssText = 'flex:1;background:#111;color:#fff;border:1px solid #444;padding:5px 8px;border-radius:4px;font-size:11px;';

                var mSel = document.createElement('select');
                ['ALL','GET','POST','SPIDER','DISCOVERED'].forEach(function(m){
                    var o=document.createElement('option'); o.value=m; o.text=m; mSel.appendChild(o);
                });
                mSel.style.cssText = 'background:#111;color:#fff;border:1px solid #444;padding:5px;border-radius:4px;font-size:11px;';

                fRow.appendChild(fInp); fRow.appendChild(mSel);
                container.appendChild(fRow);

                // Table
                var tWrap = document.createElement('div');
                tWrap.style.cssText = 'overflow-y:auto;max-height:280px;border:1px solid #1a1a24;border-radius:4px;';
                var tbl = document.createElement('table');
                tbl.style.cssText = 'width:100%;border-collapse:collapse;font-size:10px;';
                tbl.innerHTML = `<thead style="position:sticky;top:0;background:#12121e;z-index:1;">
                  <tr>
                    <th style="text-align:left;padding:5px 4px;color:#555;width:70px;">Method</th>
                    <th style="text-align:left;padding:5px 4px;color:#555;width:42px;">Code</th>
                    <th style="text-align:left;padding:5px 4px;color:#555;width:30px;">Dep</th>
                    <th style="text-align:left;padding:5px 4px;color:#555;">URL</th>
                  </tr></thead>`;
                var tb = document.createElement('tbody');

                function sColor(c){ return c===0?'#444':c===-1?'#ff4444':c<300?'#00ff55':c<400?'#ffcc00':c<500?'#ff9900':'#ff4444'; }
                function mColor(m){ return m==='POST'?'#ff9900':m==='PUT'?'#ff5500':m==='DELETE'?'#ff0055':m==='SPIDER'?'#00ccff':m==='DISCOVERED'?'#7c4dff':'#888'; }

                function renderRows(rows) {
                    tb.innerHTML = '';
                    rows.forEach(function(e){
                        var tr = document.createElement('tr');
                        tr.style.borderBottom = '1px solid #13131d';
                        tr.style.cursor = 'pointer';
                        tr.onmouseenter = function(){ tr.style.background='rgba(255,255,255,0.04)'; };
                        tr.onmouseleave = function(){ tr.style.background=''; };
                        tr.onclick = function(){ if(e.url) window.open(e.url,'_blank'); };

                        var cells = [
                            {text: e.method||'GET',  color: mColor(e.method), css:'padding:4px;font-weight:bold;'},
                            {text: e.status_code>0?e.status_code:(e.status_code===-1?'ERR':'—'), color: sColor(e.status_code), css:'padding:4px;font-weight:bold;'},
                            {text: e.depth!==undefined?e.depth:'—', color:'#444', css:'padding:4px;text-align:center;'},
                            {text: e.display_url||e.url||'', color:'#bbb', css:'padding:4px;word-break:break-all;'}
                        ];
                        cells.forEach(function(cd){
                            var td = document.createElement('td');
                            td.style.cssText = cd.css + 'color:' + cd.color;
                            td.innerText = cd.text;
                            tr.appendChild(td);
                        });
                        tb.appendChild(tr);
                    });
                    document.getElementById('vx_map_badge').innerText = rows.length + ' / ' + traffic.length + ' URLs';
                }

                function applyFilter(){
                    var q = fInp.value.toLowerCase(), m = mSel.value;
                    renderRows(traffic.filter(function(e){
                        return (!q||(e.url||'').toLowerCase().includes(q))&&(m==='ALL'||(e.method||'GET')===m);
                    }));
                }
                fInp.oninput = applyFilter; mSel.onchange = applyFilter;
                tbl.appendChild(tb); tWrap.appendChild(tbl); container.appendChild(tWrap);
                renderRows(traffic);

                // Bottom stat chips
                var bStats = document.createElement('div');
                bStats.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;';
                var byM = {};
                traffic.forEach(function(e){ var m=e.method||'GET'; byM[m]=(byM[m]||0)+1; });
                Object.keys(byM).forEach(function(m){
                    var c=document.createElement('div');
                    c.style.cssText='background:#111;border:1px solid #222;border-radius:4px;padding:3px 8px;font-size:10px;';
                    c.innerHTML='<b style="color:'+mColor(m)+'">'+byM[m]+'</b> <span style="color:#444">'+m+'</span>';
                    bStats.appendChild(c);
                });
                container.appendChild(bStats);
"""
