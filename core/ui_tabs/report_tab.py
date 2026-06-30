REPORT_TAB_JS = r"""
container.innerHTML = '';

                var rptTitle = document.createElement('div');
                rptTitle.innerText = 'Engagement Report';
                rptTitle.style.fontWeight = 'bold';
                rptTitle.style.marginBottom = '10px';
                rptTitle.style.color = '#aa00ff';
                rptTitle.style.textAlign = 'center';
                container.appendChild(rptTitle);

                var findings = window.__vulcanx_state.findings || [];
                var counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
                findings.forEach(function(f) { var sev = (f.severity||'INFO').toUpperCase(); if (counts[sev] !== undefined) counts[sev]++; });

                var statsDiv = document.createElement('div');
                statsDiv.style.display = 'flex';
                statsDiv.style.gap = '6px';
                statsDiv.style.marginBottom = '12px';
                statsDiv.style.flexWrap = 'wrap';
                var sevColors = {CRITICAL:'#ff0055', HIGH:'#ff6600', MEDIUM:'#ffcc00', LOW:'#00aaff', INFO:'#888'};
                Object.keys(counts).forEach(function(sev) {
                    var pill = document.createElement('div');
                    pill.style.flex = '1';
                    pill.style.textAlign = 'center';
                    pill.style.padding = '6px 4px';
                    pill.style.background = '#1a1a24';
                    pill.style.border = '1px solid ' + (sevColors[sev]||'#333');
                    pill.style.borderRadius = '4px';
                    pill.style.fontSize = '10px';
                    pill.style.color = sevColors[sev]||'#888';
                    pill.innerHTML = '<strong>' + counts[sev] + '</strong><br>' + sev;
                    statsDiv.appendChild(pill);
                });
                container.appendChild(statsDiv);

                var sortedFindings = findings.slice().sort(function(a,b) {
                    var order = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
                    return (order[(a.severity||'INFO').toUpperCase()]||4) - (order[(b.severity||'INFO').toUpperCase()]||4);
                });
                var top5 = sortedFindings.slice(0, 5);
                if (top5.length === 0) {
                    var noFindingsDiv = document.createElement('div');
                    noFindingsDiv.innerText = 'No findings yet.';
                    noFindingsDiv.style.color = '#666';
                    noFindingsDiv.style.fontSize = '11px';
                    container.appendChild(noFindingsDiv);
                } else {
                    top5.forEach(function(f) {
                        var fItem = document.createElement('div');
                        fItem.style.marginBottom = '6px';
                        fItem.style.padding = '6px';
                        fItem.style.background = '#1a1a24';
                        fItem.style.borderLeft = '2px solid ' + (sevColors[(f.severity||'INFO').toUpperCase()] || '#888');
                        fItem.style.borderRadius = '0 4px 4px 0';
                        fItem.innerHTML = '<div style="font-weight:bold;color:' + (sevColors[(f.severity||'INFO').toUpperCase()]||'#888') + ';font-size:10px;">' + (f.severity||'INFO') + ' – ' + (f.type||'') + '</div><div style="color:#aaa;font-size:9px;word-break:break-all;">' + (f.url||'').slice(0,100) + '</div>';
                        container.appendChild(fItem);
                    });
                }

                var rptBtnRow = document.createElement('div');
                rptBtnRow.style.display = 'flex';
                rptBtnRow.style.gap = '6px';
                rptBtnRow.style.marginTop = '12px';
                rptBtnRow.style.flexWrap = 'wrap';

                var dlHtmlBtn = document.createElement('button');
                dlHtmlBtn.innerText = '\u2b07 HTML Report';
                dlHtmlBtn.style.flex = '1';
                dlHtmlBtn.style.background = '#004488';
                dlHtmlBtn.style.color = '#fff';
                dlHtmlBtn.style.border = '1px solid #0088ff';
                dlHtmlBtn.style.padding = '6px';
                dlHtmlBtn.style.borderRadius = '3px';
                dlHtmlBtn.style.cursor = 'pointer';
                dlHtmlBtn.style.fontSize = '10px';
                dlHtmlBtn.onclick = async function() {
                    try {
                        var resp = await fetch('/api/report');
                        if (resp.ok) {
                            var html = await resp.text();
                            var blob = new Blob([html], {type:'text/html'});
                            var a = document.createElement('a');
                            a.href = URL.createObjectURL(blob);
                            a.download = 'vulcanx_report.html';
                            a.click();
                        } else {
                            alert('Could not fetch /api/report');
                        }
                    } catch(e) {
                        alert('Error fetching report: ' + e.message);
                    }
                };
                rptBtnRow.appendChild(dlHtmlBtn);

                var dlJsonBtn = document.createElement('button');
                dlJsonBtn.innerText = '\u2b07 JSON';
                dlJsonBtn.style.flex = '1';
                dlJsonBtn.style.background = '#333';
                dlJsonBtn.style.color = '#fff';
                dlJsonBtn.style.border = '1px solid #555';
                dlJsonBtn.style.padding = '6px';
                dlJsonBtn.style.borderRadius = '3px';
                dlJsonBtn.style.cursor = 'pointer';
                dlJsonBtn.style.fontSize = '10px';
                dlJsonBtn.onclick = function() {
                    var data = {
                        findings: window.__vulcanx_state.findings,
                        traffic: window.__vulcanx_state.traffic,
                        domSinks: window.__vulcanx_state.domSinks,
                        scope: window.__vulcanx_state.scope,
                        generatedAt: new Date().toISOString()
                    };
                    var blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'vulcanx_report.json';
                    a.click();
                };
                rptBtnRow.appendChild(dlJsonBtn);

                var copySummaryBtn = document.createElement('button');
                copySummaryBtn.innerText = '\uD83D\uDCCB Copy Summary';
                copySummaryBtn.style.flex = '1';
                copySummaryBtn.style.background = '#440055';
                copySummaryBtn.style.color = '#fff';
                copySummaryBtn.style.border = '1px solid #aa00ff';
                copySummaryBtn.style.padding = '6px';
                copySummaryBtn.style.borderRadius = '3px';
                copySummaryBtn.style.cursor = 'pointer';
                copySummaryBtn.style.fontSize = '10px';
                copySummaryBtn.onclick = function() {
                    var lines = ['# VulcanX Engagement Summary', ''];
                    lines.push('**Generated:** ' + new Date().toISOString());
                    lines.push('**Target:** ' + window.location.hostname);
                    lines.push('');
                    lines.push('## Severity Breakdown');
                    Object.keys(counts).forEach(function(sev) {
                        lines.push('- **' + sev + ':** ' + (counts[sev]||0));
                    });
                    lines.push('');
                    lines.push('## Top Findings');
                    top5.forEach(function(f,i) {
                        lines.push((i+1) + '. [' + (f.severity||'INFO') + '] ' + (f.type||'') + ' \u2014 ' + (f.url||'').slice(0,80));
                    });
                    var notes = window.__vulcanx_state.engagementNotes || '';
                    if (notes.trim()) {
                        lines.push('');
                        lines.push('## Engagement Notes');
                        lines.push(notes);
                    }
                    navigator.clipboard.writeText(lines.join('\n')).then(function() {
                        copySummaryBtn.innerText = 'Copied!';
                        setTimeout(function() { copySummaryBtn.innerText = '\uD83D\uDCCB Copy Summary'; }, 2000);
                    });
                };
                rptBtnRow.appendChild(copySummaryBtn);
                container.appendChild(rptBtnRow);

                var notesLabel = document.createElement('div');
                notesLabel.innerText = 'Engagement Notes:';
                notesLabel.style.color = '#aaa';
                notesLabel.style.fontWeight = 'bold';
                notesLabel.style.fontSize = '11px';
                notesLabel.style.marginTop = '12px';
                notesLabel.style.marginBottom = '4px';
                container.appendChild(notesLabel);

                var notesArea = document.createElement('textarea');
                notesArea.style.width = '100%';
                notesArea.style.height = '80px';
                notesArea.style.background = '#111';
                notesArea.style.color = '#ccc';
                notesArea.style.border = '1px solid #333';
                notesArea.style.fontFamily = 'monospace';
                notesArea.style.fontSize = '11px';
                notesArea.style.padding = '6px';
                notesArea.style.borderRadius = '3px';
                notesArea.placeholder = 'Enter engagement notes, credentials found, key observations...';
                notesArea.value = window.__vulcanx_state.engagementNotes || '';
                notesArea.oninput = function() {
                    window.__vulcanx_state.engagementNotes = notesArea.value;
                };
                container.appendChild(notesArea);
"""
