MAP_TAB_JS = r"""
container.innerHTML = '';
                
                var scanBtn = document.createElement('button');
                scanBtn.innerText = 'Scan LinkMap';
                scanBtn.style.width = '100%';
                scanBtn.style.padding = '8px';
                scanBtn.style.background = '#800000';
                scanBtn.style.color = '#fff';
                scanBtn.style.border = '1px solid #ff0055';
                scanBtn.style.borderRadius = '4px';
                scanBtn.style.cursor = 'pointer';
                scanBtn.style.fontWeight = 'bold';
                scanBtn.style.marginBottom = '12px';
                
                var statusDiv = document.createElement('div');
                statusDiv.style.marginBottom = '12px';
                statusDiv.style.fontSize = '10px';
                statusDiv.style.color = '#aaa';
                statusDiv.innerText = "Status: Ready";
                
                var linksList = document.createElement('ul');
                linksList.style.listStyleType = 'none';
                linksList.style.padding = '0';
                linksList.style.margin = '0';
                
                var links = Array.from(document.querySelectorAll('a[href]')).map(a => {
                    // Browsers usually resolve a.href to a full URL, but just in case:
                    try { return new URL(a.getAttribute('href'), window.location.href).href; }
                    catch(e) { return a.href; }
                });
                var internalLinks = links.filter(href => href.startsWith(window.location.origin) && !href.includes('#') && !href.startsWith('javascript:'));
                var uniqueLinks = [...new Set(internalLinks)];
                
                scanBtn.onclick = async function() {
                    if (uniqueLinks.length === 0) {
                        alert("No internal links found to scan.");
                        return;
                    }
                    scanBtn.disabled = true;
                        scanBtn.style.opacity = '0.5';
                        statusDiv.innerText = `Scanning: 0 / ${uniqueLinks.length}`;
                        
                        let completed = 0;
                        for (let i = 0; i < uniqueLinks.length; i++) {
                            let link = uniqueLinks[i];
                            let li = linksList.children[i];
                            try {
                                li.style.color = '#ffcc00'; // in progress
                                
                                // Open link in a new background tab
                                var newWin = window.open(link, '_blank');
                                
                                // Wait for it to load, then close it
                                await new Promise(r => setTimeout(r, 2500)); 
                                if (newWin && !newWin.closed) {
                                    newWin.close();
                                }
                                
                                li.style.color = '#00ff55'; // done
                            } catch(e) {
                                li.style.color = '#ff0055'; // error
                            }
                            completed++;
                            statusDiv.innerText = `Scanning: ${completed} / ${uniqueLinks.length}`;
                        }
                        
                        statusDiv.innerText = 'Scan Complete! Check Traffic and Findings tabs.';
                        setTimeout(() => {
                            scanBtn.disabled = false;
                            scanBtn.style.opacity = '1';
                        }, 2000);
                };
                
                container.appendChild(scanBtn);
                container.appendChild(statusDiv);
                
                uniqueLinks.forEach(link => {
                    var li = document.createElement('li');
                    li.style.padding = '4px 0';
                    li.style.borderBottom = '1px solid #333';
                    li.style.fontSize = '10px';
                    li.style.wordBreak = 'break-all';
                    li.style.color = '#aaa';
                    li.innerText = link.replace(window.location.origin, '');
                    linksList.appendChild(li);
                });
                
                if (uniqueLinks.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.innerText = 'No internal links found on this page.';
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '20px';
                    container.appendChild(emptyDiv);
                } else {
                    container.appendChild(linksList);
                }


                if (items.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '20px';
                    emptyDiv.innerText = 'No cookies or storage keys found.';
                    container.appendChild(emptyDiv);
                    return;
                }

                var fillAllXSS = document.createElement('button');
                fillAllXSS.innerText = 'Fill All XSS';
                fillAllXSS.style.width = '30%';
                fillAllXSS.style.padding = '8px';
                fillAllXSS.style.background = '#440055';
                fillAllXSS.style.color = '#fff';
                fillAllXSS.style.border = '1px solid #ff00ff';
                fillAllXSS.style.borderRadius = '4px';
                fillAllXSS.style.cursor = 'pointer';
                fillAllXSS.style.fontWeight = 'bold';
                fillAllXSS.style.marginBottom = '12px';
                fillAllXSS.style.marginRight = '2%';
                fillAllXSS.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, '\"><script>alert(document.domain)</script>'); } else { input.value = '\"><script>alert(document.domain)</script>'; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '2px solid #ff00ff';
                    });
                };
                container.appendChild(fillAllXSS);
                
                var fillAllSQLi = document.createElement('button');
                fillAllSQLi.innerText = 'Fill All SQLi';
                fillAllSQLi.style.width = '30%';
                fillAllSQLi.style.padding = '8px';
                fillAllSQLi.style.background = '#331100';
                fillAllSQLi.style.color = '#fff';
                fillAllSQLi.style.border = '1px solid #ff5500';
                fillAllSQLi.style.borderRadius = '4px';
                fillAllSQLi.style.cursor = 'pointer';
                fillAllSQLi.style.fontWeight = 'bold';
                fillAllSQLi.style.marginBottom = '12px';
                fillAllSQLi.style.marginRight = '2%';
                fillAllSQLi.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, "admin' --"); } else { input.value = "admin' --"; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '2px solid #ff5500';
                    });
                };
                container.appendChild(fillAllSQLi);
                
                var tamperDOM = document.createElement('button');
                tamperDOM.innerText = 'Tamper DOM (Reveal All)';
                tamperDOM.style.width = '100%';
                tamperDOM.style.padding = '8px';
                tamperDOM.style.background = '#004400';
                tamperDOM.style.color = '#00ff55';
                tamperDOM.style.border = '1px solid #00ff55';
                tamperDOM.style.borderRadius = '4px';
                tamperDOM.style.cursor = 'pointer';
                tamperDOM.style.fontWeight = 'bold';
                tamperDOM.style.marginBottom = '12px';
                tamperDOM.onclick = function() {
                    // Reveal hidden inputs, convert passwords to text, remove maxlengths and disabled attributes
                    var modifiedCount = 0;
                    document.querySelectorAll('input, select, textarea, button').forEach(el => {
                        if (el.type === 'hidden') {
                            el.type = 'text';
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.type === 'password') {
                            el.type = 'text';
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('disabled')) {
                            el.removeAttribute('disabled');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('readonly')) {
                            el.removeAttribute('readonly');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                        if (el.hasAttribute('maxlength')) {
                            el.removeAttribute('maxlength');
                            el.style.border = '2px solid #00ff55';
                            modifiedCount++;
                        }
                    });
                    if (modifiedCount > 0) {
                        alert("DOM Tampering Active! " + modifiedCount + " elements modified (revealed hidden fields, removed disabled/readonly/maxlength attributes).");
                    } else {
                        alert("No restricted DOM elements found to tamper with.");
                    }
                };
                container.appendChild(tamperDOM);

                var clearAll = document.createElement('button');
                clearAll.innerText = 'Clear Forms';
                clearAll.style.width = '30%';
                clearAll.style.padding = '8px';
                clearAll.style.background = '#222';
                clearAll.style.color = '#fff';
                clearAll.style.border = '1px solid #444';
                clearAll.style.borderRadius = '4px';
                clearAll.style.cursor = 'pointer';
                clearAll.style.fontWeight = 'bold';
                clearAll.style.marginBottom = '12px';
                clearAll.onclick = function() {
                    inputs.forEach(input => {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, ""); } else { input.value = ""; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.style.border = '';
                    });
                };
                container.appendChild(clearAll);


                var table = document.createElement('table');
                table.className = 'vx-table';
                table.innerHTML = `<thead>
                                    <tr>
                                        <th>Source</th>
                                        <th>Key</th>
                                        <th>Value</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                
                var sensitiveKeys = /token|session|secret|jwt|password|key|admin|auth|role/i;
                items.forEach(item => {
                    var tr = document.createElement('tr');
                    var isSensitive = sensitiveKeys.test(item.key) || sensitiveKeys.test(item.value);
                    if (isSensitive) {
                        tr.style.background = 'rgba(255, 0, 85, 0.15)';
                    }
                    tr.innerHTML = `<td style="color:#00ff55;font-weight:bold;">${item.source}</td>
                                    <td style="color:#ffcc00;font-weight:bold;">${item.key}</td>
                                    <td style="color:#aaa;word-break:break-all;">${item.value}</td>`;
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);
"""
