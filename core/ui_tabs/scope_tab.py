SCOPE_TAB_JS = r"""
container.innerHTML = '';

                var scopeTitle = document.createElement('div');
                scopeTitle.innerText = 'Scope Manager';
                scopeTitle.style.fontWeight = 'bold';
                scopeTitle.style.marginBottom = '10px';
                scopeTitle.style.color = '#ffcc00';
                scopeTitle.style.textAlign = 'center';
                container.appendChild(scopeTitle);

                var scopeInfo = document.createElement('div');
                scopeInfo.innerText = 'Add hostnames or URL patterns to restrict scanning scope. One entry per line.';
                scopeInfo.style.color = '#888';
                scopeInfo.style.fontSize = '10px';
                scopeInfo.style.marginBottom = '10px';
                container.appendChild(scopeInfo);

                var scopeArea = document.createElement('textarea');
                scopeArea.style.width = '100%';
                scopeArea.style.height = '200px';
                scopeArea.style.background = '#111';
                scopeArea.style.color = '#ffcc00';
                scopeArea.style.border = '1px solid #333';
                scopeArea.style.fontFamily = 'monospace';
                scopeArea.style.fontSize = '11px';
                scopeArea.style.padding = '8px';
                scopeArea.style.borderRadius = '4px';
                scopeArea.placeholder = 'example.com\napi.example.com\n*.example.com';
                scopeArea.value = (window.__vulcanx_state.scope || []).join('\n');
                container.appendChild(scopeArea);

                var scopeSaveBtn = document.createElement('button');
                scopeSaveBtn.innerText = 'Save Scope';
                scopeSaveBtn.style.marginTop = '10px';
                scopeSaveBtn.style.width = '100%';
                scopeSaveBtn.style.padding = '10px';
                scopeSaveBtn.style.background = '#004488';
                scopeSaveBtn.style.color = '#fff';
                scopeSaveBtn.style.border = 'none';
                scopeSaveBtn.style.cursor = 'pointer';
                scopeSaveBtn.style.borderRadius = '4px';
                scopeSaveBtn.style.fontWeight = 'bold';
                scopeSaveBtn.onclick = function() {
                    var lines = scopeArea.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
                    window.__vulcanx_state.scope = lines;
                    var tst = document.createElement('div');
                    tst.style.position = 'fixed';
                    tst.style.bottom = '20px';
                    tst.style.right = '20px';
                    tst.style.background = 'rgba(0,68,136,0.9)';
                    tst.style.color = '#fff';
                    tst.style.padding = '10px 16px';
                    tst.style.borderRadius = '6px';
                    tst.style.zIndex = '999999';
                    tst.style.fontSize = '12px';
                    tst.innerText = 'Scope saved! (' + lines.length + ' entries)';
                    document.body.appendChild(tst);
                    setTimeout(function() { tst.style.opacity = '0'; setTimeout(function() { tst.remove(); }, 500); }, 3000);
                };
                container.appendChild(scopeSaveBtn);
"""
