DOM_TAB_JS = r"""
container.innerHTML = '';

                var domTitle = document.createElement('div');
                domTitle.innerText = 'DOM Sink Monitor';
                domTitle.style.fontWeight = 'bold';
                domTitle.style.marginBottom = '10px';
                domTitle.style.color = '#ff0055';
                domTitle.style.textAlign = 'center';
                container.appendChild(domTitle);

                var domSinks = window.__vulcanx_state.domSinks || [];
                if (domSinks.length === 0) {
                    var noSinks = document.createElement('div');
                    noSinks.innerText = 'No DOM sinks triggered yet. Browse the app to collect data.';
                    noSinks.style.color = '#666';
                    noSinks.style.fontSize = '11px';
                    noSinks.style.textAlign = 'center';
                    noSinks.style.marginTop = '20px';
                    container.appendChild(noSinks);
                } else {
                    domSinks.forEach(function(sink) {
                        var sinkDiv = document.createElement('div');
                        sinkDiv.style.marginBottom = '8px';
                        sinkDiv.style.padding = '8px';
                        sinkDiv.style.background = '#1a0a0a';
                        sinkDiv.style.border = '1px solid #660000';
                        sinkDiv.style.borderRadius = '4px';
                        sinkDiv.style.fontFamily = 'monospace';
                        sinkDiv.style.fontSize = '10px';
                        sinkDiv.style.color = '#ff6666';
                        sinkDiv.style.wordBreak = 'break-all';
                        sinkDiv.innerText = '[' + (sink.sink||'unknown') + '] ' + (sink.value||'').slice(0, 200);
                        container.appendChild(sinkDiv);
                    });
                }

                var clearDomBtn = document.createElement('button');
                clearDomBtn.type = 'button';
                clearDomBtn.innerText = '🗑️ Clear DOM Sinks';
                clearDomBtn.style.marginTop = '10px';
                clearDomBtn.style.width = '100%';
                clearDomBtn.style.padding = '8px';
                clearDomBtn.style.background = '#440000';
                clearDomBtn.style.color = '#fff';
                clearDomBtn.style.border = 'none';
                clearDomBtn.style.cursor = 'pointer';
                clearDomBtn.style.borderRadius = '4px';
                clearDomBtn.onclick = function() {
                    window.__vulcanx_cmd = '{"action": "clear_dom_sinks"}';
                    window.__vulcanx_state.domSinks = [];
                    window.__vulcanx_render();
                };
                container.appendChild(clearDomBtn);
"""
