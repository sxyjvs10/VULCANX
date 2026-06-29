"""
oauth_analyzer.py - OAuth/OIDC Security Analyzer for VulcanX
Detects common OAuth flow vulnerabilities: missing state param (CSRF),
open redirect in redirect_uri, token leakage in Referer headers, etc.
"""

import re
import json
import urllib.parse
import requests


class OAuthAnalyzer:
    """
    Analyses OAuth 2.0 / OIDC flows for common security misconfigurations
    including state-based CSRF, open redirect abuse, and token leakage.
    """

    # Patterns that indicate OAuth-related URLs
    _OAUTH_PATTERNS = [
        r'[?&]code=[^&\s]+',
        r'[?&]state=[^&\s]+',
        r'[?&]access_token=[^&\s]+',
        r'[?&]id_token=[^&\s]+',
        r'[?&]refresh_token=[^&\s]+',
        r'[?&]grant_type=[^&\s]+',
        r'/oauth2?/',
        r'/authorize\b',
        r'/token\b',
        r'/callback\b',
    ]

    # Dangling / open-redirect test values
    _EVIL_REDIRECT_URIS = [
        'https://evil.com',
        'https://attacker.com/callback',
        'http://127.0.0.1/callback',
        'https://evil.com%2f@legitimate.example.com',
        'javascript:alert(1)',
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _make_finding(self, title: str, severity: str, url: str,
                      description: str, evidence: str,
                      recommendation: str) -> dict:
        """Return a normalised finding dict."""
        return {
            'title': title,
            'severity': severity,
            'url': url,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'source': 'OAuthAnalyzer',
        }

    def _parse_url(self, raw_url: str) -> urllib.parse.ParseResult:
        """Safely parse a URL, returning an empty ParseResult on failure."""
        try:
            return urllib.parse.urlparse(raw_url)
        except Exception:
            return urllib.parse.urlparse('')

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def detect_oauth_flows(self, traffic_log: list[str]) -> list[dict]:
        """
        Scan a list of URLs/log lines for OAuth-related parameters.

        Args:
            traffic_log: List of URL strings or raw HTTP log lines.

        Returns:
            List of finding dicts describing detected OAuth flows.
        """
        findings = []
        seen_flows: dict[str, list[str]] = {}

        for entry in traffic_log:
            for pattern in self._OAUTH_PATTERNS:
                if re.search(pattern, entry, re.IGNORECASE):
                    parsed = self._parse_url(entry)
                    params = urllib.parse.parse_qs(parsed.query)
                    flow_type = 'unknown'
                    if 'code' in params:
                        flow_type = 'authorization_code'
                    elif 'access_token' in params:
                        flow_type = 'implicit'
                    elif 'grant_type' in params:
                        flow_type = params['grant_type'][0]

                    key = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                    seen_flows.setdefault(flow_type, []).append(key)

                    has_state = 'state' in params
                    findings.append(self._make_finding(
                        title=f'OAuth Flow Detected ({flow_type})',
                        severity='INFO',
                        url=entry[:300],
                        description=(
                            f'An OAuth {flow_type} flow was observed. '
                            f'State parameter {"present" if has_state else "MISSING"}.'
                        ),
                        evidence=f'Matched pattern: {pattern}\nParams: '
                                 f'{list(params.keys())}',
                        recommendation=(
                            'Verify the state parameter is present and validated. '
                            'Use PKCE for public clients.'
                        ),
                    ))
                    break  # one finding per entry

        return findings

    def check_state_csrf(self, flow: dict,
                         session: requests.Session) -> list[dict]:
        """
        Test whether the OAuth authorisation endpoint enforces the state param.

        Args:
            flow:    Dict with at least 'url' key pointing to the auth endpoint.
            session: An authenticated/configured requests.Session.

        Returns:
            List of finding dicts.
        """
        findings = []
        url = flow.get('url', '')
        if not url:
            return findings

        parsed = self._parse_url(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        # Test 1: Send request WITHOUT state
        params_no_state = {k: v for k, v in params.items() if k != 'state'}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(params_no_state))
        )
        try:
            resp = session.get(test_url, timeout=self.timeout,
                               allow_redirects=False, verify=False)
            if resp.status_code in (200, 302):
                findings.append(self._make_finding(
                    title='OAuth Missing State Parameter – CSRF Risk',
                    severity='HIGH',
                    url=test_url,
                    description=(
                        'The OAuth authorisation endpoint accepted a request '
                        'without a `state` parameter. This enables CSRF attacks '
                        'that can force account linkage or session fixation.'
                    ),
                    evidence=f'HTTP {resp.status_code} received without state param.',
                    recommendation=(
                        'Require and validate a cryptographically random `state` '
                        'parameter on every authorisation request.'
                    ),
                ))
        except Exception:
            pass

        # Test 2: Send with predictable/static state
        params_static_state = dict(params)
        params_static_state['state'] = 'abc123'
        test_url2 = urllib.parse.urlunparse(
            parsed._replace(
                query=urllib.parse.urlencode(params_static_state))
        )
        try:
            resp2 = session.get(test_url2, timeout=self.timeout,
                                allow_redirects=False, verify=False)
            if resp2.status_code in (200, 302):
                findings.append(self._make_finding(
                    title='OAuth Predictable State Parameter Accepted',
                    severity='MEDIUM',
                    url=test_url2,
                    description=(
                        'The server accepted a static, predictable `state` value '
                        '("abc123"). If state is not cryptographically random, '
                        'CSRF protection is ineffective.'
                    ),
                    evidence=f'HTTP {resp2.status_code} with state=abc123.',
                    recommendation=(
                        'Generate state values using a CSPRNG (e.g. secrets.token_urlsafe). '
                        'Bind state to the user session.'
                    ),
                ))
        except Exception:
            pass

        return findings

    def check_redirect_uri(self, url: str,
                           session: requests.Session) -> list[dict]:
        """
        Probe for open redirect vulnerabilities in the redirect_uri parameter.

        Args:
            url:     OAuth authorisation endpoint URL.
            session: Configured requests.Session.

        Returns:
            List of finding dicts.
        """
        findings = []
        parsed = self._parse_url(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        for evil_uri in self._EVIL_REDIRECT_URIS:
            test_params = dict(params)
            test_params['redirect_uri'] = evil_uri
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(test_params))
            )
            try:
                resp = session.get(test_url, timeout=self.timeout,
                                   allow_redirects=False, verify=False)
                location = resp.headers.get('Location', '')
                if resp.status_code in (301, 302, 303, 307, 308):
                    if 'evil.com' in location or 'attacker.com' in location:
                        findings.append(self._make_finding(
                            title='OAuth Open Redirect via redirect_uri',
                            severity='HIGH',
                            url=test_url,
                            description=(
                                'The OAuth server redirected to an attacker-controlled '
                                'domain supplied as redirect_uri, enabling token theft.'
                            ),
                            evidence=f'redirect_uri={evil_uri}\n'
                                     f'Location header: {location}',
                            recommendation=(
                                'Whitelist allowed redirect_uri values server-side. '
                                'Never perform open redirects based on untrusted input.'
                            ),
                        ))
            except Exception:
                continue

        return findings

    def check_token_leakage(self, traffic_log: list[str]) -> list[dict]:
        """
        Search HTTP log lines for OAuth tokens exposed in Referer headers
        or other unsafe locations.

        Args:
            traffic_log: List of raw HTTP log strings (e.g. from a proxy log).

        Returns:
            List of finding dicts.
        """
        findings = []

        token_patterns = [
            (r'access_token=([A-Za-z0-9\-_.~+/]{20,})', 'access_token'),
            (r'id_token=([A-Za-z0-9\-_.~+/]{20,})', 'id_token'),
            (r'code=([A-Za-z0-9\-_.~+/]{10,})', 'authorization_code'),
            (r'refresh_token=([A-Za-z0-9\-_.~+/]{20,})', 'refresh_token'),
            (r'ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*',
             'JWT'),
        ]

        for entry in traffic_log:
            is_referer_line = re.search(r'referer\s*:', entry,
                                        re.IGNORECASE) is not None
            for pattern, token_type in token_patterns:
                match = re.search(pattern, entry, re.IGNORECASE)
                if match:
                    severity = 'HIGH' if is_referer_line else 'MEDIUM'
                    findings.append(self._make_finding(
                        title=f'OAuth Token Leakage in '
                              f'{"Referer Header" if is_referer_line else "Log/URL"}',
                        severity=severity,
                        url=entry[:300],
                        description=(
                            f'An OAuth {token_type} was found '
                            f'{"in the Referer header" if is_referer_line else "in traffic logs"}. '
                            'This can expose credentials to third-party servers.'
                        ),
                        evidence=f'Matched token type: {token_type}\n'
                                 f'Fragment: ...{match.group(0)[:60]}...',
                        recommendation=(
                            'Never send tokens in URL query strings. '
                            'Use the Authorization header. '
                            'Set Referrer-Policy: no-referrer on sensitive pages.'
                        ),
                    ))
                    break  # one finding per log entry

        return findings
