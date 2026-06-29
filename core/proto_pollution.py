"""
proto_pollution.py - Prototype Pollution Scanner for VulcanX
Tests URL parameters, JSON body payloads, and query strings for
JavaScript prototype pollution vulnerabilities.
"""

import re
import json
import urllib.parse
import requests


class PrototypePollutionScanner:
    """
    Detects Prototype Pollution vulnerabilities by injecting __proto__,
    constructor.prototype, and related payloads into URL parameters,
    JSON request bodies, and query strings.
    """

    # Canonical probe key used to detect pollution reflection
    _PROBE_KEY = 'vulcanx_pp_test'
    _PROBE_VAL = 'vulcanx_pp_value_9z2x'

    # URL param injection variants
    _URL_PARAM_PAYLOADS = [
        {f'__proto__[{_PROBE_KEY}]': _PROBE_VAL},
        {f'constructor[prototype][{_PROBE_KEY}]': _PROBE_VAL},
        {f'__proto__.{_PROBE_KEY}': _PROBE_VAL},
        {f'Object.prototype.{_PROBE_KEY}': _PROBE_VAL},
    ]

    # Query-string-specific combos
    _QS_PAYLOADS = [
        f'__proto__[admin]=1&constructor[prototype][admin]=1',
        f'__proto__[isAdmin]=true&__proto__[role]=admin',
        f'constructor[prototype][isAdmin]=true',
        f'__proto__[{_PROBE_KEY}]={_PROBE_VAL}',
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
            'source': 'PrototypePollutionScanner',
        }

    def _probe_value_reflected(self, response_text: str) -> bool:
        """Return True if our probe value appears in the response."""
        return self._PROBE_VAL in response_text

    def _get_baseline(self, url: str,
                      session: requests.Session) -> str | None:
        """Fetch a baseline response body for comparison."""
        try:
            resp = session.get(url, timeout=self.timeout, verify=False)
            return resp.text
        except Exception:
            return None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def scan_url_params(self, url: str,
                        session: requests.Session) -> list[dict]:
        """
        Inject __proto__ and constructor.prototype payloads into existing
        URL parameters to test for prototype pollution reflection.

        Args:
            url:     Target URL (may already contain query params).
            session: Configured requests.Session.

        Returns:
            List of finding dicts.
        """
        findings = []
        parsed = urllib.parse.urlparse(url)
        existing_params = dict(urllib.parse.parse_qsl(parsed.query))
        baseline = self._get_baseline(url, session)

        for payload_dict in self._URL_PARAM_PAYLOADS:
            merged = dict(existing_params)
            merged.update(payload_dict)
            test_qs = urllib.parse.urlencode(merged)
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=test_qs)
            )
            try:
                resp = session.get(test_url, timeout=self.timeout,
                                   verify=False)
                body = resp.text
            except Exception:
                continue

            reflected = self._probe_value_reflected(body)
            # Also flag if behaviour changes significantly
            behaviour_change = (
                baseline is not None
                and abs(len(body) - len(baseline)) > 200
            )

            if reflected or behaviour_change:
                param_key = list(payload_dict.keys())[0]
                findings.append(self._make_finding(
                    title='Prototype Pollution via URL Parameter',
                    severity='HIGH',
                    url=test_url,
                    description=(
                        f'Injecting `{param_key}` into URL parameters caused '
                        f'{"probe value reflection" if reflected else "an anomalous response change"}, '
                        'suggesting a prototype pollution vulnerability.'
                    ),
                    evidence=(
                        f'Payload key: {param_key}\n'
                        f'Probe reflected: {reflected}\n'
                        f'Response length diff: '
                        f'{abs(len(body) - len(baseline)) if baseline else "N/A"}\n'
                        f'Response snippet: {body[:300]}'
                    ),
                    recommendation=(
                        'Sanitise all user-supplied property names server-side. '
                        'Use Object.create(null) for lookup tables or libraries '
                        'such as lodash ≥4.17.21 that patch this issue.'
                    ),
                ))

        return findings

    def scan_json_body(self, url: str, session: requests.Session,
                       base_body: dict) -> list[dict]:
        """
        Inject __proto__ keys into a JSON request body to test for
        server-side or client-reflected prototype pollution.

        Args:
            url:       Target endpoint URL.
            session:   Configured requests.Session.
            base_body: Dict representing a valid baseline JSON body.

        Returns:
            List of finding dicts.
        """
        findings = []

        payloads = [
            {**base_body,
             '__proto__': {self._PROBE_KEY: self._PROBE_VAL}},
            {**base_body,
             'constructor': {'prototype': {self._PROBE_KEY: self._PROBE_VAL}}},
            {**base_body,
             '__proto__': {'admin': True, 'role': 'admin',
                           self._PROBE_KEY: self._PROBE_VAL}},
        ]

        headers = {'Content-Type': 'application/json'}
        for payload in payloads:
            try:
                resp = session.post(url, json=payload, headers=headers,
                                    timeout=self.timeout, verify=False)
                body = resp.text
            except Exception:
                continue

            reflected = self._probe_value_reflected(body)
            if reflected or resp.status_code == 500:
                proto_key = (
                    '__proto__' if '__proto__' in payload
                    else 'constructor.prototype'
                )
                findings.append(self._make_finding(
                    title='Prototype Pollution via JSON Body',
                    severity='HIGH',
                    url=url,
                    description=(
                        f'Injecting `{proto_key}` into the JSON request body '
                        f'{"reflected the probe value" if reflected else "caused a 500 error"}, '
                        'suggesting server-side prototype pollution.'
                    ),
                    evidence=(
                        f'Payload key: {proto_key}\n'
                        f'Probe reflected: {reflected}\n'
                        f'HTTP status: {resp.status_code}\n'
                        f'Response snippet: {body[:300]}'
                    ),
                    recommendation=(
                        'Validate and reject any JSON keys named __proto__, '
                        'constructor, or prototype. '
                        'Use a JSON schema validator that strips dangerous keys.'
                    ),
                ))

        return findings

    def scan_query_string(self, url: str,
                          session: requests.Session) -> list[dict]:
        """
        Append prototype pollution payloads directly to the query string
        using known dangerous patterns like ?__proto__[admin]=1.

        Args:
            url:     Target URL.
            session: Configured requests.Session.

        Returns:
            List of finding dicts.
        """
        findings = []
        parsed = urllib.parse.urlparse(url)
        base_qs = parsed.query

        for qs_payload in self._QS_PAYLOADS:
            separator = '&' if base_qs else ''
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=base_qs + separator + qs_payload)
            )
            try:
                resp = session.get(test_url, timeout=self.timeout,
                                   verify=False)
                body = resp.text
            except Exception:
                continue

            reflected = self._probe_value_reflected(body)
            # Also flag admin=1/isAdmin=true appearing in response
            priv_esc_indicators = any(
                indicator in body.lower()
                for indicator in ('"isadmin":true', '"admin":true',
                                   '"role":"admin"', '"is_admin":true')
            )

            if reflected or priv_esc_indicators:
                findings.append(self._make_finding(
                    title='Prototype Pollution via Query String',
                    severity='CRITICAL' if priv_esc_indicators else 'HIGH',
                    url=test_url,
                    description=(
                        'Appending prototype pollution parameters to the query '
                        'string caused '
                        + ('privilege escalation indicators' if priv_esc_indicators
                           else 'probe value reflection')
                        + ' in the response.'
                    ),
                    evidence=(
                        f'Query string payload: {qs_payload}\n'
                        f'Probe reflected: {reflected}\n'
                        f'Priv-esc indicator: {priv_esc_indicators}\n'
                        f'Response snippet: {body[:300]}'
                    ),
                    recommendation=(
                        'Block or strip __proto__, constructor.prototype, and '
                        'related keys in all query parsers. '
                        'Apply Content Security Policy and validate server state.'
                    ),
                ))

        return findings
