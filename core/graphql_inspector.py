"""
graphql_inspector.py - GraphQL Security Inspector for VulcanX
Detects GraphQL endpoints, runs introspection, fuzzes arguments,
checks for IDOR, and tests batch attack vectors.
"""

import re
import json
import requests


INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
          defaultValue
        }
        type {
          name
          kind
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type { name kind }
      }
      enumValues(includeDeprecated: true) {
        name
      }
    }
    directives {
      name
      locations
    }
  }
}
"""


class GraphQLInspector:
    """
    Inspects GraphQL endpoints for security misconfigurations,
    information disclosure via introspection, IDOR vulnerabilities,
    and batch query abuse.
    """

    COMMON_PATHS = [
        '/graphql',
        '/api/graphql',
        '/v1/graphql',
        '/graphiql',
        '/api/v1/graphql',
        '/graph',
        '/query',
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
            'source': 'GraphQLInspector',
        }

    def _post_graphql(self, url: str, session: requests.Session,
                      payload: dict) -> requests.Response | None:
        """POST a GraphQL payload to *url*, return response or None."""
        try:
            headers = {'Content-Type': 'application/json'}
            resp = session.post(url, json=payload, headers=headers,
                                timeout=self.timeout, verify=False)
            return resp
        except Exception:
            return None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def detect(self, url: str, session: requests.Session) -> list[dict]:
        """
        Probe common GraphQL paths to discover active endpoints.

        Args:
            url:     Base URL (e.g. https://example.com)
            session: An authenticated requests.Session object.

        Returns:
            List of finding dicts for every discovered endpoint.
        """
        findings = []
        base = url.rstrip('/')
        for path in self.COMMON_PATHS:
            target = base + path
            try:
                resp = session.get(target, timeout=self.timeout, verify=False)
                body = resp.text.lower()
                if resp.status_code in (200, 400, 405) and (
                        'graphql' in body or '"data"' in body
                        or '"errors"' in body or 'schema' in body):
                    findings.append(self._make_finding(
                        title='GraphQL Endpoint Discovered',
                        severity='INFO',
                        url=target,
                        description=f'A GraphQL endpoint was found at {target}.',
                        evidence=f'HTTP {resp.status_code} – body snippet: '
                                 f'{resp.text[:200]}',
                        recommendation=(
                            'Ensure the endpoint requires authentication '
                            'and that introspection is disabled in production.'
                        ),
                    ))
            except Exception:
                continue
        return findings

    def run_introspection(self, url: str,
                          session: requests.Session) -> tuple[dict | None,
                                                              list[dict]]:
        """
        Send a full introspection query.  Returns (schema_dict, findings).

        If introspection succeeds a finding is raised because introspection
        should typically be disabled in production.
        """
        findings = []
        resp = self._post_graphql(url, session,
                                  {'query': INTROSPECTION_QUERY})
        if resp is None:
            return None, findings

        try:
            data = resp.json()
        except Exception:
            return None, findings

        if 'data' in data and data['data']:
            schema = data['data']
            findings.append(self._make_finding(
                title='GraphQL Introspection Enabled',
                severity='MEDIUM',
                url=url,
                description=(
                    'The GraphQL endpoint allows full schema introspection. '
                    'Attackers can enumerate all types, fields, and mutations.'
                ),
                evidence=f'Introspection returned schema with '
                         f'{len(schema.get("__schema", {}).get("types", []))} '
                         f'types.',
                recommendation=(
                    'Disable introspection in production or restrict it to '
                    'authenticated administrators only.'
                ),
            ))
            return schema, findings

        # Introspection blocked – check for error message
        if 'errors' in data:
            findings.append(self._make_finding(
                title='GraphQL Introspection Blocked',
                severity='INFO',
                url=url,
                description='The server rejected introspection (good practice).',
                evidence=str(data['errors'])[:300],
                recommendation='No action needed – introspection is already blocked.',
            ))
        return None, findings

    def fuzz_arguments(self, url: str, session: requests.Session,
                       schema: dict, payloads: list[str]) -> list[dict]:
        """
        Inject *payloads* into every String argument discovered in *schema*.

        Args:
            url:      GraphQL endpoint URL.
            session:  Authenticated session.
            schema:   Schema dict returned by run_introspection.
            payloads: List of injection strings (XSS, SQLi, etc.)

        Returns:
            List of finding dicts.
        """
        findings = []
        if not schema:
            return findings

        types = schema.get('__schema', {}).get('types', [])
        for gql_type in types:
            if gql_type.get('kind') not in ('OBJECT', 'INPUT_OBJECT'):
                continue
            fields = gql_type.get('fields') or gql_type.get('inputFields') or []
            for field in fields:
                for arg in (field.get('args') or []):
                    arg_type = (arg.get('type') or {}).get('name', '')
                    if arg_type not in ('String', 'ID', None, ''):
                        continue
                    for payload in payloads:
                        query = (
                            f'{{ {field["name"]}({arg["name"]}: '
                            f'{json.dumps(payload)}) }}'
                        )
                        resp = self._post_graphql(
                            url, session, {'query': query})
                        if resp is None:
                            continue
                        try:
                            body = resp.text
                        except Exception:
                            continue
                        # Reflection check
                        if payload in body:
                            findings.append(self._make_finding(
                                title='GraphQL Argument Reflection (Potential Injection)',
                                severity='HIGH',
                                url=url,
                                description=(
                                    f'Payload reflected in response for field '
                                    f'`{field["name"]}`, argument `{arg["name"]}`.'
                                ),
                                evidence=f'Payload: {payload}\n'
                                         f'Response snippet: {body[:300]}',
                                recommendation=(
                                    'Validate and sanitise all GraphQL input. '
                                    'Use parameterised resolvers.'
                                ),
                            ))
        return findings

    def detect_idor(self, url: str, session: requests.Session,
                    schema: dict) -> list[dict]:
        """
        Probe integer ID arguments with values 1-10 looking for IDOR.

        Returns:
            List of finding dicts.
        """
        findings = []
        if not schema:
            return findings

        types = schema.get('__schema', {}).get('types', [])
        probed = set()
        for gql_type in types:
            fields = gql_type.get('fields') or []
            for field in fields:
                for arg in (field.get('args') or []):
                    arg_type_info = arg.get('type') or {}
                    arg_type_name = arg_type_info.get('name', '') or ''
                    if arg['name'].lower() not in ('id', 'user_id', 'userid',
                                                   'account_id', 'record_id'):
                        if 'Int' not in arg_type_name and 'ID' not in arg_type_name:
                            continue
                    key = (field['name'], arg['name'])
                    if key in probed:
                        continue
                    probed.add(key)
                    successes = []
                    for id_val in range(1, 11):
                        query = (
                            f'{{ {field["name"]}({arg["name"]}: {id_val}) '
                            f'{{ id }} }}'
                        )
                        resp = self._post_graphql(
                            url, session, {'query': query})
                        if resp is None:
                            continue
                        try:
                            data = resp.json()
                        except Exception:
                            continue
                        if 'data' in data and data['data']:
                            successes.append(id_val)
                    if len(successes) > 1:
                        findings.append(self._make_finding(
                            title='GraphQL IDOR – Unrestricted ID Enumeration',
                            severity='HIGH',
                            url=url,
                            description=(
                                f'Field `{field["name"]}` with argument '
                                f'`{arg["name"]}` returns data for multiple '
                                f'sequential IDs without access control.'
                            ),
                            evidence=f'Accessible IDs: {successes}',
                            recommendation=(
                                'Implement object-level authorisation. '
                                'Verify that the authenticated user owns the '
                                'requested resource before returning data.'
                            ),
                        ))
        return findings

    def check_batch_attack(self, url: str,
                           session: requests.Session) -> list[dict]:
        """
        Send 50 identical queries as a JSON array (batch) to test for
        rate-limit bypass via GraphQL batching.

        Returns:
            List of finding dicts.
        """
        findings = []
        batch = [{'query': '{ __typename }'}] * 50
        try:
            headers = {'Content-Type': 'application/json'}
            resp = session.post(url, json=batch, headers=headers,
                                timeout=self.timeout, verify=False)
        except Exception:
            return findings

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                return findings
            if isinstance(data, list) and len(data) >= 10:
                findings.append(self._make_finding(
                    title='GraphQL Batch Query Abuse Possible',
                    severity='MEDIUM',
                    url=url,
                    description=(
                        'The server processed a batch of 50 identical GraphQL '
                        'queries in a single HTTP request, enabling potential '
                        'brute-force or rate-limit bypass attacks.'
                    ),
                    evidence=f'Batch returned {len(data)} results.',
                    recommendation=(
                        'Implement query depth/complexity limits and restrict '
                        'batch size to a sensible maximum (e.g. 10).'
                    ),
                ))
        elif resp.status_code == 400:
            # Batching rejected – good
            pass
        return findings
