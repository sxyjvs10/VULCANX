"""
core/correlate.py â€” Vulnerability suggestion / correlation engine.

Consumes the SAME finding dicts produced by core.engine.Analyzer.scan()
and core.live_browser.LiveBrowserInterceptor (the existing 'type' strings
like DOM_XSS_STATIC_TAINT, JWT_TOKEN, KNOWN_VULNERABILITY, etc.). No new
finding schema, no separate fact taxonomy you have to maintain in parallel
with engine.py's `self.patterns` dict.

Design constraints driven by how live_browser.py actually runs:
- _monitor_loop() calls this once per NEW finding, synchronously, in the
  same thread that's polling driver.requests every 1s. So CorrelationEngine
  must be cheap per-call (O(facts on same url), not O(all facts ever seen))
  and must never raise (a bug in a rule must not kill the monitor loop,
  same fault-isolation guarantee Analyzer.scan() doesn't currently have
  for individual regex patterns, but matters more here since rules run
  on a hot path during live browsing).
- 'confidence' on existing findings is a string like '90%' or 'N/A' (see
  engine.py L154-260), not a float. Rules need a numeric value to do
  weakest-link math, so normalize once at ingestion (`_norm_confidence`)
  rather than re-parsing inside every rule.
- Same finding can arrive twice if the user revisits a page (selenium-wire
  re-fires). `live_findings` in live_browser.py already dedupes by exact
  dict equality; we additionally dedupe by (url, type, match) so a
  hypothesis doesn't get a confidence boost purely from a re-render.

USAGE (see core/live_browser.py for the actual wiring):

    from core.correlate import CorrelationEngine
    corr = CorrelationEngine()
    ...
    for f in new_findings:
        new_hypotheses = corr.ingest(f)   # returns only NEWLY surfaced/changed hypotheses
        for h in new_hypotheses:
            self._inject_suggestion_alert(h)   # render into HUD, see live_browser.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("vulcanx.correlate")


# ---------------------------------------------------------------------------
# Confidence normalization
# ---------------------------------------------------------------------------

def _norm_confidence(raw) -> float:
    """
    engine.py findings carry confidence as '90%', '60%', or 'N/A' (string).
    Some live_browser.py-generated findings (MISSING_SECURITY_HEADER, and
    the new CORS/cookie checks below) carry no confidence key at all.
    Normalize all of it to a 0.0-1.0 float so rule math is uniform.
    """
    if raw is None:
        return 0.75  # no stated confidence -> assume moderate, not blind trust
    if isinstance(raw, (int, float)):
        return max(0.0, min(1.0, float(raw)))
    s = str(raw).strip()
    if s.upper() == "N/A":
        return 0.7  # pattern fired with no explicit confidence annotation in engine.py
    if s.endswith("%"):
        try:
            return max(0.0, min(1.0, float(s[:-1]) / 100.0))
        except ValueError:
            return 0.7
    try:
        return max(0.0, min(1.0, float(s)))
    except ValueError:
        return 0.7


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Fact = a normalized view of one finding dict, kept alongside the original
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Fact:
    type: str               # the existing finding['type'] string, untouched
    url: str
    severity: str
    confidence: float       # normalized 0-1
    match: str = ""
    context: str = ""
    source: str = ""        # 'STATIC' | 'NETWORK' | 'PAYLOAD_CONFIRMED' | ...
    raw: dict = field(default_factory=dict, compare=False)

    @property
    def dedupe_key(self):
        return (self.url, self.type, self.match)


def fact_from_finding(finding: dict) -> Fact:
    return Fact(
        type=finding.get("type", "UNKNOWN"),
        url=finding.get("url", ""),
        severity=finding.get("severity", "INFO"),
        confidence=_norm_confidence(finding.get("confidence")),
        match=finding.get("match", "") or "",
        context=finding.get("context", "") or "",
        source=finding.get("source", "STATIC") or "STATIC",
        raw=finding,
    )


# ---------------------------------------------------------------------------
# Hypothesis = engine output
# ---------------------------------------------------------------------------

@dataclass
class VulnHypothesis:
    rule_id: str
    title: str
    cwe: str
    severity: str
    confidence: float
    url: str
    evidence: list = field(default_factory=list)   # list[Fact]
    rationale: str = ""
    next_steps: list = field(default_factory=list)

    @property
    def key(self):
        # one hypothesis per (url, cwe) â€” see CorrelationEngine._dedupe_hypothesis
        return (self.url, self.cwe)

    def to_finding_dict(self) -> dict:
        """
        Shape-compatible with the existing finding dict so it can be dropped
        straight into live_browser.py's existing _inject_ui_alert grouping
        logic if you don't want a separate panel â€” same keys it already reads:
        url/type/severity/match. 'type' is prefixed so it visually separates
        from raw scanner findings in a shared list.
        """
        return {
            "url": self.url,
            "type": f"SUGGESTED::{self.rule_id}",
            "severity": self.severity,
            "confidence": f"{int(self.confidence * 100)}%",
            "description": self.title,
            "remediation": "; ".join(self.next_steps) if self.next_steps else "Manual verification required.",
            "match": self.rationale,
            "context": self.cwe,
            "line": 0,
            "source": "CORRELATION_ENGINE",
        }


def confidence_from(*facts: Fact, base: float = 1.0) -> float:
    """Weakest-link: a correlated hypothesis is only as strong as its least confident input fact."""
    if not facts:
        return base
    return max(0.0, min(1.0, base * min(f.confidence for f in facts)))


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RuleFn = Callable[["CorrelationEngine", Fact], list]  # (engine, new_fact) -> list[VulnHypothesis]
_RULES: list[tuple[str, RuleFn, float]] = []


def rule(rule_id: str, weight: float = 1.0):
    """Decorator to register a correlation rule. See bottom of file for all registered rules."""
    def deco(fn: RuleFn):
        _RULES.append((rule_id, fn, weight))
        return fn
    return deco


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Streaming/incremental: call .ingest(finding_dict) once per NEW finding
    as it's discovered (i.e. from inside live_browser.py's monitor loop,
    right where it currently calls self._inject_ui_alert(f)).

    Internally keeps facts indexed by URL so each rule only re-evaluates
    against the small set of facts relevant to the URL that just changed,
    not the entire history of the scan â€” required for the 1s poll loop
    not to degrade as a scan runs longer.
    """

    def __init__(self):
        self._facts_by_url: dict[str, list[Fact]] = {}
        self._seen_dedupe_keys: set = set()
        self._hypotheses: dict[tuple, VulnHypothesis] = {}  # key=(url, cwe)

    def all_hypotheses(self) -> list[VulnHypothesis]:
        out = list(self._hypotheses.values())
        out.sort(key=lambda h: (SEVERITY_RANK.get(h.severity, 9), -h.confidence))
        return out

    def ingest(self, finding: dict) -> list[VulnHypothesis]:
        """
        Returns hypotheses that are NEW or were just RAISED in confidence
        as a result of this single finding â€” i.e. exactly what the HUD
        should render/update right now. Returns [] if nothing changed
        (including: this finding was a dedupe of one already seen).
        """
        fact = fact_from_finding(finding)

        if fact.dedupe_key in self._seen_dedupe_keys:
            return []
        self._seen_dedupe_keys.add(fact.dedupe_key)
        self._facts_by_url.setdefault(fact.url, []).append(fact)

        changed: list[VulnHypothesis] = []
        for rule_id, fn, weight in _RULES:
            try:
                new_hyps = fn(self, fact) or []
            except Exception as e:
                # A broken rule must never take down the live monitor loop.
                logger.warning("correlation rule %s raised %s â€” skipped", rule_id, e)
                continue
            for h in new_hyps:
                h.rule_id = rule_id
                h.confidence = max(0.0, min(1.0, h.confidence * weight))
                if self._upsert(h):
                    changed.append(h)
        return changed

    def facts_for_url(self, url: str) -> list[Fact]:
        return self._facts_by_url.get(url, [])

    def facts_of_type(self, ftype: str, url: str | None = None) -> list[Fact]:
        pool = self.facts_for_url(url) if url else [f for fl in self._facts_by_url.values() for f in fl]
        return [f for f in pool if f.type == ftype]

    def facts_of_types(self, ftypes: set, url: str | None = None) -> list[Fact]:
        pool = self.facts_for_url(url) if url else [f for fl in self._facts_by_url.values() for f in fl]
        return [f for f in pool if f.type in ftypes]

    def _upsert(self, h: VulnHypothesis) -> bool:
        """
        Keep the higher-confidence hypothesis per (url, cwe), merging
        evidence. Returns True if this call changed the stored state
        (new hypothesis, or confidence increased) â€” that's the signal
        the HUD uses to decide whether to re-render this row.
        """
        existing = self._hypotheses.get(h.key)
        if existing is None:
            self._hypotheses[h.key] = h
            return True
        if h.confidence > existing.confidence + 1e-9:
            merged_evidence = list({id(e): e for e in (existing.evidence + h.evidence)}.values())
            h.evidence = merged_evidence
            self._hypotheses[h.key] = h
            return True
        # Same or lower confidence: still merge evidence for completeness,
        # but don't report it as "changed" (avoids HUD flicker on no-op repeats).
        new_ev = [e for e in h.evidence if e not in existing.evidence]
        if new_ev:
            existing.evidence.extend(new_ev)
        return False


# ---------------------------------------------------------------------------
# Rules â€” written against the REAL `type` strings from core/engine.py and
# core/live_browser.py. Each docstring cites the exact finding type(s) it
# reacts to so this stays maintainable as engine.py's pattern dict grows.
# ---------------------------------------------------------------------------

SECRET_TYPES = {
    "STRIPE_API_KEY", "GITHUB_PAT_TOKEN", "PRIVATE_KEY", "API_KEY_AWS",
    "API_KEY_GOOGLE", "SLACK_TOKEN", "AUTHORIZATION_BEARER",
    "HARDCODED_ENCRYPT_KEY", "CRYPTOJS_AES_ENCRYPT", "HARDCODED_KEK",
    "CUSTOM_HARDCODED_SECRETS", "BASE64_POTENTIAL_KEY",
}
CRITICAL_SECRET_TYPES = {"STRIPE_API_KEY", "GITHUB_PAT_TOKEN", "PRIVATE_KEY", "API_KEY_AWS", "HARDCODED_KEK"}


@rule("R-XSS-NOHEADER", weight=1.0)
def rule_taint_plus_no_csp(engine: CorrelationEngine, fact: Fact):
    """
    DOM_XSS_STATIC_TAINT (engine.py _check_dom_xss_taint) + MISSING_SECURITY_HEADER
    mentioning CSP on the same URL (live_browser.py header check) => the static
    taint guess has no compensating control if the sanitizer assumption is wrong.
    """
    out = []
    if fact.type == "DOM_XSS_STATIC_TAINT":
        csp_missing = [f for f in engine.facts_of_type("MISSING_SECURITY_HEADER", fact.url)
                       if "Content-Security-Policy" in f.match]
        if csp_missing:
            out.append(_xss_csp_hyp(fact, csp_missing[0]))
    elif fact.type == "MISSING_SECURITY_HEADER" and "Content-Security-Policy" in fact.match:
        taint_facts = engine.facts_of_type("DOM_XSS_STATIC_TAINT", fact.url)
        for t in taint_facts:
            out.append(_xss_csp_hyp(t, fact))
    return out


def _xss_csp_hyp(taint: Fact, csp: Fact) -> VulnHypothesis:
    return VulnHypothesis(
        rule_id="R-XSS-NOHEADER", title="Static XSS taint path with no CSP fallback",
        cwe="CWE-79", severity="CRITICAL",
        confidence=confidence_from(taint, csp, base=0.9),
        url=taint.url, evidence=[taint, csp],
        rationale=f"Static taint match ({taint.match[:60]}) + missing CSP on same page â€” no defense-in-depth if sanitizer assumption is wrong.",
        next_steps=[
            "Build a PoC payload for the tainted source identified in the static match",
            "Confirm no CSP is served on any response for this exact URL (not just the page shell)",
        ],
    )


@rule("R-JWT-NONE", weight=1.0)
def rule_jwt_alg_none(engine: CorrelationEngine, fact: Fact):
    """
    JWT_TOKEN (engine.py L121-126, L358-377). engine.py already bumps the raw
    finding's severity to CRITICAL when alg=none is detected (sets
    data['severity']='CRITICAL' in-place) but doesn't separately flag the
    *implication* (forgeable auth) as its own actionable hypothesis with steps.
    """
    if fact.type != "JWT_TOKEN":
        return []
    if "none" not in fact.raw.get("description", "").lower() and "none" not in fact.match.lower():
        return []
    # engine.py's description field carries "[!] CRITICAL: JWT accepts 'none'..." when triggered
    if "alg" not in fact.raw.get("description", "").lower() and "'none'" not in fact.raw.get("description", "").lower():
        return []
    return [VulnHypothesis(
        rule_id="R-JWT-NONE", title="JWT alg:none accepted â€” forgeable authentication",
        cwe="CWE-347", severity="CRITICAL", confidence=confidence_from(fact, base=0.95),
        url=fact.url, evidence=[fact],
        rationale="JWT decode shows alg=none accepted by the issuer/verifier path.",
        next_steps=[
            "Forge a token with header {\"alg\":\"none\"}, modified claims, empty signature; replay against any endpoint that reads this token",
            "If forgery succeeds: enumerate which claims (role, sub, tenant_id) control authorization decisions server-side",
        ],
    )]


@rule("R-SECRET-PLUS-API", weight=1.0)
def rule_secret_plus_related_route(engine: CorrelationEngine, fact: Fact):
    """
    Any SECRET_TYPES finding + API_ROUTE_DISCOVERED (engine.py _extract_api_map)
    on the same URL/page raises confidence the secret is live/reachable rather
    than dead test data, since the page that ships the secret also ships code
    that calls a backend route â€” i.e. it's wired into something real.
    """
    out = []
    if fact.type in SECRET_TYPES:
        routes = engine.facts_of_type("API_ROUTE_DISCOVERED", fact.url)
        if routes:
            out.append(_secret_route_hyp(fact, routes))
    elif fact.type == "API_ROUTE_DISCOVERED":
        secrets = engine.facts_of_types(SECRET_TYPES, fact.url)
        if secrets:
            for s in secrets:
                out.append(_secret_route_hyp(s, [fact]))
    return out


def _secret_route_hyp(secret: Fact, routes: list) -> VulnHypothesis:
    sev = "CRITICAL" if secret.type in CRITICAL_SECRET_TYPES else "HIGH"
    return VulnHypothesis(
        rule_id="R-SECRET-PLUS-API", title=f"{secret.type} found alongside live API route(s) on same page",
        cwe="CWE-798", severity=sev,
        confidence=confidence_from(secret, *routes, base=0.85),
        url=secret.url, evidence=[secret] + routes,
        rationale=f"{secret.type} co-occurs with {len(routes)} discovered API route(s) â€” suggests the secret is wired into active client logic, not dead/test data.",
        next_steps=[
            "Test the discovered route(s) directly with the leaked credential",
            "If credential is a key/token: check issuing service for a read-only liveness check before any destructive test",
        ],
    )


@rule("R-IDOR-CHAIN", weight=0.9)
def rule_idor_chain(engine: CorrelationEngine, fact: Fact):
    """
    POTENTIAL_IDOR_PATH / POTENTIAL_IDOR_PATH_UUID / POTENTIAL_IDOR_BASE64_JSON
    (engine.py _check_idor) â€” multiple independent IDOR-flavored hits on the
    SAME url path pattern raise confidence this isn't a one-off false positive
    from the heuristic but a systemic pattern across the app's routing.
    """
    idor_types = {"POTENTIAL_IDOR_PATH", "POTENTIAL_IDOR_PATH_UUID", "POTENTIAL_IDOR_BASE64_JSON"}
    if fact.type not in idor_types:
        return []
    same_url_idor = [f for f in engine.facts_for_url(fact.url) if f.type in idor_types]
    if len(same_url_idor) < 2:
        return []
    return [VulnHypothesis(
        rule_id="R-IDOR-CHAIN", title=f"Multiple IDOR-pattern indicators on {fact.url}",
        cwe="CWE-639", severity="HIGH",
        confidence=confidence_from(*same_url_idor, base=0.75),
        url=fact.url, evidence=same_url_idor,
        rationale=f"{len(same_url_idor)} independent IDOR-flavored heuristic hits on the same URL â€” pattern, not noise.",
        next_steps=[
            "Manually swap the identified ID/UUID values with another known/guessed account's identifiers",
            "Test with no-auth and with a different low-privilege account's session to confirm access control is actually enforced server-side",
        ],
    )]


@rule("R-KNOWNVULN-ESCALATE", weight=1.0)
def rule_known_vuln_with_secrets(engine: CorrelationEngine, fact: Fact):
    """
    KNOWN_VULNERABILITY (utils/component_checker.py) on a page that ALSO ships
    a secret â€” an outdated vulnerable library plus exposed credentials on the
    same page raises the practical exploitability ceiling (e.g. an old jQuery
    XSS-prone version next to a live bearer token is a much better chain than
    either alone).
    """
    out = []
    if fact.type == "KNOWN_VULNERABILITY":
        secrets = engine.facts_of_types(SECRET_TYPES, fact.url)
        if secrets:
            out.append(_knownvuln_secret_hyp(fact, secrets))
    elif fact.type in SECRET_TYPES:
        kv = engine.facts_of_type("KNOWN_VULNERABILITY", fact.url)
        if kv:
            for k in kv:
                out.append(_knownvuln_secret_hyp(k, [fact]))
    return out


def _knownvuln_secret_hyp(kv: Fact, secrets: list) -> VulnHypothesis:
    cve_ref = kv.context or kv.match
    return VulnHypothesis(
        rule_id="R-KNOWNVULN-ESCALATE",
        title=f"Known-vulnerable component ({kv.match}) co-located with exposed credential(s)",
        cwe="CWE-1104", severity="CRITICAL",
        confidence=confidence_from(kv, *secrets, base=0.8),
        url=kv.url, evidence=[kv] + secrets,
        rationale=f"{kv.match} has a known CVE ({cve_ref}) and the same page exposes {len(secrets)} credential(s) â€” combine for a higher-impact chain than either alone.",
        next_steps=[
            f"Check public PoC/exploit availability for {cve_ref}",
            "Assess whether the known vuln's impact (e.g. XSS, prototype pollution) could be used to exfiltrate the co-located credential at runtime",
        ],
    )


@rule("R-CORS-COOKIE-CHAIN", weight=1.0)
def rule_cors_cookie_chain(engine: CorrelationEngine, fact: Fact):
    """
    CORS_WILDCARD + INSECURE_COOKIE (both NEW checks added to
    live_browser.py's _monitor_loop in this change) on the same URL =>
    cross-origin session theft is plausible, not just two unrelated low/info
    findings.
    """
    out = []
    if fact.type == "CORS_WILDCARD":
        cookies = engine.facts_of_type("INSECURE_COOKIE", fact.url)
        if cookies:
            out.append(_cors_cookie_hyp(fact, cookies[0]))
    elif fact.type == "INSECURE_COOKIE":
        cors = engine.facts_of_type("CORS_WILDCARD", fact.url)
        if cors:
            out.append(_cors_cookie_hyp(cors[0], fact))
    return out


def _cors_cookie_hyp(cors: Fact, cookie: Fact) -> VulnHypothesis:
    missing = cookie.match
    sev = "CRITICAL" if "samesite" in missing.lower() else "HIGH"
    return VulnHypothesis(
        rule_id="R-CORS-COOKIE-CHAIN",
        title="Permissive CORS + weak cookie flags => cross-origin session theft",
        cwe="CWE-942", severity=sev,
        confidence=confidence_from(cors, cookie, base=0.85),
        url=cors.url, evidence=[cors, cookie],
        rationale=f"CORS reflects an arbitrary/wildcard origin while cookie is missing {missing} â€” a malicious origin can likely read authenticated responses.",
        next_steps=[
            "Confirm Access-Control-Allow-Origin reflects the request's Origin header AND Access-Control-Allow-Credentials:true together (the actually exploitable combo, not just wildcard alone)",
            "Build a cross-origin fetch() PoC with credentials:'include' from an attacker-controlled origin and check if the response is readable",
        ],
    )


@rule("R-SSRF-ROUTE", weight=0.8)
def rule_ssrf_param_on_discovered_route(engine: CorrelationEngine, fact: Fact):
    """
    SSRF_URL_PARAM (engine.py) seen on a URL that's also a confirmed
    API_ROUTE_DISCOVERED target â€” i.e. it's not just a stray query string
    in static JS, it's a parameter on a route the app actually calls.
    """
    out = []
    if fact.type == "SSRF_URL_PARAM":
        routes = engine.facts_of_type("API_ROUTE_DISCOVERED", fact.url)
        if routes:
            out.append(_ssrf_hyp(fact, routes[0]))
    elif fact.type == "API_ROUTE_DISCOVERED":
        ssrf = engine.facts_of_type("SSRF_URL_PARAM", fact.url)
        if ssrf:
            out.append(_ssrf_hyp(ssrf[0], fact))
    return out


def _ssrf_hyp(ssrf: Fact, route: Fact) -> VulnHypothesis:
    return VulnHypothesis(
        rule_id="R-SSRF-ROUTE", title="SSRF-prone parameter on a confirmed live API route",
        cwe="CWE-918", severity="HIGH", confidence=confidence_from(ssrf, route, base=0.7),
        url=ssrf.url, evidence=[ssrf, route],
        rationale="URL/redirect-style parameter co-occurs with a route the app's own JS calls â€” worth testing for outbound request control, not just a static string match.",
        next_steps=[
            "Replace the parameter value with a request to an attacker-controlled listener (e.g. webhook.site) and confirm an outbound hit",
            "If confirmed: attempt to reach internal/metadata endpoints (e.g. 169.254.169.254) through the same parameter",
        ],
    )
