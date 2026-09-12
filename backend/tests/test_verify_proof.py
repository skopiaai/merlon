"""The proof tier.

Merlon's gate used to ask one question: does this reproduce? That is weaker
than what the leading AI pentesters claim ("no exploit, no report") and it flat
under-sold the engines that genuinely demonstrate a bug. This adds a tier above
"reproduced" for rules the engine *proved*, while still keeping everything it
could not prove instead of discarding it.

The load-bearing tests: a rule is only `proven` if its engine declared it, and
a judgement-call engine can never be promoted by one.
"""

from app import verify
from app.engines import fetch

from .conftest import run_coroutine


def _ok(url, **kw):
    async def _r(u, **k):
        return fetch.Resp(url=u, status=200, body="<html>" + "a" * 200 + "</html>")
    return _r


def _finding(engine, rule_id, url="https://x.com/p?id=1"):
    return {
        "engine": engine, "rule_id": rule_id, "url": url, "matched_at": url,
        "evidence": "Parameter: id\nSent: 1'\nResponse: HTTP 200 contained a MySQL error signature",
        "remediation": "use parameterised queries",
        "references": ["https://portswigger.net/web-security/sql-injection"],
        "cwe": ["CWE-89"],
    }


# ---------------------------------------------------------------- declaration

def test_declared_rules_are_proven():
    assert verify.is_proven_rule("sqli", "sqli-error") is True
    assert verify.is_proven_rule("ssti", "ssti-arithmetic") is True
    assert verify.is_proven_rule("xss", "xss-reflected") is True
    assert verify.is_proven_rule("jwt", "jwt-weak-secret") is True
    assert verify.is_proven_rule("nosqli", "nosqli-operator") is True
    assert verify.is_proven_rule("redirect", "open-redirect") is True


def test_undeclared_rules_are_not_proven():
    # Same engine, a rule it only observes rather than demonstrates.
    assert verify.is_proven_rule("jwt", "jwt-no-expiry") is False
    assert verify.is_proven_rule("jwt", "jwt-alg-none") is False
    # An engine with no proves at all.
    assert verify.is_proven_rule("cors", "cors-wildcard") is False
    assert verify.is_proven_rule("", "") is False
    assert verify.is_proven_rule("nope", "nope") is False


# ---------------------------------------------------------------- tiers

def test_proven_rule_gets_the_proven_tier(monkeypatch):
    monkeypatch.setattr(fetch, "request", _ok(None))
    v = run_coroutine(verify.verify_finding(_finding("sqli", "sqli-error")))
    assert v.tier == "proven"
    assert v.submittable is True
    assert any("PROVEN" in r for r in v.reasons)


def test_unproven_rule_stays_reproduced(monkeypatch):
    monkeypatch.setattr(fetch, "request", _ok(None))
    v = run_coroutine(verify.verify_finding(_finding("jwt", "jwt-no-expiry")))
    assert v.tier == "reproduced"


def test_proof_outranks_reproduction(monkeypatch):
    """A proven finding must sort above a merely reproduced one."""
    monkeypatch.setattr(fetch, "request", _ok(None))
    proven = run_coroutine(verify.verify_finding(_finding("sqli", "sqli-error")))
    plain = run_coroutine(verify.verify_finding(_finding("jwt", "jwt-no-expiry")))
    assert proven.rank < plain.rank
    assert proven.confidence > plain.confidence


def test_nothing_that_fails_to_reproduce_is_proven(monkeypatch):
    async def _dead(u, **k):
        return fetch.Resp(url=u, status=0)
    monkeypatch.setattr(fetch, "request", _dead)
    v = run_coroutine(verify.verify_finding(_finding("sqli", "sqli-error")))
    assert v.tier == "unverified"
    assert v.submittable is False


def test_unproven_findings_are_kept_not_discarded(monkeypatch):
    """The difference from 'no exploit, no report': it still comes back."""
    monkeypatch.setattr(fetch, "request", _ok(None))
    v = run_coroutine(verify.verify_finding(_finding("cors", "cors-wildcard")))
    assert v is not None and v.tier == "reproduced"
    assert v.confidence > 0


def test_judgement_call_engine_is_never_promoted(monkeypatch):
    """ALWAYS_REVIEW outranks a proof, even a declared one."""
    monkeypatch.setattr(fetch, "request", _ok(None))
    monkeypatch.setattr(verify, "is_proven_rule", lambda e, r: True)
    v = run_coroutine(verify.verify_finding(_finding("jsintel", "whatever")))
    assert v.tier == "reproduced"
    assert v.submittable is False


def test_tier_is_serialised():
    d = verify.Verdict(0.9, True, [], [], tier="proven").as_dict()
    assert d["tier"] == "proven"
    assert verify.Verdict(0.9, True, [], [], tier="proven").rank == 0
