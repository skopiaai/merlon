"""Cache poisoning and cache deception logic, offline.

The detection lives in pure functions precisely so it can be judged here
without a network. The safety property — every probe is cache-busted — is
tested too, because a scanner that poisons a real shared cache is worse than
the bug it is looking for.
"""

from app.engines import cachepoison as cp
from app.models import Severity

# ---------------------------------------------------------------- safety

def test_every_deception_probe_is_cache_busted():
    urls = cp.deception_urls("https://example.com/account", "deadbeef")
    assert urls, "no probes generated"
    for probe, _kind in urls:
        assert "cb=deadbeef" in probe, (
            f"{probe} would land in a shared cache under a guessable URL")


def test_buster_preserves_an_existing_query():
    out = cp.with_buster("https://example.com/a?x=1", "tok")
    assert out == "https://example.com/a?x=1&cb=tok"


def test_buster_is_unique_per_call():
    assert cp.cache_buster() != cp.cache_buster()


def test_canaries_cannot_resolve():
    """A reflected canary must not be able to become a live third-party link."""
    assert cp.CANARY_HOST.endswith(".invalid")
    for _h, value, _why in cp.POISON_HEADERS:
        assert ".invalid" in value


# ------------------------------------------------------------ cacheability

def test_no_store_is_believed():
    assert cp.cacheability({"cache-control": "no-store"})[0] is False
    assert cp.cacheability({"cache-control": "private, max-age=60"})[0] is False


def test_a_hit_header_is_positive_evidence():
    ok, why = cp.cacheability({"x-cache": "HIT"})
    assert ok and "x-cache" in why
    assert cp.cacheability({"cf-cache-status": "HIT"})[0] is True


def test_a_miss_is_not_evidence_of_storage():
    assert cp.cacheability({"x-cache": "MISS"})[0] is False


def test_nonzero_age_means_it_came_from_a_cache():
    assert cp.cacheability({"age": "42"})[0] is True
    assert cp.cacheability({"age": "0"})[0] is False


def test_max_age_zero_is_not_storage():
    assert cp.cacheability({"cache-control": "max-age=0"})[0] is False
    assert cp.cacheability({"cache-control": "max-age=600"})[0] is True


def test_silence_is_not_cacheable():
    """Guessing from an absent header is how this check becomes noise."""
    assert cp.cacheability({})[0] is False


# ------------------------------------------------------------- same-page

def test_a_404_is_not_the_same_page():
    base = "x" * 200 + "UNIQUE-MARKER-THAT-IS-LONG-ENOUGH-TO-COUNT-HERE" + "y" * 200
    assert cp.looks_like_same_page(base, "Not Found") is False


def test_the_same_page_with_a_different_csrf_token_still_matches():
    body = ("<html>" + "a" * 150
            + "PROFILE PAGE FOR THE LOGGED IN USER, SETTINGS AND BILLING"
            + "b" * 150 + "</html>")
    variant = body.replace("aaaa", "aaab", 1)
    assert cp.looks_like_same_page(body, variant) is True


def test_empty_bodies_never_match():
    assert cp.looks_like_same_page("", "") is False


# ------------------------------------------------------------ reflection

def _reflected(resp_headers, body):
    return cp.analyse_reflection("X-Forwarded-Host", cp.CANARY_HOST,
                                 "absolute URLs are built from it",
                                 resp_headers, body)


def test_reflection_into_a_cacheable_response_is_a_finding():
    issue = _reflected({"x-cache": "HIT"},
                       f'<script src="https://{cp.CANARY_HOST}/a.js">')
    assert issue is not None
    assert issue["rule"] == "cache-poison-unkeyed-header"
    assert issue["severity"] is Severity.high


def test_reflection_without_caching_is_not_a_cache_bug():
    """Reflection alone is someone else's finding, not this engine's."""
    assert _reflected({"cache-control": "no-store"},
                      f"https://{cp.CANARY_HOST}/") is None


def test_caching_without_reflection_is_not_a_finding():
    assert _reflected({"x-cache": "HIT"}, "<html>nothing here</html>") is None


def test_reflection_in_the_location_header_counts():
    issue = _reflected({"age": "5"}, "")
    assert issue is None
    issue = cp.analyse_reflection("X-Forwarded-Host", cp.CANARY_HOST, "why",
                                  {"age": "5",
                                   "location": f"https://{cp.CANARY_HOST}/next"},
                                  "")
    assert issue is not None and "location header" in issue["where"]


# --------------------------------------------------------- private markers

def test_session_markers_are_spotted():
    assert cp.private_markers("<a>Log out</a> My Account") != []


def test_a_public_page_has_no_markers():
    assert cp.private_markers("<h1>Welcome to our marketing site</h1>") == []


# ------------------------------------------------------------- registration

def test_engine_is_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("cachepoison")
    assert spec is not None
    assert spec.phase == "post_http"
    assert "standard" in spec.default_in
