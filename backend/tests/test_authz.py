"""Authenticated scanning and access control testing.

Two things are being protected here, and they pull in opposite directions.

**Credentials must reach the target.** An engine that quietly runs logged-out
produces a scan that looks thorough and covers a fraction of the application.
That failure is invisible: nothing errors, the report just has less in it.

**Credentials must reach nothing else.** Enumeration turns up hosts that aren't
yours. Attaching a session cookie to a request for one of them hands your
session to a third party — on a bug bounty program, that's an incident you
caused.

The rest of the file is false-positive suppression for the access-control
engine, which matters more here than anywhere else in the codebase. "IDOR" gets
a triage team's immediate attention; a wrong one burns credibility you need for
the next report.
"""

import pytest

from app import auth
from app.engines import registry
from app.engines.authz import addresses_a_record, is_real_content, same_resource
from app.engines.fetch import auth_for, scoped_identity

from .conftest import run_coroutine

SESSION = {"Cookie": "session=secret-value-1234"}
CTX = {"auth_headers": SESSION, "allow": ["*.example.com"], "deny": []}


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ------------------------------------------------- credentials reach the target

def test_in_scope_requests_carry_the_session():
    assert auth_for("https://app.example.com/account", CTX) == SESSION


def test_apex_is_in_scope_under_a_wildcard_rule():
    assert auth_for("https://example.com/", CTX) == SESSION


# --------------------------------------------- credentials reach nothing else

def test_out_of_scope_requests_carry_nothing():
    assert auth_for("https://evil.com/collect", CTX) == {}


def test_suffix_confusion_does_not_leak_the_session():
    """example.com.evil.net is not example.com."""
    assert auth_for("https://example.com.evil.net/", CTX) == {}


def test_denied_hosts_carry_nothing_even_when_allowed():
    ctx = {**CTX, "deny": ["admin.example.com"]}
    assert auth_for("https://admin.example.com/", ctx) == {}


def test_no_context_means_no_credentials():
    assert auth_for("https://app.example.com/", None) == {}
    assert auth_for("https://app.example.com/", {}) == {}


def test_second_identity_goes_through_the_same_gate():
    """A second account's cookie is exactly as sensitive as the first's."""
    identity = {"name": "user-b", "headers": {"Cookie": "session=b-secret"}}
    assert scoped_identity("https://app.example.com/", identity, CTX)["Cookie"] \
        == "session=b-secret"
    assert scoped_identity("https://evil.com/", identity, CTX) == {}


def test_identity_without_credentials_sends_nothing():
    assert scoped_identity("https://app.example.com/", {"name": "x"}, CTX) == {}
    assert scoped_identity("https://app.example.com/", None, CTX) == {}


def test_every_engine_request_goes_through_the_scope_gate():
    """Regression guard for the wiring itself.

    Engines call fetch.request; if one is added later without passing ctx it
    runs logged-out, and if fetch ever attaches headers without consulting
    scope it leaks. This asserts the single chokepoint still exists.

    Reads `_execute` rather than `request`: the redirect follower was lifted
    out into `request()` and simultaneous-request coalescing into
    `_one_request()`, so the code that actually builds the curl argv and
    attaches credentials now lives two levels down. Asserting on the wrong
    function is how a guard like this ends up passing while guarding nothing —
    so these read the function that builds the command line, wherever it is.
    """
    import inspect

    from app.engines import fetch
    source = inspect.getsource(fetch._execute)
    assert "auth_for" in source and "scoped_identity" in source, \
        "fetch._execute no longer routes credentials through the scope check"


def test_redirects_are_checked_against_the_hard_deny_list():
    """The seed is scope-checked; the redirect target used to not be.

    `follow=True` handed `-L` to curl, so an in-scope target answering
    `302 Location: http://169.254.169.254/…` got followed straight into the
    cloud metadata service. Verified against curl before the fix: the request
    was made.
    """
    import inspect

    from app.engines import fetch
    source = inspect.getsource(fetch.request)
    assert "hard_denied" in source, \
        "fetch.request follows redirects without re-checking scope"
    assert '"-L"' not in inspect.getsource(fetch._execute), \
        "curl is following redirects itself again, bypassing the scope check"


def test_curl_cannot_be_talked_out_of_http():
    """`Location: file:///etc/passwd` made curl read a local file and return
    it as a response body. Belt and braces alongside the redirect loop."""
    import inspect

    from app.engines import fetch
    source = inspect.getsource(fetch._execute)
    assert "--proto-redir" in source and "=http,https" in source


def test_a_url_cannot_become_a_curl_flag():
    """URLs come from tool output and crawled pages, so their shape is not
    guaranteed. Passed positionally, a leading dash is read as an option —
    `-o/path` writes a file, `-K file` reads a config."""
    import inspect

    from app.engines import fetch
    assert '"--url"' in inspect.getsource(fetch._execute), \
        "the URL is passed positionally again and can be parsed as a flag"


# -------------------------------------------- what counts as successful access

LOGIN_PAGE = ("<html><body><h1>Sign in</h1>"
              "<form><input type='password' name='p'></form>"
              + "filler " * 60 + "</body></html>")
REAL_PAGE = "<html><body><h1>Invoice 1042</h1>" + "line item " * 60 + "</body></html>"


def test_real_content_is_recognised():
    assert is_real_content(200, REAL_PAGE)


def test_a_login_page_is_not_access():
    """The single most important check in the engine — a 200 carrying a login
    form is a refusal, and counting it as access invents an IDOR."""
    assert not is_real_content(200, LOGIN_PAGE)


def test_access_denied_text_is_not_access():
    body = "<html><body>Access denied. You are not authorised to view this."\
           + "x" * 300 + "</body></html>"
    assert not is_real_content(200, body)


def test_empty_and_tiny_responses_are_not_access():
    assert not is_real_content(200, "")
    assert not is_real_content(200, "ok")


def test_error_statuses_are_not_access():
    assert not is_real_content(403, REAL_PAGE)
    assert not is_real_content(302, REAL_PAGE)
    assert not is_real_content(500, REAL_PAGE)


# ---------------------------------------------------- resource identity

def test_same_page_rendered_for_two_sessions_is_one_resource():
    """CSRF token and greeting differ; the record doesn't."""
    a = "<html>" + "content " * 200 + "<span>csrf=aaaaaaaa</span></html>"
    b = "<html>" + "content " * 200 + "<span>csrf=bbbbbbbb</span></html>"
    assert same_resource(a, b)


def test_different_records_are_not_the_same_resource():
    assert not same_resource("x" * 1000, "x" * 4000)


def test_empty_responses_are_never_the_same_resource():
    assert not same_resource("", "")
    assert not same_resource("content", "")


# ------------------------------------------------- which URLs are worth testing

@pytest.mark.parametrize("url", [
    "https://a.example.com/orders/1042",
    "https://a.example.com/api/v1/users/93012/profile",
    "https://a.example.com/doc/550e8400-e29b-41d4-a716-446655440000",
    "https://a.example.com/account?id=57",
    "https://a.example.com/view?invoice_id=9931",
])
def test_record_addressing_urls_are_tested(url):
    assert addresses_a_record(url)


@pytest.mark.parametrize("url", [
    "https://a.example.com/",
    "https://a.example.com/dashboard",
    "https://a.example.com/about-us",
    "https://a.example.com/search?q=laptop",
])
def test_plain_pages_are_not_compared_across_accounts(url):
    """Two users legitimately see the same dashboard. Comparing pages rather
    than records is how a scanner generates a hundred fake IDORs."""
    assert not addresses_a_record(url)


# ------------------------------------------------------- identity verification

def test_dead_identities_are_dropped(monkeypatch):
    """A silently expired second session makes 'no IDOR found' meaningless —
    it looks the same as an application that is correctly locked down."""
    async def fake_verify(check_url, check_string, headers, **_kw):
        return (headers.get("Cookie") == "good", "checked")

    monkeypatch.setattr(auth, "verify_session", fake_verify)

    identities = [
        {"name": "alive", "headers": {"Cookie": "good"}},
        {"name": "expired", "headers": {"Cookie": "stale"}},
        {"name": "empty", "headers": {}},
    ]
    live = run_coroutine(auth.verify_identities(identities))
    assert [i["name"] for i in live] == ["alive"]


def test_unnamed_identities_get_a_label(monkeypatch):
    async def fake_verify(*_a, **_k):
        return True, "ok"
    monkeypatch.setattr(auth, "verify_session", fake_verify)
    live = run_coroutine(auth.verify_identities([{"headers": {"Cookie": "x"}}]))
    assert live[0]["name"] == "identity-1"


def test_identity_summary_leaks_no_credentials():
    summary = auth.identity_summary(
        [{"name": "user-b", "role": "standard",
          "headers": {"Cookie": "session=supersecret123"}}])
    assert "supersecret" not in summary
    assert "user-b" in summary


# ------------------------------------------------------------ schema and model

def test_identity_rejects_header_injection():
    from pydantic import ValidationError

    from app.schemas import Identity
    with pytest.raises(ValidationError):
        Identity(name="b", headers={"Cookie": "a=b\r\nX-Evil: 1"})
    with pytest.raises(ValidationError):
        Identity(name="b", headers={"Bad\nName": "x"})


def test_identity_requires_a_name():
    from pydantic import ValidationError

    from app.schemas import Identity
    with pytest.raises(ValidationError):
        Identity(name="", headers={"Cookie": "x"})


def test_auth_config_accepts_identities():
    from app.schemas import AuthConfig
    cfg = AuthConfig(headers={"Cookie": "a"},
                     identities=[{"name": "user-b", "headers": {"Cookie": "b"}}])
    assert cfg.identities[0].name == "user-b"


def test_engagements_table_has_the_identities_column():
    """Existing databases must gain the column without a manual migration."""
    from app.db import ensure_schema
    from app.models import Engagement
    columns = {c.name for c in Engagement.__table__.columns}
    assert "auth_identities" in columns
    ensure_schema()   # idempotent; would raise if the migration were malformed


# ----------------------------------------------------------- wiring

def test_engine_is_registered_and_wired():
    from app.schemas import DEPTH_PRESETS, VALID_STAGES
    spec = registry.get("authz")
    assert spec is not None
    assert "authz" in VALID_STAGES
    for depth in ("standard", "deep"):
        assert "authz" in DEPTH_PRESETS[depth][1]


def test_engine_does_nothing_without_credentials():
    """Unauthenticated scans must not produce access-control findings — there
    is nothing to compare against."""
    spec = registry.get("authz")
    logged = []

    async def log(level, message, stage=""):
        logged.append(message)

    result = run_coroutine(spec.run(["https://a.example.com/x"], {"log": log}))
    assert result == []
    assert any("no credentials" in m for m in logged)


@pytest.mark.parametrize("rule", ["missing-authentication", "idor-cross-account"])
def test_access_control_findings_map_to_a01(rule):
    from app import compliance
    controls = compliance.controls_for({"rule_id": rule, "tags": [], "cwe": []})
    assert controls.owasp_top10.startswith("A01")
    assert controls.asvs, f"{rule} needs ASVS references for the audit report"


def test_stored_credentials_are_never_returned_by_the_api():
    """The configuration endpoint describes what's set; it must not echo it."""
    import inspect

    from app import main
    source = inspect.getsource(main.get_engagement_auth)
    assert "auth_headers" in source
    assert "eng.auth_headers," not in source.replace(" ", "")
    assert "header_names" in source, "only header names should leave the server"
