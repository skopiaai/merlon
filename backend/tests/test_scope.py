"""Scope guard tests.

These are the most important tests in the project. If scope enforcement
breaks, the tool scans things it has no permission to scan. Run them before
every commit:  pytest backend/tests
"""

import pytest

from app import normalize, scope

ALLOW = ["*.example.com", "10.0.0.0/24", "single.org"]
DENY = ["payments.example.com", "*.internal.example.com"]


@pytest.mark.parametrize("host,expected", [
    ("example.com", True),                      # apex matches wildcard
    ("api.example.com", True),
    ("a.b.c.example.com", True),                # deep subdomain
    ("EXAMPLE.COM", True),                      # case insensitive
    ("example.com.", True),                     # trailing dot
    ("https://api.example.com:8443/path", True),  # URL input
    ("api.example.com:443", True),              # host:port input
    ("single.org", True),
    ("10.0.0.7", True),                         # inside CIDR
    ("notexample.com", False),                  # suffix confusion
    ("example.com.evil.net", False),            # suffix injection
    ("sub.single.org", False),                  # exact rule, not wildcard
    ("10.0.1.7", False),                        # outside CIDR
    ("evil.com", False),
    ("payments.example.com", False),            # explicit deny
    ("db.internal.example.com", False),         # wildcard deny
    ("169.254.169.254", False),                 # cloud metadata, hard deny
    ("127.0.0.1", False),                       # loopback, hard deny
    ("localhost", False),
])
def test_scope_decisions(host, expected):
    assert scope.check(host, ALLOW, DENY).allowed is expected


def test_deny_beats_allow():
    d = scope.check("payments.example.com", ["*.example.com"], ["payments.example.com"])
    assert not d.allowed and "excluded" in d.reason


def test_empty_allowlist_denies_everything():
    assert not scope.check("example.com", [], []).allowed


def test_filter_hosts_dedupes_and_reports():
    kept, rejected = scope.filter_hosts(
        ["api.example.com", "API.EXAMPLE.COM", "evil.com"], ALLOW, DENY
    )
    assert kept == ["api.example.com"]
    assert [r.host for r in rejected] == ["evil.com"]


@pytest.mark.parametrize("rule", ["not a domain!", "10.0.0.0/99", "", "   "])
def test_invalid_rules_rejected(rule):
    with pytest.raises(scope.ScopeViolation):
        scope.validate_rule(rule)


@pytest.mark.parametrize("rule", ["example.com", "*.example.com", "10.0.0.0/24", "192.168.1.5"])
def test_valid_rules_accepted(rule):
    assert scope.validate_rule(rule)


# ---- normalization / dedupe ----

def test_volatile_ids_collapse():
    a = normalize.make_dedupe_key("nuclei", "r", "h", "https://h/user/1234/p?x=1")
    b = normalize.make_dedupe_key("nuclei", "r", "h", "https://h/user/9999/p?x=2")
    assert a == b


def test_distinct_paths_do_not_collapse():
    a = normalize.make_dedupe_key("nuclei", "r", "h", "https://h/admin")
    b = normalize.make_dedupe_key("nuclei", "r", "h", "https://h/login")
    assert a != b


def test_nuclei_normalization():
    rec = {
        "host": "https://x.example.com:443",
        "matched-at": "https://x.example.com/a",
        "template-id": "tls-version",
        "info": {
            "name": "TLS Version", "severity": "high", "tags": ["ssl"],
            "classification": {"cve-id": ["CVE-2024-1"], "cwe-id": ["CWE-327"], "cvss-score": 7.5},
        },
    }
    f = normalize.from_nuclei(rec)
    assert f["host"] == "x.example.com"
    assert f["severity"].value == "high"
    assert f["cve"] == ["CVE-2024-1"]
    assert f["cvss_score"] == 7.5


# ---------------------------------------------------------------- hostname shape

class TestHostnameValidation:
    """A typo used to sail through.

    `normalize_host("not a domain!!")` returned that string verbatim, a scan was
    created against it, every engine found nothing, and the operator got an
    empty report. An empty result that reads like a clean bill of health is the
    worst failure this tool can have, so the shape is checked.
    """

    @pytest.mark.parametrize("value,expected", [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
        ("http://x.com/a/b?q=1", "x.com"),
        ("x.com:8443", "x.com"),
        ("host-with-dash.com", "host-with-dash.com"),
        # Real names this tool looks up — underscore labels must survive.
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("_acme-challenge.x.com", "_acme-challenge.x.com"),
        # Punycode / IDN.
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        # A single label is legitimate: localhost, an internal short name.
        ("localhost", "localhost"),
        # Hack The Box and home labs are bare addresses.
        ("10.10.10.1", "10.10.10.1"),
        ("192.168.0.5", "192.168.0.5"),
        # IPv6 is full of colons and must never meet the hostname pattern.
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
    ])
    def test_accepts_real_targets(self, value, expected):
        assert scope.normalize_host(value) == expected

    @pytest.mark.parametrize("value", [
        "not a domain!!",      # the case that started this
        "exa mple.com",        # a stray space
        'quote"s.com',
        "has/slash.com",
        "-bad.com",            # a label may not start with a hyphen
        "bad-.com",            # ...nor end with one
        "x..y.com",            # empty label
        "a" * 64 + ".com",     # label over 63 characters
        ("a" * 60 + ".") * 5 + "com",   # name over 253 characters
        "",
        "   ",
        "..",
    ])
    def test_rejects_malformed(self, value):
        with pytest.raises(scope.ScopeViolation):
            scope.normalize_host(value)

    def test_a_malformed_host_is_out_of_scope_not_allowed(self):
        """check() must refuse it rather than pass it to the rules."""
        decision = scope.check("not a domain!!", ["*.example.com"], [])
        assert decision.allowed is False
