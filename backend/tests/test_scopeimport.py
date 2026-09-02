"""Scope import and duplicate detection.

Scope is the one piece of configuration in this tool where being wrong is a
legal problem rather than a bug. Testing a host the program excluded is the
most common way researchers get removed from programs, and it is almost always
a transcription error rather than a decision.

So the tests below are heavily weighted towards the failure direction: an
exclusion that gets lost, a wildcard that gets narrowed, an asset type that
gets silently dropped so you believe you have covered the program when you
haven't.
"""

import pytest

from app import scopeimport, watch

HACKERONE_STYLE = """
In scope
| Asset | Type | Eligible for bounty | Max severity |
| *.example.com | URL | Yes | Critical |
| api.example.com | URL | Yes | Critical |
| https://shop.example.com/ | URL | Yes | High |
| com.example.mobile | GOOGLE_PLAY_APP_ID | Yes | High |
| https://github.com/example/backend | SOURCE_CODE | No | Medium |

Out of scope
| Asset | Type |
| legacy.example.com | URL |
| blog.example.com | URL |
| status.example.com | URL |
"""

PLAIN_LIST = """
*.target.org
app.target.org
203.0.113.0/24
"""


# ============================================================ parsing assets

def test_wildcards_and_hosts_are_parsed():
    scope = scopeimport.parse(HACKERONE_STYLE)
    assert "*.example.com" in scope.allow
    assert "api.example.com" in scope.allow
    assert "shop.example.com" in scope.allow


def test_wildcards_are_never_flattened_to_the_apex():
    """Flattening silently narrows scope and nobody would notice — the scan
    would just cover less than the program allows."""
    scope = scopeimport.parse("*.example.com")
    assert scope.allow == ["*.example.com"]


def test_urls_reduce_to_hosts():
    scope = scopeimport.parse("https://shop.example.com/checkout?a=1")
    assert scope.allow == ["shop.example.com"]


def test_ports_and_paths_are_stripped():
    scope = scopeimport.parse("api.example.com:8443/v2/")
    assert scope.allow == ["api.example.com"]


def test_cidr_ranges_are_kept():
    scope = scopeimport.parse(PLAIN_LIST)
    assert "203.0.113.0/24" in scope.allow


def test_duplicates_collapse():
    scope = scopeimport.parse("api.example.com\napi.example.com\napi.example.com")
    assert scope.allow == ["api.example.com"]


# ==================================================== out of scope wins

def test_out_of_scope_section_is_recognised():
    scope = scopeimport.parse(HACKERONE_STYLE)
    assert "legacy.example.com" in scope.deny
    assert "blog.example.com" in scope.deny


def test_excluded_hosts_never_appear_in_allow():
    """The rule that matters. A host in both lists is denied — programs publish
    a wildcard plus specific exclusions precisely so the exclusion is
    authoritative."""
    scope = scopeimport.parse("""
    In scope
    *.example.com
    legacy.example.com

    Out of scope
    legacy.example.com
    """)
    assert "legacy.example.com" in scope.deny
    assert "legacy.example.com" not in scope.allow


def test_reconcile_is_order_independent():
    allow, deny = scopeimport.reconcile(["a.com", "b.com"], ["b.com"])
    assert allow == ["a.com"] and deny == ["b.com"]


@pytest.mark.parametrize("heading", [
    "Out of scope", "OUT OF SCOPE", "Excluded", "Not in scope",
    "## Out-of-Scope", "Do not test", "Ineligible",
])
def test_every_common_exclusion_heading_is_understood(heading):
    """Missing one of these silently turns an exclusion list into an allowlist,
    which is the worst possible failure of this parser."""
    scope = scopeimport.parse(f"a.example.com\n{heading}\nb.example.com")
    assert "b.example.com" in scope.deny, f"{heading!r} not recognised"
    assert "b.example.com" not in scope.allow


# ============================================ assets this tool cannot test

def test_mobile_apps_are_named_not_dropped():
    """Silently discarding them leaves you believing the program is fully
    scanned when a whole asset class is untouched."""
    scope = scopeimport.parse(HACKERONE_STYLE)
    kinds = {kind for _asset, kind in scope.unscannable}
    assert any("mobile" in k for k in kinds)


def test_source_repositories_are_named():
    scope = scopeimport.parse(HACKERONE_STYLE)
    assert any("repository" in kind for _a, kind in scope.unscannable)


def test_asset_type_words_are_not_reported_as_assets():
    """A scope table has a type column. "CIDR" in it is a column value, not a
    network block, and reporting it as an uncoverable asset is a phantom."""
    scope = scopeimport.parse("| 203.0.113.0/24 | CIDR | High |")
    assert "203.0.113.0/24" in scope.allow
    assert not any(a.lower() == "cidr" for a, _k in scope.unscannable)


def test_a_real_asn_is_still_named():
    scope = scopeimport.parse("AS64512")
    assert any("autonomous system" in k for _a, k in scope.unscannable)


def test_unscannable_assets_do_not_become_scan_targets():
    scope = scopeimport.parse(HACKERONE_STYLE)
    assert not any("github.com" in a for a in scope.allow)
    assert "com.example.mobile" not in scope.allow


# ==================================================== table noise

@pytest.mark.parametrize("noise", [
    "Asset", "Type", "Eligible for bounty", "Max severity",
    "Critical", "High", "Yes", "No", "---", "|",
    # Asset-type column values. "CIDR" sitting in a type column was being
    # reported as an unscannable asset in its own right.
    "CIDR", "ASN", "IP", "Wildcard", "Hardware", "Other",
])
def test_table_headers_are_not_treated_as_assets(noise):
    scope = scopeimport.parse(noise)
    assert scope.allow == [], f"{noise!r} was parsed as an asset"


def test_empty_input_is_handled():
    scope = scopeimport.parse("")
    assert scope.allow == [] and scope.deny == []
    assert scope.as_dict()["counts"]["allow"] == 0


def test_result_serialises_for_the_api():
    import json
    json.dumps(scopeimport.parse(HACKERONE_STYLE).as_dict())


# ==================================================== the operator summary

def test_summary_tells_you_to_check_it():
    """The parser is a convenience. The human confirming it against the program
    page is the authorization step, and the summary has to say so."""
    summary = scopeimport.summarise(scopeimport.parse(HACKERONE_STYLE))
    assert "program page" in summary.lower()


def test_summary_shows_exclusions_win():
    summary = scopeimport.summarise(scopeimport.parse(HACKERONE_STYLE))
    assert "out of scope" in summary.lower()
    assert "legacy.example.com" in summary


def test_summary_warns_when_nothing_parsed():
    summary = scopeimport.summarise(scopeimport.parse("Asset | Type"))
    assert "Nothing parsed" in summary


def test_summary_names_what_cannot_be_covered():
    summary = scopeimport.summarise(scopeimport.parse(HACKERONE_STYLE))
    assert "cannot test" in summary.lower()


# ===================================================== no fetching, ever

def test_the_module_never_fetches_a_program_page():
    """Deriving an authorization decision from a regex over someone else's
    markup is not a shortcut worth taking."""
    import inspect
    source = inspect.getsource(scopeimport)
    for network in ("httpx", "requests", "urlopen", "fetch.request", "curl"):
        assert network not in source, f"scopeimport reaches the network via {network}"


def test_the_endpoint_only_parses():
    import inspect

    from app import main
    source = inspect.getsource(main.parse_scope)
    assert "db.add" not in source and "commit" not in source, \
        "parsing scope must not create an engagement — the human confirms first"


# ================================================== duplicate detection

def _entry(key: str, name: str = "x") -> dict:
    return {"id": 1, "dedupe_key": key, "name": name}


def test_findings_seen_before_are_marked():
    history = {"abc": {"first_seen": "2026-06-01T00:00:00+00:00",
                       "scan_id": 3, "status": "reported", "name": "old"}}
    entries = watch.annotate_new([_entry("abc"), _entry("xyz")], history)
    assert entries[0]["is_new"] is False
    assert entries[0]["first_seen"].startswith("2026-06-01")
    assert entries[0]["previously"] == "reported"
    assert entries[1]["is_new"] is True


def test_everything_is_new_without_history():
    entries = watch.annotate_new([_entry("a"), _entry("b")], {})
    assert all(e["is_new"] for e in entries)


def test_annotation_does_not_reorder():
    """Whether something is new matters less than whether it reproduces, and
    the queue's ordering already encodes that priority."""
    entries = [_entry("a", "first"), _entry("b", "second"), _entry("c", "third")]
    out = watch.annotate_new(entries, {"b": {"first_seen": "x", "scan_id": 1,
                                             "status": "new", "name": "second"}})
    assert [e["name"] for e in out] == ["first", "second", "third"]


def test_entries_without_a_key_are_treated_as_new():
    out = watch.annotate_new([{"id": 1}], {"abc": {"first_seen": "x",
                                                   "scan_id": 1, "status": "new",
                                                   "name": "n"}})
    assert out[0]["is_new"] is True
