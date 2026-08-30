"""Attack surface mapping tests."""

import pytest

from app.surface import CATEGORIES, classify_url, map_surface, priority_hint


@pytest.mark.parametrize("url,expected", [
    ("https://a.com/login", "auth"),
    ("https://a.com/password/reset", "auth"),
    ("https://a.com/api/v1/things", "api"),
    ("https://a.com/graphql", "api"),
    ("https://a.com/admin/dashboard", "admin"),
    ("https://a.com/upload", "upload"),
    ("https://a.com/checkout", "payment"),
    ("https://a.com/invoice/12", "payment"),
    ("https://a.com/user/5/profile", "user-object"),
    ("https://a.com/export/csv", "export"),
    ("https://a.com/webhook/stripe", "webhook"),
    ("https://a.com/actuator/env", "debug"),
    ("https://a.com/search?q=x", "search"),
])
def test_classification(url, expected):
    assert expected in classify_url(url)


def test_plain_url_matches_nothing():
    assert classify_url("https://a.com/about-us") == []


def test_classification_is_case_insensitive():
    assert classify_url("https://a.com/ADMIN/Panel") == classify_url("https://a.com/admin/panel")


def test_url_can_be_in_several_categories():
    cats = classify_url("https://a.com/api/v1/user/1/invoice/export")
    assert {"api", "user-object", "payment", "export"} <= set(cats)


def test_every_category_declares_why_and_classes():
    for name, (signals, why, classes) in CATEGORIES.items():
        assert signals and why and classes, f"{name} is incomplete"
        assert len(why) > 60, f"{name} needs a real explanation"


# ---------------- full map ----------------

ASSETS = [
    {"url": "https://a.com/", "host": "a.com", "status_code": 200},
    {"url": "https://a.com/api/v1/users/1042/profile", "host": "a.com", "status_code": 200},
    {"url": "https://a.com/admin", "host": "a.com", "status_code": 403},
    {"url": "https://a.com/login", "host": "a.com", "status_code": 200},
    {"url": "https://a.com/go?url=http://x&next=/y", "host": "a.com", "status_code": 302},
    {"url": "https://a.com/doc/550e8400-e29b-41d4-a716-446655440000", "host": "a.com",
     "status_code": 200},
    {"url": "https://a.com/panel", "host": "a.com", "status_code": 401},
]


def test_map_counts_urls():
    assert map_surface(ASSETS)["total_urls"] == len(ASSETS)


def test_map_extracts_interesting_params():
    params = {p["name"]: p for p in map_surface(ASSETS)["params_interesting"]}
    assert params["url"]["class"] == "redirect-ssrf"
    assert params["next"]["class"] == "redirect-ssrf"


def test_map_detects_sequential_and_uuid_ids():
    kinds = {c["kind"] for c in map_surface(ASSETS)["idor_candidates"]}
    assert "sequential numeric ID" in kinds
    assert "UUID" in kinds


def test_map_records_auth_boundaries():
    boundaries = map_surface(ASSETS)["auth_boundaries"]
    assert {b["status"] for b in boundaries} == {401, 403}


def test_map_handles_empty_input():
    m = map_surface([])
    assert m["total_urls"] == 0
    assert m["categories"] == []
    assert priority_hint(m) == []


def test_map_deduplicates_urls():
    dupes = ASSETS + ASSETS
    assert map_surface(dupes)["total_urls"] == len(ASSETS)


def test_hints_mention_high_value_categories():
    hints = " ".join(priority_hint(map_surface(ASSETS))).lower()
    assert "authentication" in hints
    assert "ssrf" in hints or "redirect" in hints
    assert "401/403" in hints


def test_categories_sorted_by_count():
    counts = [c["count"] for c in map_surface(ASSETS)["categories"]]
    assert counts == sorted(counts, reverse=True)


def test_malformed_urls_do_not_crash():
    weird = [{"url": u, "host": "a.com", "status_code": 200}
             for u in ["not a url", "https://", "://broken", "https://a.com/%zz"]]
    assert map_surface(weird)["total_urls"] >= 0
