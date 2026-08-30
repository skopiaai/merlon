"""Attack surface discovery engines.

These widen what gets scanned — certificate transparency, archived URLs,
endpoints buried in JavaScript, paths the site declares. The parsing is the
part worth testing: everything else is a network call.

The property that matters most is at the bottom: assets these engines produce
are scope-checked exactly like any other discovery, so a wider surface can
never become a surface outside the engagement.
"""

import json

import pytest

from app.engines import registry
from app.engines.archive import filter_urls, interesting
from app.engines.ctlogs import parse_crtsh
from app.engines.jsendpoints import extract_paths, to_urls
from app.engines.wellknown import parse_robots, parse_sitemap

# ------------------------------------------------- certificate transparency

CRTSH = json.dumps([
    {"name_value": "www.example.com\nexample.com", "common_name": "www.example.com"},
    {"name_value": "*.example.com", "common_name": "*.example.com"},
    {"name_value": "staging-internal.example.com", "common_name": ""},
    {"name_value": "admin.dev.example.com", "common_name": ""},
    {"name_value": "unrelated.othersite.com", "common_name": ""},
])


def test_ct_extracts_subdomains():
    names = parse_crtsh(CRTSH, "example.com")
    assert "staging-internal.example.com" in names
    assert "admin.dev.example.com" in names
    assert "example.com" in names


def test_ct_drops_wildcards():
    """A wildcard proves the wildcard exists, not that any host does."""
    assert not any(n.startswith("*") for n in parse_crtsh(CRTSH, "example.com"))


def test_ct_drops_other_domains():
    assert "unrelated.othersite.com" not in parse_crtsh(CRTSH, "example.com")


def test_ct_survives_malformed_input():
    assert parse_crtsh("not json", "example.com") == []
    assert parse_crtsh("", "example.com") == []
    assert parse_crtsh('{"not": "a list"}', "example.com") == []


def test_ct_suffix_confusion_is_rejected():
    body = json.dumps([{"name_value": "evil-example.com", "common_name": ""}])
    assert parse_crtsh(body, "example.com") == []


# ------------------------------------------------------------- archived URLs

ARCHIVE = """https://example.com/admin/login.php
https://example.com/admin/login.php
https://example.com/static/logo.png
https://example.com/assets/app.css
https://example.com/item?id=1
https://example.com/item?id=99999
https://example.com/item?id=1&sort=asc
https://old.example.com/backup/db.sql
https://evil.com/phish
not a url at all
"""


def test_archive_keeps_real_endpoints():
    urls = filter_urls(ARCHIVE, "example.com")
    assert any("/admin/login.php" in u for u in urls)


def test_archive_drops_static_assets():
    urls = filter_urls(ARCHIVE, "example.com")
    assert not any(u.endswith((".png", ".css")) for u in urls)


def test_archive_collapses_by_endpoint_shape():
    """/item?id=1 and /item?id=99999 are one endpoint, not two."""
    urls = filter_urls(ARCHIVE, "example.com")
    item_urls = [u for u in urls if "/item" in u]
    # one for ?id=, one for ?id=&sort=  — different parameter sets, same path
    assert len(item_urls) == 2


def test_archive_stays_in_domain():
    assert not any("evil.com" in u for u in filter_urls(ARCHIVE, "example.com"))


def test_archive_includes_subdomains():
    assert any("old.example.com" in u for u in filter_urls(ARCHIVE, "example.com"))


def test_archive_flags_backup_files():
    urls = filter_urls(ARCHIVE, "example.com")
    assert any(u.endswith(".sql") for u in interesting(urls))


def test_archive_respects_cap():
    many = "\n".join(f"https://example.com/p{i}" for i in range(500))
    assert len(filter_urls(many, "example.com", cap=50)) == 50


# ------------------------------------------------------- JS endpoint mining

BUNDLE = """
const routes = {
  users: "/api/v1/users",
  admin: "/admin/settings/flags",
};
fetch("/internal/metrics");
axios.get('/api/v2/orders/{orderId}');
const css = "/static/theme.css";
var re = /^\\/[a-z]+$/;
const remote = "https://api.example.com/v1/health";
const other = "https://cdn.thirdparty.net/api/x";
"""


def test_js_finds_api_routes():
    paths = extract_paths(BUNDLE)
    assert "/api/v1/users" in paths
    assert "/internal/metrics" in paths


def test_js_finds_admin_routes():
    assert "/admin/settings/flags" in extract_paths(BUNDLE)


def test_js_ignores_static_assets():
    assert "/static/theme.css" not in extract_paths(BUNDLE)


def test_js_resolves_to_same_origin_urls():
    urls = to_urls(extract_paths(BUNDLE), "https://example.com/app")
    assert "https://example.com/api/v1/users" in urls
    assert not any("thirdparty.net" in u for u in urls), \
        "a third party's API is not this target's attack surface"


def test_js_strips_template_placeholders():
    urls = to_urls({"/api/v2/orders/{orderId}"}, "https://example.com/")
    assert "https://example.com/api/v2/orders" in urls
    assert not any("{" in u for u in urls)


def test_js_handles_empty_input():
    assert extract_paths("") == set()
    assert to_urls(set(), "https://example.com/") == []


# ------------------------------------------------------------ declared paths

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /internal/backup
Disallow: /images/
Disallow: /
Allow: /public
Sitemap: https://example.com/sitemap.xml
"""

SITEMAP = """<?xml version="1.0"?>
<urlset><url><loc>https://example.com/page-one</loc></url>
<url><loc>https://example.com/hidden/report</loc></url>
<url><loc>https://elsewhere.com/nope</loc></url></urlset>"""


def test_robots_yields_paths():
    paths, sitemaps, sensitive = parse_robots(ROBOTS, "https://example.com")
    assert "https://example.com/admin/" in paths
    assert "https://example.com/sitemap.xml" in sitemaps


def test_robots_flags_sensitive_entries():
    """A Disallow entry is the owner naming what they consider sensitive."""
    _p, _s, sensitive = parse_robots(ROBOTS, "https://example.com")
    assert "/admin/" in sensitive
    assert "/internal/backup" in sensitive
    assert "/images/" not in sensitive


def test_robots_ignores_bare_root_disallow():
    paths, _s, _x = parse_robots(ROBOTS, "https://example.com")
    assert "https://example.com/" not in paths


def test_sitemap_parses_and_stays_in_domain():
    urls = parse_sitemap(SITEMAP, "example.com")
    assert "https://example.com/hidden/report" in urls
    assert not any("elsewhere.com" in u for u in urls)


def test_declared_parsers_survive_junk():
    assert parse_robots("", "https://example.com") == ([], [], [])
    assert parse_sitemap("<html>nope</html>", "example.com") == []


# ------------------------------------------------- the architectural property

def test_discovery_engines_declare_what_they_produce():
    for name in ("ctlogs", "archive", "jsendpoints", "wellknown"):
        spec = registry.get(name)
        assert spec is not None, f"{name} did not register"
        assert spec.produces in ("hosts", "urls"), \
            f"{name} is a discovery engine and must produce assets"


def test_produced_assets_are_scope_filtered():
    """The safety property: widening the surface must not widen the scope."""
    from app.orchestrator import ScanRunner
    runner = ScanRunner(1)

    items = ["api.example.com", "https://staging.example.com/x", "evil.com",
             "https://attacker.net/y"]
    hosts = [runner._host_of(i) for i in items]
    kept = runner._guard(hosts, ["*.example.com"], [], "ctlogs")

    assert "api.example.com" in kept
    assert "staging.example.com" in kept
    assert "evil.com" not in kept
    assert "attacker.net" not in kept
    assert len(runner.rejected) == 2, "out-of-scope assets must be recorded"


@pytest.mark.parametrize("item,expected", [
    ("example.com", "example.com"),
    ("https://api.example.com/path?x=1", "api.example.com"),
    ("example.com:8443", "example.com"),
    ("HTTPS://API.EXAMPLE.COM/", "api.example.com"),
])
def test_host_extraction(item, expected):
    from app.orchestrator import ScanRunner
    assert ScanRunner._host_of(item) == expected
