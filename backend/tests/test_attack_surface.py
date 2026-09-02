"""Active testing engines.

Everything here is a pure function pulled out of an engine so the judgement
can be tested without a network. The judgement is the part that goes wrong:
deciding whether a 200 is real, whether a redirect actually leaves the site,
whether a CNAME is claimable. Getting those wrong doesn't crash anything — it
produces a report full of findings that aren't true, which is worse.

Several tests below exist specifically to hold a false positive down. They're
marked where that's the point.
"""

import pytest

from app.engines import registry
from app.engines.apidocs import introspection_enabled, looks_like_spec, spec_paths
from app.engines.cors import analyse, probe_origins
from app.engines.exposures import confirms, redact
from app.engines.favicon import favicon_hash, icon_urls, murmur3_32
from app.engines.fetch import _parse, origins
from app.engines.methods import parse_allow, path_variants, risky
from app.engines.netblock import parse_asnmap, usable_networks
from app.engines.paramminer import chunk, differs, with_params
from app.engines.redirect import candidate_urls, inject, payloads, redirects_offsite
from app.engines.takeover import body_confirms, match_service
from app.engines.vhosts import is_distinct
from app.models import Severity


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ------------------------------------------------------------ HTTP plumbing

def test_response_parsing():
    raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<h1>hi</h1>"
    status, headers, body = _parse(raw)
    assert status == 200
    assert headers["server"] == "nginx"
    assert body == b"<h1>hi</h1>"


def test_redirect_chain_keeps_the_last_response():
    raw = (b"HTTP/1.1 301 Moved\r\nLocation: /next\r\n\r\n"
           b"HTTP/1.1 200 OK\r\nX-Final: yes\r\n\r\nbody")
    status, headers, body = _parse(raw)
    assert status == 200 and headers["x-final"] == "yes" and body == b"body"


def test_duplicate_headers_are_joined_not_overwritten():
    """Two Allow-Origin values is itself the finding — don't lose one."""
    raw = (b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: a\r\n"
           b"Access-Control-Allow-Origin: b\r\n\r\n")
    _s, headers, _b = _parse(raw)
    assert headers["access-control-allow-origin"] == "a, b"


def test_parse_survives_junk():
    assert _parse(b"") == (0, {}, b"")
    assert _parse(b"not http at all")[0] == 0


def test_origins_are_deduplicated():
    assert origins(["https://a.com/x", "https://a.com/y", "http://a.com/z"]) == \
        ["http://a.com", "https://a.com"]


# ------------------------------------------------------------- takeover

def test_service_matched_by_cname():
    assert match_service("myapp.herokuapp.com").name == "Heroku"
    assert match_service("proj.github.io").name == "GitHub Pages"


def test_longest_suffix_wins():
    """.s3.amazonaws.com must beat the shorter .amazonaws.com entry."""
    assert match_service("bucket.s3.amazonaws.com").name == "Amazon S3"


def test_unknown_cname_is_not_a_service():
    assert match_service("internal.corp.example.com") is None
    assert match_service("") is None


def test_unclaimable_services_are_flagged_as_such():
    """The point of listing them: suppressing a false critical."""
    cf = match_service("d1234.cloudfront.net")
    assert cf is not None and cf.claimable is False
    assert match_service("www.akamaiedge.net").claimable is False


def test_body_confirms_only_on_the_service_error_page():
    heroku = match_service("x.herokuapp.com")
    assert body_confirms(heroku, "<h1>No such app</h1>")
    assert not body_confirms(heroku, "<h1>Welcome to our store</h1>")


def test_body_confirms_is_false_without_a_fingerprint():
    assert not body_confirms(match_service("x.cloudfront.net"), "anything")


# ----------------------------------------------------------------- CORS

BASE = {"access-control-allow-origin": "https://attacker.invalid",
        "access-control-allow-credentials": "true"}


def test_reflected_origin_with_credentials_is_critical():
    issue = analyse("https://attacker.invalid", "arbitrary-origin", BASE, "t.com")
    assert issue["severity"] is Severity.critical


def test_reflected_origin_without_credentials_is_lower():
    headers = {"access-control-allow-origin": "https://attacker.invalid"}
    issue = analyse("https://attacker.invalid", "arbitrary-origin", headers, "t.com")
    assert issue["severity"] is Severity.medium


def test_null_origin_detected():
    headers = {"access-control-allow-origin": "null",
               "access-control-allow-credentials": "true"}
    assert analyse("null", "null-origin", headers, "t.com")["rule"] == "cors-null-origin"


def test_wildcard_with_credentials_is_not_overstated():
    """Browsers refuse it, so it isn't exploitable — don't report it as if it is."""
    headers = {"access-control-allow-origin": "*",
               "access-control-allow-credentials": "true"}
    issue = analyse("https://attacker.invalid", "arbitrary-origin", headers, "t.com")
    assert issue["severity"] is Severity.low


def test_fixed_allowed_origin_is_not_a_finding():
    """Echoing a different, configured origin is correct behaviour."""
    headers = {"access-control-allow-origin": "https://app.t.com",
               "access-control-allow-credentials": "true"}
    assert analyse("https://attacker.invalid", "arbitrary-origin", headers, "t.com") is None


def test_absent_cors_headers_are_not_a_finding():
    assert analyse("https://attacker.invalid", "arbitrary-origin", {}, "t.com") is None


def test_bypass_probes_cover_prefix_and_suffix_confusion():
    kinds = {k for _o, k in probe_origins("t.com")}
    assert {"suffix-bypass", "prefix-bypass", "null-origin"} <= kinds


def test_probe_origins_never_name_an_unrelated_third_party():
    """Probe origins are sent as header values and never connected to — but an
    origin naming a real, unrelated company would still appear in the report and
    in the target's logs. Every probe is either unresolvable (.invalid) or a
    variation on the target's own name."""
    for origin, _kind in probe_origins("t.com"):
        if origin == "null":
            continue
        assert ".invalid" in origin or "t.com" in origin, \
            f"{origin} names a third party that has nothing to do with this scan"


# ------------------------------------------------------------ open redirect

def test_absolute_offsite_redirect_detected():
    assert redirects_offsite("https://redirect-canary.invalid/")


def test_protocol_relative_and_backslash_forms_detected():
    assert redirects_offsite("//redirect-canary.invalid/x")
    assert redirects_offsite("https:/\\redirect-canary.invalid")


def test_userinfo_confusion_detected():
    assert redirects_offsite("https://target.com@redirect-canary.invalid/")


def test_reflected_canary_in_a_local_redirect_is_not_a_finding():
    """The most common false positive in open-redirect scanning."""
    assert not redirects_offsite(
        "https://target.com/login?next=https://redirect-canary.invalid")
    assert not redirects_offsite("/login?next=https://redirect-canary.invalid")


def test_unrelated_redirect_is_not_a_finding():
    assert not redirects_offsite("https://target.com/home")
    assert not redirects_offsite("")


def test_existing_redirect_parameters_are_preferred():
    found = candidate_urls("https://t.com/login?next=/home&lang=en")
    assert [p for _u, p, _v in found] == ["next"]


def test_urls_without_redirect_parameters_get_candidates_appended():
    found = candidate_urls("https://t.com/login")
    assert len(found) >= 5
    assert all(p for _u, p, _v in found)


def test_injection_replaces_rather_than_duplicates():
    out = inject("https://t.com/a?next=/home&x=1", "next", "https://c.invalid")
    assert out.count("next=") == 1
    assert "x=1" in out


def test_every_payload_targets_the_reserved_tld():
    for value, _kind in payloads("t.com"):
        assert ".invalid" in value


# ------------------------------------------------------ methods and bypass

def test_allow_header_parsing():
    assert parse_allow("GET, POST,  PUT , TRACE") == ["GET", "POST", "PUT", "TRACE"]
    assert parse_allow("") == []


def test_only_risky_methods_are_reported():
    assert risky(["GET", "POST", "HEAD", "OPTIONS"]) == []
    assert set(risky(["GET", "PUT", "TRACE"])) == {"PUT", "TRACE"}


def test_bypass_variants_are_read_only():
    """No variant may imply a write — proving PUT works means modifying a
    server you don't own."""
    for variant, _why in path_variants("/admin"):
        assert "?" not in variant or variant.endswith("?")


def test_bypass_variants_cover_the_known_proxy_confusions():
    whys = {w for _v, w in path_variants("/admin")}
    assert {"trailing slash", "dot segment", "encoded dot prefix"} <= whys


# --------------------------------------------------------------- API docs

SWAGGER = """{"swagger":"2.0","info":{"title":"x"},"basePath":"/api",
"paths":{"/users":{},"/users/{id}":{},"/admin/reset":{}}}"""

OPENAPI3 = """{"openapi":"3.0.0","info":{"title":"x"},
"paths":{"/v1/orders":{},"/v1/orders/{orderId}/items":{}}}"""


def test_spec_detection():
    assert looks_like_spec(SWAGGER)
    assert looks_like_spec(OPENAPI3)
    assert not looks_like_spec("<html><body>404</body></html>")


def test_spec_routes_extracted_with_base_path():
    routes = spec_paths(SWAGGER)
    assert "/api/users" in routes
    assert "/api/admin/reset" in routes


def test_template_placeholders_collapse_to_the_real_prefix():
    routes = spec_paths(OPENAPI3)
    assert "/v1/orders" in routes
    assert not any("{" in r for r in routes)


def test_spec_parsing_survives_junk():
    assert spec_paths("not json") == []
    assert spec_paths('{"paths": "not a dict"}') == []


def test_graphql_introspection_detection():
    assert introspection_enabled('{"data":{"__schema":{"types":[]}}}')
    assert not introspection_enabled('{"errors":[{"message":"disabled"}]}')
    assert not introspection_enabled("")


# ------------------------------------------------------------ param mining

def test_batches_cover_every_candidate_exactly_once():
    items = [f"p{i}" for i in range(50)]
    flat = [x for group in chunk(items, 24) for x in group]
    assert flat == items


def test_parameters_are_appended_not_replacing_existing():
    out = with_params("https://t.com/a?keep=1", ["debug"])
    assert "keep=1" in out and "debug=" in out


def test_reflection_is_the_strong_signal():
    assert differs(200, 100, "hello", 200, 100, "hello z9q4x7t2") == "reflected"


def test_small_length_jitter_is_not_a_finding():
    """Pages carry CSRF tokens and timestamps; 20 bytes of drift means nothing."""
    assert differs(200, 5000, "x", 200, 5020, "x") == ""


def test_large_length_change_is_a_signal():
    assert differs(200, 1000, "x", 200, 4000, "x") == "length"


def test_status_change_is_a_signal():
    assert differs(200, 100, "x", 500, 100, "x") == "status"


def test_canary_already_present_in_baseline_is_ignored():
    assert differs(200, 10, "z9q4x7t2", 200, 10, "z9q4x7t2") == ""


# ---------------------------------------------------------------- exposures

SPA_SHELL = "<!doctype html><html><head><title>App</title></head><body></body></html>"


def test_real_git_config_confirmed():
    assert confirms("/.git/config", "[core]\n\trepositoryformatversion = 0", 200)


def test_spa_catch_all_is_rejected():
    """Without this, every single-page app reports forty exposed files."""
    assert not confirms("/.env", SPA_SHELL, 200)
    assert not confirms("/.git/config", SPA_SHELL, 200)


def test_non_200_is_rejected():
    assert not confirms("/.env", "DB_PASSWORD=hunter2", 404)


def test_unknown_path_is_rejected():
    assert not confirms("/nothing-we-check", "anything", 200)


def test_credentials_are_redacted_from_evidence():
    text = redact("DB_PASSWORD=hunter2\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\napp=demo")
    assert "hunter2" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "app=demo" in text, "redaction shouldn't destroy the useful context"


def test_private_keys_are_truncated():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
    assert "MIIEow" not in redact(body)


# ------------------------------------------------------------------ favicon

def test_murmur3_known_vectors():
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"hello") == 613153351
    assert murmur3_32(b"The quick brown fox jumps over the lazy dog") == 776992547


def test_favicon_hash_is_stable_and_signed():
    value = favicon_hash(b"\x00\x01\x02" * 200)
    assert isinstance(value, int)
    assert favicon_hash(b"\x00\x01\x02" * 200) == value
    assert -2**31 <= value < 2**31


def test_declared_icons_and_the_conventional_path_are_both_tried():
    html = '<link rel="shortcut icon" href="/static/brand.png">'
    urls = icon_urls(html, "https://t.com/page")
    assert "https://t.com/static/brand.png" in urls
    assert "https://t.com/favicon.ico" in urls


# ------------------------------------------------------------------- vhosts

def test_default_response_is_not_a_vhost():
    assert not is_distinct(200, 5000, 200, 5010)


def test_different_status_is_a_vhost():
    assert is_distinct(404, 200, 200, 3000)


def test_much_larger_body_is_a_vhost():
    assert is_distinct(200, 500, 200, 9000)


def test_failed_request_is_not_a_vhost():
    assert not is_distinct(200, 500, 0, 0)


# ----------------------------------------------------------------- netblock

ASNMAP = "\n".join([
    '{"as_number":"AS64512","as_name":"EXAMPLE-ORG","as_country":"IN",'
    '"as_range":["203.0.113.0/24"]}',
    '{"as_number":"AS64512","as_name":"EXAMPLE-ORG","as_range":["198.51.100.0/22"]}',
])


def test_asnmap_records_parsed():
    records = parse_asnmap(ASNMAP)
    assert records[0]["asn"] == "AS64512"
    assert "203.0.113.0/24" in records[0]["ranges"]


def test_asnmap_survives_junk():
    assert parse_asnmap("not json\n\n") == []
    assert parse_asnmap("") == []


def test_reasonable_prefixes_are_expanded():
    addresses = usable_networks(parse_asnmap(ASNMAP))
    assert "203.0.113.1" in addresses


def test_oversized_prefixes_are_skipped_not_truncated():
    """The first 1024 addresses of a /16 aren't a sample of it."""
    huge = '{"as_number":"AS1","as_name":"X","as_range":["10.0.0.0/16"]}'
    assert usable_networks(parse_asnmap(huge)) == []


def test_expansion_is_capped():
    assert len(usable_networks(parse_asnmap(ASNMAP), limit=10)) == 10


# ------------------------------------------- registration and safety wiring

NEW_ENGINES = ["takeover", "cors", "redirect", "methods", "authbypass",
               "apidocs", "apispec", "paramminer", "exposures", "favicon",
               "vhosts", "netblock", "asninfo"]


@pytest.mark.parametrize("name", NEW_ENGINES)
def test_engine_is_registered_and_wired(name):
    from app.schemas import DEPTH_PRESETS, VALID_STAGES
    spec = registry.get(name)
    assert spec is not None, f"{name} did not register"
    assert name in VALID_STAGES
    for depth in spec.default_in:
        assert name in DEPTH_PRESETS[depth][1]


@pytest.mark.parametrize("name", NEW_ENGINES)
def test_engine_findings_map_to_a_control(name):
    """Nothing new may land in a compliance report as uncategorised."""
    from app import compliance
    spec = registry.get(name)
    if spec.produces != "findings":
        pytest.skip("discovery engine, produces assets")
    assert compliance.controls_for({"rule_id": f"{name}-anything",
                                    "tags": [], "cwe": []}).owasp_top10


@pytest.mark.parametrize("rule", [
    "subdomain-takeover-confirmed", "dangling-cname", "cors-null-origin",
    "open-redirect", "dangerous-http-methods", "access-control-bypass",
    "api-spec-exposed", "graphql-introspection", "debug-endpoint-actuator-env",
    "hidden-parameter-privileged", "exposed-.git-config", "favicon-hash",
    "hidden-vhost", "asn-inventory",
])
def test_new_rules_have_specific_control_mappings(rule):
    from app import compliance
    controls = compliance.controls_for({"rule_id": rule, "tags": [], "cwe": []})
    assert controls.owasp_top10
    assert controls.gigw != "General security", \
        f"{rule} fell through to the catch-all instead of a real mapping"


def test_existing_exposure_rules_were_not_shadowed():
    """A broad `exposed-` prefix must not steal the specific mappings."""
    from app import compliance
    assert compliance.controls_for({"rule_id": "exposed-surface", "tags": [],
                                    "cwe": []}).owasp_top10.startswith("A01")
    assert compliance.controls_for({"rule_id": "exposed-service", "tags": [],
                                    "cwe": []}).owasp_top10.startswith("A05")


def test_active_engines_are_not_in_the_quick_preset():
    """Quick is what someone runs against their own site to see if it works.
    It should stay fast and quiet; heavy probing belongs in deeper presets."""
    from app.schemas import DEPTH_PRESETS
    quick = DEPTH_PRESETS["quick"][1]
    for name in ("paramminer", "authbypass", "vhosts", "netblock"):
        assert name not in quick
