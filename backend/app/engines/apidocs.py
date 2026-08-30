"""API documentation, GraphQL introspection and framework debug endpoints.

An exposed API specification is not itself a vulnerability, and reporting one
as though it were is a good way to get a report closed as informational. What
it is, is a complete map: every route, every parameter, every expected type,
every authentication scheme — written by the developers and kept current.

For finding real bugs that is worth more than any wordlist. It converts blind
guessing into a checklist of endpoints to test for broken access control, and
it names the parameters that take IDs.

Framework debug endpoints are a different matter and are genuinely severe on
their own. Spring Boot's actuator is the standout: `/actuator/env` prints the
application's configuration including database passwords, and
`/actuator/heapdump` returns a memory dump from which session tokens and
credentials can be extracted with no exploitation at all — it's a file
download.

Two engines live here. One reports exposures; the other parses any specification
it finds and feeds the routes back into the scan, so everything downstream tests
the API the developers documented rather than the pages a crawler could reach.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api/v1/swagger.json",
    "/swagger-ui.html", "/swagger-ui/index.html", "/docs", "/redoc",
    "/api/docs", "/api/schema", "/graphql/schema.json",
]

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                 "/query", "/gql", "/altair", "/playground"]

# Spring Boot actuator and friends. Severity is per-endpoint because the range
# runs from "tells you the version" to "hands you the database password".
DEBUG_PATHS: list[tuple[str, Severity, str]] = [
    ("/actuator/heapdump", Severity.critical,
     "a full memory dump — session tokens, credentials and in-flight data are "
     "recoverable from it with a standard heap analyser, no exploitation needed"),
    ("/actuator/env", Severity.critical,
     "the application's entire configuration, routinely including database "
     "passwords and API keys"),
    ("/actuator/configprops", Severity.high,
     "resolved configuration properties, often including secrets"),
    ("/actuator/threaddump", Severity.medium,
     "a thread dump, which leaks internal class and request detail"),
    ("/actuator/mappings", Severity.medium,
     "every route the application serves, including unlinked ones"),
    ("/actuator/beans", Severity.low, "the internal object graph"),
    ("/actuator/health", Severity.info,
     "health detail — low risk alone, but it confirms actuator is exposed"),
    ("/actuator", Severity.medium, "the actuator index, listing what else is open"),
    ("/_profiler", Severity.high, "the Symfony profiler, with full request history"),
    ("/debug/pprof/", Severity.high, "Go's profiling endpoints, including memory dumps"),
    ("/server-status", Severity.medium, "Apache server-status, listing live requests"),
    ("/server-info", Severity.medium, "Apache configuration detail"),
    ("/telescope/requests", Severity.high, "Laravel Telescope request history"),
    ("/_debugbar/open", Severity.high, "the Laravel debug bar"),
    ("/console", Severity.critical,
     "a Werkzeug/Flask interactive console — if unlocked this is remote code execution"),
    ("/api/__debug__", Severity.medium, "a framework debug endpoint"),
    ("/metrics", Severity.low, "Prometheus metrics, which can leak internal hostnames"),
    ("/.env", Severity.critical, "the application's environment file"),
]

INTROSPECTION = json.dumps({
    "query": "{__schema{queryType{name} types{name kind}}}"
})

SPEC_HINT = re.compile(r'"(?:swagger|openapi)"\s*:', re.I)


def looks_like_spec(body: str) -> bool:
    return bool(SPEC_HINT.search(body or "")) or (
        '"paths"' in (body or "") and '"info"' in (body or ""))


def spec_paths(body: str) -> list[str]:
    """Route templates from an OpenAPI/Swagger document.

    Path templates contain `{id}` placeholders that can't be requested as-is;
    the prefix before the first placeholder is kept, because that prefix is a
    real endpoint and is usually the collection route.
    """
    try:
        doc = json.loads(body or "{}")
    except json.JSONDecodeError:
        return []
    if not isinstance(doc, dict):
        return []

    base = ""
    if isinstance(doc.get("basePath"), str):
        base = doc["basePath"].rstrip("/")
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url") or ""
        if isinstance(url, str) and not url.startswith("http"):
            base = url.rstrip("/")

    out: set[str] = set()
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    for route in paths:
        if not isinstance(route, str) or not route.startswith("/"):
            continue
        clean = route.split("{")[0].rstrip("/") or "/"
        out.add((base + clean) or "/")
    return sorted(out)


def introspection_enabled(body: str) -> bool:
    try:
        doc = json.loads(body or "{}")
    except json.JSONDecodeError:
        return False
    data = doc.get("data") if isinstance(doc, dict) else None
    return isinstance(data, dict) and isinstance(data.get("__schema"), dict)


@register(EngineSpec(
    name="apidocs",
    label="Looking for API docs and debug endpoints",
    description="Swagger/OpenAPI specifications, GraphQL introspection, and "
                "framework debug endpoints. Actuator heapdump and env are "
                "credential disclosure, not information disclosure.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=5,
    limit=20,
    default_in=("standard", "deep"),
))
async def _apidocs(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []

    for origin in fetch.origins(targets)[:8]:
        host = (urlparse(origin).hostname or "").lower()

        # --- debug endpoints ---
        async def debug(entry):
            path, sev, what = entry
            resp = await fetch.request(urljoin(origin, path), timeout=10, ctx=ctx)
            if resp.status != 200 or len(resp.body) < 20:
                return None
            if "<html" in resp.body[:200].lower() and path != "/console":
                return None      # the site's own 200 error page
            return path, sev, what, resp

        for hit in await fetch.gather_limited(
                [debug(e) for e in DEBUG_PATHS], limit=6):
            if not hit:
                continue
            path, sev, what, resp = hit
            findings.append({
                "engine": "apidocs", "rule_id": f"debug-endpoint{path.replace('/', '-')}",
                "name": f"Debug endpoint exposed: {path}",
                "severity": sev,
                "host": host, "url": urljoin(origin, path),
                "matched_at": urljoin(origin, path),
                "description": (
                    f"`{path}` is reachable without authentication and returns "
                    f"{what}.\n\n"
                    f"Endpoints like this are almost never exposed deliberately — "
                    f"they are enabled in a development profile and the profile "
                    f"reaches production. Treat the presence of one as a reason to "
                    f"check for the others in the same family."),
                "evidence": f"GET {urljoin(origin, path)} → HTTP {resp.status}, "
                            f"{len(resp.body)} bytes\n"
                            f"{resp.body[:400]}",
                "remediation": (
                    "Disable the endpoint in production rather than firewalling it.\n\n"
                    "  Spring Boot: management.endpoints.web.exposure.include=health\n"
                    "               management.endpoint.health.show-details=never\n"
                    "  Symfony:     remove the profiler bundle from prod\n"
                    "  Laravel:     APP_DEBUG=false, remove Telescope from prod\n"
                    "  Flask:       never run with debug=True outside development\n"
                    "  Apache:      remove mod_status / mod_info\n\n"
                    "If `env`, `heapdump` or `.env` was reachable, treat every "
                    "credential the application holds as disclosed and rotate them "
                    "— you cannot know who fetched it."),
                "references": [
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                "tags": ["exposure", "misconfig", "debug"], "cve": [],
                "cwe": ["CWE-200", "CWE-489"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("apidocs", f"debug{path}", host, origin),
                "raw": {"path": path},
            })

        # --- API specifications ---
        async def spec(path):
            resp = await fetch.request(urljoin(origin, path), timeout=12, ctx=ctx)
            return path, resp

        for path, resp in [r for r in await fetch.gather_limited(
                [spec(p) for p in SPEC_PATHS], limit=6) if r]:
            if resp.status != 200 or not looks_like_spec(resp.body):
                continue
            routes = spec_paths(resp.body)
            findings.append({
                "engine": "apidocs", "rule_id": "api-spec-exposed",
                "name": "API specification publicly readable",
                "severity": Severity.low,
                "host": host, "url": urljoin(origin, path),
                "matched_at": urljoin(origin, path),
                "description": (
                    f"An OpenAPI/Swagger document is served at `{path}` without "
                    f"authentication, describing "
                    f"{len(routes) or 'an unknown number of'} routes.\n\n"
                    f"This is low severity by itself and may be intentional for a "
                    f"public API. It matters because it removes all guesswork from "
                    f"attacking the API: every route, parameter and auth scheme is "
                    f"documented. If any of those routes rely on being unknown, "
                    f"they no longer are.\n\n"
                    f"The routes it names have been added to this scan."),
                "evidence": f"GET {urljoin(origin, path)} → HTTP 200\n"
                            + "\n".join(f"  {r}" for r in routes[:25]),
                "remediation": (
                    "If the API is internal, require authentication for the spec "
                    "and the UI, or don't ship them to production at all.\n\n"
                    "If the API is public, leaving the spec up is reasonable — but "
                    "then confirm every documented route enforces authorisation "
                    "server-side, because you have published the map."),
                "references": ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                "tags": ["exposure", "api"], "cve": [], "cwe": ["CWE-200"],
                "cvss_score": None,
                "dedupe_key": make_dedupe_key("apidocs", "api-spec", host, origin),
                "raw": {"path": path, "routes": routes[:200]},
            })

        # --- GraphQL introspection ---
        async def gql(path):
            url = urljoin(origin, path)
            resp = await fetch.request(
                url, method="POST", data=INTROSPECTION,
                headers={"Content-Type": "application/json"}, timeout=12, ctx=ctx)
            return url, resp

        for url, resp in [r for r in await fetch.gather_limited(
                [gql(p) for p in GRAPHQL_PATHS], limit=4) if r]:
            if not introspection_enabled(resp.body):
                continue
            findings.append({
                "engine": "apidocs", "rule_id": "graphql-introspection",
                "name": "GraphQL introspection enabled",
                "severity": Severity.medium,
                "host": host, "url": url, "matched_at": url,
                "description": (
                    "The GraphQL endpoint answers introspection queries, returning "
                    "its complete schema — every type, field, mutation and "
                    "argument, including the ones the published client never "
                    "calls.\n\n"
                    "GraphQL concentrates a lot of surface behind one URL, and "
                    "authorisation is enforced per-resolver. Introspection hands "
                    "over the list of resolvers to try. Deprecated mutations and "
                    "admin-only fields left in the schema are the usual finding."),
                "evidence": f"POST {url} → HTTP {resp.status}, __schema returned\n"
                            f"{resp.body[:300]}",
                "remediation": (
                    "Disable introspection in production (Apollo: "
                    "`introspection: false`; graphql-js: a validation rule "
                    "rejecting `__schema`).\n\n"
                    "Then treat that as defence in depth rather than a fix — the "
                    "schema can still be recovered field by field through error "
                    "messages and suggestion hints. The real work is enforcing "
                    "authorisation in every resolver, plus query depth and "
                    "complexity limits so a nested query can't become a denial of "
                    "service."),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                ],
                "tags": ["exposure", "api", "graphql"], "cve": [],
                "cwe": ["CWE-200"], "cvss_score": 5.3,
                "dedupe_key": make_dedupe_key("apidocs", "graphql-introspection",
                                              host, url),
                "raw": {},
            })

    if log:
        await log("info", f"[apidocs] {len(findings)} API/debug exposure(s)", "apidocs")
        crit = [f for f in findings if f["severity"] is Severity.critical]
        if crit:
            await log("error",
                      f"[apidocs] {len(crit)} endpoint(s) disclose credentials "
                      f"directly — rotate anything they exposed: "
                      f"{', '.join(f['raw'].get('path', '') for f in crit)}",
                      "apidocs")
    return findings


@register(EngineSpec(
    name="apispec",
    label="Importing documented API routes",
    description="Parses any OpenAPI/Swagger document found and adds the routes it "
                "declares to the scan, so later stages test the API the developers "
                "documented rather than the pages a crawler can reach.",
    phase="post_http",
    takes="urls",
    produces="urls",
    weight=3,
    limit=10,
    default_in=("standard", "deep"),
))
async def _apispec(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")
    found: set[str] = set()

    for origin in fetch.origins(targets)[:6]:
        for path in SPEC_PATHS:
            resp = await fetch.request(urljoin(origin, path), timeout=12, ctx=ctx)
            if resp.status != 200 or not looks_like_spec(resp.body):
                continue
            for route in spec_paths(resp.body):
                found.add(urljoin(origin, route))
            break   # one spec per origin is enough

    result = sorted(found)
    if log and result:
        await log("info",
                  f"[apispec] {len(result)} documented route(s) added to the scan",
                  "apispec")
    return result
