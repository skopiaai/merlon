"""Agent manifests and RAG infrastructure — the AI surface that isn't a chatbox.

`llmapps` and `aiexfil` test the assistant a user talks to. This engine looks
for the parts nobody put a login on because they are "internal":

**Agent manifests.** `/.well-known/ai-plugin.json`, `agent-card.json`,
`agents.json`, `llms.txt`, `/.well-known/mcp.json`. These are published on
purpose and are meant to be read — that is not the finding. The finding is what
they disclose: internal API base URLs, the full tool list an agent can call,
auth schemes, and often a staging host nobody meant to name. It is the
`swagger.json` of 2026, and it is being deployed with the same care swagger was
in 2016.

**Vector databases.** Qdrant, Weaviate, Chroma, Milvus and friends ship with
authentication *off* by default, and get stood up next to an app by whoever
built the RAG pipeline. An open one is worth more than it first looks:

  * every embedded document is readable — that is the knowledge base, often
    including whatever internal wiki was fed into it;
  * collections are writable, which is memory poisoning (ASI06) with
    persistence — you are not injecting into one conversation, you are editing
    what the assistant believes for everybody, permanently;
  * in a shared-tenant deployment, retrieval crosses tenants (LLM08).

**Inference servers.** Ollama, vLLM, text-generation-inference, LM Studio, and
the OpenAI-compatible ports they listen on. An exposed one is free compute at
the operator's expense (LLM10) and frequently reveals which fine-tuned models
exist, which is itself intelligence about the product.

Read-only, throughout. Collections are listed, never written; models are
enumerated, never invoked. Writing a document into someone's vector store to
prove it is writable would be planting an instruction inside a system that
feeds an LLM — the exact attack this engine exists to warn about.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .exposures import redact
from .registry import EngineSpec, register

# ------------------------------------------------------------------ manifests

MANIFEST_PATHS = [
    ("/.well-known/ai-plugin.json", "OpenAI plugin manifest"),
    ("/.well-known/agent.json", "agent descriptor"),
    ("/.well-known/agent-card.json", "A2A agent card"),
    ("/.well-known/mcp.json", "MCP server descriptor"),
    ("/.well-known/llms.txt", "llms.txt"),
    ("/llms.txt", "llms.txt"),
    ("/llms-full.txt", "llms-full.txt"),
    ("/agents.json", "agent descriptor"),
    ("/ai-plugin.json", "OpenAI plugin manifest"),
    ("/.well-known/openai.json", "OpenAI descriptor"),
]

# What makes a manifest worth reporting rather than noting. Each of these is a
# thing the operator probably did not mean to publish.
INTERNAL_HOST = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"(?:10|127)\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"[\w.-]*\.(?:internal|local|localdomain|intranet|corp|lan)\b|"
    r"[\w.-]*(?:staging|stage|dev|test|qa|uat|preprod|sandbox)[\w.-]*)",
    re.I)

SECRET_ISH = re.compile(
    r"(?i)\"(?:api[_-]?key|apikey|token|secret|password|passwd|bearer|"
    r"client[_-]?secret|authorization)\"\s*:\s*\"([^\"]{8,})\"")

# Auth schemes that mean the manifest describes something unauthenticated.
NO_AUTH = re.compile(r"\"type\"\s*:\s*\"none\"", re.I)

# Tool names are overwhelmingly snake_case — `delete_user`, `run_query`,
# `send_email`. A trailing `\b` after the verb never matches those, because
# underscore is a word character, so the anchored version finds a `delete` tool
# and misses every `delete_*` one. The optional suffix group is the whole point.
DANGEROUS_CAPABILITY = re.compile(
    r"(?i)\b(?:delete|drop|remove|destroy|exec|execute|run|shell|eval|write|"
    r"send|transfer|payment|refund|purchase|admin|sudo|terminate|deploy|"
    r"revoke|grant|disable|reset)(?:[_-]?[a-z]+){0,2}\b")

# ------------------------------------------------------------- vector stores
#
# Path + a fingerprint that must appear in the body. The fingerprint matters:
# port 8000 and /api/v1/collections are common enough that a path match alone
# would report half the internet as an exposed Chroma instance.

VECTOR_PROBES = [
    ("/collections", r"\"result\"\s*:\s*\{\s*\"collections\"", 6333,
     "Qdrant"),
    ("/", r"\"title\"\s*:\s*\"qdrant", 6333, "Qdrant"),
    ("/v1/schema", r"\"classes\"\s*:", 8080, "Weaviate"),
    ("/v1/meta", r"\"version\"\s*:.*\"hostname\"", 8080, "Weaviate"),
    ("/api/v1/collections", r"^\s*\[|\"name\"\s*:.*\"id\"\s*:", 8000,
     "Chroma"),
    ("/api/v2/heartbeat", r"nanosecond heartbeat", 8000, "Chroma"),
    ("/v1/vector/collections", r"\"data\"\s*:\s*\[", 19530, "Milvus"),
]

INFERENCE_PROBES = [
    ("/api/tags", r"\"models\"\s*:\s*\[", 11434, "Ollama"),
    ("/v1/models", r"\"object\"\s*:\s*\"list\".*\"data\"", 8000, "vLLM"),
    ("/info", r"\"model_id\"\s*:", 8080, "text-generation-inference"),
    ("/v1/models", r"\"object\"\s*:\s*\"list\"", 1234, "LM Studio"),
    ("/v2/models", r"\"name\"\s*:.*\"versions\"", 8000,
     "NVIDIA Triton"),
]


# Keys that only a real agent/plugin manifest declares. A generic JSON health
# response has none of them, which is what separates "this is a manifest" from
# "this server returns JSON for every path".
MANIFEST_KEYS = re.compile(
    r"\"(?:schema_version|name_for_(?:human|model)|description_for_(?:human|model)|"
    r"api|auth|tools|functions|capabilities|skills|endpoints|"
    r"protocolVersion|mcpVersion|serverInfo|agent|provider|contact_email|"
    r"logo_url|legal_info_url|model|version)\"\s*:", re.I)


def looks_like_manifest(body: str) -> bool:
    """Does this JSON actually declare an agent surface?

    Deliberately requires two distinct keys rather than one. `"version":` alone
    appears in most health endpoints, and a single-key threshold put the
    catch-all responses straight back into the report.
    """
    keys = {m.group(0).lower() for m in MANIFEST_KEYS.finditer(body or "")}
    return len(keys) >= 2


def manifest_risks(body: str) -> list[str]:
    """What a published manifest gives away that it should not."""
    risks = []

    internal = sorted({m.group(0) for m in INTERNAL_HOST.finditer(body)})
    if internal:
        risks.append(
            "names non-public hosts: " + ", ".join(internal[:5])
            + (f" (+{len(internal) - 5} more)" if len(internal) > 5 else ""))

    secrets = SECRET_ISH.findall(body)
    if secrets:
        # Never echo the value. The count and the key name are enough to act on.
        keys = sorted({m.group(1) for m in
                       re.finditer(r"\"([\w-]*(?:key|token|secret|password)[\w-]*)\"\s*:\s*\"[^\"]{8,}\"",
                                   body, re.I)})
        risks.append(f"contains {len(secrets)} credential-shaped value(s) "
                     f"under key(s): {', '.join(keys[:5]) or 'unnamed'} "
                     f"— values withheld from this report")

    if NO_AUTH.search(body):
        risks.append('declares "auth": {"type": "none"} — anything the tools '
                     'expose is reachable without a credential')

    caps = sorted({m.group(0).lower() for m in DANGEROUS_CAPABILITY.finditer(body)})
    if caps:
        risks.append("advertises state-changing capabilities: "
                     + ", ".join(caps[:8]))

    return risks


def parse_collections(body: str) -> list[str]:
    """Collection or class names from a vector store listing, best-effort.

    Each product shapes this differently and the names themselves are the
    useful part — `hr_policies_2026` tells you what was embedded, which is the
    impact sentence the report needs.
    """
    names: list[str] = []
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return names

    def walk(node, depth=0):
        if depth > 6 or len(names) > 60:
            return
        if isinstance(node, dict):
            for key in ("name", "class", "collection_name", "collectionName"):
                val = node.get(key)
                if isinstance(val, str) and val and val not in names:
                    names.append(val)
            for v in node.values():
                walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node:
                walk(v, depth + 1)

    walk(data)
    return names[:40]


def parse_models(body: str) -> list[str]:
    """Model names from an inference server listing."""
    names: list[str] = []
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return names
    for key in ("models", "data"):
        items = data.get(key) if isinstance(data, dict) else None
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("id") or item.get("model")
                    if isinstance(name, str) and name not in names:
                        names.append(name)
    if isinstance(data, dict) and isinstance(data.get("model_id"), str):
        names.append(data["model_id"])
    return names[:40]


async def _check(url: str, pattern: str, ctx: dict):
    """GET and confirm the fingerprint. Returns the response or None."""
    resp = await fetch.request(url, ctx=ctx, timeout=12)
    if not resp.ok or not resp.body:
        return None
    if re.search(pattern, resp.body, re.I | re.S):
        return resp
    return None


@register(EngineSpec(
    name="aisurface",
    label="Finding agent manifests and RAG infrastructure",
    description="Looks for the AI surface that isn't a chat box: published "
                "agent and plugin manifests that disclose internal endpoints "
                "and tool lists, vector databases running with authentication "
                "off, and exposed inference servers. Read-only — lists "
                "collections and models, never writes or invokes.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=8,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []

    for origin in fetch.origins(targets)[:6]:
        host = (urlparse(origin).hostname or "").lower()

        # --- 1. published manifests ----------------------------------------
        # Per origin, not global: two different hosts legitimately serving the
        # same manifest are two findings.
        seen_bodies: dict[int, int] = {}
        for path, kind in MANIFEST_PATHS:
            url = urljoin(origin, path)
            resp = await fetch.request(url, ctx=ctx, timeout=12)
            if not resp.ok or not resp.body or len(resp.body) < 20:
                continue
            # An SPA that returns index.html for everything would otherwise
            # report ten manifests per origin.
            ctype = (resp.headers or {}).get("content-type", "").lower()
            is_json = "json" in ctype or resp.body.lstrip().startswith(("{", "["))
            is_text = path.endswith(".txt") and "html" not in ctype
            if not (is_json or is_text):
                continue

            # Being JSON is not enough. A catch-all route — an API gateway
            # default, a framework returning {"status":"ok"} for anything
            # unmatched — answers all ten of these paths and produced ten
            # "manifest" findings, which is the kind of noise that teaches you
            # to skim past the engine entirely.
            #
            # Two guards. First: the body has to contain something a manifest
            # actually declares.
            if is_json and not looks_like_manifest(resp.body):
                continue
            # Second: identical bodies across different paths mean the server
            # is not serving ten manifests, it is ignoring the path.
            fingerprint = hash(resp.body[:2000])
            if fingerprint in seen_bodies:
                seen_bodies[fingerprint] += 1
                continue
            seen_bodies[fingerprint] = 1

            risks = manifest_risks(resp.body)
            severity = Severity.info
            if any("credential-shaped" in r for r in risks):
                severity = Severity.high
            elif any("non-public hosts" in r for r in risks):
                severity = Severity.medium
            elif risks:
                severity = Severity.low

            findings.append({
                "engine": "aisurface",
                "rule_id": "ai-manifest",
                "name": f"{kind} published at {path}",
                "severity": severity,
                "host": host,
                "url": url,
                "description": (
                    f"A {kind} is served here. Publishing one is intentional and "
                    f"not itself a problem — agents are meant to read it.\n\n"
                    + ("What it discloses is the issue:\n"
                       + "\n".join(f"  • {r}" for r in risks)
                       if risks else
                       "Nothing sensitive was detected in it. Recorded so you "
                       "know the AI surface exists and can revisit it when the "
                       "manifest changes — these files gain tools over time and "
                       "rarely get re-reviewed.")
                    + "\n\nTreat this the way you would treat an exposed OpenAPI "
                      "document: it is a map of the internal API, written by the "
                      "developer, kept up to date."),
                # Redacted, not truncated. A manifest that names a credential
                # is precisely the one worth quoting, and quoting it verbatim
                # copies the secret into a report that gets stored, exported to
                # SARIF and pasted into a ticket.
                "evidence": (f"GET {url}\n"
                             f"HTTP {resp.status} · {ctype or 'no content-type'} · "
                             f"{len(resp.body)} bytes\n\n"
                             + redact(resp.body[:1200])
                             + ("\n… (truncated)" if len(resp.body) > 1200 else "")),
                "remediation": (
                    "  • Keep internal hostnames, staging URLs and credentials out "
                    "of the manifest. It is a public file by design.\n"
                    "  • Publish only the tools an anonymous agent should know "
                    "about; describe privileged ones in an authenticated "
                    "manifest, if at all.\n"
                    "  • Review it whenever a tool is added — manifests accrete "
                    "and nobody re-reads them.\n"
                    "  • Make sure every endpoint it names enforces its own "
                    "authorization. The manifest is a description, not a control."),
                "references": [
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
                    "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
                ],
                "tags": ["ai", "agent", "manifest", "disclosure", "asi04"],
                "cve": [], "cwe": ["CWE-200"],
                "cvss_score": 7.5 if severity is Severity.high else
                              5.3 if severity is Severity.medium else 0.0,
                "dedupe_key": make_dedupe_key("aisurface", "ai-manifest", host, url),
                "raw": {"kind": kind, "risks": risks},
            })

        # --- 2. vector stores ------------------------------------------------
        for path, pattern, default_port, product in VECTOR_PROBES:
            for base in (origin, f"{urlparse(origin).scheme}://{host}:{default_port}"):
                url = urljoin(base, path)
                resp = await _check(url, pattern, ctx)
                if not resp:
                    continue

                collections = parse_collections(resp.body)
                findings.append({
                    "engine": "aisurface",
                    "rule_id": "ai-vector-open",
                    "name": f"{product} vector database reachable without authentication",
                    "severity": Severity.critical,
                    "host": host,
                    "url": url,
                    "description": (
                        f"A {product} instance answered an unauthenticated request "
                        f"and returned its contents. {product} ships with auth "
                        f"disabled, and this one was deployed that way.\n\n"
                        f"Three separate problems, and the third is the one people "
                        f"miss:\n\n"
                        f"  1. **Read.** Every embedded document is retrievable. "
                        f"This is the knowledge base behind the assistant — "
                        f"typically internal documentation, support history or "
                        f"customer records that were never meant to leave.\n\n"
                        f"  2. **Cross-tenant retrieval.** If tenants share this "
                        f"store and are separated only in application code after "
                        f"retrieval, a crafted query pulls another tenant's data "
                        f"into the context window (LLM08).\n\n"
                        f"  3. **Memory poisoning.** The API that reads is the API "
                        f"that writes. Inserting a document places instructions "
                        f"inside what the assistant treats as ground truth — for "
                        f"every user, until someone notices. That is not a "
                        f"conversation-scoped prompt injection; it is persistent, "
                        f"and it is attributed to the vendor's own knowledge base "
                        f"(ASI06).\n\n"
                        f"Parapet only read. It did not write, and you should "
                        f"confirm writability by asking the owner rather than by "
                        f"inserting a document."
                        + (f"\n\nCollections present: {', '.join(collections[:15])}"
                           + (f" (+{len(collections) - 15} more)"
                              if len(collections) > 15 else "")
                           if collections else "")),
                    "evidence": (f"GET {url}\n"
                                 f"HTTP {resp.status} — no credentials supplied\n\n"
                                 + redact(resp.body[:900])
                                 + ("\n… (truncated)" if len(resp.body) > 900 else "")),
                    "remediation": (
                        f"  • Turn on {product}'s API key or JWT authentication and "
                        f"restart. This is a configuration flag, not a "
                        f"rearchitecture.\n"
                        "  • Bind the service to localhost or a private network and "
                        "reach it from the application only. A vector store has no "
                        "reason to be internet-facing.\n"
                        "  • Enforce tenant separation *inside* the query — a "
                        "per-tenant collection or a mandatory metadata filter — "
                        "not by discarding rows after retrieval.\n"
                        "  • Log and review writes. Poisoning is invisible in "
                        "output; the insert is the only place it shows."),
                    "references": [
                        "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
                    ],
                    "tags": ["ai", "rag", "vector", "exposure", "owasp-llm08",
                             "asi06"],
                    "cve": [], "cwe": ["CWE-306", "CWE-284"], "cvss_score": 9.1,
                    "dedupe_key": make_dedupe_key("aisurface", "vector-open", host,
                                                  f"{product}:{path}"),
                    "raw": {"product": product, "collections": collections},
                })
                break   # found it on one base; no need to try the other

        # --- 3. inference servers --------------------------------------------
        for path, pattern, default_port, product in INFERENCE_PROBES:
            for base in (origin, f"{urlparse(origin).scheme}://{host}:{default_port}"):
                url = urljoin(base, path)
                resp = await _check(url, pattern, ctx)
                if not resp:
                    continue

                models = parse_models(resp.body)
                findings.append({
                    "engine": "aisurface",
                    "rule_id": "ai-inference-open",
                    "name": f"{product} inference server exposed without authentication",
                    "severity": Severity.high,
                    "host": host,
                    "url": url,
                    "description": (
                        f"A {product} server responded to an unauthenticated "
                        f"request and listed its models.\n\n"
                        f"Impact is mostly financial and reputational rather than "
                        f"a data breach, which is why it gets under-reported and "
                        f"then stays open for months:\n\n"
                        f"  • Anyone can run inference at the operator's expense. "
                        f"On a GPU instance that is real money, continuously.\n"
                        f"  • The model list is product intelligence — a "
                        f"fine-tuned model named after an unreleased feature is a "
                        f"disclosure in itself.\n"
                        f"  • Some deployments expose more than inference: "
                        f"model pull, delete, or file paths on the host.\n"
                        f"  • Nothing constrains the prompt, so the server is an "
                        f"open text generator attached to someone's brand."
                        + (f"\n\nModels loaded: {', '.join(models[:12])}"
                           + (f" (+{len(models) - 12} more)" if len(models) > 12 else "")
                           if models else "")),
                    "evidence": (f"GET {url}\n"
                                 f"HTTP {resp.status} — no credentials supplied\n\n"
                                 + redact(resp.body[:700])
                                 + ("\n… (truncated)" if len(resp.body) > 700 else "")),
                    "remediation": (
                        "  • Bind to 127.0.0.1 and put the application in front of "
                        "it. These servers are built to sit behind something.\n"
                        "  • If it must be reachable, require an API key at a "
                        "reverse proxy and rate limit per key.\n"
                        "  • Disable management operations (model pull/delete) on "
                        "any listener that is not local.\n"
                        "  • Set a spend or utilisation alert — it is the control "
                        "that bounds the damage while the others are being fixed."),
                    "references": [
                        "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
                    ],
                    "tags": ["ai", "inference", "exposure", "cost", "owasp-llm10"],
                    "cve": [], "cwe": ["CWE-306"], "cvss_score": 7.5,
                    "dedupe_key": make_dedupe_key("aisurface", "inference-open", host,
                                                  f"{product}:{path}"),
                    "raw": {"product": product, "models": models},
                })
                break

    if log:
        await log("info", f"[aisurface] {len(findings)} AI-surface finding(s)",
                  "aisurface")
    return findings
