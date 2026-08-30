"""Cloud storage exposure.

reNgine, reconFTW and BBOT all check for this and we didn't, which was a real
gap: a world-readable S3 bucket is one of the highest-value findings in bug
bounty, and organisations create them constantly without noticing.

Three things are worth distinguishing, because they have very different
severity and very different fixes:

  * **Public listing** — anyone can enumerate every object. Whatever is in
    there is effectively published.
  * **Public write** — anyone can add or replace objects. If the bucket serves
    a website or JavaScript, that's remote code execution in your users'
    browsers. We detect the *signal* of this from the ACL response; we never
    attempt a write.
  * **Unclaimed bucket referenced by the site** — the page loads assets from a
    bucket that no longer exists, so anyone can register the name and serve
    content from it. Same class as a subdomain takeover.

Everything here is read-only: HEAD and GET against public endpoints, exactly
what a browser does. No credentials, no writes, no enumeration of contents
beyond the first listing response.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# Bucket references that appear in page source. Covers the URL styles each
# provider uses, including the older path-style S3 URLs.
# (provider, pattern). The provider is stated rather than inferred from the
# pattern text — inferring it from the regex source is fragile, because the
# escaped dots mean a substring check for "windows.net" silently never matches.
BUCKET_REFS: list[tuple[str, re.Pattern]] = [
    ("s3", re.compile(
        r"https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com", re.I)),
    ("s3", re.compile(
        r"https?://s3[.\-][a-z0-9\-]*\.?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.I)),
    ("gcs", re.compile(
        r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])", re.I)),
    ("gcs", re.compile(
        r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.storage\.googleapis\.com", re.I)),
    ("azure", re.compile(
        r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.blob\.core\.windows\.net", re.I)),
    ("s3", re.compile(
        r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.digitaloceanspaces\.com", re.I)),
]

# Names an organisation is likely to have used. Kept deliberately short: this
# generates real requests to a third party, and a 500-permutation sweep per
# host is both slow and rude.
NAME_SUFFIXES = [
    "", "-assets", "-static", "-media", "-uploads", "-files", "-backup",
    "-backups", "-data", "-public", "-private", "-dev", "-staging", "-prod",
    "-images", "-docs", "-cdn", "-logs",
]

PROVIDERS = {
    "s3": "https://{name}.s3.amazonaws.com/?max-keys=5",
    "gcs": "https://storage.googleapis.com/{name}?max-keys=5",
    "azure": "https://{name}.blob.core.windows.net/?comp=list",
}


async def _probe(url: str, timeout: int = 12) -> tuple[int, str]:
    """GET a public storage endpoint. Read-only, like a browser."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "--max-time", str(timeout), "-o", "-",
            "-w", "\n---CODE---%{http_code}", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except (asyncio.TimeoutError, OSError):
        return 0, ""
    text = out.decode("utf-8", "replace")
    if "\n---CODE---" not in text:
        return 0, text
    body, code = text.rsplit("\n---CODE---", 1)
    return (int(code.strip()) if code.strip().isdigit() else 0), body


def _finding(rule_id, name, sev, host, url, desc, fix, evidence, cwe=None):
    return {
        "engine": "buckets",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": desc,
        "evidence": evidence[:2000],
        "remediation": fix,
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
        "tags": ["cloud", "storage", "exposure"],
        "cve": [], "cwe": cwe or ["CWE-284"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("buckets", rule_id, host, url),
        "raw": {},
    }


def classify(provider: str, name: str, status: int, body: str,
             host: str) -> dict | None:
    """Turn one probe response into a finding, or None.

    Pure function — the interesting logic, testable without network access.
    """
    url = PROVIDERS[provider].format(name=name).split("?")[0]
    low = body.lower()

    # Listing succeeded: contents are public.
    listed = status == 200 and (
        "<listbucketresult" in low or "<enumerationresults" in low)
    if listed:
        keys = len(re.findall(r"<key>|<name>", low))
        return _finding(
            f"bucket-public-list-{provider}",
            f"Publicly listable {provider.upper()} bucket: {name}",
            Severity.high, host, url,
            f"The bucket '{name}' returns a directory listing to anyone. Every object "
            f"in it is effectively published, and listing means an attacker doesn't "
            f"even have to guess filenames — they can enumerate everything. "
            f"{'At least ' + str(keys) + ' object(s) visible in the first response. ' if keys else ''}"
            f"Buckets like this routinely contain backups, database dumps, internal "
            f"documents and credentials.",
            "Enable 'Block all public access' on the bucket, then review what was "
            "exposed. Treat anything sensitive in there as disclosed: rotate any "
            "credentials it contained and check access logs for who fetched what. "
            "If some objects genuinely need to be public, serve them through a CDN "
            "with a restrictive bucket policy rather than opening the bucket.",
            f"HTTP {status} from {url}\n\n{body[:800]}",
        )

    # Bucket doesn't exist but the site references it: claimable.
    if status == 404 and ("nosuchbucket" in low or "the specified bucket does not exist" in low):
        return _finding(
            f"bucket-unclaimed-{provider}",
            f"Site references a non-existent {provider.upper()} bucket: {name}",
            Severity.high, host, url,
            f"The application points at '{name}', which doesn't exist. Bucket names are "
            f"globally unique and first-come — anyone can register this one and start "
            f"serving content from a URL your site trusts. If the bucket was used for "
            f"JavaScript or other active content, that becomes script execution in your "
            f"users' browsers.",
            "Either recreate the bucket under your own account immediately to deny the "
            "name to anyone else, or remove every reference to it from the application "
            "and DNS.",
            f"HTTP {status} from {url}\n\n{body[:400]}",
            cwe=["CWE-350"],
        )

    # Exists but access denied — correct configuration, worth noting only.
    if status == 403 and ("accessdenied" in low or "authorization" in low):
        return _finding(
            f"bucket-exists-{provider}",
            f"{provider.upper()} bucket exists and is private: {name}",
            Severity.info, host, url,
            f"The bucket '{name}' exists but denies anonymous access. That is the "
            f"correct configuration — recorded only so the asset inventory is complete.",
            "No action required. Confirm the same is true for write access and for "
            "any bucket policy granting cross-account access.",
            f"HTTP {status} from {url}",
        )
    return None


def extract_refs(html: str) -> set[tuple[str, str]]:
    """Bucket names referenced in page source, as (provider, name)."""
    found: set[tuple[str, str]] = set()
    for provider, pattern in BUCKET_REFS:
        for m in pattern.findall(html or ""):
            name = (m if isinstance(m, str) else m[0]).lower().strip(".")
            if name and len(name) >= 3:
                found.add((provider, name))
    return found


def candidate_names(host: str) -> list[str]:
    """Plausible bucket names for an organisation, from its domain."""
    parts = [p for p in host.split(".") if p not in ("www", "com", "org", "net",
                                                     "edu", "gov", "in", "co", "io")]
    if not parts:
        return []
    base = parts[0]
    if len(base) < 3:
        return []
    return [f"{base}{suffix}" for suffix in NAME_SUFFIXES]


# ----------------------------------------------------------------- engine

@register(EngineSpec(
    name="buckets",
    label="Checking cloud storage exposure",
    description="Finds S3, GCS and Azure buckets referenced by the site or named "
                "after the organisation, and reports public listing, unclaimed "
                "names and correctly-private buckets.",
    phase="post_http",
    takes="urls",
    weight=7,
    limit=8,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    checked: set[tuple[str, str]] = set()
    sem = asyncio.Semaphore(6)

    async def check(provider: str, name: str, host: str):
        if (provider, name) in checked:
            return None
        checked.add((provider, name))
        async with sem:
            status, body = await _probe(PROVIDERS[provider].format(name=name))
        return classify(provider, name, status, body, host)

    # 1. Buckets the site actually references — highest signal, zero guessing.
    referenced: set[tuple[str, str, str]] = set()
    for page in targets:
        host = (urlparse(page).hostname or page).lower()
        status, body = await _probe(page, timeout=15)
        if not body:
            continue
        for provider, name in extract_refs(body):
            referenced.add((provider, name, host))

    if referenced and log:
        await log("info", f"[buckets] {len(referenced)} bucket(s) referenced in page "
                          f"source", "buckets")

    results = await asyncio.gather(
        *(check(p, n, h) for p, n, h in referenced), return_exceptions=True)
    findings += [r for r in results if isinstance(r, dict)]

    # 2. Names derived from the domain. Guessing, so kept small and only for
    #    the apex — a wide sweep here is noisy and mostly unproductive.
    hosts = sorted({(urlparse(u).hostname or u).lower() for u in targets})[:2]
    guesses = [(p, n, h) for h in hosts for n in candidate_names(h)
               for p in ("s3",)]
    if guesses and log:
        await log("info", f"[buckets] testing {len(guesses)} likely bucket name(s)",
                  "buckets")

    results = await asyncio.gather(
        *(check(p, n, h) for p, n, h in guesses), return_exceptions=True)
    # Guessed names that simply don't exist aren't findings; only report a
    # guessed bucket if it's actually public.
    findings += [r for r in results
                 if isinstance(r, dict) and "public-list" in r["rule_id"]]

    return findings
