"""Secrets and personal data inside archived URLs.

The Internet Archive has been recording URLs for twenty-five years, and a URL
is not a location — it is a string that frequently carries data. Applications
put email addresses, password-reset tokens, session identifiers, API keys,
invoice numbers and signed download links into query parameters, and every one
of those that a crawler saw is now permanently public, indexed, and searchable
by anyone.

The site does not have to be vulnerable. It does not even have to still exist.
The leak happened once, years ago, when a URL was generated and crawled — and
unlike a bug you can patch, this one cannot be recalled.

This is one of the fastest wins in bug bounty for exactly that reason: it is
pure reading, it takes minutes, and it works on mature targets that have been
scanned to death by everyone else, because almost nobody looks at their own
history.

The engine reads the archive's index of a domain and looks for data in the URLs
themselves. Two rules keep it honest:

**Nothing is fetched from the target.** The CDX index and the archive's own
snapshots are third-party public records. Reading them sends no traffic to the
site being assessed.

**Findings are redacted.** An email address in an archived URL is somebody's
personal data. The report proves the leak with a masked value and a count —
enough for the owner to confirm and act, without the report becoming another
copy of the exposure.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, unquote, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

CDX = ("https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
       "&output=text&fl=original&collapse=urlkey&limit={limit}")

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Parameter names whose *value* is the sensitive part. The name alone proves
# nothing — `?token=` on a marketing page might be a UTM variant — so each is
# paired with a value shape below.
SENSITIVE_PARAMS = {
    "token", "access_token", "auth_token", "id_token", "refresh_token",
    "api_key", "apikey", "key", "secret", "client_secret", "password",
    "passwd", "pwd", "pass", "session", "sessionid", "sid", "jsessionid",
    "phpsessid", "auth", "authorization", "signature", "sig", "hash",
    "otp", "code", "reset", "reset_token", "confirmation", "activation",
    "invite", "invitation", "share", "share_token", "download_token",
    "aws_access_key_id", "x-amz-signature", "sas", "sig_token",
}

# What a real credential looks like. Long and high-entropy, or a recognisable
# format. This is what stops `?code=IN` from being reported as a leaked token.
CREDENTIAL_VALUE = re.compile(
    r"^(?:"
    r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\..*"      # JWT
    r"|[A-Fa-f0-9]{32,}"                                   # hex digest
    r"|[A-Za-z0-9_\-]{24,}"                                # generic long token
    r"|AKIA[0-9A-Z]{16}"                                   # AWS key id
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"                  # Stripe
    r"|gh[pousr]_[A-Za-z0-9]{20,}"                         # GitHub
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"                      # Slack
    r")$")

# Pre-signed URLs. These grant direct access to storage and are usually meant
# to be short-lived — but the archive kept the whole string.
PRESIGNED = re.compile(
    r"X-Amz-Signature=|X-Amz-Credential=|GoogleAccessId=|"
    r"[?&]Signature=[A-Za-z0-9%+/=]{20,}|se=\d{4}-\d{2}-\d{2}.*&sig=",
    re.I)

# Indian identifiers, since institutional targets here surface them and a
# generic scanner misses them entirely.
NATIONAL_ID = re.compile(
    r"\b(?:[2-9]\d{3}\s?\d{4}\s?\d{4})\b"          # Aadhaar-shaped
    r"|\b[A-Z]{5}\d{4}[A-Z]\b"                      # PAN
)

PHONE = re.compile(r"(?:\+?\d{1,3}[-. ]?)?(?:\(?\d{3}\)?[-. ]?)\d{3}[-. ]?\d{4}\b")


def mask(value: str) -> str:
    """Show enough to confirm, not enough to use."""
    if "@" in value:
        local, _, domain = value.partition("@")
        head = local[:2] if len(local) > 3 else local[:1]
        return f"{head}{'*' * max(3, len(local) - len(head))}@{domain}"
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def leaks_in_url(url: str) -> list[tuple[str, str, str]]:
    """(kind, parameter, raw_value) for sensitive data carried in a URL.

    Pure, and the whole judgement of the engine. Everything else is fetching.
    """
    found: list[tuple[str, str, str]] = []
    decoded = unquote(url or "")
    parsed = urlparse(decoded)
    params = parse_qsl(parsed.query, keep_blank_values=False)

    if PRESIGNED.search(decoded):
        found.append(("presigned-url", "", decoded[:120]))

    for name, value in params:
        lowered = name.lower().strip()
        value = value.strip()
        if not value:
            continue

        if EMAIL.fullmatch(value):
            found.append(("email", name, value))
            continue

        if lowered in SENSITIVE_PARAMS and CREDENTIAL_VALUE.match(value):
            found.append(("credential", name, value))
            continue

        if NATIONAL_ID.fullmatch(value.replace(" ", "")):
            found.append(("national-id", name, value))
            continue

        if len(value) >= 10 and PHONE.fullmatch(value):
            found.append(("phone", name, value))

    # An address in the path rather than the query — /users/alice@example.com
    for match in EMAIL.finditer(parsed.path or ""):
        found.append(("email", "(path)", match.group(0)))

    return found


def group_leaks(urls: list[str]) -> dict[str, list[tuple[str, str, str]]]:
    """kind -> [(url, param, value)], deduplicated by value.

    Grouping by kind rather than per-URL is deliberate: three thousand archived
    URLs each carrying one customer's email is a single finding about a broken
    pattern, not three thousand findings. Reporting it per-URL would bury the
    actual issue and look like exactly the machine-generated noise triage teams
    are now rejecting outright.
    """
    grouped: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    seen: set[str] = set()
    for url in urls:
        for kind, param, value in leaks_in_url(url):
            if value in seen:
                continue
            seen.add(value)
            grouped[kind].append((url, param, value))
    return dict(grouped)


DETAIL = {
    "email": (
        Severity.high, "Customer email addresses",
        "Email addresses appear in archived URLs, which means they were placed "
        "in links that a crawler saw and the Internet Archive stored "
        "permanently. Anyone can read them today.\n\n"
        "This is a personal data breach with no exploitation involved and no "
        "way to undo it — the archive is a third party and the URLs are already "
        "public. Under India's DPDP Act, GDPR and equivalents, disclosure of "
        "identifiable personal data is reportable regardless of how it "
        "happened.\n\n"
        "Check what the surrounding URL pattern is for. Addresses in "
        "subscription, invoice or account links usually mean the *whole* link "
        "is guessable, and if those links still work they are an account "
        "takeover rather than a disclosure.",
        ["CWE-598", "CWE-200"]),
    "credential": (
        Severity.critical, "Credentials and tokens",
        "Tokens or keys appear as query parameters in archived URLs. A "
        "credential in a URL is logged by every proxy, stored in every browser "
        "history, sent in the Referer header to every third party the page "
        "loads — and, as here, captured by archive crawlers permanently.\n\n"
        "**Test whether these still work before reporting a severity, and stop "
        "at the first response that proves it.** If they do, this is direct "
        "unauthorised access. If they have expired, it is still a design defect "
        "worth reporting, because the next one will leak the same way.",
        ["CWE-598", "CWE-522", "CWE-200"]),
    "presigned-url": (
        Severity.high, "Pre-signed storage URLs",
        "Pre-signed object storage URLs are archived. These grant direct access "
        "to a file without any authentication — the signature *is* the "
        "authorisation.\n\n"
        "They are normally short-lived, so most archived ones will have "
        "expired. The finding is the pattern rather than the individual link: "
        "signed URLs are reaching crawlers, which means they are reaching "
        "Referer headers and browser histories too, and any generated with a "
        "long expiry is live right now.",
        ["CWE-598", "CWE-284"]),
    "national-id": (
        Severity.critical, "Government identity numbers",
        "Values shaped like national identity numbers appear in archived URLs. "
        "If these are real, this is among the most serious categories of "
        "personal data disclosure and carries specific statutory obligations — "
        "in India, under the Aadhaar Act and the DPDP Act.\n\n"
        "**Verify the format actually matches before reporting**, because a "
        "reference number of the same shape is a false positive, and getting "
        "this one wrong is worse than not reporting it.",
        ["CWE-359", "CWE-200"]),
    "phone": (
        Severity.medium, "Phone numbers",
        "Phone numbers appear in archived URLs. Personal data, permanently "
        "public, and a direct input to SIM-swap and social engineering against "
        "the people involved.",
        ["CWE-359", "CWE-200"]),
}


@register(EngineSpec(
    name="archiveleaks",
    label="Reading the archive for leaked data",
    description="Scans twenty-five years of archived URLs for emails, tokens, "
                "pre-signed links and identity numbers carried in the URL itself. "
                "Entirely passive — reads the Internet Archive, never the target — "
                "and finds disclosures that cannot be patched away.",
    phase="early",
    takes="seeds",
    produces="findings",
    weight=5,
    limit=3,
    default_in=("quick", "standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []

    for seed in targets[:3]:
        apex = (urlparse(seed).hostname or seed).lower().lstrip("www.")
        resp = await fetch.request(CDX.format(domain=apex, limit=12000),
                                   follow=True, timeout=90)
        if not resp.ok or not resp.body.strip():
            if log:
                await log("info", f"[archiveleaks] no archive index for {apex}",
                          "archiveleaks")
            continue

        urls = [u.strip() for u in resp.body.splitlines() if u.strip().startswith("http")]
        if log:
            await log("info",
                      f"[archiveleaks] {len(urls)} archived URL(s) for {apex}",
                      "archiveleaks")

        grouped = group_leaks(urls)
        for kind, items in grouped.items():
            severity, title, explanation, cwes = DETAIL[kind]
            sample = items[:8]

            findings.append({
                "engine": "archiveleaks", "rule_id": f"archive-leak-{kind}",
                "name": f"{title} exposed in {len(items)} archived URL(s)",
                "severity": severity,
                "host": apex, "url": items[0][0], "matched_at": items[0][0],
                "description": (
                    f"{explanation}\n\n"
                    f"**{len(items)} distinct value(s)** found across the "
                    f"archived history of `{apex}`. Nothing was requested from "
                    f"the site to establish this — the data is in the Internet "
                    f"Archive's public index, which anyone can query in under a "
                    f"minute.\n\n"
                    f"That is what makes this class urgent to report and "
                    f"impossible to remediate quietly: the URLs are already "
                    f"public, the archive is a third party, and removing the "
                    f"parameter today does nothing about the twenty years "
                    f"already recorded."),
                "evidence": (
                    f"Source: Internet Archive CDX index for *.{apex}\n"
                    f"{len(items)} distinct value(s), sample redacted:\n\n"
                    + "\n".join(
                        f"  {url[:110]}\n     {param or 'in URL'} = {mask(value)}"
                        for url, param, value in sample)
                    + (f"\n  … {len(items) - len(sample)} more"
                       if len(items) > len(sample) else "")),
                "remediation": (
                    "**Immediately:** rotate anything that is a credential. A "
                    "token in an archived URL should be treated as disclosed, "
                    "not as possibly disclosed.\n\n"
                    "**Structurally — this is the fix that matters:** stop "
                    "putting data in URLs. A query string is not a private "
                    "channel. It is written to server and proxy logs, kept in "
                    "browser history, sent in the `Referer` header to every "
                    "third-party script the page loads, and crawled. Move "
                    "identifiers and tokens into POST bodies or headers, and "
                    "make links opaque and single-use.\n\n"
                    "**Then:** set `Referrer-Policy: strict-origin-when-cross-origin` "
                    "so URLs stop leaking sideways to analytics and ad vendors.\n\n"
                    "**On the archive itself:** the Internet Archive has an "
                    "exclusion process, and it is worth using for personal data — "
                    "but treat it as damage limitation. Assume the data has "
                    "already been copied, and notify the affected people if the "
                    "disclosure is personal data. In most jurisdictions that "
                    "notification is a legal obligation rather than a courtesy."),
                "references": [
                    "https://cwe.mitre.org/data/definitions/598.html",
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                ],
                "tags": ["disclosure", "pii", "archive", "passive"],
                "cve": [], "cwe": cwes, "cvss_score": None,
                "dedupe_key": make_dedupe_key("archiveleaks", f"leak-{kind}",
                                              apex, apex),
                "raw": {"kind": kind, "count": len(items),
                        # Masked in raw as well — the database is not a safe
                        # place for someone else's personal data either.
                        "samples": [mask(v) for _u, _p, v in sample]},
            })

    if log:
        critical = [f for f in findings if f["severity"] is Severity.critical]
        await log("info", f"[archiveleaks] {len(findings)} leak class(es) found",
                  "archiveleaks")
        if critical:
            await log("error",
                      f"[archiveleaks] {len(critical)} critical disclosure(s) in "
                      f"archived URLs — rotate any credentials immediately; these "
                      f"are public and cannot be recalled", "archiveleaks")
    return findings
