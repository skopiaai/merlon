"""JSON Web Token weaknesses.

A JWT is three base64url segments — header, payload, signature — and the first
two are *encoded, not encrypted*. Anyone holding the token can read the claims,
and if the signature can be forged, anyone can mint a token the server trusts.
The whole security of the scheme rests on the signature, which is exactly where
the recurring mistakes live.

Everything here is decided offline from a token the crawl already saw — a
Set-Cookie, a body that stashes one in localStorage, an Authorization header
echoed back. Nothing is sent to the target beyond the one fetch every engine
does, so there is no forged token put on the wire and no account touched.

What is checked, and why each is decidable from the token alone:

  * **alg=none** — a token whose header says `"alg":"none"` carries no signature
    at all. If one is in live use, the server accepted it, which means it can be
    minted by anyone. Provable from the header.
  * **Weak HMAC secret** — HS256 signs with a shared secret. If that secret is a
    dictionary word, the signature can be recomputed and the token forged. We
    recompute the HMAC against a small list of the secrets that actually leak
    (framework defaults, tutorial copy-paste). A match is proof, not a guess.
  * **Sensitive claims** — passwords, keys or full PII sitting in the payload are
    disclosed to anyone who intercepts the token, encryption or not.
  * **No expiry / absurd expiry** — a token with no `exp`, or one valid for
    years, stays usable long after it should; a single interception is then
    permanent access.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# header.payload.signature — each segment base64url. The signature segment is
# empty for alg=none, hence the final group being zero-or-more.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# The secrets that actually turn up in disclosed HS256 forgeries: framework
# defaults, the strings from the most-copied tutorials, and the obvious ones.
# A dictionary check, deliberately not a brute-force — a match is a real,
# reproducible forgery; a miss says nothing either way.
WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "your-256-bit-secret",
    "your_jwt_secret", "jwt_secret", "jwtsecret", "supersecret",
    "changeme", "change_me", "password", "admin", "test", "key",
    "mysecret", "my_secret", "signingkey", "signing_key", "s3cr3t",
    "default", "default_secret", "example_key", "0000000000",
    "1234567890", "qwerty", "token", "auth", "authsecret",
    "shhhhh", "topsecret", "development", "dev", "prod", "production",
    "HS256", "django-insecure", "keyboardcat", "iloveyou", "hunter2",
]

# Claim names that should never appear in a token payload.
_SENSITIVE_CLAIMS = re.compile(
    r"(?:pass(?:word|wd)?|secret|api[_-]?key|private[_-]?key|"
    r"ssn|credit[_-]?card|cvv|access[_-]?key|client[_-]?secret)",
    re.I,
)

_ONE_YEAR = 365 * 24 * 3600


def _b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, tolerating missing padding."""
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> dict | None:
    """Split and decode a JWT. Returns None for anything that isn't really one.

    The header decoding to JSON with an `alg` field is the discriminator: a
    random base64 blob does not decode to `{"alg": ...}`, so this does not fire
    on arbitrary tokens that merely look base64-ish.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    if not isinstance(payload, dict):
        return None
    return {
        "header": header,
        "payload": payload,
        "signing_input": f"{parts[0]}.{parts[1]}".encode(),
        "signature": parts[2],
        "raw": token,
    }


def crack_hs_secret(decoded: dict, wordlist: list[str] | None = None) -> str | None:
    """Return the signing secret if it is in the wordlist, else None.

    Only HS256/384/512 are keyed on a shared secret. The signature is
    recomputed with each candidate and compared in constant time; a match means
    the token can be forged, which is proof rather than suspicion.
    """
    alg = str(decoded["header"].get("alg", "")).upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    try:
        want = _b64url_decode(decoded["signature"])
    except (binascii.Error, ValueError):
        return None
    for secret in (wordlist or WEAK_SECRETS):
        got = hmac.new(secret.encode(), decoded["signing_input"], digest).digest()
        if hmac.compare_digest(got, want):
            return secret
    return None


def analyse_jwt(token: str, *, now: int | None = None) -> list[dict]:
    """Every issue a single token reveals on its own. Pure and offline."""
    decoded = decode_jwt(token)
    if not decoded:
        return []
    now = now if now is not None else int(time.time())
    header, payload = decoded["header"], decoded["payload"]
    alg = str(header.get("alg", "")).lower()
    issues: list[dict] = []

    if alg == "none":
        issues.append({
            "rule": "jwt-alg-none", "severity": Severity.high,
            "detail": "This token's header declares `alg: none`, so it carries "
                      "no signature. A token in this form is accepted only by a "
                      "server that does not verify signatures — which means "
                      "anyone can mint one with any claims, including elevated "
                      "roles or another user's identity."})

    secret = crack_hs_secret(decoded)
    if secret is not None:
        issues.append({
            "rule": "jwt-weak-secret", "severity": Severity.critical,
            "detail": f"The HMAC signing secret is `{secret}` — a value from a "
                      f"short list of common defaults, recovered by recomputing "
                      f"the signature. With the secret, any token can be forged: "
                      f"change the subject or role, re-sign, and the server "
                      f"accepts it. This is full authentication bypass.",
            "secret": secret})

    flat = json.dumps(payload)
    if _SENSITIVE_CLAIMS.search(flat):
        names = sorted({k for k in payload if _SENSITIVE_CLAIMS.search(k)})
        if names:
            issues.append({
                "rule": "jwt-sensitive-claims", "severity": Severity.medium,
                "detail": "The token payload is base64, not encrypted, and "
                          f"carries sensitive field(s): {', '.join(names)}. "
                          "Anyone who intercepts the token reads them in clear."})

    exp = payload.get("exp")
    if exp is None:
        issues.append({
            "rule": "jwt-no-expiry", "severity": Severity.medium,
            "detail": "The token has no `exp` claim, so it never expires. A "
                      "single interception is then permanent access — the token "
                      "cannot be aged out, only revoked server-side if that is "
                      "even implemented."})
    elif isinstance(exp, (int, float)):
        lifetime = int(exp) - (int(payload["iat"]) if isinstance(payload.get("iat"), (int, float)) else now)
        if lifetime > _ONE_YEAR:
            issues.append({
                "rule": "jwt-long-lived", "severity": Severity.low,
                "detail": f"The token is valid for about {lifetime // 86400} "
                          f"days. A lifetime this long defeats the point of "
                          f"expiry: a leaked token stays usable for months."})

    return issues


def _finding(host: str, url: str, source: str, token: str, issue: dict) -> dict:
    redacted = token[:12] + "…" + token[-6:] if len(token) > 24 else token[:8] + "…"
    evidence = (f"Token seen in: {source}\n"
                f"Token (truncated): {redacted}\n"
                f"Header alg: {decode_jwt(token)['header'].get('alg')}")
    if issue["rule"] == "jwt-weak-secret":
        evidence += f"\nSigning secret recovered: {issue['secret']!r}"
    return {
        "engine": "jwt", "rule_id": issue["rule"],
        "name": {
            "jwt-alg-none": "JWT accepts unsigned tokens (alg=none)",
            "jwt-weak-secret": "JWT signed with a guessable secret",
            "jwt-sensitive-claims": "Sensitive data in JWT payload",
            "jwt-no-expiry": "JWT never expires",
            "jwt-long-lived": "JWT valid for an excessive period",
        }[issue["rule"]],
        "severity": issue["severity"],
        "host": host, "url": url, "matched_at": url,
        "description": issue["detail"],
        "evidence": evidence,
        "remediation": (
            "Verify signatures with a fixed algorithm — pin the expected `alg` "
            "server-side and reject any other, especially `none`; never trust "
            "the algorithm named in the token header. Sign HMAC tokens with a "
            "high-entropy secret from a secrets manager, not a literal in the "
            "source. Keep only non-sensitive claims in the payload, set a short "
            "`exp`, and treat the token as readable by anyone who holds it."),
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "tags": ["jwt", "authentication", "session"],
        "cve": [], "cwe": ["CWE-347", "CWE-345"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("jwt", issue["rule"], host, url),
        "raw": {"source": source, "alg": decode_jwt(token)["header"].get("alg")},
    }


@register(EngineSpec(
    name="jwt",
    label="Inspecting JSON Web Tokens",
    description="JWT weaknesses decided from the token itself — alg=none, a "
                "guessable HMAC secret recovered by recomputing the signature, "
                "sensitive claims in the payload, and tokens that never expire. "
                "No forged token is ever sent to the target.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=3,
    limit=40,
    default_in=("standard", "deep"),
    # Only the cracked secret is a proof — we recomputed the signature and it
    # matched. alg=none and the expiry rules are observations about a token.
    proves=("jwt-weak-secret",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()

    async def check(url: str) -> list[dict]:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return []
        resp = await fetch.request(url, timeout=12, ctx=ctx)
        if not resp.ok:
            return []

        # Where a token can turn up in one response: the Set-Cookie header, an
        # Authorization echo, and the body (localStorage assignments, JSON).
        sources = [
            ("Set-Cookie header", resp.header("set-cookie")),
            ("Authorization header", resp.header("authorization")),
            ("response body", resp.body or ""),
        ]
        out: list[dict] = []
        for source, text in sources:
            if not text:
                continue
            for token in dict.fromkeys(_JWT_RE.findall(text)):
                for issue in analyse_jwt(token):
                    key = f"{host}|{issue['rule']}"
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(_finding(host, url, source, token, issue))
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=8)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[jwt] {len(findings)} token weakness(es) across "
                          f"{len(targets)} endpoint(s)", "jwt")
    return findings
