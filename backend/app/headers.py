"""Response header and cookie auditing.

Nuclei is template-driven and deliberately conservative — it won't flag a
missing security header on every page because that would drown its output.
But for someone hardening their own site, those gaps are exactly the
actionable findings. So we audit headers ourselves, strictly.

This is the "harsh" layer: it reports everything that falls short of current
best practice, with the exact directive to add.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Severity
from .normalize import make_dedupe_key


def _norm(headers: dict) -> dict[str, str]:
    """Lowercase keys; join repeated values."""
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        key = k.lower().strip()
        val = ", ".join(v) if isinstance(v, list) else str(v)
        out[key] = f"{out[key]}, {val}" if key in out else val
    return out


def _finding(rule_id, name, sev, url, host, desc, fix, cwe=None, tags=None, evidence=""):
    return {
        "engine": "headers",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": desc,
        "evidence": evidence,
        "remediation": fix,
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "tags": ["headers"] + (tags or []),
        "cve": [],
        "cwe": cwe or [],
        "cvss_score": None,
        "dedupe_key": make_dedupe_key("headers", rule_id, host, url),
        "raw": {},
    }


def audit(asset: dict) -> list[dict]:
    """Return every header/cookie shortcoming for one live endpoint."""
    url = asset.get("url") or ""
    host = (asset.get("host") or "").lower()
    h = _norm(asset.get("headers") or {})
    if not url or not h:
        return []

    is_https = url.lower().startswith("https://")
    out: list[dict] = []

    # ---------- transport ----------
    if is_https and "strict-transport-security" not in h:
        out.append(_finding(
            "missing-hsts", "HSTS not enabled", Severity.medium, url, host,
            "The site serves HTTPS but never tells browsers to require it. A visitor "
            "on a hostile network — public Wi-Fi, a compromised router — can be silently "
            "downgraded to HTTP on their first visit and have their traffic read or modified.",
            "Add to every HTTPS response:\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            cwe=["CWE-319"], tags=["tls"],
        ))
    elif is_https:
        hsts = h["strict-transport-security"]
        age = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if age and int(age.group(1)) < 15552000:  # 180 days
            out.append(_finding(
                "weak-hsts", f"HSTS max-age is too short ({age.group(1)}s)",
                Severity.low, url, host,
                "HSTS is enabled but expires soon enough that a visitor who hasn't returned "
                "recently is unprotected again.",
                "Raise max-age to at least 31536000 (one year) and add includeSubDomains.",
                cwe=["CWE-319"], tags=["tls"], evidence=hsts,
            ))
        if "includesubdomains" not in hsts.lower():
            out.append(_finding(
                "hsts-no-subdomains", "HSTS doesn't cover subdomains", Severity.low, url, host,
                "Subdomains aren't protected by the HSTS policy, so an attacker can target "
                "one of those instead to intercept traffic or steal cookies scoped to the domain.",
                "Append includeSubDomains to the Strict-Transport-Security header — but confirm "
                "every subdomain serves valid HTTPS first, or you'll break them.",
                cwe=["CWE-319"], tags=["tls"], evidence=hsts,
            ))

    if not is_https:
        out.append(_finding(
            "no-https", "Service reachable over plain HTTP", Severity.high, url, host,
            "This endpoint answers over unencrypted HTTP. Anything sent to it — passwords, "
            "session cookies, form data — travels in clear text and can be read or altered "
            "by anyone on the network path.",
            "Redirect all HTTP traffic to HTTPS with a 301, obtain a certificate "
            "(Let's Encrypt is free and automated), then enable HSTS.",
            cwe=["CWE-319"], tags=["tls"],
        ))

    # ---------- injection defence ----------
    if "content-security-policy" not in h:
        out.append(_finding(
            "missing-csp", "No Content Security Policy", Severity.medium, url, host,
            "There's no CSP, which is the browser-level control that stops injected scripts "
            "from executing. It's the safety net for any cross-site scripting bug in the "
            "application — including ones nobody has found yet.",
            "Start with Content-Security-Policy-Report-Only to see what a policy would break, "
            "then enforce it. A reasonable starting point:\n"
            "  default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'",
            cwe=["CWE-1021", "CWE-79"], tags=["xss"],
        ))
    else:
        csp = h["content-security-policy"]
        weak = [d for d in ("unsafe-inline", "unsafe-eval") if d in csp]
        if weak:
            out.append(_finding(
                "weak-csp", f"CSP weakened by {' and '.join(weak)}", Severity.low, url, host,
                "The policy allows inline scripts or eval, which is what most XSS payloads "
                "rely on. The CSP is present but much of its protection is disabled.",
                "Remove 'unsafe-inline' and 'unsafe-eval'. Move inline scripts to files, or "
                "use per-request nonces or hashes.",
                cwe=["CWE-79"], tags=["xss"], evidence=csp[:400],
            ))
        if "default-src *" in csp or "script-src *" in csp:
            out.append(_finding(
                "wildcard-csp", "CSP allows scripts from any origin", Severity.medium, url, host,
                "A wildcard source lets any site on the internet supply executable script, "
                "which defeats the point of having a policy.",
                "Replace * with an explicit list of origins you control.",
                cwe=["CWE-79"], tags=["xss"], evidence=csp[:400],
            ))

    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(_finding(
            "missing-xfo", "Page can be framed by other sites (clickjacking)",
            Severity.medium, url, host,
            "Nothing stops another site from loading these pages in a hidden frame. An attacker "
            "can overlay invisible controls so a logged-in visitor clicks something they never "
            "intended — approving a payment, changing a setting, deleting an account.",
            "Add Content-Security-Policy: frame-ancestors 'none' (preferred), or "
            "X-Frame-Options: DENY. Use 'self' / SAMEORIGIN if you frame your own pages.",
            cwe=["CWE-1021"], tags=["clickjacking"],
        ))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_finding(
            "missing-nosniff", "Browsers allowed to guess content types", Severity.low, url, host,
            "Without nosniff, a browser may ignore the declared Content-Type and infer its own. "
            "A user-uploaded file that looks like an image can end up executed as script.",
            "Add X-Content-Type-Options: nosniff to every response.",
            cwe=["CWE-430"],
        ))

    if "referrer-policy" not in h:
        out.append(_finding(
            "missing-referrer-policy", "No Referrer-Policy set", Severity.low, url, host,
            "Full URLs — including any tokens, IDs, or search terms in them — get sent to "
            "third-party sites when a visitor clicks an outbound link or loads an external resource.",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
            cwe=["CWE-200"], tags=["privacy"],
        ))

    if "permissions-policy" not in h and "feature-policy" not in h:
        out.append(_finding(
            "missing-permissions-policy", "No Permissions-Policy set", Severity.low, url, host,
            "Nothing restricts which browser features — camera, microphone, geolocation — the "
            "page or anything embedded in it may request.",
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), and re-enable "
            "only what the site actually uses.",
            cwe=["CWE-693"],
        ))

    # ---------- cross-origin ----------
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(_finding(
            "cors-wildcard-credentials", "CORS allows any origin with credentials",
            Severity.high, url, host,
            "The API accepts cross-origin requests from any website AND permits credentials. "
            "Any site a victim visits while logged in can read authenticated responses from "
            "this endpoint — that's account data exfiltration by any third party.",
            "Never combine Access-Control-Allow-Origin: * with credentials. Echo back only "
            "origins from an explicit allowlist.",
            cwe=["CWE-942"], tags=["cors"], evidence=f"ACAO: {acao}\nACAC: {acac}",
        ))
    elif acao == "*":
        out.append(_finding(
            "cors-wildcard", "CORS open to any origin", Severity.low, url, host,
            "Any website can make cross-origin requests and read the responses. Harmless for "
            "genuinely public data, serious if anything here is user-specific.",
            "Restrict Access-Control-Allow-Origin to origins you control, unless this endpoint "
            "is deliberately public.",
            cwe=["CWE-942"], tags=["cors"], evidence=acao,
        ))

    # ---------- information disclosure ----------
    for header, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"),
                          ("x-aspnet-version", "X-AspNet-Version"),
                          ("x-generator", "X-Generator")):
        val = h.get(header, "")
        if val and re.search(r"\d+\.\d+", val):
            out.append(_finding(
                f"version-disclosure-{header}", f"{label} header reveals exact version",
                Severity.low, url, host,
                f"The {label} header advertises '{val}'. It doesn't create a vulnerability by "
                f"itself, but it lets an attacker skip reconnaissance and go straight to exploits "
                f"matching your exact build.",
                f"Suppress the version. Nginx: server_tokens off;  Apache: ServerTokens Prod  "
                f"Express: app.disable('x-powered-by')",
                cwe=["CWE-200"], tags=["disclosure"], evidence=f"{label}: {val}",
            ))

    # ---------- cookies ----------
    raw_cookies = (asset.get("headers") or {}).get("Set-Cookie") \
        or (asset.get("headers") or {}).get("set-cookie") or []
    if isinstance(raw_cookies, str):
        raw_cookies = [raw_cookies]

    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        problems, sev = [], Severity.low

        if is_https and "secure" not in low:
            problems.append("missing Secure")
            sev = Severity.medium
        if "httponly" not in low:
            problems.append("missing HttpOnly")
            sev = Severity.medium
        if "samesite" not in low:
            problems.append("missing SameSite")

        if problems:
            session_like = any(w in name.lower() for w in
                               ("sess", "auth", "token", "jwt", "sid", "login"))
            if session_like and sev is Severity.medium:
                sev = Severity.high
            out.append(_finding(
                f"insecure-cookie-{name}", f"Cookie '{name}': {', '.join(problems)}",
                sev, url, host,
                (f"This cookie {'looks like a session cookie and ' if session_like else ''}"
                 f"is set without {', '.join(problems)}. Without HttpOnly, any XSS on the site "
                 f"can read it and hijack the session; without Secure it can leak over plain "
                 f"HTTP; without SameSite it's sent on cross-site requests, enabling CSRF."),
                f"Set the cookie as: Set-Cookie: {name}=…; Secure; HttpOnly; SameSite=Lax; Path=/",
                cwe=["CWE-1004", "CWE-614"], tags=["cookies", "session"],
                evidence=cookie[:300],
            ))

    return out
