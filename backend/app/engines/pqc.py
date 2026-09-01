"""Post-quantum readiness of TLS.

The threat here is unusual because it is retroactive. An adversary with a tap on
a network backbone records encrypted traffic *today* and stores it, waiting for
a quantum computer capable of breaking the RSA or elliptic-curve key exchange
that protected it. The attack — "harvest now, decrypt later" — costs nothing to
run and needs no vulnerability, only patience and disk.

Which means the deadline is not when quantum computers arrive. It is now, minus
the confidentiality lifetime of whatever is crossing the wire. Anything that has
to stay secret past roughly 2030 and is protected by classical key exchange
today should be treated as already exposed.

That stopped being a research topic in 2026. Executive Order 14412, signed in
June, sets a hard deadline of **31 December 2030** for federal systems to move
to post-quantum encryption and **31 December 2031** for authentication, against
the NIST standards FIPS 203–205. Meanwhile hybrid ML-KEM key agreement went
from a fresh standard to carrying the majority of web traffic in under two
years, deployed silently through browser and CDN defaults — so a site that
*doesn't* have it in 2026 is behind its own CDN's defaults, not ahead of the
curve.

What this engine reports:

  **Key exchange** — whether the server will negotiate a hybrid post-quantum
  group (X25519MLKEM768 and relatives). This is the part that matters for
  harvest-now-decrypt-later, and it is also the easy part: on most stacks it is
  a configuration line or a CDN toggle.

  **Signatures** — certificates are still classical, and will be for years. That
  is expected and is *not* reported as a defect, because a forged signature has
  to be produced while the connection is live. Recording traffic doesn't help an
  attacker forge a certificate retroactively, so the deadline is genuinely later
  for authentication than for confidentiality — which is exactly why the
  executive order sets two different dates.

The distinction in that last paragraph is the whole point of the engine. A
scanner that flags "RSA certificate — not quantum safe!" on every site on the
internet is noise. Confidentiality is urgent; authentication is not yet.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# NIST-standardised post-quantum key agreement, and the hybrid constructions
# that pair it with a classical curve. Hybrid is what everyone actually
# deploys: if the post-quantum half turns out to be broken you still have
# X25519 underneath, so it is strictly safer than either alone.
PQ_GROUPS = re.compile(
    r"X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|"
    r"X25519Kyber768|X25519Kyber512|P256Kyber768|"
    r"MLKEM768|MLKEM1024|MLKEM512|"
    r"Kyber768|Kyber512|Kyber1024|"
    r"0x11ec|0x11eb|0x6399|0x639a",     # IANA codepoints seen in raw output
    re.I)

# Post-quantum signature algorithms, for the certificate side.
PQ_SIGNATURES = re.compile(
    r"ML-DSA|MLDSA|Dilithium|SLH-DSA|SPHINCS|Falcon|FN-DSA", re.I)

# Deadlines from Executive Order 14412 (22 June 2026).
ENCRYPTION_DEADLINE = "31 December 2030"
AUTHENTICATION_DEADLINE = "31 December 2031"


def supports_pq_keyexchange(handshake: str) -> bool:
    """Did the handshake negotiate a post-quantum group?"""
    return bool(PQ_GROUPS.search(handshake or ""))


def negotiated_group(handshake: str) -> str:
    """The group name openssl reported, for the evidence block."""
    for pattern in (r"Negotiated TLS1\.3 group:\s*(\S+)",
                    r"Server Temp Key:\s*([^\n,]+)",
                    r"Peer signing digest:.*\n.*?group:\s*(\S+)"):
        match = re.search(pattern, handshake or "", re.I)
        if match:
            return match.group(1).strip()
    return ""


def tls_version(handshake: str) -> str:
    match = re.search(r"Protocol\s*:\s*(TLSv[\d.]+)", handshake or "", re.I)
    return match.group(1) if match else ""


def uses_pq_certificate(handshake: str) -> bool:
    return bool(PQ_SIGNATURES.search(handshake or ""))


async def _handshake(host: str, port: int = 443, timeout: int = 20) -> str:
    """One TLS handshake, offering post-quantum groups.

    `-groups` asks the server for exactly these. If it picks one, it supports
    it; if the handshake fails, we retry without the constraint so a server
    that simply lacks post-quantum support is reported as "no" rather than as
    unreachable — those are very different findings and confusing them would
    make the whole engine untrustworthy.
    """
    if not shutil.which("openssl"):
        return ""

    async def connect(groups: str | None) -> str:
        argv = ["openssl", "s_client", "-connect", f"{host}:{port}",
                "-servername", host, "-tls1_3", "-brief"]
        if groups:
            argv += ["-groups", groups]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return ""
        return out.decode("utf-8", "replace")

    # Offer hybrid groups first, alongside a classical fallback so the
    # connection still completes on a server that doesn't know them.
    hybrid = await connect("X25519MLKEM768:X25519Kyber768:x25519")
    if hybrid.strip():
        return hybrid
    return await connect(None)


@register(EngineSpec(
    name="pqc",
    label="Checking post-quantum TLS readiness",
    description="Whether TLS negotiates hybrid post-quantum key agreement. "
                "Traffic recorded today under classical key exchange is decryptable "
                "later, so the deadline for confidentiality is already here — "
                "EO 14412 sets 2030 for federal systems.",
    phase="post_http",
    takes="hosts",
    produces="findings",
    weight=4,
    limit=15,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")

    if not shutil.which("openssl"):
        if log:
            await log("warn", "[pqc] openssl is not available — skipping", "pqc")
        return []

    findings: list[dict] = []
    ready: list[str] = []

    async def check(target: str):
        host = urlparse(target).hostname if "://" in target else target
        host = (host or target).split(":")[0].lower()
        handshake = await _handshake(host)
        if not handshake.strip():
            return None
        return host, handshake

    results = await asyncio.gather(*(check(t) for t in targets[:15]),
                                   return_exceptions=True)

    for item in results:
        if isinstance(item, Exception) or not item:
            continue
        host, handshake = item

        version = tls_version(handshake)
        group = negotiated_group(handshake)

        if supports_pq_keyexchange(handshake):
            ready.append(host)
            findings.append({
                "engine": "pqc", "rule_id": "pqc-ready",
                "name": "Post-quantum key agreement supported",
                "severity": Severity.info,
                "host": host, "url": f"https://{host}", "matched_at": host,
                "description": (
                    f"`{host}` negotiates hybrid post-quantum key agreement"
                    + (f" ({group})" if group else "")
                    + ". Traffic to this host is protected against "
                      "harvest-now-decrypt-later: an adversary recording it today "
                      "cannot decrypt it with a future quantum computer.\n\n"
                      "Recorded as evidence of compliance rather than as a "
                      "problem — this is the state an audit wants to see, and it "
                      "belongs in the report for that reason."),
                "evidence": f"TLS handshake with {host}\n"
                            f"  {version or 'TLS 1.3'}, group: {group or 'hybrid PQ'}",
                "remediation": "No action needed. Keep it enabled through "
                               "infrastructure changes — this is easy to lose "
                               "silently in a CDN or load balancer migration.",
                "references": [
                    "https://csrc.nist.gov/pubs/fips/203/final",
                ],
                "tags": ["tls", "post-quantum", "compliance"],
                "cve": [], "cwe": [], "cvss_score": None,
                "dedupe_key": make_dedupe_key("pqc", "pqc-ready", host, host),
                "raw": {"group": group, "version": version},
            })
            continue

        # --- not ready ---
        findings.append({
            "engine": "pqc", "rule_id": "pqc-not-ready",
            "name": "TLS key exchange is not quantum-resistant",
            "severity": Severity.low,
            "host": host, "url": f"https://{host}", "matched_at": host,
            "description": (
                f"`{host}` does not negotiate post-quantum key agreement. It "
                f"handshakes with {version or 'TLS'}"
                + (f" using {group}" if group else " using a classical group")
                + ", which is secure against every computer that exists today and "
                  "decryptable by one that doesn't yet.\n\n"
                  "**Why this is not a future problem.** Encrypted traffic can be "
                  "recorded now and stored. The attack needs no vulnerability and "
                  "no access — only a tap and patience. So the exposure window "
                  "opened the moment the data crossed the wire, and the relevant "
                  "question is how long this traffic needs to stay confidential. "
                  "If the answer is past about 2030, it is already at risk.\n\n"
                  f"**Why it is urgent in a different sense.** Executive Order "
                  f"14412 (June 2026) requires federal systems to move to "
                  f"post-quantum encryption by {ENCRYPTION_DEADLINE}. Hybrid "
                  f"ML-KEM is already carrying the majority of web traffic, "
                  f"deployed through browser and CDN defaults — so this is not an "
                  f"early-adopter ask, it is catching up with the rest of the "
                  f"web.\n\n"
                  "**What is deliberately not reported:** the certificate. "
                  "Signatures remain classical almost everywhere, and that is "
                  "fine — forging one has to happen while the connection is live, "
                  "so stored traffic doesn't help. That is precisely why the "
                  f"executive order sets a later date ({AUTHENTICATION_DEADLINE}) "
                  "for authentication than for encryption."),
            "evidence": f"TLS handshake with {host}\n"
                        f"  {version or 'unknown version'}"
                        + (f", group: {group}" if group else "")
                        + "\n  offered X25519MLKEM768 and X25519Kyber768 — "
                          "neither was selected",
            "remediation": (
                "For most stacks this is a configuration change, not a project.\n\n"
                "  • **Behind a CDN:** Cloudflare, Fastly and Akamai enable hybrid "
                "post-quantum key agreement by default or behind a toggle. Check "
                "the setting rather than assuming.\n"
                "  • **nginx:** OpenSSL 3.5+ supports it natively —\n"
                "      `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;`\n"
                "  • **Go:** 1.24+ enables X25519MLKEM768 by default in crypto/tls.\n"
                "  • **Java / .NET:** track your runtime's roadmap; support is "
                "arriving now.\n\n"
                "Hybrid is the right target, not pure post-quantum. It pairs "
                "ML-KEM with X25519 so a flaw in the new algorithm leaves you no "
                "worse off than today.\n\n"
                "Then do the part that outlasts this finding: **inventory where "
                "you use public-key cryptography and build in crypto-agility.** "
                "The organisations that struggle with this migration are the ones "
                "that cannot answer where RSA is used, not the ones that picked "
                "the wrong algorithm."),
            "references": [
                "https://csrc.nist.gov/pubs/fips/203/final",
                "https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/",
                "https://blog.cloudflare.com/post-quantum-eo-2026/",
            ],
            "tags": ["tls", "post-quantum", "cryptography", "compliance"],
            "cve": [], "cwe": ["CWE-327"], "cvss_score": None,
            "dedupe_key": make_dedupe_key("pqc", "pqc-not-ready", host, host),
            "raw": {"group": group, "version": version,
                    "pq_certificate": uses_pq_certificate(handshake)},
        })

    if log:
        checked = len([r for r in results if r and not isinstance(r, Exception)])
        await log("info",
                  f"[pqc] {checked} host(s) checked, {len(ready)} negotiate "
                  f"post-quantum key agreement", "pqc")
    return findings
