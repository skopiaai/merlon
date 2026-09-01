"""Encoding and cryptography analysis.

Two jobs, both of which eat time in a CTF if done by hand:

1. **Decode chains.** Challenge text is routinely base64 of hex of rot13 of the
   flag. Peeling those layers one at a time in a terminal is slow, so we do it
   breadth-first and report every layer that produced something readable.

2. **RSA weakness analysis.** Given n, e and optionally a ciphertext, check the
   classic implementation failures — small exponent, close primes, tiny n,
   shared factors. These are analysis of parameters the challenge gave you, not
   attacks on anything live.

Nothing here touches a network or another system.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import string

PRINTABLE = set(string.printable.encode())


def _readable(data: bytes, threshold: float = 0.85) -> bool:
    """Is this plausibly text a human would read?"""
    if not data or len(data) < 3:
        return False
    printable = sum(1 for b in data if b in PRINTABLE)
    return printable / len(data) >= threshold


def _try_base64(s: str) -> bytes | None:
    t = re.sub(r"\s+", "", s)
    if len(t) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=]+", t):
        return None
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def _try_base32(s: str) -> bytes | None:
    t = re.sub(r"\s+", "", s).upper()
    if len(t) < 8 or not re.fullmatch(r"[A-Z2-7=]+", t):
        return None
    try:
        return base64.b32decode(t + "=" * (-len(t) % 8))
    except (binascii.Error, ValueError):
        return None


def _try_hex(s: str) -> bytes | None:
    t = re.sub(r"[\s:]+", "", s)
    if len(t) < 4 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def _try_rot(s: str, n: int) -> bytes:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out).encode()


def _try_binary(s: str) -> bytes | None:
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or len(t) % 8 or not re.fullmatch(r"[01]+", t):
        return None
    try:
        return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))
    except ValueError:
        return None


def _try_decimal(s: str) -> bytes | None:
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 3 or not all(p.isdigit() and int(p) < 256 for p in parts if p):
        return None
    try:
        return bytes(int(p) for p in parts if p)
    except ValueError:
        return None


def _try_url(s: str) -> bytes | None:
    if "%" not in s:
        return None
    from urllib.parse import unquote_to_bytes
    try:
        out = unquote_to_bytes(s)
        return out if out != s.encode() else None
    except Exception:  # noqa: BLE001
        return None


DECODERS = [
    ("base64", _try_base64),
    ("base32", _try_base32),
    ("hex", _try_hex),
    ("binary", _try_binary),
    ("decimal bytes", _try_decimal),
    ("url-encoding", _try_url),
    ("rot13", lambda s: _try_rot(s, 13)),
    ("reversed", lambda s: s[::-1].encode()),
]


def decode_chain(text: str, max_depth: int = 6) -> list[dict]:
    """Breadth-first peel of encoding layers.

    Reports every path that yields readable output, so you can see e.g.
    base64 → hex → rot13 → flag without trying each by hand.
    """
    results: list[dict] = []
    seen: set[str] = {text.strip()}
    frontier = [(text.strip(), [])]

    for _depth in range(max_depth):
        nxt = []
        for current, path in frontier:
            for label, fn in DECODERS:
                try:
                    out = fn(current)
                except Exception:  # noqa: BLE001
                    continue
                if not out:
                    continue
                try:
                    as_text = out.decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    continue
                key = as_text.strip()
                if not key or key in seen:
                    continue
                seen.add(key)
                chain = path + [label]

                if _readable(out):
                    results.append({
                        "chain": " → ".join(chain),
                        "output": as_text[:2000],
                        "depth": len(chain),
                    })
                nxt.append((as_text, chain))
        frontier = nxt[:60]   # keep the search bounded
        if not frontier:
            break

    # Shortest chain first — usually the intended one.
    results.sort(key=lambda r: r["depth"])
    return results[:25]


# ---------------------------------------------------------------- classical

def caesar_all(text: str) -> list[dict]:
    """All 25 shifts. Cheap, and instantly obvious when one is right."""
    return [{"shift": n, "output": _try_rot(text, n).decode("utf-8", "replace")[:300]}
            for n in range(1, 26)]


def xor_single_byte(data: bytes) -> list[dict]:
    """Single-byte XOR brute force, scored by how English-like the result is."""
    common = b"etaoinshrdlu ETAOIN"
    scored = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        if not _readable(out, 0.9):
            continue
        score = sum(out.count(bytes([c])) for c in common)
        scored.append({"key": key, "score": score,
                       "output": out.decode("utf-8", "replace")[:300]})
    scored.sort(key=lambda r: -r["score"])
    return scored[:10]


# --------------------------------------------------------------------- RSA

def _int_root(n: int, k: int) -> int:
    """Exact integer k-th root via Newton's method (no float precision loss)."""
    if n < 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k + 1)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def _fermat(n: int, rounds: int = 200_000) -> tuple[int, int] | None:
    """Factor n when p and q are close together."""
    if n % 2 == 0:
        return (2, n // 2)
    a = _int_root(n, 2)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = _int_root(b2, 2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
    return None


def analyse_rsa(n: int, e: int, c: int | None = None,
                other_n: list[int] | None = None) -> dict:
    """Check the classic RSA implementation failures.

    This inspects parameters the challenge handed you — it isn't an attack on
    any live system.
    """
    findings: list[dict] = []
    bits = n.bit_length()

    if bits < 512:
        findings.append({
            "issue": f"Modulus is only {bits} bits",
            "why": "Anything under 512 bits is factorable directly. Try an online "
                   "factor database or a local factoring tool before anything clever.",
            "next": f"python3 -c \"import sympy; print(sympy.factorint({n}))\"",
        })

    if e == 3 or e < 100:
        note = {
            "issue": f"Very small public exponent (e = {e})",
            "why": "With no padding and a short message, c = m^e can be smaller than "
                   "n, so the plaintext is just the integer e-th root of c — no "
                   "factoring needed.",
        }
        if c is not None:
            root = _int_root(c, e)
            if root ** e == c:
                m = root
                try:
                    text = m.to_bytes((m.bit_length() + 7) // 8, "big")
                    note["recovered"] = text.decode("utf-8", "replace")
                    note["why"] += " Confirmed: the exact root exists."
                except (OverflowError, ValueError):
                    note["recovered"] = str(m)
        findings.append(note)

    fermat = _fermat(n)
    if fermat:
        p, q = fermat
        if p != 1 and q != 1 and p * q == n:
            findings.append({
                "issue": "Primes are close together (Fermat factorisation succeeded)",
                "why": "p and q were generated too near each other, so n factors "
                       "almost immediately.",
                "p": str(p), "q": str(q),
            })

    for idx, m in enumerate(other_n or []):
        if m == n:
            continue
        g = math.gcd(n, m)
        if g > 1:
            findings.append({
                "issue": f"Shared prime factor with key #{idx + 1}",
                "why": "Two moduli share a prime, so GCD recovers it instantly. This "
                       "happens when keys are generated with a weak entropy source.",
                "p": str(g), "q": str(n // g),
            })

    if not findings:
        findings.append({
            "issue": "No classic weakness detected",
            "why": "Modulus size, exponent, prime distance and shared factors all look "
                   "reasonable. Look at how the challenge uses RSA rather than the "
                   "parameters — padding, signing, or a side channel.",
        })

    return {"bits": bits, "e": e, "findings": findings}
