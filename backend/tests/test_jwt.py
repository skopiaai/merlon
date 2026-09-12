"""JWT weakness detection, offline.

The interesting property is that jwt-weak-secret is a *proof*, not a guess: the
test mints a token with a known-weak secret and asserts the engine recovers it,
and mints one with a strong secret and asserts it does not. If the crack ever
became a heuristic, the second test fails.
"""

import base64
import hashlib
import hmac
import json
import time

from app.engines import jwt as J
from app.models import Severity


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint(payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    """Build a real, correctly-signed JWT for the tests to detect."""
    header = {"alg": alg, "typ": "JWT"}
    seg = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    if alg == "none":
        return seg + "."
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret.encode(), seg.encode(), digest).digest()
    return f"{seg}.{_b64(sig)}"


# ------------------------------------------------------------ decode

def test_decode_rejects_non_jwts():
    assert J.decode_jwt("not.a.jwt") is None
    assert J.decode_jwt("aGVsbG8.d29ybGQ.c2ln") is None  # base64 but not JSON
    assert J.decode_jwt("only.two") is None
    assert J.decode_jwt(mint({"sub": "1"})) is not None


def test_decode_requires_alg_in_header():
    # A header that is JSON but has no alg is not treated as a JWT.
    header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()
    assert J.decode_jwt(f"{header}.{body}.x") is None


# ------------------------------------------------------------ weak secret (the proof)

def test_weak_secret_is_recovered():
    token = mint({"sub": "admin"}, secret="secret")
    issues = {i["rule"]: i for i in J.analyse_jwt(token)}
    assert "jwt-weak-secret" in issues
    assert issues["jwt-weak-secret"]["severity"] is Severity.critical
    assert issues["jwt-weak-secret"]["secret"] == "secret"


def test_strong_secret_is_not_cracked():
    token = mint({"sub": "admin"}, secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    rules = {i["rule"] for i in J.analyse_jwt(token)}
    assert "jwt-weak-secret" not in rules


def test_crack_only_targets_hmac():
    # An RS256 token must never be reported as weak-secret, even with a payload
    # that would otherwise trip nothing — there is no shared secret to recover.
    token = mint({"sub": "1", "exp": int(time.time()) + 60}, alg="HS256",
                 secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    decoded = J.decode_jwt(token)
    decoded["header"]["alg"] = "RS256"
    assert J.crack_hs_secret(decoded) is None


# ------------------------------------------------------------ alg=none

def test_alg_none_is_high():
    issues = {i["rule"]: i for i in J.analyse_jwt(mint({"sub": "1"}, alg="none"))}
    assert issues["jwt-alg-none"]["severity"] is Severity.high


# ------------------------------------------------------------ claims / expiry

def test_sensitive_claims_flagged():
    token = mint({"sub": "1", "password": "hunter2", "exp": int(time.time()) + 60},
                 secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    rules = {i["rule"] for i in J.analyse_jwt(token)}
    assert "jwt-sensitive-claims" in rules


def test_no_expiry_flagged():
    token = mint({"sub": "1"}, secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    rules = {i["rule"] for i in J.analyse_jwt(token)}
    assert "jwt-no-expiry" in rules


def test_normal_short_lived_token_is_quiet():
    now = int(time.time())
    token = mint({"sub": "1", "iat": now, "exp": now + 900},
                 secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    assert J.analyse_jwt(token, now=now) == []


def test_long_lived_flagged():
    now = int(time.time())
    token = mint({"sub": "1", "iat": now, "exp": now + 5 * 365 * 24 * 3600},
                 secret="Zx9$k2Lp!qW7mV3nR8sT1uY6bE4cH0aJ")
    rules = {i["rule"] for i in J.analyse_jwt(token, now=now)}
    assert "jwt-long-lived" in rules


# ------------------------------------------------------------ extraction

def test_regex_pulls_tokens_from_a_cookie_string():
    token = mint({"sub": "1"})
    cookie = f"session={token}; Path=/; HttpOnly"
    assert token in J._JWT_RE.findall(cookie)


def test_regex_ignores_ordinary_base64():
    assert J._JWT_RE.findall("aGVsbG8gd29ybGQ=") == []


# ------------------------------------------------------------ registration

def test_engine_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("jwt")
    assert spec is not None and spec.phase == "post_http"
    assert "standard" in spec.default_in
