"""Shared HTTP client for engines.

Every active engine needs the same three things: send a request, see the
status and headers, read the body. Each one growing its own private `_get`
meant subtly different timeout handling and no shared place to enforce limits.

curl is used rather than a Python client on purpose — it's already in the
image, it handles TLS quirks on broken hosts that stricter clients refuse
outright, and a hung request is a dead subprocess rather than a stuck task.

Nothing here follows redirects by default. Half the checks in this package
(open redirect, verb tampering, CORS) are *about* the response the server gives
before a redirect is followed, and a client that silently follows destroys the
evidence.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

# A response body big enough to be a download rather than a page tells you
# nothing extra and costs memory in every engine that holds one.
MAX_BODY = 2 * 1024 * 1024

DEFAULT_UA = "Mozilla/5.0 (compatible; security-assessment)"

_STATUS_LINE = re.compile(rb"^HTTP/[\d.]+\s+(\d{3})", re.M)


@dataclass
class Resp:
    """One HTTP response. `ok` is false for transport failures, not 4xx/5xx."""
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: bytes = b""

    @property
    def ok(self) -> bool:
        return self.status > 0

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _parse(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    """Split a curl -i response into status, headers and body.

    With redirects followed there are several header blocks; the last one is
    the response that actually produced the body.
    """
    if not raw:
        return 0, {}, b""

    # Find the final status line, then the header/body split after it.
    starts = [m.start() for m in _STATUS_LINE.finditer(raw)]
    if not starts:
        return 0, {}, raw
    block = raw[starts[-1]:]

    split = block.find(b"\r\n\r\n")
    sep = 4
    if split == -1:
        split = block.find(b"\n\n")
        sep = 2
    if split == -1:
        head, body = block, b""
    else:
        head, body = block[:split], block[split + sep:]

    lines = head.decode("iso-8859-1").splitlines()
    status = 0
    if lines:
        m = _STATUS_LINE.match(lines[0].encode("iso-8859-1"))
        status = int(m.group(1)) if m else 0

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        # Duplicate headers matter here: two Access-Control-Allow-Origin values
        # is itself a finding, so join rather than overwrite.
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return status, headers, body


def auth_for(url: str, ctx: dict | None) -> dict[str, str]:
    """Scope-checked credentials for this URL, from the scan context.

    Two failure modes this exists to prevent. Without it, engines silently scan
    the logged-out view of an application the operator believes they configured
    credentials for. And a naive fix — attaching the headers unconditionally —
    would send the user's session cookie to every host enumeration turned up,
    which for a bug bounty program means handing your session to a third party.

    So the scope check runs on every single request, not once per scan.
    """
    if not ctx:
        return {}
    headers = ctx.get("auth_headers") or {}
    if not headers:
        return {}
    from ..auth import scoped_headers
    return scoped_headers(url, headers, ctx.get("allow") or [], ctx.get("deny") or [])


async def request(url: str, *, method: str = "GET",
                  headers: dict[str, str] | None = None,
                  data: str | None = None,
                  follow: bool = False,
                  timeout: int = 15,
                  binary: bool = False,
                  ctx: dict | None = None,
                  identity: dict | None = None,
                  authenticated: bool = True) -> Resp:
    """One request. Never raises — a failure comes back as `status == 0`.

    Pass `ctx` to carry the scan's authenticated session. `identity` overrides
    it with a specific account's headers, and `authenticated=False` forces the
    request to go out logged-out — both of which the access-control engine
    needs in order to compare what different callers can see.
    """
    argv = ["curl", "-sS", "-i", "-k", "--path-as-is",
            "--max-time", str(timeout),
            "--max-filesize", str(MAX_BODY),
            "-A", DEFAULT_UA,
            "-X", method]
    if follow:
        argv += ["-L", "--max-redirs", "3"]

    merged: dict[str, str] = {}
    if authenticated:
        merged.update(auth_for(url, ctx) if identity is None
                      else scoped_identity(url, identity, ctx))
    # Explicit headers win: an engine setting Origin or Host means it.
    merged.update(headers or {})

    for key, value in merged.items():
        argv += ["-H", f"{key}: {value}"]
    if data is not None:
        argv += ["--data-binary", data]
    argv.append(url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 8)
    except (asyncio.TimeoutError, OSError):
        return Resp(url=url)
    except Exception:  # noqa: BLE001 - a broken request must not kill a scan
        return Resp(url=url)

    status, hdrs, body = _parse(out or b"")
    return Resp(url=url, status=status, headers=hdrs, raw=body,
                body="" if binary else body.decode("utf-8", "replace"))


def scoped_identity(url: str, identity: dict | None, ctx: dict | None) -> dict[str, str]:
    """Headers for a named identity, scope-checked the same way.

    A second account's credentials are exactly as sensitive as the first's, so
    they go through the identical gate rather than a shortcut.
    """
    if not identity:
        return {}
    headers = identity.get("headers") or {}
    if not headers:
        return {}
    from ..auth import scoped_headers
    return scoped_headers(url, headers,
                          (ctx or {}).get("allow") or [],
                          (ctx or {}).get("deny") or [])


async def gather_limited(coros, limit: int = 8) -> list:
    """Run coroutines with a concurrency cap.

    Engines fan out across dozens of URLs. Unbounded, that's a burst of
    hundreds of simultaneous connections — which looks like a denial of service
    attempt to the target and gets the scan blocked, or worse, causes the
    outage you were trying to help them avoid.
    """
    sem = asyncio.Semaphore(max(1, limit))

    async def run(coro):
        async with sem:
            try:
                return await coro
            except Exception:  # noqa: BLE001
                return None

    return await asyncio.gather(*(run(c) for c in coros))


def origins(urls: list[str]) -> list[str]:
    """Distinct scheme://host:port origins from a URL list."""
    from urllib.parse import urlparse
    out = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            out.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(out)
