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
from dataclasses import dataclass, field, replace
from urllib.parse import urljoin, urlparse

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
    # Set when a redirect was refused. Surfaced rather than swallowed: a target
    # pointing the scanner at link-local or loopback is worth seeing.
    redirect_blocked: str = ""

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


async def _execute(url: str, *, method: str = "GET",
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
            # A URL is data, never a curl glob. By default curl reads `[` and
            # `]` as range/list globbing, so a perfectly ordinary crawled URL
            # like `?filter[]=x` — or an operator-injection probe like
            # `user[$ne]=1` — fails with "bad range specification" and the
            # request never goes out. --globoff turns that off for every fetch.
            "--globoff",
            "--max-time", str(timeout),
            "--max-filesize", str(MAX_BODY),
            # Defence in depth against a `Location:` that leaves HTTP entirely.
            # Without this, `Location: file:///etc/passwd` makes curl read a
            # local file and hand it back as a response body — verified against
            # curl 7.81. The redirect loop below would catch it anyway; this
            # catches anything the loop does not.
            "--proto", "=http,https",
            "--proto-redir", "=http,https",
            "-A", DEFAULT_UA,
            "-X", method]

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
    # `--url` rather than a positional argument. A "URL" harvested from tool
    # output or a crawled page can begin with a dash, and curl would read it as
    # a flag — `-o/path` writes a file, `-K file` reads a config. Nothing
    # upstream guarantees the shape of these strings.
    argv += ["--url", url]

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


# ---------------------------------------------------------------- coalescing
#
# Engines inside a phase run concurrently, and several of them independently
# fetch the same handful of URLs — the site root, /robots.txt, the login page,
# a JS bundle. Each of those was its own curl subprocess and its own request
# hitting the target.
#
# This merges requests that are *simultaneously in flight* into one. What it
# deliberately does not do is cache completed responses, and that distinction
# is load-bearing: verify.py establishes whether a finding is real by fetching
# its URL twice, a fifth of a second apart, and comparing. A response cache
# would hand it the same bytes both times, every finding would "reproduce",
# and the submission queue — which is ordered by exactly that signal — would
# become noise sorted confidently.
#
# So an entry exists only while a request is actually running. Two engines
# asking at the same moment share one answer; anything sequential re-requests
# for real, exactly as before.
_inflight: dict[tuple, asyncio.Future[Resp]] = {}

# Only requests that are safe to answer twice with one response. A body means
# the caller is changing something, and a non-idempotent verb means the second
# caller wanted its own side effect.
_COALESCABLE_METHODS = {"GET", "HEAD"}


def _coalesce_key(url: str, method: str, headers: dict[str, str],
                  timeout: int, binary: bool, authenticated: bool,
                  identity: dict | None, ctx: dict | None) -> tuple:
    """Everything that can change the bytes that come back.

    Identity and ctx are part of the key because the access-control engine's
    whole method is asking for the same URL as different callers and comparing
    what each gets. Keying on the URL alone would hand user B the response that
    was fetched for user A — inventing an access-control finding, or hiding a
    real one.
    """
    ident = id(identity) if identity is not None else 0
    session = id(ctx) if ctx is not None else 0
    return (url, method, tuple(sorted((headers or {}).items())),
            timeout, binary, authenticated, ident, session)


async def _one_request(url: str, **kw) -> Resp:
    """`_execute`, with simultaneous identical requests sharing one subprocess."""
    method = (kw.get("method") or "GET").upper()
    fresh = kw.pop("fresh", False)

    if (fresh or kw.get("data") is not None
            or method not in _COALESCABLE_METHODS):
        return await _execute(url, **kw)

    key = _coalesce_key(url, method, kw.get("headers") or {},
                        kw.get("timeout", 15), kw.get("binary", False),
                        kw.get("authenticated", True),
                        kw.get("identity"), kw.get("ctx"))

    existing = _inflight.get(key)
    if existing is not None:
        resp = await asyncio.shield(existing)
        # A copy per caller: `request()` writes redirect_blocked onto the Resp
        # it is handed, and two callers must not scribble on each other's.
        return replace(resp)

    loop = asyncio.get_running_loop()
    fut: asyncio.Future[Resp] = loop.create_future()
    _inflight[key] = fut
    try:
        resp = await _execute(url, **kw)
    except BaseException as exc:       # noqa: BLE001 - re-raised below
        if not fut.done():
            fut.set_exception(exc)
        # Nobody may be waiting; stop asyncio reporting it as never retrieved.
        fut.exception()
        raise
    else:
        if not fut.done():
            fut.set_result(resp)
        return replace(resp)
    finally:
        _inflight.pop(key, None)


REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 3


async def request(url: str, *, follow: bool = False, **kw) -> Resp:
    """One request, following redirects *through the scope guard* if asked.

    Redirects used to be handed to curl with `-L`, which is where this went
    wrong: the scope guard runs over the targets an engine is given, and a
    target that is legitimately in scope can still answer

        302 Location: http://169.254.169.254/latest/meta-data/

    and curl would fetch it. The seed was checked; the hop never was. On a
    cloud host that reaches the instance metadata service — credentials — and
    on any host it reaches loopback, where this application's own unauthenticated
    API is listening.

    So each hop is resolved here and passed through `scope.hard_denied` before
    it is fetched. Only the absolute prohibitions are enforced, not the
    engagement allowlist: a site redirecting to its own CDN or to a login on a
    sibling domain is normal, and refusing those would break ordinary scanning
    to prevent nothing.
    """
    from .. import scope

    # `fresh=True` opts out of coalescing entirely. Nothing sequential needs
    # it — an in-flight entry only lives while a request is running — but the
    # verification gate passes it so that the guarantee is stated in the code
    # rather than inferred from timing, and survives verification ever being
    # made concurrent.
    resp = await _one_request(url, **kw)
    if not follow:
        return resp

    seen = {url}
    for _ in range(MAX_REDIRECTS):
        if resp.status not in REDIRECT_CODES:
            return resp
        location = (resp.headers or {}).get("location", "").strip()
        if not location:
            return resp

        nxt = urljoin(resp.url, location)
        parsed = urlparse(nxt)
        if parsed.scheme not in ("http", "https"):
            resp.redirect_blocked = f"refused non-HTTP redirect to {parsed.scheme}:"
            return resp
        reason = scope.hard_denied(nxt)
        if reason:
            # Recorded rather than raised: a scan must not die because one
            # target pointed somewhere it should not, and the fact that it
            # *tried* is itself worth seeing in the log.
            resp.redirect_blocked = f"refused redirect — {reason}"
            return resp
        if nxt in seen:
            return resp
        seen.add(nxt)

        resp = await _one_request(nxt, **kw)
    return resp


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
