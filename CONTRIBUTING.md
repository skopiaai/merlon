# Contributing

The most useful thing you can contribute is a detection engine. The
architecture was built so that costs one file.

---

## Adding an engine

An engine is a self-describing module in `backend/app/engines/`. Registering it
makes it a valid scan stage, puts it in the right depth presets, gives it a
progress weight, shows a label in the UI, and routes its findings through
dedupe, compliance mapping, correlation and reporting. You don't edit the
orchestrator, the schemas, or the frontend.

```python
"""One paragraph on what this looks for and why it matters.

Then the part that makes the file worth reading: what an attacker does with
this, and what the false positives are.
"""

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register


def judge(response_headers: dict) -> str | None:
    """Pure functions do the deciding. This is what gets tested."""
    ...


@register(EngineSpec(
    name="myengine",
    label="Checking for X",           # shown in the UI while it runs
    description="What it finds, and why that matters.",
    phase="post_http",                # "early" (seeds) | "post_http" (live URLs)
    takes="urls",                     # seeds | hosts | urls | assets
    produces="findings",              # findings | hosts | urls
    weight=5,                         # rough cost; drives ordering and progress
    limit=20,                         # cap on targets (0 = uncapped)
    default_in=("standard", "deep"),  # which depth presets include it
))
async def run(targets: list[str], ctx: dict) -> list[dict]:
    findings = []
    for url in targets:
        resp = await fetch.request(url, ctx=ctx, timeout=12)   # ctx carries auth
        ...
    return findings
```

Then `pytest`. If your engine registers correctly, existing tests in
`test_registry.py` will already be checking that it's wired up, weighted, and
mapped to a compliance control.

### Rules for engines

**Use `fetch.request` and pass `ctx`.** That's the single chokepoint where the
authenticated session gets attached and where scope is checked. An engine that
builds its own HTTP call runs logged-out and bypasses the scope guard — the
first is a silent coverage loss, the second is a serious bug.

**Put the judgement in a pure function.** Network calls can't be unit tested
usefully; the decision about what a response *means* can, and that's where the
bugs are. Every engine here has its parsing and its verdict logic pulled out
into functions that take strings and return verdicts.

**Cap your requests.** Use `limit`, use `fetch.gather_limited`. Unbounded
fan-out looks like a denial of service to the target, and might be one.

**Redact secrets from evidence.** If your engine finds a credential, the
finding must not contain it. There's a test for this in the existing engines;
write one for yours.

**Never modify the target.** See SECURITY.md. If confirming your finding
requires a write, a delete, or claiming a resource, the engine should report
what to verify manually instead.

---

## What findings must contain

The report is the product. A finding that's technically correct and badly
explained doesn't get fixed, and doesn't get paid.

```python
{
    "engine": "myengine",
    "rule_id": "stable-identifier",       # used for compliance mapping + dedupe
    "name": "Short human title",
    "severity": Severity.high,
    "host": host, "url": url, "matched_at": url,
    "description": "...",                 # what it is AND what it means
    "evidence": "...",                    # the actual request/response, redacted
    "remediation": "...",                 # what to do, specifically
    "references": ["https://..."],
    "tags": [...], "cve": [], "cwe": ["CWE-..."],
    "cvss_score": None,
    "dedupe_key": make_dedupe_key("myengine", "rule", host, url),
    "raw": {},
}
```

On `description`: write for the person who has to fix it, not for another
security researcher. "Missing HSTS header" is a fact; "someone on the same
café wifi can downgrade this to HTTP and read the session cookie" is a reason
to act. Say what an attacker does with it and what they get.

On `remediation`: be specific enough to act on. Config snippets and code
examples beat "implement proper validation."

On new `rule_id`s: add a mapping in `compliance.py` so the finding lands in a
real OWASP/ASVS/ISO control rather than the catch-all. There's a test that
checks new rules don't fall through.

---

## Tests

```bash
cd backend && pytest                                    # unit, ~2 seconds
./run-lab-tests.sh                                      # integration vs. a real
                                                        # vulnerable target
cd frontend && npx tsc --noEmit                          # typecheck
```

Unit tests must not touch the network. Anything that does belongs in
`tests/integration/`, which runs against deliberately vulnerable containers
(Juice Shop, DVWA) brought up by Docker Compose.

**Write tests for the false positives, not just the true positives.** Look at
the existing test files — a large fraction of them exist to hold down a
plausible-looking non-finding: a single-page app that answers 200 for `/.env`,
a CNAME to CloudFront that isn't takeoverable, a `Location` header containing
a canary as a query parameter rather than a redirect target, a login page
returned with HTTP 200 that isn't successful access.

That's not incidental. A scanner's reputation is set by its precision, and
every wrong finding costs the operator credibility with a triage team they
need for their next report. **A pull request that adds a detection without
adding a test for its most likely false positive will be asked for one.**

Use the `run_async` fixture (or `run_coroutine` from `conftest.py`) to drive
coroutines from sync tests. Don't call `asyncio.run` directly — it closes the
loop and breaks other tests in the same session.

---

## What won't be merged

- Exploitation, weaponisation, or anything that modifies a target.
- Evasion, log avoidance, or WAF bypass for concealment.
- Anything that weakens or works around the scope guard.
- Detections with no test.
- Vendored binaries or large blobs.
- Formatting-only churn across files you didn't otherwise change.

---

## Style

Python: standard library first, then third party, then local. Type hints on
anything non-obvious. `ruff` defaults are fine.

Comments should explain **why**, not what. The code says what it does; the
comment is for the reason that isn't obvious from reading it — the bug you hit,
the assumption you're relying on, the reason the obvious approach doesn't work.
Several files here carry a paragraph at the top explaining the attack the
module exists to catch, and those are the most useful documentation in the
repository.

Frontend: TypeScript, no `any`. Tailwind isn't used — plain CSS in
`styles.css` with variables for theming.

---

## Reporting bugs

Include what you scanned (or a description if it's private), the depth preset,
what you expected, and what happened. For a scan that misbehaved, the scan log
from the Console tab is the single most useful thing you can attach.

**Never attach real findings about a third party's systems to a public issue.**
Redact hostnames, or describe the shape of the problem instead.

---

## A note on the licence

Contributions are accepted under the MIT Licence, the same licence as the project.
By opening a pull request you're agreeing that your contribution can be
distributed under it.
