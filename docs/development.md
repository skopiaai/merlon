# Development

[← back to the README](../README.md)

## Architecture

```
React (Vite)  ──REST + WebSocket──>  FastAPI
                                       │
                                       ├── orchestrator.py   pipeline + scope re-checks
                                       ├── engines/          subfinder, naabu, httpx, katana, nuclei
                                       ├── normalize.py      → unified Finding
                                       ├── triage.py         → Ollama (advisory only)
                                       └── SQLite (WAL)
```

Scans run as asyncio tasks with streaming subprocess output — no Celery, no
Redis, no broker. For a single-user local tool that's the right amount of
machinery.

### Adding an engine

One file. Drop it in `backend/app/engines/` and declare what it is:

```python
from .registry import EngineSpec, register

@register(EngineSpec(
    name="myengine",
    label="Checking for X",          # shown in the progress view
    description="What it looks for and why it matters.",
    phase="post_http",               # "early" (seeds) or "post_http" (live URLs)
    takes="urls",                    # seeds | hosts | urls | assets
    weight=6,                        # relative duration, for the progress bar
    limit=25,                        # cap on targets (0 = no cap)
    skip_cdn=False,                  # skip hosts behind a CDN
    default_in=("standard", "deep"), # which depth presets include it
))
async def run(targets: list[str], ctx: dict) -> list[dict]:
    return [ ...finding dicts... ]
```

That's the whole integration. The stage becomes valid, joins the right depth
presets in the right order, gets a progress weight, names itself in the UI, and
its findings flow through scope filtering, dedupe, compliance enrichment,
correlation, triage and both reports — with no edits to the orchestrator,
schemas, or the frontend.

`engines/secrets.py` is the worked example: credential and source-map detection
in client-side JavaScript, written entirely as one file. `tests/test_registry.py`
asserts the architecture holds, including a guard that the orchestrator contains
no direct reference to any engine.

---

## Tests

Two layers, and the second one is the important one.

### Unit tests — components in isolation

```bash
cd backend && python -m pytest -q
```

Scope rules, parsers, compliance mapping, crypto solvers, log forensics. The
scope tests matter most: suffix-confusion (`example.com.evil.net`), CIDR
boundaries, deny-beats-allow, hard-denied cloud metadata.

### Integration tests — the real pipeline against a real vulnerable target

```bash
./run-lab-tests.sh            # ~1 min
./run-lab-tests.sh --slow     # includes the nuclei stage, ~15 min
```

This starts **OWASP Juice Shop** and **DVWA** on an internal Docker network,
runs the genuine orchestrator against them, and asserts what it should find:
the service is discovered, response headers are captured, the missing CSP is
reported, every finding carries a compliance mapping, nothing is duplicated,
and an out-of-scope host produces zero findings.

Why this layer exists: the unit tests passed happily while the scanner was
broken in five separate ways — `/dev/stdin` failing under asyncio, the 64 KiB
stream limit, `create_task` with no event loop, unmigrated schema columns,
missing arm64 packages. Every one of those is caught here in seconds.

> The lab containers are **deliberately insecure**. They sit on an `internal`
> Docker network with no host ports and no internet route, and never start
> during a normal `docker compose up`. Don't expose them.

---

## Layout

```
parapet/
├── docker-compose.yml
├── docs/UPDATING.md          ← the weekly maintenance runbook
├── backend/
│   ├── Dockerfile            ← pins scanner versions
│   └── app/
│       ├── scope.py          ← read this first
│       ├── orchestrator.py   ← the pipeline
│       ├── normalize.py      ← unified finding schema
│       ├── compliance.py     ← OWASP / ASVS / ISO / CIS / GIGW mapping
│       ├── updater.py        ← keeps templates and tools current
│       ├── triage.py         ← LLM prompts
│       ├── reporting.py
│       └── engines/          ← one file per detection
└── frontend/src/
```

---

## Contributing

The architecture was built so that adding a detection costs **one file**.
Register an engine and it becomes a valid scan stage, joins the right depth
presets, gets a progress weight, shows a label in the UI, and flows through
dedupe, compliance mapping and reporting — with no edits to the orchestrator,
the schemas, or the frontend.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the template and the rules. The
short version: put the judgement in a pure function, pass `ctx` to
`fetch.request`, cap your requests, and **write a test for your detection's
most likely false positive** — a large fraction of the existing test suite
exists for exactly that, because precision is what a scanner's reputation is
made of.

- [CONTRIBUTING.md](CONTRIBUTING.md) — adding engines, tests, what won't be merged
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities, known limitations, acceptable use
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

