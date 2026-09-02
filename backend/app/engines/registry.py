"""Engine registry — the plugin layer.

Adding a detection used to mean editing four files: the orchestrator (to call
it), schemas (to allow the stage name), compliance (to map its findings), and
the frontend (to label it). Four places to half-finish.

Now an engine is one self-describing file:

    from .registry import EngineSpec, register

    @register(EngineSpec(
        name="myengine",
        label="Checking for X",
        description="What this looks for and why it matters.",
        phase="post_http",
        takes="urls",
        weight=6,
        default_in=("standard", "deep"),
    ))
    async def run(targets, ctx):
        return [ ...finding dicts... ]

That's the whole integration. The stage becomes valid, appears in the right
depth presets, gets a progress weight, shows a human label in the UI, and its
findings flow through dedupe, compliance enrichment, correlation and reporting
like any other.

Two phases exist because of data dependencies:

  early      — runs on the seed domains, before anything has been probed
               (DNS and email policy, for instance)
  post_http  — runs on live URLs discovered by httpx

Engines within a phase run concurrently; the orchestrator handles that.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

Phase = Literal["early", "post_http"]
Takes = Literal["seeds", "hosts", "urls", "assets"]

# What an engine gives back:
#   findings — the usual case; dicts that become Finding rows
#   hosts    — newly discovered hostnames, merged into the scan's host list
#   urls     — newly discovered URLs, merged into the scan's URL list
#
# Asset-producing engines are how the attack surface widens: certificate
# transparency, archived URLs, endpoints buried in JavaScript. Everything they
# return goes through the same scope guard as any other discovery, so a
# widened surface can never widen past the engagement.
Produces = Literal["findings", "hosts", "urls"]

# What an engine receives besides its targets: the scan's logger and context.
RunFn = Callable[[list, dict], Awaitable[list[dict]]]


@dataclass(frozen=True)
class EngineSpec:
    name: str                       # stage id, e.g. "domainsec"
    label: str                      # human label shown while it runs
    description: str = ""
    phase: Phase = "post_http"
    takes: Takes = "urls"
    produces: Produces = "findings"
    weight: int = 5                 # relative duration, for the progress bar
    default_in: tuple[str, ...] = ()   # depth presets: quick | standard | deep
    skip_cdn: bool = False          # pointless against a CDN edge
    limit: int = 0                  # cap on targets passed in (0 = no cap)
    run: RunFn | None = field(default=None, compare=False)

    def with_run(self, fn: RunFn) -> EngineSpec:
        return EngineSpec(**{**self.__dict__, "run": fn})


_REGISTRY: dict[str, EngineSpec] = {}

# Tracked separately from `_REGISTRY` being empty. Importing a single engine
# module directly — as a test or another module might — registers that one
# engine, which would otherwise make the registry look "already discovered"
# and silently hide every other engine.
_DISCOVERED = False


def register(spec: EngineSpec):
    """Decorator. Attaches the run function and registers the engine."""
    def wrap(fn: RunFn) -> RunFn:
        if spec.name in _REGISTRY:
            raise ValueError(f"engine '{spec.name}' is already registered")
        _REGISTRY[spec.name] = spec.with_run(fn)
        return fn
    return wrap


def discover(force: bool = False) -> dict[str, EngineSpec]:
    """Import every module in this package so the decorators run.

    Import-time failure of one engine must not take the others down — a missing
    optional dependency should cost you that detection, not the whole scan.
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return _REGISTRY

    import app.engines as pkg

    _DISCOVERED = True   # set first, so a re-entrant import can't loop
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name in ("registry", "base"):
            continue
        try:
            importlib.import_module(f"app.engines.{mod.name}")
        except Exception as exc:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning(
                "engine module %s failed to import — that detection is "
                "unavailable: %s", mod.name, exc)
    return _REGISTRY


def all_engines() -> dict[str, EngineSpec]:
    discover()
    return dict(_REGISTRY)


def get(name: str) -> EngineSpec | None:
    return all_engines().get(name)


def for_phase(phase: Phase, stages: list[str]) -> list[EngineSpec]:
    """Registered engines in this phase that the scan actually asked for."""
    return [e for e in all_engines().values()
            if e.phase == phase and e.name in stages]


def stage_names() -> list[str]:
    return sorted(all_engines())


def weights() -> dict[str, int]:
    return {name: spec.weight for name, spec in all_engines().items()}


def labels() -> dict[str, str]:
    return {name: spec.label for name, spec in all_engines().items()}


def defaults_for(depth: str) -> list[str]:
    """Engine stages that belong in a given depth preset."""
    return [name for name, spec in all_engines().items() if depth in spec.default_in]


def describe() -> list[dict]:
    """Machine-readable inventory, for the API and the UI."""
    return [
        {
            "name": s.name, "label": s.label, "description": s.description,
            "phase": s.phase, "takes": s.takes, "produces": s.produces,
            "weight": s.weight,
            "default_in": list(s.default_in), "skip_cdn": s.skip_cdn,
        }
        for s in sorted(all_engines().values(), key=lambda e: (e.phase, e.name))
    ]
