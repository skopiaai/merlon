"""Shared test fixtures.

The `run_async` helper exists because of a real bug this suite hit. Several
files drove coroutines with `asyncio.get_event_loop().run_until_complete(...)`,
which reuses whatever loop happens to be installed; another file used
`asyncio.run(...)`, which creates a loop and *closes it on the way out*. Run
either alone and it passes. Run them in the same session and the second style
tears down the loop the first style depends on, so six unrelated tests fail
with "no current event loop" — an error that points nowhere near the cause.

`asyncio.get_event_loop()` is also deprecated outside a running loop and stops
working entirely in newer Pythons, so the old form was going to break on the
next interpreter bump regardless.

One helper, one loop per call, always cleaned up.
"""

import asyncio

import pytest


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        asyncio.set_event_loop(None)
        loop.close()


@pytest.fixture
def run_async():
    """Drive a coroutine from a synchronous test."""
    return _run


# Importable directly for module-level helpers that predate the fixture.
run_coroutine = _run
