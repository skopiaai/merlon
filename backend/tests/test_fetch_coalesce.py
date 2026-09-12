"""Simultaneous identical requests share one subprocess — and nothing else does.

The second half of that sentence is the important half. verify.py decides
whether a finding is real by fetching its URL twice and comparing, so anything
that hands both fetches the same response turns the verification gate into a
rubber stamp. These tests pin the boundary.
"""

import asyncio

import pytest

from app.engines import fetch

from .conftest import run_coroutine


@pytest.fixture(autouse=True)
def _clear_inflight():
    fetch._inflight.clear()
    yield
    fetch._inflight.clear()


def _counting_execute(calls, *, delay=0.05, status=200, body="hello"):
    async def _execute(url, **kw):
        calls.append((url, kw.get("method", "GET")))
        await asyncio.sleep(delay)
        return fetch.Resp(url=url, status=status, body=body)
    return _execute


def test_concurrent_identical_requests_run_once(monkeypatch):
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        results = await asyncio.gather(*[
            fetch._one_request("https://example.com/", method="GET")
            for _ in range(5)
        ])

        assert len(calls) == 1, "five simultaneous identical GETs should run once"
        assert all(r.status == 200 and r.body == "hello" for r in results)
    run_coroutine(_body())

def test_each_caller_gets_its_own_object(monkeypatch):
    """request() writes redirect_blocked onto the Resp it is handed."""
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        a, b = await asyncio.gather(
            fetch._one_request("https://example.com/"),
            fetch._one_request("https://example.com/"),
        )
        assert a is not b
        a.redirect_blocked = "scribbled"
        assert b.redirect_blocked == "", "callers must not share mutable state"
    run_coroutine(_body())

def test_sequential_requests_are_not_shared(monkeypatch):
    """The verification gate's whole method. Two fetches, two real requests."""
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls, delay=0))

        await fetch._one_request("https://example.com/")
        await fetch._one_request("https://example.com/")

        assert len(calls) == 2, "a later request must never reuse an earlier answer"
    run_coroutine(_body())

def test_fresh_opts_out(monkeypatch):
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        await asyncio.gather(
            fetch._one_request("https://example.com/", fresh=True),
            fetch._one_request("https://example.com/", fresh=True),
        )
        assert len(calls) == 2
    run_coroutine(_body())

def test_posts_are_never_coalesced(monkeypatch):
    """A body means the caller is changing something; each one must be sent."""
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        await asyncio.gather(
            fetch._one_request("https://example.com/x", method="POST", data="a=1"),
            fetch._one_request("https://example.com/x", method="POST", data="a=1"),
        )
        assert len(calls) == 2
    run_coroutine(_body())

def test_different_identities_are_not_shared(monkeypatch):
    """The access-control engine compares what two accounts can see."""
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        alice, bob = {"name": "alice"}, {"name": "bob"}
        await asyncio.gather(
            fetch._one_request("https://example.com/acct", identity=alice),
            fetch._one_request("https://example.com/acct", identity=bob),
        )
        assert len(calls) == 2, "one user's response must never answer for another"
    run_coroutine(_body())

def test_logged_out_request_is_not_shared_with_logged_in(monkeypatch):
    async def _body():
        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls))

        await asyncio.gather(
            fetch._one_request("https://example.com/acct", authenticated=True),
            fetch._one_request("https://example.com/acct", authenticated=False),
        )
        assert len(calls) == 2
    run_coroutine(_body())

def test_failure_propagates_and_clears(monkeypatch):
    """A raising request must not leave a poisoned entry behind."""
    async def _body():
        async def _boom(url, **kw):
            await asyncio.sleep(0)
            raise OSError("boom")
        monkeypatch.setattr(fetch, "_execute", _boom)

        with pytest.raises(OSError):
            await fetch._one_request("https://example.com/")
        assert fetch._inflight == {}, "in-flight entry must be cleared on failure"

        calls = []
        monkeypatch.setattr(fetch, "_execute", _counting_execute(calls, delay=0))
        resp = await fetch._one_request("https://example.com/")
        assert resp.status == 200
    run_coroutine(_body())
