"""In-process pub/sub for live scan updates over WebSocket."""

from __future__ import annotations

import asyncio
from collections import defaultdict


class EventHub:
    def __init__(self) -> None:
        self._subs: dict[int, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, scan_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs[scan_id].add(q)
        return q

    def unsubscribe(self, scan_id: int, q: asyncio.Queue) -> None:
        self._subs[scan_id].discard(q)
        if not self._subs[scan_id]:
            self._subs.pop(scan_id, None)

    async def publish(self, scan_id: int, event: dict) -> None:
        for q in list(self._subs.get(scan_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # A stalled client must never back-pressure a running scan.
                pass


hub = EventHub()
