"""In-memory async publish/subscribe event bus.

``detector`` -> ``decider`` -> ``bouncer`` never call each other: a stage
publishes typed events, interested stages subscribe.  This is the
crowdsec-style decoupling point, rebuilt on ``asyncio.Queue`` with typed
payloads, per-subscriber backpressure, and a bounded history ring.

Concept inspired by: crowdsec — alert pipeline decoupling; crowdsec's
decoupled bouncer/decision model.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from core.models import Decision, HardeningEvent

__all__ = ["BusOverflow", "EventBus", "Subscription"]

Subscriber = Callable[[HardeningEvent | Decision], Awaitable[None]]


class BusOverflow(RuntimeError):
    """A subscriber queue exceeded its bound; the slow consumer is dropped."""


@dataclass
class Subscription[T: (HardeningEvent, Decision)]:
    """One subscriber's delivery channel."""

    name: str
    queue: asyncio.Queue[tuple[type, object]]
    event_types: tuple[type, ...]
    maxsize: int

    async def get(self) -> tuple[type, object]:
        """Await the next matching event; returns ``(kind, payload)``."""
        return await self.queue.get()

    @property
    def pending(self) -> int:
        return self.queue.qsize()


class EventBus:
    """Typed pub/sub over ``HardeningEvent`` and ``Decision`` payloads.

    Publishing never blocks the producer: each subscriber owns a bounded
    ``asyncio.Queue``; an overflowing slow consumer gets its queue drained
    with a ``BusOverflow`` logged into the dead-letter list (observable, not
    silent).
    """

    def __init__(self, history_size: int = 256, default_maxsize: int = 512) -> None:
        self._subs: dict[str, Subscription] = {}
        self._by_type: dict[type, list[str]] = defaultdict(list)
        self._history: deque = deque(maxlen=history_size)
        self._default_maxsize = default_maxsize
        self._dead_letters: list[str] = []
        self._seq = itertools.count()

    def subscribe(
        self,
        name: str,
        handler: Subscriber | None = None,
        *,
        types: tuple[type, ...] = (HardeningEvent, Decision),
        maxsize: int | None = None,
    ) -> Subscription:
        """Register a subscriber under ``name``.

        ``handler`` is optional — with one, the bus drives delivery itself via
        :meth:`run_forever`; without one, the consumer pulls from the returned
        :class:`Subscription` (e.g. in tests or a CLI loop).
        """
        if name in self._subs:
            raise ValueError(f"subscriber name taken: {name!r}")
        sub: Subscription = Subscription(
            name=name,
            queue=asyncio.Queue(maxsize=maxsize or self._default_maxsize),
            event_types=types,
            maxsize=maxsize or self._default_maxsize,
        )
        if handler is not None:
            sub.handler = handler  # type: ignore[attr-defined]
        self._subs[name] = sub
        for t in types:
            self._by_type[t].append(name)
        return sub

    def unsubscribe(self, name: str) -> None:
        sub = self._subs.pop(name, None)
        if sub is None:
            return
        for t in sub.event_types:
            self._by_type[t] = [n for n in self._by_type[t] if n != name]

    def publish(self, event: HardeningEvent | Decision) -> None:
        """Fan one event out to every matching subscriber (non-blocking).

        Safe to call from a synchronous pipeline stage running inside the bus
        loop's thread: queue puts are awaited opportunistically, falling back
        to bounded drop-on-overflow.
        """
        self._history.append((next(self._seq), event))
        names = self._by_type.get(type(event), [])
        for name in list(names):
            sub = self._subs[name]
            try:
                sub.queue.put_nowait((type(event), event))
            except asyncio.QueueFull:
                # Slow consumer: drop oldest half to shed load, record it.
                dropped = 0
                while sub.queue.qsize() > sub.maxsize // 2:
                    try:
                        sub.queue.get_nowait()
                        sub.queue.task_done()  # keep join() bookkeeping balanced
                        dropped += 1
                    except asyncio.QueueEmpty:
                        break
                self._dead_letters.append(
                    f"{name}:overflow:{type(event).__name__}:"
                    f"{getattr(event, 'event_id', getattr(event, 'decision_id', '?'))}"
                    f":dropped={dropped}"
                )
                with contextlib.suppress(asyncio.QueueFull):
                    sub.queue.put_nowait((type(event), event))

    # -- handler-driven operation -------------------------------------------------

    async def run_forever(self) -> None:
        """Drive every handler-subscriber until cancelled."""
        async def _loop(sub: Subscription) -> None:
            handler = getattr(sub, "handler", None)
            while True:
                _kind, payload = await sub.queue.get()
                try:
                    await handler(payload)  # type: ignore[misc]
                finally:
                    sub.queue.task_done()

        tasks = [
            asyncio.ensure_future(_loop(sub))
            for sub in self._subs.values()
            if getattr(sub, "handler", None) is not None
        ]
        if not tasks:
            return
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise

    async def drain(self) -> None:
        """Wait until every handler-subscriber has processed its backlog."""
        for sub in self._subs.values():
            if getattr(sub, "handler", None) is not None:
                await sub.queue.join()

    # -- observability ------------------------------------------------------------

    @property
    def history(self) -> list[tuple[int, HardeningEvent | Decision]]:
        return list(self._history)

    @property
    def dead_letters(self) -> list[str]:
        return list(self._dead_letters)

    @property
    def subscriber_names(self) -> list[str]:
        return list(self._subs)
