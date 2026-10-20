"""Ayrık olay (discrete-event) çekirdeği.

Olaylar (t, seq, event) üçlüsüyle bir min-heap'te tutulur. `seq`, aynı zamanlı
olayların deterministik sırasını garanti eder.
"""
from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass(order=False)
class Event:
    time_ms: float
    target: str                       # düğüm adı (host, cov, isp, dns, server)
    kind: str                         # olay türü (ör. "packet", "timer")
    payload: Any = None
    seq: int = field(default=0)

    def __lt__(self, other: "Event") -> bool:
        return (self.time_ms, self.seq) < (other.time_ms, other.seq)


class EventQueue:
    def __init__(self) -> None:
        self._heap: list[Event] = []
        self._counter = itertools.count()

    def push(self, event: Event) -> None:
        event.seq = next(self._counter)
        heapq.heappush(self._heap, event)

    def pop(self) -> Event:
        return heapq.heappop(self._heap)

    def peek_time(self) -> Optional[float]:
        return self._heap[0].time_ms if self._heap else None

    def __len__(self) -> int:
        return len(self._heap)


Handler = Callable[[Event], "list[Event]"]


class Scheduler:
    """Olay döngüsü. Düğümler `handle(event) -> list[Event]` döndürür."""

    def __init__(self) -> None:
        self.clock_ms: float = 0.0
        self.queue = EventQueue()
        self._handlers: dict[str, Handler] = {}
        self._observers: list[Callable[[Event], None]] = []

    def register(self, name: str, handler: Handler) -> None:
        self._handlers[name] = handler

    def observe(self, fn: Callable[[Event], None]) -> None:
        self._observers.append(fn)

    def schedule(self, delay_ms: float, target: str, kind: str, payload: Any = None) -> None:
        if delay_ms < 0:
            raise ValueError("delay_ms negatif olamaz")
        self.queue.push(Event(self.clock_ms + delay_ms, target, kind, payload))

    def run(self, until_ms: float) -> None:
        while len(self.queue) and self.queue.peek_time() <= until_ms:
            event = self.queue.pop()
            self.clock_ms = event.time_ms
            for obs in self._observers:
                obs(event)
            handler = self._handlers.get(event.target)
            if handler is None:
                continue
            for new_event in handler(event) or []:
                self.queue.push(new_event)
        self.clock_ms = until_ms
