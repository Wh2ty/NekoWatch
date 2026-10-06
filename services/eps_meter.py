"""In-memory EPS meter — no database involvement.

Events are observed as JSON arrives (enqueue / parse time). A sliding
1-second window yields the live Events-Per-Second figure pushed over
WebSocket. SQL is never consulted on this path.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EpsSnapshot:
    """Point-in-time EPS reading."""

    events_per_second: float
    events_in_window: int
    window_seconds: float
    observed_total: int
    sampled_at: float  # monotonic


class EpsMeter:
    """Thread-safe / async-safe ring of arrival timestamps.

    Designed for the ingestion hot path: ``observe()`` is O(1) amortized and
    never awaits I/O. Safe to call from the asyncio event loop and from
    worker threads (uses a lightweight lock).
    """

    def __init__(self, *, window_seconds: float = 1.0, maxlen: int = 50_000) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._window = float(window_seconds)
        self._times: deque[float] = deque(maxlen=maxlen)
        self._observed_total = 0
        self._lock = threading.Lock()

    @property
    def window_seconds(self) -> float:
        return self._window

    @property
    def observed_total(self) -> int:
        with self._lock:
            return self._observed_total

    def observe(self, count: int = 1, *, at: float | None = None) -> None:
        """Record ``count`` events arriving at ``at`` (monotonic seconds)."""
        if count <= 0:
            return
        stamp = time.monotonic() if at is None else at
        with self._lock:
            for _ in range(count):
                self._times.append(stamp)
            self._observed_total += count

    def snapshot(self, *, now: float | None = None) -> EpsSnapshot:
        """Count events inside the trailing window (pure memory)."""
        now_m = time.monotonic() if now is None else now
        cutoff = now_m - self._window
        with self._lock:
            while self._times and self._times[0] < cutoff:
                self._times.popleft()
            count = len(self._times)
            total = self._observed_total
        # 1s window → rate equals the raw count.
        rate = float(count) / self._window if self._window else float(count)
        return EpsSnapshot(
            events_per_second=rate,
            events_in_window=count,
            window_seconds=self._window,
            observed_total=total,
            sampled_at=now_m,
        )

    def reset(self) -> None:
        """Clear history (e.g. after full wipe)."""
        with self._lock:
            self._times.clear()
            self._observed_total = 0
