"""In-memory EPS meter — SQL-free by design."""

from __future__ import annotations

import time

from services.eps_meter import EpsMeter


def test_eps_meter_counts_window() -> None:
    meter = EpsMeter(window_seconds=1.0)
    now = time.monotonic()
    meter.observe(3, at=now)
    meter.observe(2, at=now)
    snap = meter.snapshot(now=now)
    assert snap.events_in_window == 5
    assert snap.events_per_second == 5.0
    assert snap.observed_total == 5
    assert snap.window_seconds == 1.0


def test_eps_meter_expires_old_samples() -> None:
    meter = EpsMeter(window_seconds=1.0)
    t0 = time.monotonic()
    meter.observe(4, at=t0)
    # Outside the 1s window.
    snap = meter.snapshot(now=t0 + 1.5)
    assert snap.events_in_window == 0
    assert snap.events_per_second == 0.0
    assert snap.observed_total == 4


def test_eps_meter_reset() -> None:
    meter = EpsMeter()
    meter.observe(10)
    meter.reset()
    snap = meter.snapshot()
    assert snap.events_in_window == 0
    assert snap.observed_total == 0
