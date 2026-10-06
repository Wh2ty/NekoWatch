"""Event grouping and time-window brute-force detection.

Grouping is delegated to SQL (``GROUP BY`` on an allow-listed signature).
Brute-force detection needs ordered, per-key reasoning that SQL does poorly, so
it streams candidates in time order and runs a sliding window per source.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Sequence

from core.config import Settings
from domain.models import Severity
from domain.queries import (
    BruteForceIncident,
    CorrelationGroup,
    CorrelationResponse,
    LogFilter,
)
from repositories.base import LogRepository

logger = logging.getLogger("nekowatch.correlation")

#: Logener rules representing a failed or abused authentication attempt.
AUTH_FAILURE_RULE_IDS: tuple[str, ...] = ("5712", "5752")

#: Default correlation signature.
DEFAULT_GROUP_BY: tuple[str, ...] = ("rule_id", "src_ip")

#: Upper bound on records scanned by brute-force detection per request.
DEFAULT_MAX_SCAN = 20_000


@dataclass(slots=True)
class _Attempt:
    """A single authentication failure, reduced to what detection needs."""

    seq: int
    ts: datetime
    user: str | None
    rule_id: str | None
    level: int | None
    reported_attempts: int | None


class CorrelationService:
    """Groups similar events and flags authentication-failure bursts."""

    def __init__(self, repository: LogRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings

    async def group(
        self,
        log_filter: LogFilter,
        group_by: Sequence[str] | None = None,
        *,
        min_count: int = 2,
        limit: int = 25,
    ) -> list[CorrelationGroup]:
        """Collapse similar events into signature groups.

        Args:
            log_filter: Active selection.
            group_by: Signature columns; defaults to ``rule_id`` + ``src_ip``.
            min_count: Minimum group size worth reporting.
            limit: Maximum groups returned.
        """
        return await self._repository.group_events(
            log_filter,
            list(group_by or DEFAULT_GROUP_BY),
            min_count=min_count,
            limit=limit,
        )

    async def detect_brute_force(
        self,
        log_filter: LogFilter,
        *,
        window_seconds: int = 60,
        threshold: int = 5,
        rule_ids: Sequence[str] | None = None,
        by_user: bool = False,
        max_scan: int = DEFAULT_MAX_SCAN,
        limit: int = 50,
    ) -> tuple[list[BruteForceIncident], int]:
        """Flag sources exceeding ``threshold`` failures within ``window_seconds``.

        Candidates are authentication-failure rules (5712 "authentication
        failed" and 5752 "brute force attack detected" by default), intersected
        with whatever the analyst already filtered on. Adjacent qualifying
        windows are merged, so one attack reports as one incident rather than
        one incident per event.

        Args:
            log_filter: Active selection narrowing the candidate set.
            window_seconds: Sliding window width.
            threshold: Failures within the window required to alert.
            rule_ids: Override the candidate rule ids.
            by_user: Key incidents by ``(src_ip, user)`` instead of ``src_ip``,
                separating password spraying from single-account guessing.
            max_scan: Safety cap on records examined per request.
            limit: Maximum incidents returned.

        Returns:
            ``(incidents, scanned)``, incidents ordered by attempt count.
        """
        candidate_filter = self._candidate_filter(log_filter, rule_ids)
        attempts: dict[tuple[str, str | None], list[_Attempt]] = defaultdict(list)
        scanned = 0

        async for record in self._repository.iter_records(
            candidate_filter, chunk_size=1_000, max_rows=max_scan, ascending=True
        ):
            scanned += 1
            key = (
                record.src_ip or "unknown",
                record.user_name if by_user else None,
            )
            attempts[key].append(
                _Attempt(
                    seq=record.seq,
                    ts=record.timestamp,
                    user=record.user_name,
                    rule_id=record.rule_id,
                    level=record.rule_level,
                    reported_attempts=record.failed_attempts,
                )
            )

        incidents: list[BruteForceIncident] = []
        for (src_ip, user), events in attempts.items():
            incidents.extend(
                _scan_windows(
                    src_ip=src_ip,
                    user=user,
                    events=events,
                    window_seconds=window_seconds,
                    threshold=threshold,
                )
            )

        incidents.sort(key=lambda inc: (inc.attempts, inc.last_seen), reverse=True)
        return incidents[:limit], scanned

    async def analyze(
        self,
        log_filter: LogFilter,
        *,
        group_by: Sequence[str] | None = None,
        min_count: int = 2,
        window_seconds: int = 60,
        threshold: int = 5,
        limit: int = 25,
    ) -> CorrelationResponse:
        """Run grouping and brute-force detection in one call."""
        groups = await self.group(
            log_filter, group_by, min_count=min_count, limit=limit
        )
        incidents, scanned = await self.detect_brute_force(
            log_filter,
            window_seconds=window_seconds,
            threshold=threshold,
            limit=limit,
        )
        return CorrelationResponse(
            groups=groups,
            brute_force=incidents,
            window_seconds=window_seconds,
            threshold=threshold,
            scanned=scanned,
        )

    # ------------------------------------------------------------- internals
    @staticmethod
    def _candidate_filter(
        log_filter: LogFilter, rule_ids: Sequence[str] | None
    ) -> LogFilter:
        """Narrow a filter to authentication-failure rules.

        When the analyst already filtered by rule, the two sets are intersected
        so detection never widens the selection behind their back.
        """
        wanted = list(rule_ids or AUTH_FAILURE_RULE_IDS)
        if log_filter.rule_ids:
            wanted = [r for r in wanted if r in log_filter.rule_ids] or ["__none__"]
        return log_filter.model_copy(update={"rule_ids": wanted})


def _scan_windows(
    *,
    src_ip: str,
    user: str | None,
    events: list[_Attempt],
    window_seconds: int,
    threshold: int,
) -> list[BruteForceIncident]:
    """Sliding-window scan over one key's ordered failures.

    Walks a two-pointer window; while the window holds at least ``threshold``
    events an incident stays open and keeps absorbing events, and it closes once
    the window has drained past the incident's end.
    """
    if len(events) < threshold:
        return []

    events.sort(key=lambda event: event.ts)
    incidents: list[BruteForceIncident] = []
    start = 0
    open_start: int | None = None
    open_end = 0

    for end, event in enumerate(events):
        while (event.ts - events[start].ts).total_seconds() > window_seconds:
            start += 1

        if end - start + 1 >= threshold:
            if open_start is None:
                open_start = start
            open_end = end
        elif open_start is not None and start > open_end:
            incidents.append(
                _build_incident(
                    src_ip,
                    user,
                    events[open_start : open_end + 1],
                    window_seconds,
                    threshold,
                )
            )
            open_start = None

    if open_start is not None:
        incidents.append(
            _build_incident(
                src_ip,
                user,
                events[open_start : open_end + 1],
                window_seconds,
                threshold,
            )
        )
    return incidents


def _build_incident(
    src_ip: str,
    user: str | None,
    events: list[_Attempt],
    window_seconds: int,
    threshold: int,
) -> BruteForceIncident:
    """Summarise a qualifying burst into a reportable incident."""
    users = {event.user for event in events if event.user}
    reported = [e.reported_attempts for e in events if e.reported_attempts]
    attempts = max(len(events), max(reported) if reported else 0)
    levels = [event.level for event in events if event.level is not None]
    max_level = max(levels) if levels else None
    span = (events[-1].ts - events[0].ts).total_seconds()

    return BruteForceIncident(
        src_ip=src_ip if src_ip != "unknown" else None,
        user_name=user or (next(iter(users)) if len(users) == 1 else None),
        attempts=attempts,
        window_seconds=round(span, 2) or float(window_seconds),
        first_seen=events[0].ts,
        last_seen=events[-1].ts,
        rule_ids=sorted({e.rule_id for e in events if e.rule_id}),
        unique_users=len(users),
        max_level=max_level,
        severity=Severity.from_level(max_level),
        confidence=_confidence(attempts, len(users), threshold),
        sample_seqs=[event.seq for event in events[:10]],
    )


def _confidence(
    attempts: int, unique_users: int, threshold: int
) -> Literal["low", "medium", "high"]:
    """Rate an incident relative to the configured threshold.

    Many distinct usernames from a single source looks like credential
    stuffing, so that alone is enough for high confidence.
    """
    if attempts >= 3 * threshold or unique_users >= 3:
        return "high"
    if attempts >= int(1.5 * threshold):
        return "medium"
    return "low"
