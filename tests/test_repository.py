"""Repository tests: filtering, aggregation, triage and retention."""

from __future__ import annotations

import json
from datetime import timedelta

from domain.models import Severity, TriageStatus
from domain.queries import LogFilter, Pagination, SortOrder
from repositories.sqlalchemy_repo import SqlAlchemyLogRepository
from services.parser import AlertParser
from tests.conftest import BASE_TIME, make_alert


async def test_insert_assigns_monotonic_sequence(
    repo: SqlAlchemyLogRepository, parser: AlertParser
) -> None:
    batch = [
        parser.parse_line(json.dumps(make_alert(offset_seconds=index)))
        for index in range(3)
    ]
    stored = await repo.insert_many(batch)

    assert [record.seq for record in stored] == [1, 2, 3]
    assert await repo.count(LogFilter()) == 3
    assert await repo.stored_count() == 3


async def test_search_orders_newest_first_and_paginates(
    seeded: SqlAlchemyLogRepository,
) -> None:
    page = await seeded.search(LogFilter(), Pagination(limit=3, offset=0))
    assert [r.seq for r in page] == sorted((r.seq for r in page), reverse=True)

    second = await seeded.search(LogFilter(), Pagination(limit=3, offset=3))
    assert not {r.seq for r in page} & {r.seq for r in second}

    ascending = await seeded.search(
        LogFilter(), Pagination(limit=1, order=SortOrder.ASC)
    )
    assert ascending[0].seq == 1


async def test_filters_combine_with_and_semantics(seeded: SqlAlchemyLogRepository) -> None:
    assert await seeded.count(LogFilter(severities=[Severity.HIGH])) > 0
    assert (
        await seeded.count(
            LogFilter(severities=[Severity.HIGH], src_ips=["10.10.10.10"])
        )
        == 0
    )
    assert await seeded.count(LogFilter(rule_ids=["100300"])) == 1
    assert await seeded.count(LogFilter(min_level=13)) == 1
    assert await seeded.count(LogFilter(users=["carol"])) == 1
    assert (
        await seeded.count(
            LogFilter(time_from=BASE_TIME, time_to=BASE_TIME + timedelta(seconds=31))
        )
        >= 2
    )


async def test_full_text_search_matches_description(
    seeded: SqlAlchemyLogRepository,
) -> None:
    hits = await seeded.search(LogFilter(q="impossible travel"), Pagination(limit=10))

    assert len(hits) == 1
    assert hits[0].rule_id == "100300"
    assert await seeded.count(LogFilter(q="no-such-text-anywhere")) == 0


async def test_mitre_filter_accepts_parent_technique(
    seeded: SqlAlchemyLogRepository,
) -> None:
    by_technique = await seeded.count(LogFilter(mitre_techniques=["T1110"]))
    by_tactic = await seeded.count(LogFilter(mitre_tactics=["TA0006"]))

    assert by_technique > 0
    assert by_tactic >= by_technique


async def test_analytics_aggregations(seeded: SqlAlchemyLogRepository) -> None:
    overview = await seeded.overview(LogFilter())
    assert overview.total_events == 12
    assert overview.unique_source_ips >= 3
    assert overview.mail_flagged == 2

    distribution = await seeded.severity_distribution(LogFilter())
    assert sum(item.count for item in distribution) == 12
    assert abs(sum(item.percentage for item in distribution) - 100.0) < 0.5

    timeline = await seeded.timeline(LogFilter(), 60)
    assert sum(point.count for point in timeline) == 12
    assert any(point.high for point in timeline)

    rules = await seeded.top_rules(LogFilter(), 10)
    assert rules[0].rule_id == "5712"
    assert rules[0].count == 9

    ips = await seeded.top_ips(LogFilter(), "src_ip", 10)
    assert ips[0].ip == "185.220.101.44"
    assert ips[0].unique_users >= 3

    mitre = await seeded.mitre_breakdown(LogFilter(), 10)
    assert any(tactic.id == "TA0006" for tactic in mitre.tactics)

    services = await seeded.top_field(LogFilter(), "service", 10)
    assert services[0].key == "sshd"


async def test_grouping_collapses_repeated_events(seeded: SqlAlchemyLogRepository) -> None:
    groups = await seeded.group_events(
        LogFilter(), ["rule_id", "src_ip"], min_count=2, limit=10
    )

    assert groups
    assert groups[0].count == 9
    assert groups[0].unique_users >= 3
    assert groups[0].duration_seconds > 0


async def test_triage_transitions_are_recorded(seeded: SqlAlchemyLogRepository) -> None:
    assert await seeded.set_triage([1], TriageStatus.IN_PROGRESS, "analyst", "looking") == 1
    assert await seeded.set_triage([1], TriageStatus.RESOLVED, "analyst", "benign") == 1

    history = await seeded.triage_history(1)
    assert [event.status for event in history] == [
        TriageStatus.IN_PROGRESS,
        TriageStatus.RESOLVED,
    ]
    assert history[1].previous_status is TriageStatus.IN_PROGRESS
    assert await seeded.count(LogFilter(triage_statuses=[TriageStatus.RESOLVED])) == 1
    assert await seeded.set_triage([9_999], TriageStatus.RESOLVED) == 0

    summary = await seeded.triage_summary()
    assert summary.total == 12
    assert {item.key for item in summary.by_status} >= {"new", "resolved"}


async def test_get_returns_record_and_raw_payload(seeded: SqlAlchemyLogRepository) -> None:
    found = await seeded.get(1)

    assert found is not None
    record, raw = found
    assert record.seq == 1
    assert json.loads(raw)["rule"]["id"] == "5710"
    assert await seeded.get(9_999) is None


async def test_cursor_streams_every_match(seeded: SqlAlchemyLogRepository) -> None:
    seen = [
        record.seq
        async for record in seeded.iter_records(
            LogFilter(), chunk_size=5, ascending=True
        )
    ]

    assert seen == sorted(seen)
    assert len(seen) == 12


async def test_prune_keeps_newest_events(seeded: SqlAlchemyLogRepository) -> None:
    removed = await seeded.prune(max_events=5)

    remaining = await seeded.search(LogFilter(), Pagination(limit=20))
    assert removed == 7
    assert len(remaining) == 5
    assert min(record.seq for record in remaining) == 8


async def test_ingest_state_round_trip(repo: SqlAlchemyLogRepository) -> None:
    assert await repo.load_ingest_state("/tmp/alerts.json") is None

    await repo.save_ingest_state("/tmp/alerts.json", 42, 1024)
    assert await repo.load_ingest_state("/tmp/alerts.json") == (42, 1024)

    await repo.save_ingest_state("/tmp/alerts.json", 42, 2048)
    assert await repo.load_ingest_state("/tmp/alerts.json") == (42, 2048)
