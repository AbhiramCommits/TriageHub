from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.analytics.metrics import (
    false_positive_rate_by_rule,
    median_time_to_triage,
    percentile,
    summarize,
    two_proportion_z_test,
    variant_comparison,
)
from app.models import Event, Surface
from tests.conftest import make_finding, make_workspace

WORKSPACE = uuid.uuid4()
BASE = datetime(2026, 11, 1, 0, 0, tzinfo=UTC)


def created(finding_id: uuid.UUID, seconds: int, severity: str, rule_id: str = "rule.one") -> Event:
    return Event(
        workspace_id=WORKSPACE,
        finding_id=finding_id,
        kind="finding.created",
        surface=Surface.system,
        payload={"severity": severity, "rule_id": rule_id, "repo": "acme/api"},
        created_at=BASE + timedelta(seconds=seconds),
    )


def notified(finding_id: uuid.UUID, variant: str, seconds: int = 0) -> Event:
    return Event(
        workspace_id=WORKSPACE,
        finding_id=finding_id,
        kind="notification.sent",
        surface=Surface.slack,
        payload={"variant": variant},
        created_at=BASE + timedelta(seconds=seconds),
    )


def terminal(finding_id: uuid.UUID, kind: str, seconds: int) -> Event:
    return Event(
        workspace_id=WORKSPACE,
        finding_id=finding_id,
        kind=kind,
        surface=Surface.console,
        payload={"action": kind.split(".")[-1]},
        created_at=BASE + timedelta(seconds=seconds),
    )


def test_percentile_hand_checked() -> None:
    values = [10.0, 20.0, 30.0, 40.0]
    assert percentile(values, 0.5) == 25.0
    assert percentile(values, 0.9) == 37.0


def test_median_and_p90_time_to_triage() -> None:
    finding_ids = [uuid.uuid4() for _ in range(4)]
    events: list[Event] = []
    for finding_id, seconds in zip(finding_ids, (10, 20, 30, 40), strict=True):
        events.append(created(finding_id, 0, "high"))
        events.append(terminal(finding_id, "finding.accepted", seconds))
    result = median_time_to_triage(events)
    assert result["overall"] == {"n": 4, "median_seconds": 25.0, "p90_seconds": 37.0}
    assert result["by_severity"]["high"]["n"] == 4
    assert result["by_severity"]["high"]["median_seconds"] == 25.0


def test_time_to_triage_ignores_unfinished_and_uses_first_terminal() -> None:
    finished = uuid.uuid4()
    open_finding = uuid.uuid4()
    events = [
        created(finished, 0, "critical"),
        terminal(finished, "finding.accepted", 120),
        terminal(finished, "finding.fixed", 900),
        created(open_finding, 0, "low"),
    ]
    result = median_time_to_triage(events)
    assert result["overall"]["n"] == 1
    assert result["overall"]["median_seconds"] == 120.0


def test_false_positive_rate_by_rule_with_min_n_and_latest_outcome() -> None:
    events: list[Event] = []
    for index in range(6):
        finding_id = uuid.uuid4()
        events.append(created(finding_id, index, "high", rule_id="rule.noisy"))
        if index == 5:
            events.append(terminal(finding_id, "finding.fixed", 100 + index))
        elif index == 4:
            events.append(terminal(finding_id, "finding.accepted", 100 + index))
        else:
            events.append(terminal(finding_id, "finding.muted", 100 + index))

    switched = uuid.uuid4()
    events.append(created(switched, 0, "medium", rule_id="rule.noisy"))
    events.append(terminal(switched, "finding.accepted", 50))
    events.append(terminal(switched, "finding.muted", 60))

    for index in range(4):
        finding_id = uuid.uuid4()
        events.append(created(finding_id, index, "low", rule_id="rule.quiet"))
        events.append(terminal(finding_id, "finding.accepted", 100 + index))

    rows = false_positive_rate_by_rule(events)
    assert [row["rule_id"] for row in rows] == ["rule.noisy"]
    assert rows[0] == {"rule_id": "rule.noisy", "muted": 5, "accepted": 1, "fp_rate": 0.8333}


def _ab_events() -> list[Event]:
    events: list[Event] = []
    for index in range(10):
        finding_id = uuid.uuid4()
        events.append(created(finding_id, 0, "high"))
        events.append(notified(finding_id, "A"))
        if index < 3:
            events.append(terminal(finding_id, "finding.accepted", 100 * (index + 1)))
    for index in range(10):
        finding_id = uuid.uuid4()
        events.append(created(finding_id, 0, "high"))
        events.append(notified(finding_id, "B"))
        if index < 9:
            events.append(terminal(finding_id, "finding.accepted", 100 * (index + 1)))
    return events


def test_variant_comparison_hand_checked_z_score() -> None:
    comparison = variant_comparison(_ab_events())
    assert comparison["variant_a"]["n"] == 10
    assert comparison["variant_a"]["triaged"] == 3
    assert comparison["variant_a"]["triage_rate"] == 0.3
    assert comparison["variant_a"]["median_seconds"] == 200.0
    assert comparison["variant_b"]["n"] == 10
    assert comparison["variant_b"]["triaged"] == 9
    assert comparison["variant_b"]["triage_rate"] == 0.9
    assert comparison["variant_b"]["median_seconds"] == 500.0
    assert comparison["absolute_delta"] == 0.6
    assert abs((comparison["z"] or 0) - 2.7386) < 0.001
    assert abs((comparison["p_value"] or 0) - 0.006169) < 0.0001
    assert comparison["significant"] is True


def test_two_proportion_z_test_hand_checked() -> None:
    z, p_value = two_proportion_z_test(3, 10, 9, 10)
    assert z is not None and p_value is not None
    assert abs(z - 2.7386127875) < 1e-9
    assert abs(p_value - 0.006169) < 1e-5


def test_variant_comparison_insignificant_wording() -> None:
    events = _ab_events()
    comparison = variant_comparison(events[:20] + events[20:])
    assert comparison["verdict"]
    z, p_value = two_proportion_z_test(5, 10, 5, 10)
    assert z == 0.0
    assert p_value == 1.0


async def test_metrics_endpoint_returns_computed_summary(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    db.add(
        Event(
            workspace_id=ws.id,
            finding_id=finding.id,
            kind="finding.created",
            surface=Surface.system,
            payload={"severity": "high", "rule_id": finding.rule_id},
            created_at=BASE,
        )
    )
    db.add(
        Event(
            workspace_id=ws.id,
            finding_id=finding.id,
            kind="finding.accepted",
            surface=Surface.console,
            payload={"action": "accept"},
            created_at=BASE + timedelta(seconds=42),
        )
    )
    db.flush()

    response = await client.get("/api/metrics/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["time_to_triage"]["overall"]["n"] == 1
    assert body["time_to_triage"]["overall"]["median_seconds"] == 42.0
    assert "variant_comparison" in body


def test_empty_event_stream_is_safe() -> None:
    summary = summarize([])
    assert summary["time_to_triage"]["overall"] == {
        "n": 0,
        "median_seconds": 0.0,
        "p90_seconds": 0.0,
    }
    assert summary["false_positive_rate_by_rule"] == []
