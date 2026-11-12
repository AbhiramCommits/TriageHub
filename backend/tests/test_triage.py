from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Event, Finding, FindingState, Surface
from app.services.triage import IllegalTransition, apply_bulk, apply_transition
from tests.conftest import make_finding, make_workspace


def test_accept_sets_triaged_at_and_event(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    outcome = apply_transition(finding, "accept", None, Surface.console, db=db)
    assert outcome.changed
    assert finding.state is FindingState.accepted
    assert finding.triaged_at is not None
    event = db.scalars(select(Event)).one()
    assert event.kind == "finding.accepted"
    assert event.surface is Surface.console
    assert event.payload["from"] == "open"


def test_replaying_same_action_is_a_noop(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    apply_transition(finding, "accept", None, Surface.console, db=db)
    again = apply_transition(finding, "accept", None, Surface.console, db=db)
    assert not again.changed
    assert again.event is None
    assert len(db.scalars(select(Event)).all()) == 1


def test_fixed_is_terminal(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    apply_transition(finding, "resolve", None, Surface.console, db=db)
    with pytest.raises(IllegalTransition):
        apply_transition(finding, "reopen", None, Surface.console, db=db)
    with pytest.raises(IllegalTransition):
        apply_transition(finding, "accept", None, Surface.console, db=db)


def test_reopen_clears_triaged_at(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    apply_transition(finding, "mute", None, Surface.console, db=db)
    assert finding.triaged_at is not None
    apply_transition(finding, "reopen", None, Surface.console, db=db)
    assert finding.state is FindingState.open
    assert finding.triaged_at is None


def test_assign_requires_an_assignee(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    with pytest.raises(IllegalTransition):
        apply_transition(finding, "assign", None, Surface.console, db=db)


def test_unknown_action_rejected(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    with pytest.raises(IllegalTransition):
        apply_transition(finding, "delete", None, Surface.console, db=db)


def test_bulk_reports_skipped(db: Session) -> None:
    ws = make_workspace(db)
    first = make_finding(db, ws)
    accepted = make_finding(db, ws, start_line=98, state=FindingState.accepted)
    fixed = make_finding(db, ws, start_line=99, state=FindingState.fixed)
    updated, skipped = apply_bulk(db, [first, accepted, fixed], "accept", None, Surface.console)
    assert [finding.id for finding in updated] == [first.id]
    assert skipped == [{"finding_id": str(fixed.id), "reason": "cannot accept a fixed finding"}]


async def test_transition_endpoint_and_illegal_409(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    response = await client.post(
        f"/api/findings/{finding.id}/transition", json={"action": "accept"}
    )
    assert response.status_code == 200
    assert response.json()["state"] == "accepted"

    fixed = make_finding(db, ws, start_line=77, state=FindingState.fixed)
    conflict = await client.post(f"/api/findings/{fixed.id}/transition", json={"action": "reopen"})
    assert conflict.status_code == 409
    assert "fixed" in conflict.json()["detail"]


async def test_bulk_transition_request_body(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    one = make_finding(db, ws, start_line=1)
    two = make_finding(db, ws, start_line=2)
    response = await client.post(
        "/api/findings/bulk-transition",
        json={"finding_ids": [str(one.id), str(two.id)], "action": "mute"},
    )
    assert response.status_code == 200
    body = response.json()
    assert {item["id"] for item in body["updated"]} == {str(one.id), str(two.id)}
    assert body["skipped"] == []
    db.expire_all()
    assert db.get(Finding, one.id).state is FindingState.muted


async def test_transition_rejects_cross_workspace_finding(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws1 = make_workspace(db, slug="one")
    ws2 = make_workspace(db, slug="two")
    finding = make_finding(db, ws2)
    response = await client.post(
        f"/api/findings/{finding.id}/transition",
        params={"workspace_id": str(ws1.id)},
        json={"action": "accept"},
    )
    assert response.status_code == 404
