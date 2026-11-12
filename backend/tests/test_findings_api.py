from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy.orm import Session

from app.auth.session import issue_session
from app.config import settings
from app.cursor import InvalidCursor, decode_cursor, encode_cursor
from app.models import FindingState, Severity
from tests.conftest import make_finding, make_user, make_workspace

BASE = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def test_cursor_roundtrip_and_rejection() -> None:
    finding_id = uuid.uuid4()
    cursor = encode_cursor(BASE, finding_id)
    decoded_at, decoded_id = decode_cursor(cursor)
    assert decoded_at == BASE
    assert decoded_id == finding_id
    with pytest.raises(InvalidCursor):
        decode_cursor("not-a-cursor")


async def test_healthz(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_cursor_pagination_walks_all_rows(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    for offset in range(3):
        make_finding(
            db,
            ws,
            start_line=10 + offset,
            first_seen_at=BASE + timedelta(minutes=offset),
        )

    first = await client.get("/api/findings", params={"limit": 2})
    assert first.status_code == 200
    page = first.json()
    assert len(page["items"]) == 2
    assert page["next_cursor"]
    assert [item["start_line"] for item in page["items"]] == [12, 11]

    second = await client.get("/api/findings", params={"limit": 2, "cursor": page["next_cursor"]})
    assert second.status_code == 200
    assert [item["start_line"] for item in second.json()["items"]] == [10]
    assert second.json()["next_cursor"] is None


async def test_invalid_cursor_is_400(client: httpx.AsyncClient, db: Session) -> None:
    make_workspace(db)
    response = await client.get("/api/findings", params={"cursor": "garbage"})
    assert response.status_code == 400


async def test_filters_by_state_severity_rule_repo_and_search(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db)
    target = make_finding(
        db,
        ws,
        rule_id="rule.target",
        severity=Severity.critical,
        repo="acme/target",
        state=FindingState.muted,
        message="Unsanitized innerHTML",
    )
    make_finding(db, ws, rule_id="rule.other", severity=Severity.low, repo="acme/other")

    for params in (
        {"state": "muted"},
        {"severity": "critical"},
        {"rule_id": "rule.target"},
        {"repo": "acme/target"},
        {"search": "innerHTML"},
    ):
        response = await client.get("/api/findings", params=params)
        assert response.status_code == 200
        found = response.json()["items"]
        assert [item["id"] for item in found] == [str(target.id)], params

    empty = await client.get("/api/findings", params={"search": "nothing-matches"})
    assert empty.json()["items"] == []


async def test_get_finding_and_workspace_isolation(client: httpx.AsyncClient, db: Session) -> None:
    ws1 = make_workspace(db, slug="one")
    ws2 = make_workspace(db, slug="two")
    user = make_user(db, ws1)
    mine = make_finding(db, ws1)
    other = make_finding(db, ws2)
    client.cookies.set(settings.session_cookie_name, issue_session(user.id, ws1.id))

    found = await client.get(f"/api/findings/{mine.id}")
    assert found.status_code == 200
    assert found.json()["id"] == str(mine.id)

    hidden = await client.get(f"/api/findings/{other.id}")
    assert hidden.status_code == 404

    missing = await client.get(f"/api/findings/{__import__('uuid').uuid4()}")
    assert missing.status_code == 404


async def test_users_are_workspace_scoped(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    make_user(db, ws, email="one@acme.test")
    make_user(db, ws, email="two@acme.test")
    response = await client.get("/api/users")
    assert response.status_code == 200
    assert {user["email"] for user in response.json()} == {"one@acme.test", "two@acme.test"}


async def test_invalid_filter_value_is_422(client: httpx.AsyncClient, db: Session) -> None:
    make_workspace(db)
    response = await client.get("/api/findings", params={"severity": "apocalyptic"})
    assert response.status_code == 422
