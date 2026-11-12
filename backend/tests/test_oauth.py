from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import decrypt_token, encrypt_token
from app.auth.oidc import require_workspace
from app.auth.session import issue_session
from app.auth.state import InMemoryNonceStore, issue_state, verify_state
from app.clients.fakes import FakeSlackClient
from app.config import settings
from app.models import Event, Installation, Provider
from tests.conftest import make_finding, make_user, make_workspace


async def test_install_redirects_with_signed_state(
    client: httpx.AsyncClient, db: Session, slack: FakeSlackClient
) -> None:
    ws = make_workspace(db)
    response = await client.get("/api/oauth/slack/install", params={"workspace_id": str(ws.id)})
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://slack.test/authorize")
    state = parse_qs(urlparse(location).query)["state"][0]
    claims = verify_state(state, InMemoryNonceStore())
    assert claims.workspace_id == str(ws.id)
    assert claims.provider == "slack"
    slack.assert_called("authorize_url")


async def test_callback_stores_encrypted_tokens_and_event(
    client: httpx.AsyncClient, db: Session, slack: FakeSlackClient
) -> None:
    ws = make_workspace(db)
    state = issue_state(str(ws.id), "slack", "nonce-happy")
    response = await client.get(
        "/api/oauth/slack/callback", params={"code": "code-123", "state": state}
    )
    assert response.status_code == 302
    assert response.headers["location"].endswith("/?installation=slack")

    slack.assert_called_once_with(
        "exchange_code",
        code="code-123",
        redirect_uri=settings.slack_redirect_uri,
        extra={},
    )
    installation = db.scalars(select(Installation)).one()
    assert installation.provider is Provider.slack
    assert installation.external_id == "T0TESTTEAM"
    assert installation.scopes == "commands,chat:write"
    assert slack.tokens.access_token not in installation.encrypted_access_token
    assert decrypt_token(installation.encrypted_access_token) == slack.tokens.access_token
    assert installation.encrypted_refresh_token is not None
    assert decrypt_token(installation.encrypted_refresh_token) == (slack.tokens.refresh_token or "")

    event = db.scalars(select(Event).where(Event.kind == "installation.created")).one()
    assert event.payload["provider"] == "slack"
    assert event.payload["external_id"] == "T0TESTTEAM"


async def test_callback_rejects_tampered_state(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    state = issue_state(str(ws.id), "slack", "nonce-tamper")
    tampered = state[:-4] + ("AAAA" if not state.endswith("AAAA") else "BBBB")
    response = await client.get(
        "/api/oauth/slack/callback", params={"code": "c", "state": tampered}
    )
    assert response.status_code == 400


async def test_callback_rejects_expired_state(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    state = issue_state(str(ws.id), "slack", "nonce-expired", ttl_seconds=-5)
    response = await client.get("/api/oauth/slack/callback", params={"code": "c", "state": state})
    assert response.status_code == 400


async def test_callback_rejects_replayed_state(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    state = issue_state(str(ws.id), "slack", "nonce-replay")
    first = await client.get("/api/oauth/slack/callback", params={"code": "c", "state": state})
    assert first.status_code == 302
    second = await client.get("/api/oauth/slack/callback", params={"code": "c", "state": state})
    assert second.status_code == 400


async def test_callback_rejects_provider_mismatch(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    state = issue_state(str(ws.id), "github", "nonce-mismatch")
    response = await client.get("/api/oauth/slack/callback", params={"code": "c", "state": state})
    assert response.status_code == 400


def test_ensure_fresh_token_rotates_refresh_token(db: Session, slack: FakeSlackClient) -> None:
    from app.auth.oauth import ensure_fresh_token

    ws = make_workspace(db)
    installation = Installation(
        workspace_id=ws.id,
        provider=Provider.slack,
        external_id="T0TESTTEAM",
        encrypted_access_token=encrypt_token("old-access"),
        encrypted_refresh_token=encrypt_token("old-refresh"),
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
        scopes="commands",
    )
    db.add(installation)
    db.flush()

    ensure_fresh_token(installation, slack, db)

    slack.assert_called_once_with("refresh", refresh_token="old-refresh")
    assert decrypt_token(installation.encrypted_access_token) == "xoxb-rotated-access"
    assert decrypt_token(installation.encrypted_refresh_token or "") == "xoxe-rotated-refresh"
    assert installation.expires_at is not None
    assert installation.expires_at > datetime.now(UTC) + timedelta(minutes=50)


def test_ensure_fresh_token_skips_when_not_expiring(db: Session, slack: FakeSlackClient) -> None:
    from app.auth.oauth import ensure_fresh_token

    ws = make_workspace(db)
    installation = Installation(
        workspace_id=ws.id,
        provider=Provider.slack,
        external_id="T0TESTTEAM",
        encrypted_access_token=encrypt_token("old-access"),
        encrypted_refresh_token=encrypt_token("old-refresh"),
        expires_at=datetime.now(UTC) + timedelta(hours=2),
    )
    db.add(installation)
    db.flush()

    ensure_fresh_token(installation, slack, db)
    assert not slack.calls_for("refresh")


async def test_cross_workspace_access_denied(client: httpx.AsyncClient, db: Session) -> None:
    ws1 = make_workspace(db, slug="one")
    ws2 = make_workspace(db, slug="two")
    user = make_user(db, ws1)
    client.cookies.set(settings.session_cookie_name, issue_session(user.id, ws1.id))

    response = await client.get("/api/findings", params={"workspace_id": str(ws2.id)})
    assert response.status_code == 403


def test_require_workspace_rejects_other_workspace(db: Session) -> None:
    ws1 = make_workspace(db, slug="one")
    ws2 = make_workspace(db, slug="two")
    user = make_user(db, ws1)
    with pytest.raises(HTTPException) as excinfo:
        require_workspace(uuid.UUID(str(ws2.id)), user=user, db=db)
    assert excinfo.value.status_code == 403


async def test_authenticated_session_is_used_for_reads(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db)
    user = make_user(db, ws)
    make_finding(db, ws)
    client.cookies.set(settings.session_cookie_name, issue_session(user.id, ws.id))
    response = await client.get("/api/findings")
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


async def test_bad_session_cookie_is_401(client: httpx.AsyncClient) -> None:
    client.cookies.set(settings.session_cookie_name, "garbage.token")
    response = await client.get("/api/findings")
    assert response.status_code == 401
