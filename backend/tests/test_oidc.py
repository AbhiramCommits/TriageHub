from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.crypto import encrypt_token
from app.auth.oidc import OIDC_TXN_COOKIE
from app.auth.session import issue_session
from app.auth.state import issue_state
from app.clients.fakes import FakeOIDCProvider
from app.config import settings
from app.models import Event, Role, User
from tests.conftest import make_user, make_workspace


def _login_params(response: httpx.Response) -> tuple[str, str]:
    query = parse_qs(urlparse(response.headers["location"]).query)
    return query["state"][0], query["code_challenge"][0]


async def test_sso_login_builds_pkce_authorize_request(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True)
    response = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://idp.test/authorize")
    query = parse_qs(urlparse(location).query)
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["state"][0]) > 10
    assert OIDC_TXN_COOKIE in client.cookies

    call = oidc.calls_for("authorize_url")[0]
    assert call["redirect_uri"] == settings.oidc_redirect_uri
    assert call["scopes"] == settings.oidc_scopes
    assert call["code_challenge"] == query["code_challenge"][0]


async def test_sso_callback_provisions_user_and_sets_session(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True)
    login = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    state, _challenge = _login_params(login)

    callback = await client.get(
        "/api/auth/sso/callback", params={"code": "auth-code", "state": state}
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == settings.console_url

    user = db.scalars(select(User)).one()
    assert user.email == oidc.claims.email
    assert user.workspace_id == ws.id
    assert user.role is Role.reviewer
    assert user.external_subject == oidc.claims.subject

    provisioned = db.scalars(select(Event).where(Event.kind == "user.provisioned")).one()
    assert provisioned.payload["email"] == oidc.claims.email

    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == oidc.claims.email
    assert me.json()["workspace_id"] == str(ws.id)


async def test_sso_callback_reuses_existing_user(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db, sso_only=True)
    make_user(db, ws, email="ada@acme.test")
    login = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    state, _ = _login_params(login)
    await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert db.scalar(select(func.count()).select_from(User)) == 1


async def test_sso_callback_rejects_tampered_state(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db, sso_only=True)
    login = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    state, _ = _login_params(login)
    response = await client.get(
        "/api/auth/sso/callback", params={"code": "c", "state": state + "tampered"}
    )
    assert response.status_code == 400


async def test_sso_callback_rejects_expired_state(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True)
    state = issue_state(str(ws.id), "oidc", "expired-nonce", ttl_seconds=-1)
    txn = encrypt_token(
        json.dumps({"state": state, "verifier": "v" * 64, "nonce": "expired-nonce"})
    )
    client.cookies.set(OIDC_TXN_COOKIE, txn)
    oidc.last_nonce = "expired-nonce"
    response = await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert response.status_code == 400


async def test_sso_callback_rejects_replayed_state(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True)
    state = issue_state(str(ws.id), "oidc", "replay-nonce")
    txn = encrypt_token(json.dumps({"state": state, "verifier": "v" * 64, "nonce": "replay-nonce"}))
    oidc.last_nonce = "replay-nonce"
    client.cookies.set(OIDC_TXN_COOKIE, txn)
    first = await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert first.status_code == 302
    client.cookies.set(OIDC_TXN_COOKIE, txn)
    second = await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert second.status_code == 400


async def test_sso_callback_rejects_nonce_mismatch(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True)
    state = issue_state(str(ws.id), "oidc", "right-nonce")
    txn = encrypt_token(json.dumps({"state": state, "verifier": "v" * 64, "nonce": "wrong-nonce"}))
    client.cookies.set(OIDC_TXN_COOKIE, txn)
    oidc.last_nonce = "right-nonce"
    response = await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert response.status_code == 401


async def test_sso_callback_rejects_issuer_mismatch(
    client: httpx.AsyncClient, db: Session, oidc: FakeOIDCProvider
) -> None:
    ws = make_workspace(db, sso_only=True, oidc_issuer="https://attacker.example")
    login = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    state, _ = _login_params(login)
    response = await client.get("/api/auth/sso/callback", params={"code": "c", "state": state})
    assert response.status_code == 401


async def test_dev_login_forbidden_for_sso_only_workspace(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db, sso_only=True)
    make_user(db, ws)
    response = await client.post(
        "/api/auth/dev-login", json={"workspace_id": str(ws.id), "email": "reviewer@acme.test"}
    )
    assert response.status_code == 403
    assert "SSO-only" in response.json()["detail"]


async def test_dev_login_allowed_for_non_sso_workspace(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db, sso_only=False)
    make_user(db, ws)
    response = await client.post(
        "/api/auth/dev-login", json={"workspace_id": str(ws.id), "email": "reviewer@acme.test"}
    )
    assert response.status_code == 200
    assert response.json()["workspace_id"] == str(ws.id)
    assert settings.session_cookie_name in response.cookies


async def test_expired_session_is_401(
    client: httpx.AsyncClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = make_workspace(db)
    user = make_user(db, ws)
    monkeypatch.setattr(settings, "session_ttl_seconds", -1)
    token = issue_session(user.id, ws.id)
    client.cookies.set(settings.session_cookie_name, token)
    response = await client.get("/api/auth/me")
    assert response.status_code == 401


async def test_logout_clears_session(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    user = make_user(db, ws)
    login = await client.post(
        "/api/auth/dev-login", json={"workspace_id": str(ws.id), "email": user.email}
    )
    assert login.status_code == 200
    logout = await client.post("/api/auth/logout")
    assert logout.status_code == 204
    me = await client.get("/api/auth/me")
    assert me.status_code == 401
