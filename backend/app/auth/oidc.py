"""SSO-only OIDC onboarding, session resolution and workspace authorization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import TokenDecryptionError, decrypt_token, encrypt_token
from app.auth.session import (
    SessionError,
    clear_session_cookie,
    issue_session,
    read_session,
    set_session_cookie,
)
from app.auth.state import SqlNonceStore, StateError, issue_state, verify_state
from app.clients.base import OIDCProvider
from app.clients.deps import get_oidc_provider
from app.config import settings
from app.db import get_db
from app.models import Event, Role, Surface, User, Workspace
from app.schemas import SessionUser

router = APIRouter(prefix="/api/auth", tags=["auth"])

OIDC_TXN_COOKIE = "triagehub_oidc_txn"
TXN_TTL_SECONDS = 600


class DevLoginRequest(BaseModel):
    workspace_id: uuid.UUID
    email: str


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


@router.get("/sso/login")
def sso_login(
    workspace_id: uuid.UUID | None,
    db: Annotated[Session, Depends(get_db)],
    provider: Annotated[OIDCProvider, Depends(get_oidc_provider)],
) -> RedirectResponse:
    if workspace_id is not None:
        workspace = db.get(Workspace, workspace_id)
    else:
        workspace = db.scalars(
            select(Workspace).where(Workspace.oidc_issuer == settings.oidc_issuer)
        ).first()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no workspace for issuer")

    nonce = secrets.token_urlsafe(24)
    state = issue_state(str(workspace.id), "oidc", nonce)
    verifier, challenge = _pkce_pair()
    authorize_url = provider.authorize_url(
        state=state,
        nonce=nonce,
        code_challenge=challenge,
        redirect_uri=settings.oidc_redirect_uri,
        scopes=settings.oidc_scopes,
    )
    txn = encrypt_token(json.dumps({"state": state, "verifier": verifier, "nonce": nonce}))
    response = RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=OIDC_TXN_COOKIE,
        value=txn,
        max_age=TXN_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.env == "production",
        path="/",
    )
    return response


@router.get("/sso/callback")
def sso_callback(
    code: str | None,
    state: str | None,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    provider: Annotated[OIDCProvider, Depends(get_oidc_provider)],
) -> RedirectResponse:
    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing code or state")

    transaction_raw = request.cookies.get(OIDC_TXN_COOKIE)
    if not transaction_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="missing login transaction"
        )
    try:
        transaction = json.loads(decrypt_token(transaction_raw))
        if not isinstance(transaction, dict):
            raise ValueError("transaction is not an object")
    except (TokenDecryptionError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid login transaction"
        ) from exc

    if not hmac.compare_digest(str(transaction.get("state", "")), state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="state mismatch")

    try:
        claims = verify_state(state, SqlNonceStore(db))
    except StateError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if claims.provider != "oidc":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="state provider mismatch"
        )

    workspace = db.get(Workspace, uuid.UUID(claims.workspace_id))
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown workspace")

    tokens = provider.exchange_code(code, str(transaction["verifier"]), settings.oidc_redirect_uri)
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="missing ID token")
    try:
        identity = provider.validate_id_token(str(id_token), nonce=str(transaction["nonce"]))
    except Exception as exc:  # provider-specific validation failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="ID token validation failed"
        ) from exc
    if identity.nonce != str(transaction["nonce"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="nonce mismatch")
    if workspace.oidc_issuer != identity.issuer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="issuer does not match workspace"
        )

    user = db.scalars(
        select(User).where(User.workspace_id == workspace.id, User.email == identity.email)
    ).first()
    provisioned = user is None
    if user is None:
        user = User(
            workspace_id=workspace.id,
            email=identity.email,
            external_subject=identity.subject,
            role=Role.reviewer,
        )
        db.add(user)
    else:
        user.external_subject = identity.subject
    db.flush()

    if provisioned:
        db.add(
            Event(
                workspace_id=workspace.id,
                actor_user_id=user.id,
                kind="user.provisioned",
                surface=Surface.system,
                payload={"email": user.email, "method": "oidc"},
            )
        )
    db.commit()

    response = RedirectResponse(url=settings.console_url, status_code=status.HTTP_302_FOUND)
    set_session_cookie(response, issue_session(user.id, workspace.id))
    response.delete_cookie(OIDC_TXN_COOKIE, path="/")
    return response


@router.post("/dev-login")
def dev_login(payload: DevLoginRequest, db: Annotated[Session, Depends(get_db)]) -> JSONResponse:
    workspace = db.get(Workspace, payload.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    if workspace.sso_only:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this workspace is SSO-only; use /api/auth/sso/login",
        )
    if settings.env == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="password login is disabled"
        )
    user = db.scalars(
        select(User).where(User.workspace_id == workspace.id, User.email == payload.email)
    ).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    body = SessionUser(user_id=user.id, workspace_id=workspace.id, email=user.email, role=user.role)
    response = JSONResponse(body.model_dump(mode="json"))
    set_session_cookie(response, issue_session(user.id, workspace.id))
    return response


def require_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
        )
    try:
        session = read_session(token)
    except SessionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = db.get(User, session.user_id)
    if user is None or user.workspace_id != session.workspace_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session")
    return user


def require_workspace(
    workspace_id: uuid.UUID,
    user: Annotated[User, Depends(require_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Workspace:
    if user.workspace_id != workspace_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="cross-workspace access denied"
        )
    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    return workspace


@router.get("/me", response_model=SessionUser)
def me(user: Annotated[User, Depends(require_user)]) -> SessionUser:
    return SessionUser(
        user_id=user.id, workspace_id=user.workspace_id, email=user.email, role=user.role
    )


@router.post("/logout")
def logout() -> Response:
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response)
    return response


def optional_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User | None:
    """Resolve a session user when present, without requiring authentication."""
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    try:
        session = read_session(token)
    except SessionError:
        return None
    user = db.get(User, session.user_id)
    if user is None or user.workspace_id != session.workspace_id:
        return None
    return user
