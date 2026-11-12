"""Provider-agnostic OAuth install handshake and token lifecycle."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import decrypt_token, encrypt_token
from app.auth.state import SqlNonceStore, StateError, issue_state, verify_state
from app.clients.base import ProviderClient
from app.clients.deps import get_github_client, get_slack_client
from app.config import settings
from app.db import get_db
from app.models import Event, Installation, Provider, Surface, Workspace

router = APIRouter(prefix="/api/oauth", tags=["oauth"])


def _redirect_uri(provider: Provider) -> str:
    return (
        settings.slack_redirect_uri if provider is Provider.slack else settings.github_redirect_uri
    )


def get_provider_client(
    provider: Provider,
    slack: Annotated[ProviderClient, Depends(get_slack_client)],
    github: Annotated[ProviderClient, Depends(get_github_client)],
) -> ProviderClient:
    return slack if provider is Provider.slack else github


@router.get("/{provider}/install")
def install(
    provider: Provider,
    workspace_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    client: Annotated[ProviderClient, Depends(get_provider_client)],
) -> RedirectResponse:
    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    nonce = secrets.token_urlsafe(24)
    token = issue_state(str(workspace.id), provider.value, nonce)
    url = client.authorize_url(token, _redirect_uri(provider))
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/{provider}/callback")
def callback(
    provider: Provider,
    db: Annotated[Session, Depends(get_db)],
    client: Annotated[ProviderClient, Depends(get_provider_client)],
    code: str | None = None,
    state: str | None = None,
    installation_id: str | None = None,
) -> RedirectResponse:
    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing code or state")
    try:
        claims = verify_state(state, SqlNonceStore(db))
    except StateError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if claims.provider != provider.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="state provider mismatch"
        )

    workspace = db.get(Workspace, uuid.UUID(claims.workspace_id))
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown workspace")

    extra = {"installation_id": installation_id} if installation_id else None
    tokens = client.exchange_code(code, _redirect_uri(provider), extra)
    if not tokens.access_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="provider returned no access token"
        )

    external_id = tokens.external_id or installation_id or f"{provider.value}-default"
    expires_at = (
        datetime.now(UTC) + timedelta(seconds=tokens.expires_in) if tokens.expires_in else None
    )

    installation = db.scalars(
        select(Installation).where(
            Installation.workspace_id == workspace.id,
            Installation.provider == provider,
            Installation.external_id == external_id,
        )
    ).first()
    created = installation is None
    if installation is None:
        installation = Installation(
            workspace_id=workspace.id,
            provider=provider,
            external_id=external_id,
            encrypted_access_token=encrypt_token(tokens.access_token),
        )
        db.add(installation)
    installation.encrypted_access_token = encrypt_token(tokens.access_token)
    installation.encrypted_refresh_token = (
        encrypt_token(tokens.refresh_token) if tokens.refresh_token else None
    )
    installation.expires_at = expires_at
    installation.scopes = tokens.scope
    db.flush()

    db.add(
        Event(
            workspace_id=workspace.id,
            kind="installation.created" if created else "installation.updated",
            surface=Surface.system,
            payload={
                "provider": provider.value,
                "external_id": external_id,
                "scopes": tokens.scope,
            },
        )
    )
    db.commit()
    return RedirectResponse(
        url=f"{settings.console_url}/?installation={provider.value}",
        status_code=status.HTTP_302_FOUND,
    )


def ensure_fresh_token(
    installation: Installation,
    client: ProviderClient,
    db: Session,
    now: datetime | None = None,
) -> Installation:
    """Refresh provider credentials when they expire within 60 seconds.

    A rotated refresh token is persisted so the old one can never be replayed.
    """
    current = now or datetime.now(UTC)
    if installation.expires_at is None or installation.expires_at > current + timedelta(seconds=60):
        return installation
    if not installation.encrypted_refresh_token:
        return installation
    refresh_token = decrypt_token(installation.encrypted_refresh_token)
    tokens = client.refresh(refresh_token)
    if not tokens.access_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="provider returned no access token"
        )
    installation.encrypted_access_token = encrypt_token(tokens.access_token)
    if tokens.refresh_token:
        installation.encrypted_refresh_token = encrypt_token(tokens.refresh_token)
    if tokens.expires_in:
        installation.expires_at = current + timedelta(seconds=tokens.expires_in)
    if tokens.scope:
        installation.scopes = tokens.scope
    db.flush()
    return installation
