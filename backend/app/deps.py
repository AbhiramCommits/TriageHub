"""Database-aware dependencies: workspace resolution and authorization."""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.session import SessionError, read_session
from app.config import settings
from app.db import get_db
from app.models import Workspace


def default_workspace(db: Session) -> Workspace:
    ws = db.scalars(
        select(Workspace).order_by(Workspace.created_at, Workspace.slug).limit(1)
    ).first()
    if ws is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no workspace provisioned; run scripts/seed.py",
        )
    return ws


def get_workspace(
    request: Request,
    workspace_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Workspace:
    """Resolve the request workspace and enforce session/workspace binding.

    A signed SSO session always wins. In development, unauthenticated reads fall
    back to the first workspace (or an explicit ``workspace_id``) so the console
    can be used before wiring an IdP; production rejects anonymous access.
    """
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        try:
            session = read_session(token)
        except SessionError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        workspace = db.get(Workspace, session.workspace_id)
        if workspace is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session")
        if workspace_id is not None and workspace_id != workspace.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="cross-workspace access denied"
            )
        return workspace

    if settings.env != "development":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
        )
    if workspace_id is None:
        return default_workspace(db)
    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    return workspace
