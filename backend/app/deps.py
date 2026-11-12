"""Database-aware dependency: which workspace does this request run against?"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

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
    workspace_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Workspace:
    """Resolve the request workspace.

    Unauthenticated development reads fall back to the first workspace. In
    production the SSO session binds the workspace and cross-workspace access is
    rejected by ``app.auth.oidc.require_workspace``.
    """
    if workspace_id is None:
        if settings.env != "development":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
            )
        return default_workspace(db)
    ws = db.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    return ws
