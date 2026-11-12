from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select, tuple_
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from app.cursor import InvalidCursor, decode_cursor, encode_cursor
from app.db import get_db
from app.deps import get_workspace
from app.models import Finding, FindingState, Severity, Workspace
from app.schemas import FindingOut, FindingPage

router = APIRouter(prefix="/api/findings", tags=["findings"])

DbDep = Annotated[Session, Depends(get_db)]
WorkspaceDep = Annotated[Workspace, Depends(get_workspace)]


def _apply_filters(
    stmt: Select[tuple[Finding]],
    severity: list[Severity] | None,
    state: list[FindingState] | None,
    rule_id: str | None,
    repo: str | None,
    search: str | None,
) -> Select[tuple[Finding]]:
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity))
    if state:
        stmt = stmt.where(Finding.state.in_(state))
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if repo:
        stmt = stmt.where(Finding.repo == repo)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.message.ilike(needle),
                Finding.file_path.ilike(needle),
                Finding.rule_id.ilike(needle),
            )
        )
    return stmt


@router.get("", response_model=FindingPage)
def list_findings(
    db: DbDep,
    workspace: WorkspaceDep,
    state: Annotated[list[FindingState] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    rule_id: str | None = None,
    repo: str | None = None,
    search: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: str | None = None,
) -> FindingPage:
    stmt = select(Finding).where(Finding.workspace_id == workspace.id)
    stmt = _apply_filters(stmt, severity, state, rule_id, repo, search)
    if cursor:
        try:
            ts, row_id = decode_cursor(cursor)
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        stmt = stmt.where(tuple_(Finding.first_seen_at, Finding.id) < (ts, row_id))
    stmt = stmt.order_by(Finding.first_seen_at.desc(), Finding.id.desc()).limit(limit + 1)
    rows = list(db.scalars(stmt).all())
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(rows[-1].first_seen_at, rows[-1].id)
    return FindingPage(items=[FindingOut.model_validate(r) for r in rows], next_cursor=next_cursor)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: uuid.UUID, db: DbDep, workspace: WorkspaceDep) -> FindingOut:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.workspace_id != workspace.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return FindingOut.model_validate(finding)
