from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analytics.metrics import summarize
from app.db import get_db
from app.deps import get_workspace
from app.models import Event, Workspace
from app.schemas import MetricsSummary

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("/summary", response_model=MetricsSummary)
def metrics_summary(
    db: Annotated[Session, Depends(get_db)],
    workspace: Annotated[Workspace, Depends(get_workspace)],
) -> MetricsSummary:
    events = list(
        db.scalars(
            select(Event).where(Event.workspace_id == workspace.id).order_by(Event.created_at)
        ).all()
    )
    return MetricsSummary.model_validate(summarize(events))
