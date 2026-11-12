from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_workspace
from app.models import User, Workspace
from app.schemas import UserOut

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    db: Annotated[Session, Depends(get_db)],
    workspace: Annotated[Workspace, Depends(get_workspace)],
) -> list[UserOut]:
    users = db.scalars(
        select(User).where(User.workspace_id == workspace.id).order_by(User.email)
    ).all()
    return [UserOut.model_validate(user) for user in users]
