"""Slack slash commands and Block Kit interactivity."""

from __future__ import annotations

import json
from typing import Annotated, Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clients.base import SlackClient
from app.clients.deps import get_slack_client
from app.db import get_db
from app.integrations.slack.format import (
    InvalidActionValue,
    assign_select_blocks,
    command_blocks,
    verify_action_value,
)
from app.integrations.slack.verify import verify_slack_signature
from app.models import Finding, FindingState, Installation, Provider, Surface, User, Workspace
from app.services.triage import IllegalTransition, apply_transition

router = APIRouter(prefix="/api/slack", tags=["slack"])

DbDep = Annotated[Session, Depends(get_db)]
SlackDep = Annotated[SlackClient, Depends(get_slack_client)]


def _parse_form(body: bytes) -> dict[str, str]:
    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items()}


def _require_signature(body: bytes, timestamp: str | None, signature: str | None) -> None:
    if not verify_slack_signature(body, timestamp, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid slack signature"
        )


def _workspace_for_team(db: Session, team_id: str | None) -> Workspace:
    if not team_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing slack team")
    installation = db.scalars(
        select(Installation).where(
            Installation.provider == Provider.slack,
            Installation.external_id == team_id,
        )
    ).first()
    if installation is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="workspace is not installed for this team"
        )
    workspace = db.get(Workspace, installation.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="workspace not found")
    return workspace


def _actor_for_slack_user(
    db: Session, workspace: Workspace, slack_user_id: str | None
) -> User | None:
    if not slack_user_id:
        return None
    return db.scalars(
        select(User).where(
            User.workspace_id == workspace.id, User.external_subject == slack_user_id
        )
    ).first()


def _find_finding(db: Session, finding_id: Any, workspace: Workspace) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.workspace_id != workspace.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return finding


def _thread_ts(payload: dict[str, Any]) -> str | None:
    container = payload.get("container") or {}
    thread = container.get("message_ts")
    if not thread:
        message = payload.get("message") or {}
        thread = message.get("ts")
    return str(thread) if thread else None


def _channel(payload: dict[str, Any]) -> str:
    channel = (payload.get("channel") or {}).get("id")
    if not channel:
        channel = (payload.get("container") or {}).get("channel_id")
    if not channel:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing channel")
    return str(channel)


@router.post("/commands")
async def slack_command(
    request: Request,
    db: DbDep,
    x_slack_signature: Annotated[str | None, Header()] = None,
    x_slack_request_timestamp: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    body = await request.body()
    _require_signature(body, x_slack_request_timestamp, x_slack_signature)
    form = _parse_form(body)
    workspace = _workspace_for_team(db, form.get("team_id"))
    text = (form.get("text") or "").strip()
    parts = text.split()
    subcommand = parts[0].lower() if parts else "open"

    stmt = select(Finding).where(Finding.workspace_id == workspace.id)
    if subcommand == "open":
        stmt = stmt.where(Finding.state == FindingState.open)
    elif subcommand == "rule" and len(parts) > 1:
        stmt = stmt.where(Finding.rule_id == parts[1])
    elif subcommand == "repo" and len(parts) > 1:
        stmt = stmt.where(Finding.repo == parts[1])
    elif subcommand in {"open", "rule", "repo"}:
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/triage open`, `/triage rule <rule_id>`, `/triage repo <name>`",
        }
    else:
        return {
            "response_type": "ephemeral",
            "text": "Unknown subcommand. Try `/triage open`, `/triage rule <rule_id>` or "
            "`/triage repo <name>`.",
        }

    findings = list(db.scalars(stmt.order_by(Finding.first_seen_at.desc()).limit(5)).all())
    return {"response_type": "ephemeral", "blocks": command_blocks(findings)}


@router.post("/interactions")
async def slack_interaction(
    request: Request,
    db: DbDep,
    slack: SlackDep,
    x_slack_signature: Annotated[str | None, Header()] = None,
    x_slack_request_timestamp: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    body = await request.body()
    _require_signature(body, x_slack_request_timestamp, x_slack_signature)
    form = _parse_form(body)
    try:
        payload = json.loads(form["payload"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid interaction payload"
        ) from exc

    if payload.get("type") != "block_actions":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported interaction"
        )

    actions = payload.get("actions") or []
    if not actions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing action")
    action = actions[0]
    action_id = action.get("action_id")
    try:
        finding_id, workspace_id = verify_action_value(str(action.get("value", "")))
    except InvalidActionValue as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    workspace = _workspace_for_team(db, (payload.get("team") or {}).get("id"))
    if workspace.id != workspace_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="cross-workspace access denied"
        )
    finding = _find_finding(db, finding_id, workspace)
    slack_user_id = (payload.get("user") or {}).get("id")
    actor = _actor_for_slack_user(db, workspace, slack_user_id)

    if action_id == "assign":
        return {
            "response_type": "ephemeral",
            "blocks": assign_select_blocks(str(action["value"]), finding),
        }

    if action_id == "assign_user":
        selected = action.get("selected_user")
        assignee = _actor_for_slack_user(db, workspace, selected)
        if assignee is None:
            return {
                "response_type": "ephemeral",
                "text": "That Slack user is not provisioned in this TriageHub workspace.",
            }
        try:
            outcome = apply_transition(
                finding, "assign", actor, Surface.slack, db=db, assignee=assignee
            )
        except IllegalTransition as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message) from exc
        if outcome.changed:
            slack.post_message(
                _channel(payload),
                f"Assigned `{finding.rule_id}` to <@{selected}>",
                thread_ts=_thread_ts(payload),
            )
            db.commit()
        return {
            "response_type": "ephemeral",
            "text": f"Assigned to <@{selected}>." if outcome.changed else "Already assigned.",
        }

    if action_id not in {"accept", "mute"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown action")

    try:
        outcome = apply_transition(finding, action_id, actor, Surface.slack, db=db)
    except IllegalTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message) from exc

    if outcome.changed:
        slack.post_message(
            _channel(payload),
            f"{'Accepted' if action_id == 'accept' else 'Muted'} `{finding.rule_id}` "
            f"in `{finding.repo}` by <@{slack_user_id}>",
            thread_ts=_thread_ts(payload),
        )
        db.commit()
        done = "accepted" if action_id == "accept" else "muted"
        return {"response_type": "ephemeral", "text": f"Finding {done}."}
    return {
        "response_type": "ephemeral",
        "text": f"Already {finding.state.value}; no change made.",
    }
