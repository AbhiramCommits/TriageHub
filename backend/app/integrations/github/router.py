"""GitHub App webhooks: PR review comments and fingerprint-based auto-resolve."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clients.base import GitHubClient
from app.clients.deps import get_github_client
from app.db import get_db
from app.integrations.github.app_auth import installation_token_cache
from app.integrations.github.fingerprint import fingerprint_line
from app.integrations.github.review import post_findings_as_review
from app.integrations.github.verify import verify_github_signature
from app.models import Event, Finding, FindingState, Installation, Provider, Surface, Workspace
from app.services.triage import apply_transition

router = APIRouter(prefix="/api/github", tags=["github"])

DbDep = Annotated[Session, Depends(get_db)]
GitHubDep = Annotated[GitHubClient, Depends(get_github_client)]


def _workspace_for_installation(db: Session, installation_id: str | None) -> Workspace:
    if not installation_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing installation")
    installation = db.scalars(
        select(Installation).where(
            Installation.provider == Provider.github,
            Installation.external_id == installation_id,
        )
    ).first()
    if installation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown installation")
    workspace = db.get(Workspace, installation.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown workspace")
    return workspace


def _handle_pull_request(
    db: Session,
    github: GitHubClient,
    workspace: Workspace,
    installation_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    action = payload.get("action")
    if action not in {"opened", "synchronize", "reopened"}:
        return {"posted": 0, "ignored": action}
    repo = payload["repository"]["full_name"]
    pr = payload["pull_request"]
    pr_number = int(payload["number"])
    head_sha = pr["head"]["sha"]
    base_sha = pr["base"]["sha"]
    token = installation_token_cache.get(github, installation_id)

    comparison = github.compare_commits(token, repo, base_sha, head_sha)
    changed_files = {
        str(item.get("filename")) for item in comparison.get("files", []) if item.get("filename")
    }
    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.workspace_id == workspace.id,
                Finding.repo == repo,
                Finding.state != FindingState.fixed,
            )
        ).all()
    )
    findings = [finding for finding in findings if finding.file_path in changed_files]
    if not findings:
        return {"posted": 0, "reason": "no matching findings"}

    response = post_findings_as_review(github, token, repo, pr_number, head_sha, findings)
    threads = response.get("threads") if isinstance(response, dict) else None
    db.add(
        Event(
            workspace_id=workspace.id,
            kind="review.posted",
            surface=Surface.github,
            payload={
                "repo": repo,
                "pr_number": pr_number,
                "head_sha": head_sha,
                "review_id": response.get("id") if isinstance(response, dict) else None,
                "threads": threads or {},
            },
        )
    )
    db.commit()
    return {"posted": len(findings), "review_id": response.get("id")}


def _thread_id_for(db: Session, workspace: Workspace, finding: Finding) -> str | None:
    events = db.scalars(
        select(Event)
        .where(Event.workspace_id == workspace.id, Event.kind == "review.posted")
        .order_by(Event.created_at.desc())
        .limit(50)
    ).all()
    for event in events:
        threads = event.payload.get("threads") or {}
        value = threads.get(str(finding.id))
        if value:
            return str(value)
    return None


def _handle_push(
    db: Session,
    github: GitHubClient,
    workspace: Workspace,
    installation_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    repo = payload["repository"]["full_name"]
    after = str(payload.get("after", ""))
    if not after or set(after) == {"0"}:
        return {"auto_resolved": 0, "reason": "branch deleted"}
    token = installation_token_cache.get(github, installation_id)

    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.workspace_id == workspace.id,
                Finding.repo == repo,
                Finding.state != FindingState.fixed,
            )
        ).all()
    )
    contents: dict[str, list[str]] = {}
    resolved = 0
    for finding in findings:
        if finding.file_path not in contents:
            text = github.get_file_contents(token, repo, finding.file_path, after)
            contents[finding.file_path] = text.splitlines() if text is not None else []
        lines = contents[finding.file_path]
        index = finding.start_line - 1
        still_present = (
            0 <= index < len(lines) and fingerprint_line(lines[index]) == finding.line_fingerprint
        )
        if still_present:
            continue
        apply_transition(
            finding,
            "resolve",
            None,
            Surface.github,
            db=db,
            event_kind="finding.auto_resolved",
            payload_extra={"repo": repo, "ref": after, "reason": "line_changed_or_removed"},
        )
        thread_id = _thread_id_for(db, workspace, finding)
        if thread_id:
            github.resolve_review_thread(token, thread_id)
        resolved += 1
    db.commit()
    return {"auto_resolved": resolved}


@router.post("/webhooks")
async def github_webhook(
    request: Request,
    db: DbDep,
    github: GitHubDep,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    body = await request.body()
    if not verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid github signature"
        )
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload"
        ) from exc

    installation_id = str((payload.get("installation") or {}).get("id") or "")
    workspace = _workspace_for_installation(db, installation_id)

    if x_github_event == "pull_request":
        return _handle_pull_request(db, github, workspace, installation_id, payload)
    if x_github_event == "push":
        return _handle_push(db, github, workspace, installation_id, payload)
    if x_github_event == "ping":
        return {"ok": True}
    return {"ignored": x_github_event}
