"""The single triage transition chokepoint.

Slack, GitHub and the console all call ``apply_transition`` so state changes,
``triaged_at`` stamping and event emission can never diverge by surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import Event, Finding, FindingState, Surface, User


class IllegalTransition(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class TransitionOutcome:
    finding: Finding
    changed: bool
    event: Event | None


ACTION_TARGET: dict[str, FindingState] = {
    "accept": FindingState.accepted,
    "mute": FindingState.muted,
    "resolve": FindingState.fixed,
    "reopen": FindingState.open,
}

ACTION_EVENT_KIND = {
    "accept": "finding.accepted",
    "mute": "finding.muted",
    "resolve": "finding.fixed",
    "reopen": "finding.reopened",
}

TERMINAL_STATES = {FindingState.accepted, FindingState.muted, FindingState.fixed}


def apply_transition(
    finding: Finding,
    action: str,
    actor: User | None,
    surface: Surface,
    *,
    db: Session,
    assignee: User | None = None,
    now: datetime | None = None,
    event_kind: str | None = None,
    payload_extra: dict[str, Any] | None = None,
) -> TransitionOutcome:
    """Apply one triage action, returning a no-op outcome for exact replays.

    Raises IllegalTransition for terminal-state changes (e.g. fixed -> open).
    """
    timestamp = now or datetime.now(UTC)
    before = finding.state
    after_state: FindingState

    if action == "assign":
        if assignee is None:
            raise IllegalTransition("assign requires an assignee")
        if finding.state is FindingState.fixed:
            raise IllegalTransition("a fixed finding cannot be reassigned")
        if finding.assignee_user_id == assignee.id:
            return TransitionOutcome(finding=finding, changed=False, event=None)
        finding.assignee_user_id = assignee.id
        kind = "finding.assigned"
        after_state = finding.state
    elif action in ACTION_TARGET:
        target = ACTION_TARGET[action]
        if finding.state is FindingState.fixed and target is not FindingState.fixed:
            raise IllegalTransition(f"cannot {action} a fixed finding")
        if finding.state is target:
            return TransitionOutcome(finding=finding, changed=False, event=None)
        finding.state = target
        if target in TERMINAL_STATES:
            if finding.triaged_at is None:
                finding.triaged_at = timestamp
        elif target is FindingState.open:
            finding.triaged_at = None
        kind = event_kind or ACTION_EVENT_KIND[action]
        after_state = target
    else:
        raise IllegalTransition(f"unknown action: {action}")

    payload: dict[str, Any] = {
        "action": action,
        "from": before.value,
        "to": after_state.value,
    }
    if assignee is not None:
        payload["assignee_user_id"] = str(assignee.id)
    if payload_extra:
        payload.update(payload_extra)
    event = Event(
        workspace_id=finding.workspace_id,
        finding_id=finding.id,
        actor_user_id=actor.id if actor else None,
        kind=kind,
        surface=surface,
        payload=payload,
        created_at=timestamp,
    )
    db.add(event)
    db.flush()
    return TransitionOutcome(finding=finding, changed=True, event=event)


def apply_bulk(
    db: Session,
    findings: list[Finding],
    action: str,
    actor: User | None,
    surface: Surface,
    assignee: User | None = None,
) -> tuple[list[Finding], list[dict[str, str]]]:
    updated: list[Finding] = []
    skipped: list[dict[str, str]] = []
    for finding in findings:
        try:
            outcome = apply_transition(finding, action, actor, surface, db=db, assignee=assignee)
        except IllegalTransition as exc:
            skipped.append({"finding_id": str(finding.id), "reason": exc.message})
            continue
        if outcome.changed:
            updated.append(finding)
    return updated, skipped
