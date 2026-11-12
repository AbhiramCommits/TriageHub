"""Slack Block Kit rendering, A/B notification formats and signed action values."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from typing import Any

from app.config import settings
from app.models import Finding, Variant


def pick_variant(finding_id: uuid.UUID) -> Variant:
    """Deterministic hash-based 50/50 assignment for a finding."""
    digest = hashlib.sha256(str(finding_id).encode()).digest()
    return Variant.A if digest[0] % 2 == 0 else Variant.B


def assign_variant(finding: Finding) -> Variant:
    """Pick and stamp the notification variant, preserving an existing stamp."""
    if finding.notification_variant is None:
        finding.notification_variant = pick_variant(finding.id)
    return finding.notification_variant


def render_variant_a(finding: Finding) -> str:
    return (
        f"[{finding.severity.value.upper()}] {finding.rule_id} — "
        f"{finding.repo}:{finding.file_path}:{finding.start_line} — {finding.message}"
    )


def render_variant_b(finding: Finding) -> str:
    snippet = finding.code_snippet or "(source unavailable)"
    rationale = finding.rule_rationale or finding.message
    return (
        f"*{finding.severity.value.upper()}* `{finding.rule_id}`\n"
        f"{finding.message}\n"
        f"`{finding.repo}/{finding.file_path}:{finding.start_line}`\n"
        f"```{snippet}```\n"
        f"_{rationale}_"
    )


def render_notification(finding: Finding) -> str:
    variant = assign_variant(finding)
    return render_variant_a(finding) if variant is Variant.A else render_variant_b(finding)


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _action_signature(payload: bytes) -> bytes:
    return hmac.new(
        settings.state_secret.encode(), b"slack-action:" + payload, hashlib.sha256
    ).digest()


def sign_action_value(finding_id: uuid.UUID, workspace_id: uuid.UUID) -> str:
    payload = json.dumps(
        {"finding_id": str(finding_id), "workspace_id": str(workspace_id)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"{_b64encode(payload)}.{_b64encode(_action_signature(payload))}"


class InvalidActionValue(ValueError):
    pass


def verify_action_value(value: str) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        payload_b64, signature_b64 = value.split(".")
        payload = _b64decode(payload_b64)
        signature = _b64decode(signature_b64)
    except (ValueError, TypeError) as exc:
        raise InvalidActionValue("malformed action value") from exc
    if not hmac.compare_digest(signature, _action_signature(payload)):
        raise InvalidActionValue("bad action signature")
    try:
        data = json.loads(payload)
        return uuid.UUID(data["finding_id"]), uuid.UUID(data["workspace_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidActionValue("malformed action payload") from exc


def finding_blocks(finding: Finding) -> list[dict[str, Any]]:
    value = sign_action_value(finding.id, finding.workspace_id)
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": render_notification(finding)}},
        {
            "type": "actions",
            "block_id": f"triage-actions-{finding.id}",
            "elements": [
                {
                    "type": "button",
                    "action_id": "accept",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Accept"},
                    "value": value,
                },
                {
                    "type": "button",
                    "action_id": "mute",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Mute"},
                    "value": value,
                },
                {
                    "type": "button",
                    "action_id": "assign",
                    "text": {"type": "plain_text", "text": "Assign"},
                    "value": value,
                },
            ],
        },
    ]


def command_blocks(findings: list[Finding]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"TriageHub findings ({len(findings)})"},
        }
    ]
    if not findings:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "No matching findings. Nice and quiet."},
            }
        )
        return blocks
    for finding in findings:
        blocks.extend(finding_blocks(finding))
    return blocks


def assign_select_blocks(original_value: str, finding: Finding) -> list[dict[str, Any]]:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Choose a reviewer for `{finding.rule_id}` in `{finding.repo}`",
            },
        },
        {
            "type": "actions",
            "block_id": "triage-assign",
            "elements": [
                {
                    "type": "users_select",
                    "action_id": "assign_user",
                    "placeholder": {"type": "plain_text", "text": "Select a reviewer"},
                    "value": original_value,
                }
            ],
        },
    ]
