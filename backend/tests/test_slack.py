from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import encrypt_token
from app.clients.fakes import FakeSlackClient
from app.config import settings
from app.integrations.slack.format import (
    pick_variant,
    render_variant_a,
    render_variant_b,
    sign_action_value,
    verify_action_value,
)
from app.integrations.slack.verify import verify_slack_signature
from app.models import Event, Finding, FindingState, Installation, Provider, Variant
from tests.conftest import make_finding, make_user, make_workspace

TEAM_ID = "T0TESTTEAM"
SLACK_USER = "U0TESTUSER"


def slack_installation(db: Session, workspace) -> Installation:
    installation = Installation(
        workspace_id=workspace.id,
        provider=Provider.slack,
        external_id=TEAM_ID,
        encrypted_access_token=encrypt_token("xoxb-install-token"),
        scopes="commands,chat:write",
    )
    db.add(installation)
    db.flush()
    return installation


def slack_headers(body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    signature = (
        "v0="
        + hmac.new(
            settings.slack_signing_secret.encode(),
            b"v0:" + ts.encode() + b":" + body,
            hashlib.sha256,
        ).hexdigest()
    )
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": signature,
        "Content-Type": "application/x-www-form-urlencoded",
    }


def command_body(text: str) -> bytes:
    return urlencode(
        {
            "token": "verification-token",
            "team_id": TEAM_ID,
            "user_id": SLACK_USER,
            "command": "/triage",
            "text": text,
        }
    ).encode()


def interaction_body(payload: dict) -> bytes:
    return urlencode({"payload": json.dumps(payload)}).encode()


def interaction_payload(action_id: str, value: str, **extra) -> dict:
    return {
        "type": "block_actions",
        "team": {"id": TEAM_ID},
        "user": {"id": SLACK_USER},
        "channel": {"id": "C0TESTCHANNEL"},
        "container": {"message_ts": "1700000000.000001"},
        "actions": [{"action_id": action_id, "value": value, **extra}],
    }


async def test_command_rejects_bad_signature(client: httpx.AsyncClient, db: Session) -> None:
    body = command_body("open")
    headers = slack_headers(body)
    headers["X-Slack-Signature"] = "v0=deadbeef"
    response = await client.post("/api/slack/commands", content=body, headers=headers)
    assert response.status_code == 401


async def test_command_rejects_stale_timestamp(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    body = command_body("open")
    headers = slack_headers(body, timestamp=int(time.time()) - 60 * 10)
    assert not verify_slack_signature(
        body, headers["X-Slack-Request-Timestamp"], headers["X-Slack-Signature"]
    )
    response = await client.post("/api/slack/commands", content=body, headers=headers)
    assert response.status_code == 401


async def test_open_command_returns_signed_block_kit(
    client: httpx.AsyncClient, db: Session
) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    for i in range(7):
        make_finding(db, ws, start_line=10 + i)
    body = command_body("open")
    response = await client.post("/api/slack/commands", content=body, headers=slack_headers(body))
    assert response.status_code == 200
    blocks = response.json()["blocks"]
    action_blocks = [b for b in blocks if b["type"] == "actions"]
    assert len(action_blocks) == 5
    button = action_blocks[0]["elements"][0]
    finding_id, workspace_id = verify_action_value(button["value"])
    assert workspace_id == ws.id
    assert db.get(Finding, finding_id) is not None


async def test_rule_and_repo_filters(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    make_finding(db, ws, rule_id="rule.one", repo="acme/one")
    make_finding(db, ws, rule_id="rule.two", repo="acme/two")

    body = command_body("rule rule.one")
    response = await client.post("/api/slack/commands", content=body, headers=slack_headers(body))
    assert response.json()["blocks"][0]["text"]["text"] == "TriageHub findings (1)"

    body = command_body("repo acme/two")
    response = await client.post("/api/slack/commands", content=body, headers=slack_headers(body))
    assert response.json()["blocks"][0]["text"]["text"] == "TriageHub findings (1)"


async def test_empty_command_result(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    body = command_body("repo acme/absent")
    response = await client.post("/api/slack/commands", content=body, headers=slack_headers(body))
    assert "No matching findings" in response.json()["blocks"][1]["text"]["text"]


async def test_accept_action_is_idempotent_and_threaded(
    client: httpx.AsyncClient, db: Session, slack: FakeSlackClient
) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    user = make_user(db, ws, email="slackuser@acme.test")
    user.external_subject = SLACK_USER
    finding = make_finding(db, ws)
    value = sign_action_value(finding.id, ws.id)

    body = interaction_body(interaction_payload("accept", value))
    response = await client.post(
        "/api/slack/interactions", content=body, headers=slack_headers(body)
    )
    assert response.status_code == 200
    db.refresh(finding)
    assert finding.state is FindingState.accepted
    assert finding.triaged_at is not None

    event = db.scalars(select(Event).where(Event.kind == "finding.accepted")).one()
    assert event.surface.value == "slack"
    assert event.actor_user_id == user.id
    assert event.payload["from"] == "open"
    assert event.payload["to"] == "accepted"
    slack.assert_called_once_with(
        "post_message",
        channel="C0TESTCHANNEL",
        text="Accepted `python.lang.security.audit.eval-detected` in `acme/payments-api` "
        f"by <@{SLACK_USER}>",
        thread_ts="1700000000.000001",
    )

    replay = await client.post("/api/slack/interactions", content=body, headers=slack_headers(body))
    assert replay.status_code == 200
    assert "Already" in replay.json()["text"]
    assert db.scalar(select(Event).where(Event.kind == "finding.accepted")) is not None
    assert len(db.scalars(select(Event).where(Event.kind == "finding.accepted")).all()) == 1
    assert len(slack.messages) == 1


async def test_mute_action(client: httpx.AsyncClient, db: Session, slack: FakeSlackClient) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    finding = make_finding(db, ws)
    body = interaction_body(interaction_payload("mute", sign_action_value(finding.id, ws.id)))
    response = await client.post(
        "/api/slack/interactions", content=body, headers=slack_headers(body)
    )
    assert response.status_code == 200
    db.refresh(finding)
    assert finding.state is FindingState.muted
    assert slack.calls_for("post_message")[0]["text"].startswith("Muted")


async def test_assign_opens_select_then_sets_assignee(
    client: httpx.AsyncClient, db: Session, slack: FakeSlackClient
) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    reviewer = make_user(db, ws, email="reviewer@acme.test")
    reviewer.external_subject = "UREVIEWER"
    finding = make_finding(db, ws)
    value = sign_action_value(finding.id, ws.id)

    assign = interaction_body(interaction_payload("assign", value))
    response = await client.post(
        "/api/slack/interactions", content=assign, headers=slack_headers(assign)
    )
    assert response.status_code == 200
    blocks = response.json()["blocks"]
    assert blocks[1]["elements"][0]["type"] == "users_select"

    selected = interaction_payload("assign_user", value, selected_user="UREVIEWER")
    body = interaction_body(selected)
    response = await client.post(
        "/api/slack/interactions", content=body, headers=slack_headers(body)
    )
    assert response.status_code == 200
    db.refresh(finding)
    assert finding.assignee_user_id == reviewer.id
    event = db.scalars(select(Event).where(Event.kind == "finding.assigned")).one()
    assert event.payload["assignee_user_id"] == str(reviewer.id)


async def test_tampered_action_value_is_rejected(client: httpx.AsyncClient, db: Session) -> None:
    ws = make_workspace(db)
    slack_installation(db, ws)
    finding = make_finding(db, ws)
    value = sign_action_value(finding.id, ws.id)[:-3] + "abc"
    body = interaction_body(interaction_payload("accept", value))
    response = await client.post(
        "/api/slack/interactions", content=body, headers=slack_headers(body)
    )
    assert response.status_code == 401


async def test_unknown_team_is_forbidden(client: httpx.AsyncClient, db: Session) -> None:
    body = command_body("open")
    response = await client.post("/api/slack/commands", content=body, headers=slack_headers(body))
    assert response.status_code == 403


def test_variant_assignment_is_deterministic_and_balanced() -> None:
    ids = [make_variant_id(i) for i in range(200)]
    picks = [pick_variant(value) for value in ids]
    assert picks == [pick_variant(value) for value in ids]
    assert set(picks) == {Variant.A, Variant.B}
    assert 70 <= picks.count(Variant.A) <= 130


def make_variant_id(i: int):
    import uuid

    return uuid.uuid5(uuid.NAMESPACE_URL, f"triagehub-variant-{i}")


def test_variant_renderers(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    compact = render_variant_a(finding)
    expanded = render_variant_b(finding)
    assert "\n" not in compact
    assert finding.code_snippet in expanded
    assert finding.rule_rationale in expanded
    assert compact != expanded


def test_assign_variant_stamps_finding(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws)
    from app.integrations.slack.format import assign_variant

    variant = assign_variant(finding)
    assert finding.notification_variant is variant
    again = assign_variant(finding)
    assert again is variant
