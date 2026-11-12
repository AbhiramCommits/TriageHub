from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clients.fakes import FakeGitHubClient, FakeSlackClient
from app.integrations.github.verify import expected_signature
from app.integrations.slack.format import sign_action_value
from app.models import Event, FindingState, Installation, Provider, Surface
from tests.conftest import make_finding, make_workspace
from tests.test_slack import (
    TEAM_ID,
    interaction_body,
    interaction_payload,
    slack_headers,
)


async def test_install_sso_slack_accept_github_autoresolve_and_metrics(
    client: httpx.AsyncClient,
    db: Session,
    slack: FakeSlackClient,
    github: FakeGitHubClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.integrations.github.app_auth.build_app_jwt", lambda **_: "e2e-app-jwt")
    ws = make_workspace(db, slug="e2e", sso_only=True)
    accepted = make_finding(
        db,
        ws,
        repo="acme/web-console",
        file_path="src/lib/template.ts",
        start_line=1,
        snippet="result = eval(template)",
    )
    auto = make_finding(
        db,
        ws,
        file_path="app/api/refunds.py",
        start_line=2,
        snippet="digest = hashlib.md5(payload).hexdigest()",
    )
    for finding in (accepted, auto):
        db.add(
            Event(
                workspace_id=ws.id,
                finding_id=finding.id,
                kind="finding.created",
                surface=Surface.system,
                payload={
                    "severity": finding.severity.value,
                    "rule_id": finding.rule_id,
                    "repo": finding.repo,
                },
                created_at=finding.first_seen_at,
            )
        )
    db.flush()

    # 1. OAuth install handshakes for Slack and GitHub.
    for provider in ("slack", "github"):
        install = await client.get(
            f"/api/oauth/{provider}/install", params={"workspace_id": str(ws.id)}
        )
        assert install.status_code == 302
        state = parse_qs(urlparse(install.headers["location"]).query)["state"][0]
        callback = await client.get(
            f"/api/oauth/{provider}/callback", params={"code": "e2e-code", "state": state}
        )
        assert callback.status_code == 302

    installations = db.scalars(select(Installation)).all()
    assert {installation.provider for installation in installations} == {
        Provider.slack,
        Provider.github,
    }

    # 2. SSO login provisions the reviewer and sets a workspace-scoped session.
    login = await client.get("/api/auth/sso/login", params={"workspace_id": str(ws.id)})
    sso_state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
    sso = await client.get(
        "/api/auth/sso/callback", params={"code": "e2e-sso-code", "state": sso_state}
    )
    assert sso.status_code == 302
    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["workspace_id"] == str(ws.id)

    # 3. A Slack button accepts the first finding.
    value = sign_action_value(accepted.id, ws.id)
    body = interaction_body(interaction_payload("accept", value))
    slack_response = await client.post(
        "/api/slack/interactions", content=body, headers=slack_headers(body)
    )
    assert slack_response.status_code == 200
    db.refresh(accepted)
    assert accepted.state is FindingState.accepted
    assert accepted.triaged_at is not None

    # 4. A GitHub push changes the second finding's line and auto-resolves it.
    github.files[("app/api/refunds.py", "e2e-head")] = (
        "digest = hashlib.sha256(payload).hexdigest()\n"
    )
    push = {
        "ref": "refs/heads/main",
        "before": "e2e-base",
        "after": "e2e-head",
        "installation": {"id": 4242},
        "repository": {"full_name": "acme/payments-api"},
    }
    push_body = json.dumps(push).encode()
    signature = expected_signature(push_body)
    push_response = await client.post(
        "/api/github/webhooks",
        content=push_body,
        headers={"X-Hub-Signature-256": signature, "X-GitHub-Event": "push"},
    )
    assert push_response.status_code == 200
    assert push_response.json()["auto_resolved"] == 1
    db.refresh(auto)
    assert auto.state is FindingState.fixed

    kinds = {
        event.kind
        for event in db.scalars(
            select(Event).where(
                Event.finding_id.in_([accepted.id, auto.id]),
                Event.kind.in_(["finding.accepted", "finding.auto_resolved"]),
            )
        ).all()
    }
    assert kinds == {"finding.accepted", "finding.auto_resolved"}

    # 5. Metrics reflect both terminal transitions in the signed-in workspace.
    metrics = await client.get("/api/metrics/summary")
    assert metrics.status_code == 200
    summary = metrics.json()
    assert summary["time_to_triage"]["overall"]["n"] == 2
    assert summary["variant_comparison"]["variant_a"]["n"] == 0
    assert summary["variant_comparison"]["verdict"] == "Not enough data to compare variants."

    assert TEAM_ID in {installation.external_id for installation in installations}
    assert slack.calls_for("post_message")
