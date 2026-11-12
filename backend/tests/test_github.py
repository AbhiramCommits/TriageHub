from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import encrypt_token
from app.clients.fakes import FakeGitHubClient
from app.config import settings
from app.integrations.github.app_auth import (
    InstallationTokenCache,
    build_app_jwt,
    installation_token_cache,
)
from app.integrations.github.fingerprint import fingerprint_line, normalize_line
from app.integrations.github.review import inline_comment
from app.models import Event, FindingState, Installation, Provider, Surface
from tests.conftest import make_finding, make_workspace

INSTALLATION_ID = "4242"
REPO = "acme/payments-api"


def github_installation(db: Session, workspace) -> Installation:
    installation = Installation(
        workspace_id=workspace.id,
        provider=Provider.github,
        external_id=INSTALLATION_ID,
        encrypted_access_token=encrypt_token("ghs-installed-token"),
        scopes="repo",
    )
    db.add(installation)
    db.flush()
    return installation


def webhook_headers(body: bytes, event: str = "pull_request") -> dict[str, str]:
    signature = (
        "sha256="
        + hmac.new(settings.github_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    )
    return {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
    }


def pr_payload(action: str = "opened") -> dict:
    return {
        "action": action,
        "number": 17,
        "installation": {"id": int(INSTALLATION_ID)},
        "repository": {"full_name": REPO},
        "pull_request": {
            "head": {"sha": "headsha123"},
            "base": {"sha": "basesha456"},
        },
    }


def push_payload(after: str = "aftersha789") -> dict:
    return {
        "ref": "refs/heads/main",
        "before": "beforesha000",
        "after": after,
        "installation": {"id": int(INSTALLATION_ID)},
        "repository": {"full_name": REPO},
        "head_commit": {"id": after},
    }


@pytest.fixture(autouse=True)
def _clear_token_cache() -> None:
    installation_token_cache.clear()


@pytest.fixture(autouse=True)
def _mock_app_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.integrations.github.app_auth.build_app_jwt", lambda **_: "signed-app-jwt"
    )


async def test_webhook_rejects_bad_signature(client: httpx.AsyncClient, db: Session) -> None:
    body = json.dumps(pr_payload()).encode()
    headers = webhook_headers(body)
    headers["X-Hub-Signature-256"] = "sha256=deadbeef"
    response = await client.post("/api/github/webhooks", content=body, headers=headers)
    assert response.status_code == 401


async def test_pull_request_posts_one_review_with_inline_comments(
    client: httpx.AsyncClient, db: Session, github: FakeGitHubClient
) -> None:
    ws = make_workspace(db)
    github_installation(db, ws)
    finding = make_finding(db, ws, start_line=88)
    make_finding(db, ws, file_path="app/api/refunds.py", start_line=12)
    github.compare_result = {
        "files": [{"filename": "app/api/charges.py"}],
    }

    body = json.dumps(pr_payload("synchronize")).encode()
    response = await client.post(
        "/api/github/webhooks", content=body, headers=webhook_headers(body)
    )
    assert response.status_code == 200
    assert response.json()["posted"] == 1

    review = github.reviews[0]
    assert review["repo"] == REPO
    assert review["pr_number"] == 17
    assert review["commit_id"] == "headsha123"
    assert review["comments"] == [
        {
            "path": "app/api/charges.py",
            "line": 88,
            "side": "RIGHT",
            "body": review["comments"][0]["body"],
        }
    ]
    assert "HIGH" in review["comments"][0]["body"]
    assert finding.rule_id in review["comments"][0]["body"]

    event = db.scalars(select(Event).where(Event.kind == "review.posted")).one()
    assert event.payload["pr_number"] == 17


async def test_push_auto_resolves_changed_line(
    client: httpx.AsyncClient, db: Session, github: FakeGitHubClient
) -> None:
    ws = make_workspace(db)
    github_installation(db, ws)
    changed = make_finding(db, ws, start_line=1, snippet='result = eval(request.args["expr"])')
    unchanged = make_finding(
        db,
        ws,
        file_path="app/api/refunds.py",
        start_line=2,
        snippet="digest = hashlib.md5(payload).hexdigest()",
    )
    db.add(
        Event(
            workspace_id=ws.id,
            finding_id=changed.id,
            kind="review.posted",
            surface=Surface.github,
            payload={"threads": {str(changed.id): "THREAD-1"}},
        )
    )
    db.flush()

    github.files[("app/api/charges.py", "aftersha789")] = "result = safe_eval(request)\n"
    github.files[("app/api/refunds.py", "aftersha789")] = (
        "header = 1\ndigest = hashlib.md5(payload).hexdigest()\n"
    )

    body = json.dumps(push_payload()).encode()
    response = await client.post(
        "/api/github/webhooks", content=body, headers=webhook_headers(body, event="push")
    )
    assert response.status_code == 200
    assert response.json()["auto_resolved"] == 1

    db.refresh(changed)
    db.refresh(unchanged)
    assert changed.state is FindingState.fixed
    assert unchanged.state is FindingState.open
    assert changed.triaged_at is not None

    event = db.scalars(select(Event).where(Event.kind == "finding.auto_resolved")).one()
    assert event.payload["reason"] == "line_changed_or_removed"
    assert event.surface.value == "github"
    github.assert_called_once_with(
        "resolve_review_thread",
        installation_token="ghs_cached_installation_token",
        thread_id="THREAD-1",
    )


async def test_push_leaves_unchanged_findings_open(
    client: httpx.AsyncClient, db: Session, github: FakeGitHubClient
) -> None:
    ws = make_workspace(db)
    github_installation(db, ws)
    finding = make_finding(db, ws, start_line=1, snippet='result = eval(request.args["expr"])')
    github.files[("app/api/charges.py", "aftersha789")] = 'result = eval(request.args["expr"])\n'
    body = json.dumps(push_payload()).encode()
    response = await client.post(
        "/api/github/webhooks", content=body, headers=webhook_headers(body, event="push")
    )
    assert response.status_code == 200
    assert response.json()["auto_resolved"] == 0
    db.refresh(finding)
    assert finding.state is FindingState.open


async def test_push_resolves_when_file_removed(
    client: httpx.AsyncClient, db: Session, github: FakeGitHubClient
) -> None:
    ws = make_workspace(db)
    github_installation(db, ws)
    finding = make_finding(db, ws, start_line=1)
    github.files[("app/api/charges.py", "aftersha789")] = None
    body = json.dumps(push_payload()).encode()
    response = await client.post(
        "/api/github/webhooks", content=body, headers=webhook_headers(body, event="push")
    )
    assert response.json()["auto_resolved"] == 1
    db.refresh(finding)
    assert finding.state is FindingState.fixed


async def test_unknown_installation_is_404(client: httpx.AsyncClient, db: Session) -> None:
    body = json.dumps(pr_payload()).encode()
    response = await client.post(
        "/api/github/webhooks", content=body, headers=webhook_headers(body)
    )
    assert response.status_code == 404


def test_fingerprint_normalizes_whitespace() -> None:
    assert normalize_line("  result =  eval(x)\t") == "result = eval(x)"
    assert fingerprint_line("a = 1") == fingerprint_line("  a = 1\n")
    assert fingerprint_line("a = 1") != fingerprint_line("a = 2")


def test_inline_comment_shape(db: Session) -> None:
    ws = make_workspace(db)
    finding = make_finding(db, ws, start_line=31)
    comment = inline_comment(finding)
    assert comment["path"] == "app/api/charges.py"
    assert comment["line"] == 31
    assert comment["side"] == "RIGHT"
    assert comment["body"].startswith("**HIGH**")


def test_app_jwt_is_signed_with_rs256() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    token = build_app_jwt("12345", pem)
    claims = jwt.decode(
        token,
        key.public_key(),
        algorithms=["RS256"],
        options={"verify_iss": False},
    )
    assert claims["iss"] == "12345"
    assert claims["exp"] > claims["iat"]


def test_installation_token_cache_reuses_token(github: FakeGitHubClient) -> None:
    cache = InstallationTokenCache()
    token = cache.get(github, INSTALLATION_ID)
    assert token == "ghs_cached_installation_token"
    again = cache.get(github, INSTALLATION_ID)
    assert again == token
    assert len(github.calls_for("create_installation_token")) == 1
