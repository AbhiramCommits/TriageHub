from __future__ import annotations

import base64
import json

import httpx

from app.clients.http import HttpGitHubClient, HttpSlackClient
from app.config import settings


def transport(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_slack_authorize_url_contains_state() -> None:
    client = HttpSlackClient(http=transport(lambda request: httpx.Response(200, json={})))
    url = client.authorize_url("state-1", "http://localhost/callback")
    assert url.startswith(settings.slack_authorize_url)
    assert "state=state-1" in url
    assert settings.slack_client_id in url


def test_slack_exchange_and_post_message() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("oauth.v2.access"):
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "access_token": "xoxb-real",
                    "refresh_token": "xoxe-real",
                    "expires_in": 3600,
                    "scope": "commands,chat:write",
                    "team": {"id": "T0REAL"},
                },
            )
        return httpx.Response(200, json={"ok": True, "ts": "1.2"})

    client = HttpSlackClient(http=transport(handler), bot_token="xoxb-bot")
    tokens = client.exchange_code("code-1", "http://localhost/callback")
    assert tokens.access_token == "xoxb-real"
    assert tokens.external_id == "T0REAL"
    assert "code=code-1" in seen[0].content.decode()

    message = client.post_message("C1", "hello", thread_ts="1.1", blocks=[{"type": "section"}])
    assert message["ok"] is True
    posted = json.loads(seen[1].content)
    assert posted == {
        "channel": "C1",
        "text": "hello",
        "thread_ts": "1.1",
        "blocks": [{"type": "section"}],
    }
    assert seen[1].headers["authorization"] == "Bearer xoxb-bot"


def test_github_installation_token_and_contents() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201, json={"token": "ghs-real", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if "/contents/" in request.url.path:
            content = base64.b64encode(b"line one\nline two\n").decode()
            return httpx.Response(200, json={"encoding": "base64", "content": content})
        return httpx.Response(200, json={})

    client = HttpGitHubClient(http=transport(handler))
    token = client.create_installation_token("app-jwt", "77")
    assert token["token"] == "ghs-real"
    assert seen[0].headers["authorization"] == "Bearer app-jwt"

    text = client.get_file_contents("ghs-real", "acme/api", "app/x.py", "sha")
    assert text == "line one\nline two\n"


def test_github_file_not_found_and_review_payload() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "/contents/" in request.url.path:
            return httpx.Response(404, json={"message": "Not Found"})
        if request.url.path.endswith("/reviews"):
            return httpx.Response(200, json={"id": 5, "state": "COMMENTED"})
        if request.url.path.endswith("/graphql"):
            return httpx.Response(200, json={"data": {}})
        return httpx.Response(200, json={"files": []})

    client = HttpGitHubClient(http=transport(handler))
    assert client.get_file_contents("ghs", "acme/api", "gone.py", "sha") is None

    review = client.post_review(
        "ghs",
        "acme/api",
        9,
        "head",
        "body",
        [{"path": "app/x.py", "line": 3, "side": "RIGHT", "body": "hi"}],
    )
    assert review["id"] == 5
    payload = json.loads(seen[1].content)
    assert payload["event"] == "COMMENT"
    assert payload["comments"][0]["side"] == "RIGHT"
    assert seen[1].headers["accept"] == "application/vnd.github+json"

    client.resolve_review_thread("ghs", "thread-1")
    graphql = json.loads(seen[2].content)
    assert graphql["variables"] == {"threadId": "thread-1"}
    assert "resolveReviewThread" in graphql["query"]
