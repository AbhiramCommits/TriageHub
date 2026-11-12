"""Recording fakes for every external provider, used by the test suite.

No test performs network I/O: the app's dependency overrides hand these objects
to the routers instead of the httpx-backed clients. Each fake records the exact
arguments it received so assertions can pin the request body.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlencode

from app.clients.base import IdTokenClaims, OAuthTokens


@dataclass(frozen=True)
class Call:
    method: str
    args: dict[str, Any]


class RecordingFake:
    def __init__(self) -> None:
        self.calls: list[Call] = []

    def _record(self, method: str, args: dict[str, Any]) -> None:
        self.calls.append(Call(method, args))

    def calls_for(self, method: str) -> list[dict[str, Any]]:
        return [c.args for c in self.calls if c.method == method]

    def assert_called(self, method: str) -> None:
        assert self.calls_for(method), f"{method} was not called"

    def assert_called_once_with(self, method: str, **expected: Any) -> None:
        matches = [a for a in self.calls_for(method) if a == expected]
        recorded = self.calls_for(method)
        assert (
            len(matches) == 1
        ), f"expected exactly one {method} call with {expected!r}; recorded {recorded!r}"


class FakeSlackClient(RecordingFake):
    def __init__(
        self,
        tokens: OAuthTokens | None = None,
        refreshed: OAuthTokens | None = None,
    ) -> None:
        super().__init__()
        self.tokens = tokens or OAuthTokens(
            access_token="xoxb-test-access",
            refresh_token="xoxe-test-refresh",
            expires_in=3600,
            scope="commands,chat:write",
            external_id="T0TESTTEAM",
        )
        self.refreshed = refreshed or OAuthTokens(
            access_token="xoxb-rotated-access",
            refresh_token="xoxe-rotated-refresh",
            expires_in=3600,
            scope="commands,chat:write",
            external_id="T0TESTTEAM",
        )
        self.messages: list[dict[str, Any]] = []

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        self._record("authorize_url", {"state": state, "redirect_uri": redirect_uri})
        return "https://slack.test/authorize?" + urlencode(
            {"state": state, "redirect_uri": redirect_uri}
        )

    def exchange_code(
        self, code: str, redirect_uri: str, extra: Mapping[str, str] | None = None
    ) -> OAuthTokens:
        self._record(
            "exchange_code",
            {"code": code, "redirect_uri": redirect_uri, "extra": dict(extra or {})},
        )
        return self.tokens

    def refresh(self, refresh_token: str) -> OAuthTokens:
        self._record("refresh", {"refresh_token": refresh_token})
        return self.refreshed

    def post_message(
        self,
        channel: str,
        text: str,
        *,
        thread_ts: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"channel": channel, "text": text}
        if thread_ts is not None:
            args["thread_ts"] = thread_ts
        if blocks is not None:
            args["blocks"] = blocks
        self._record("post_message", args)
        self.messages.append(args)
        return {"ok": True, "ts": "1700000000.000100", "channel": channel}


class FakeGitHubClient(RecordingFake):
    def __init__(
        self,
        tokens: OAuthTokens | None = None,
        refreshed: OAuthTokens | None = None,
    ) -> None:
        super().__init__()
        self.tokens = tokens or OAuthTokens(
            access_token="ghs_test_installation_token",
            refresh_token="ghr_test_refresh",
            expires_in=3600,
            scope="repo",
            external_id="4242",
        )
        self.refreshed = refreshed or OAuthTokens(
            access_token="ghs_rotated_token",
            refresh_token="ghr_rotated_refresh",
            expires_in=3600,
            scope="repo",
            external_id="4242",
        )
        self.reviews: list[dict[str, Any]] = []

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        self._record("authorize_url", {"state": state, "redirect_uri": redirect_uri})
        return "https://github.test/authorize?" + urlencode(
            {"state": state, "redirect_uri": redirect_uri}
        )

    def exchange_code(
        self, code: str, redirect_uri: str, extra: Mapping[str, str] | None = None
    ) -> OAuthTokens:
        self._record(
            "exchange_code",
            {"code": code, "redirect_uri": redirect_uri, "extra": dict(extra or {})},
        )
        return self.tokens

    def refresh(self, refresh_token: str) -> OAuthTokens:
        self._record("refresh", {"refresh_token": refresh_token})
        return self.refreshed

    def post_review(
        self,
        installation_token: str,
        repo: str,
        pr_number: int,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        args = {
            "installation_token": installation_token,
            "repo": repo,
            "pr_number": pr_number,
            "commit_id": commit_id,
            "body": body,
            "comments": comments,
        }
        self._record("post_review", args)
        self.reviews.append(args)
        return {"id": 9001, "state": "COMMENTED", "comments": len(comments)}

    def resolve_review_thread(self, installation_token: str, thread_id: str) -> dict[str, Any]:
        self._record(
            "resolve_review_thread",
            {"installation_token": installation_token, "thread_id": thread_id},
        )
        return {"data": {"resolveReviewThread": {"thread": {"id": thread_id, "isResolved": True}}}}

    def compare_commits(
        self, installation_token: str, repo: str, base_sha: str, head_sha: str
    ) -> dict[str, Any]:
        self._record(
            "compare_commits",
            {
                "installation_token": installation_token,
                "repo": repo,
                "base_sha": base_sha,
                "head_sha": head_sha,
            },
        )
        return {"files": []}


class FakeOIDCProvider(RecordingFake):
    """Fake IdP that mimics PKCE/nonce/issuer/audience/expiry validation."""

    def __init__(self, claims: IdTokenClaims | None = None, expected_issuer: str = "") -> None:
        super().__init__()
        self.claims = claims or IdTokenClaims(
            subject="idp|ada",
            email="ada@acme.test",
            email_verified=True,
            issuer=expected_issuer or "https://idp.example.com",
            audience="triagehub",
            nonce="",
            expires_at=int(time.time()) + 600,
            name="Ada Lovelace",
        )
        self.expected_issuer = expected_issuer or self.claims.issuer
        self.expected_audience = "triagehub"
        self.last_nonce: str | None = None

    def authorize_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: str,
    ) -> str:
        self.last_nonce = nonce
        self._record(
            "authorize_url",
            {
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "redirect_uri": redirect_uri,
                "scopes": scopes,
            },
        )
        return "https://idp.test/authorize?" + urlencode(
            {
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "redirect_uri": redirect_uri,
                "scope": scopes,
            }
        )

    def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        self._record(
            "exchange_code",
            {"code": code, "code_verifier": code_verifier, "redirect_uri": redirect_uri},
        )
        return {
            "access_token": "oidc-access-token",
            "id_token": "fake.id.token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    def validate_id_token(self, id_token: str, *, nonce: str) -> IdTokenClaims:
        self._record("validate_id_token", {"id_token": id_token, "nonce": nonce})
        now = int(time.time())
        if id_token != "fake.id.token":
            raise ValueError("unexpected ID token")
        if nonce != self.last_nonce:
            raise ValueError("ID token nonce does not match the login request")
        if self.claims.issuer != self.expected_issuer:
            raise ValueError("unexpected issuer")
        if self.claims.audience != self.expected_audience:
            raise ValueError("unexpected audience")
        if self.claims.expires_at <= now:
            raise ValueError("ID token has expired")
        return replace(self.claims, nonce=nonce)
