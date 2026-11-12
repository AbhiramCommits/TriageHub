"""Provider client protocols.

Every external provider call goes through one of these interfaces. Production
code uses the httpx implementations in ``app.clients.http``; tests inject the
recording fakes from ``app.clients.fakes`` via FastAPI dependency overrides.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    external_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IdTokenClaims:
    subject: str
    email: str
    email_verified: bool
    issuer: str
    audience: str
    nonce: str
    expires_at: int
    name: str = ""


class ProviderClient(Protocol):
    def authorize_url(self, state: str, redirect_uri: str) -> str: ...

    def exchange_code(
        self, code: str, redirect_uri: str, extra: Mapping[str, str] | None = None
    ) -> OAuthTokens: ...

    def refresh(self, refresh_token: str) -> OAuthTokens: ...


class SlackClient(ProviderClient, Protocol):
    def post_message(
        self,
        channel: str,
        text: str,
        *,
        thread_ts: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]: ...


class GitHubClient(ProviderClient, Protocol):
    def post_review(
        self,
        installation_token: str,
        repo: str,
        pr_number: int,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]],
    ) -> dict[str, Any]: ...

    def resolve_review_thread(self, installation_token: str, thread_id: str) -> dict[str, Any]: ...

    def compare_commits(
        self, installation_token: str, repo: str, base_sha: str, head_sha: str
    ) -> dict[str, Any]: ...


class OIDCProvider(Protocol):
    def authorize_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: str,
    ) -> str: ...

    def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]: ...

    def validate_id_token(self, id_token: str, *, nonce: str) -> IdTokenClaims: ...
