"""Real httpx/Authlib implementations of the provider client protocols."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlencode

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.jose import JsonWebKey, JsonWebToken

from app.clients.base import IdTokenClaims, OAuthTokens
from app.config import settings

TIMEOUT = httpx.Timeout(15.0)


class ProviderHTTPError(RuntimeError):
    pass


def _raise_for_status(response: httpx.Response, provider: str) -> None:
    if response.status_code >= 400:
        raise ProviderHTTPError(f"{provider} returned HTTP {response.status_code}")


class HttpSlackClient:
    def __init__(self, http: httpx.Client | None = None, bot_token: str | None = None) -> None:
        self._http = http or httpx.Client(timeout=TIMEOUT)
        self._bot_token = settings.slack_bot_token if bot_token is None else bot_token

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        query = urlencode(
            {
                "client_id": settings.slack_client_id,
                "scope": settings.slack_scopes,
                "redirect_uri": redirect_uri,
                "state": state,
            }
        )
        return f"{settings.slack_authorize_url}?{query}"

    def exchange_code(
        self, code: str, redirect_uri: str, extra: Mapping[str, str] | None = None
    ) -> OAuthTokens:
        response = self._http.post(
            settings.slack_token_url,
            data={
                "client_id": settings.slack_client_id,
                "client_secret": settings.slack_client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        _raise_for_status(response, "slack")
        body = response.json()
        if not body.get("ok", False):
            raise ProviderHTTPError(f"slack token exchange failed: {body.get('error')}")
        team = body.get("team") or {}
        return OAuthTokens(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token"),
            expires_in=body.get("expires_in"),
            scope=body.get("scope"),
            external_id=str(team.get("id") or body.get("team_id") or ""),
            raw=body,
        )

    def refresh(self, refresh_token: str) -> OAuthTokens:
        response = self._http.post(
            settings.slack_token_url,
            data={
                "client_id": settings.slack_client_id,
                "client_secret": settings.slack_client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        _raise_for_status(response, "slack")
        body = response.json()
        if not body.get("ok", False):
            raise ProviderHTTPError(f"slack refresh failed: {body.get('error')}")
        team = body.get("team") or {}
        return OAuthTokens(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token"),
            expires_in=body.get("expires_in"),
            scope=body.get("scope"),
            external_id=str(team.get("id") or ""),
            raw=body,
        )

    def post_message(
        self,
        channel: str,
        text: str,
        *,
        thread_ts: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": channel, "text": text}
        if thread_ts:
            payload["thread_ts"] = thread_ts
        if blocks:
            payload["blocks"] = blocks
        response = self._http.post(
            f"{settings.slack_api_base}/chat.postMessage",
            headers={"Authorization": f"Bearer {self._bot_token}"},
            json=payload,
        )
        _raise_for_status(response, "slack")
        body: dict[str, Any] = response.json()
        if not body.get("ok", False):
            raise ProviderHTTPError(f"slack postMessage failed: {body.get('error')}")
        return body


class HttpGitHubClient:
    def __init__(self, http: httpx.Client | None = None) -> None:
        self._http = http or httpx.Client(timeout=TIMEOUT)

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        query = urlencode(
            {"client_id": settings.github_client_id, "redirect_uri": redirect_uri, "state": state}
        )
        return f"{settings.github_authorize_url}?{query}"

    def exchange_code(
        self, code: str, redirect_uri: str, extra: Mapping[str, str] | None = None
    ) -> OAuthTokens:
        response = self._http.post(
            settings.github_token_url,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        _raise_for_status(response, "github")
        body = response.json()
        return OAuthTokens(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token"),
            expires_in=body.get("expires_in"),
            scope=body.get("scope"),
            external_id=str((extra or {}).get("installation_id", "")),
            raw=body,
        )

    def refresh(self, refresh_token: str) -> OAuthTokens:
        response = self._http.post(
            settings.github_token_url,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        _raise_for_status(response, "github")
        body = response.json()
        return OAuthTokens(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token"),
            expires_in=body.get("expires_in"),
            scope=body.get("scope"),
            raw=body,
        )

    @staticmethod
    def _headers(installation_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {installation_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def post_review(
        self,
        installation_token: str,
        repo: str,
        pr_number: int,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        response = self._http.post(
            f"{settings.github_api_base}/repos/{repo}/pulls/{pr_number}/reviews",
            headers=self._headers(installation_token),
            json={"commit_id": commit_id, "body": body, "event": "COMMENT", "comments": comments},
        )
        _raise_for_status(response, "github")
        return cast(dict[str, Any], response.json())

    def resolve_review_thread(self, installation_token: str, thread_id: str) -> dict[str, Any]:
        query = """
        mutation Resolve($threadId: ID!) {
          resolveReviewThread(input: {threadId: $threadId}) {
            thread { id isResolved }
          }
        }
        """
        response = self._http.post(
            f"{settings.github_api_base}/graphql",
            headers=self._headers(installation_token),
            json={"query": query, "variables": {"threadId": thread_id}},
        )
        _raise_for_status(response, "github")
        return cast(dict[str, Any], response.json())

    def compare_commits(
        self, installation_token: str, repo: str, base_sha: str, head_sha: str
    ) -> dict[str, Any]:
        response = self._http.get(
            f"{settings.github_api_base}/repos/{repo}/compare/{base_sha}...{head_sha}",
            headers=self._headers(installation_token),
        )
        _raise_for_status(response, "github")
        return cast(dict[str, Any], response.json())


class HttpOIDCProvider:
    def __init__(self, http: httpx.Client | None = None) -> None:
        self._http = http or httpx.Client(timeout=TIMEOUT)

    def _client(self) -> OAuth2Client:
        return OAuth2Client(
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            redirect_uri=settings.oidc_redirect_uri,
        )

    def authorize_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: str,
    ) -> str:
        client = self._client()
        uri, _state = client.create_authorization_url(
            settings.oidc_authorize_url,
            state=state,
            nonce=nonce,
            scope=scopes,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            redirect_uri=redirect_uri,
        )
        return str(uri)

    def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        client = self._client()
        token: dict[str, Any] = client.fetch_token(
            settings.oidc_token_url,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            grant_type="authorization_code",
        )
        return token

    def validate_id_token(self, id_token: str, *, nonce: str) -> IdTokenClaims:
        jwks_response = self._http.get(settings.oidc_jwks_url)
        _raise_for_status(jwks_response, "oidc")
        key_set = JsonWebKey.import_key_set(jwks_response.json())
        jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"])
        claims = jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": settings.oidc_issuer},
                "aud": {"essential": True, "value": settings.oidc_client_id},
            },
        )
        claims.validate(now=int(time.time()), leeway=0)
        if claims.get("nonce") != nonce:
            raise ValueError("ID token nonce does not match the login request")
        audience = claims.get("aud")
        if isinstance(audience, list):
            audience = audience[0]
        return IdTokenClaims(
            subject=str(claims.get("sub")),
            email=str(claims.get("email")),
            email_verified=bool(claims.get("email_verified", False)),
            issuer=str(claims.get("iss")),
            audience=str(audience),
            nonce=str(claims.get("nonce")),
            expires_at=int(claims.get("exp", 0)),
            name=str(claims.get("name", "")),
        )
