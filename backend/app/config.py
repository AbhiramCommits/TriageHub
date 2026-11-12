"""Application configuration loaded from environment variables."""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore"
    )

    env: str = "development"
    app_base_url: str = "http://localhost:8000"
    console_url: str = "http://localhost:5173"
    database_url: str = "postgresql+psycopg://triagehub:triagehub@localhost:5432/triagehub"

    # Session / signing
    session_secret: str = "dev-session-secret-change-me"
    session_cookie_name: str = "triagehub_session"
    session_ttl_seconds: int = 60 * 60 * 12

    # OAuth state
    state_secret: str = "dev-state-secret-change-me"
    state_ttl_seconds: int = 60 * 10

    # Token encryption: a urlsafe base64-encoded 32-byte Fernet key.
    token_encryption_key: str = ""

    # Slack
    slack_client_id: str = "dev-slack-client-id"
    slack_client_secret: str = "dev-slack-client-secret"
    slack_signing_secret: str = "dev-slack-signing-secret"
    slack_redirect_uri: str = "http://localhost:8000/api/oauth/slack/callback"
    slack_scopes: str = "commands,chat:write,users:read"
    slack_bot_token: str = ""
    slack_authorize_url: str = "https://slack.com/oauth/v2/authorize"
    slack_token_url: str = "https://slack.com/api/oauth.v2.access"
    slack_api_base: str = "https://slack.com/api"

    # GitHub App
    github_app_id: str = "0"
    github_client_id: str = "dev-github-client-id"
    github_client_secret: str = "dev-github-client-secret"
    github_redirect_uri: str = "http://localhost:8000/api/oauth/github/callback"
    github_webhook_secret: str = "dev-github-webhook-secret"
    github_private_key: str = ""
    github_api_base: str = "https://api.github.com"
    github_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_token_url: str = "https://github.com/login/oauth/access_token"

    # OIDC identity provider (SSO)
    oidc_issuer: str = "https://idp.example.com"
    oidc_client_id: str = "triagehub"
    oidc_client_secret: str = "dev-oidc-client-secret"
    oidc_redirect_uri: str = "http://localhost:8000/api/auth/sso/callback"
    oidc_authorize_url: str = "https://idp.example.com/oauth2/authorize"
    oidc_token_url: str = "https://idp.example.com/oauth2/token"
    oidc_jwks_url: str = "https://idp.example.com/.well-known/jwks.json"
    oidc_scopes: str = "openid email profile"

    @property
    def fernet_key(self) -> bytes:
        """Return a valid Fernet key, deriving one deterministically in dev if unset."""
        if self.token_encryption_key:
            return self.token_encryption_key.encode()
        digest = hashlib.sha256(self.session_secret.encode()).digest()
        return base64.urlsafe_b64encode(digest)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
