"""Dependency providers for the external clients (overridden in tests)."""

from __future__ import annotations

from app.clients.base import GitHubClient, OIDCProvider, SlackClient
from app.clients.http import HttpGitHubClient, HttpOIDCProvider, HttpSlackClient


def get_slack_client() -> SlackClient:
    return HttpSlackClient()


def get_github_client() -> GitHubClient:
    return HttpGitHubClient()


def get_oidc_provider() -> OIDCProvider:
    return HttpOIDCProvider()
