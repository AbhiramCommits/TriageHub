"""GitHub App authentication: app JWT and cached installation tokens."""

from __future__ import annotations

import threading
import time
from typing import Any

import jwt

from app.clients.base import GitHubClient
from app.config import settings


class AppAuthError(RuntimeError):
    pass


def build_app_jwt(
    app_id: str | None = None, private_key: str | None = None, now: int | None = None
) -> str:
    key = private_key if private_key is not None else settings.github_private_key
    if not key:
        raise AppAuthError("GITHUB_PRIVATE_KEY is not configured")
    key = key.replace("\\n", "\n")
    issued = int(time.time()) if now is None else now
    payload = {"iat": issued - 60, "exp": issued + 9 * 60, "iss": app_id or settings.github_app_id}
    encoded: str = jwt.encode(payload, key, algorithm="RS256")
    return encoded


class InstallationTokenCache:
    """Caches installation access tokens until 60 seconds before expiry."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def get(
        self,
        client: GitHubClient,
        installation_id: str,
        *,
        now: int | None = None,
        app_id: str | None = None,
        private_key: str | None = None,
    ) -> str:
        current = int(time.time()) if now is None else now
        with self._lock:
            cached = self._cache.get(installation_id)
            if cached is not None and cached[1] - 60 > current:
                return cached[0]
        app_jwt = build_app_jwt(app_id=app_id, private_key=private_key, now=current)
        body: dict[str, Any] = client.create_installation_token(app_jwt, installation_id)
        token = str(body.get("token", ""))
        if not token:
            raise AppAuthError("GitHub returned no installation token")
        expires_at = int(time.time()) + 3600
        raw_expiry = body.get("expires_at")
        if isinstance(raw_expiry, str):
            try:
                from datetime import datetime

                expires_at = int(
                    datetime.fromisoformat(raw_expiry.replace("Z", "+00:00")).timestamp()
                )
            except ValueError:
                expires_at = current + 3600
        with self._lock:
            self._cache[installation_id] = (token, expires_at)
        return token

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


installation_token_cache = InstallationTokenCache()
