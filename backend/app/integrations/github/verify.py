"""GitHub webhook X-Hub-Signature-256 verification."""

from __future__ import annotations

import hashlib
import hmac

from app.config import settings


def expected_signature(payload: bytes, secret: str | None = None) -> str:
    return (
        "sha256="
        + hmac.new(
            (secret or settings.github_webhook_secret).encode(), payload, hashlib.sha256
        ).hexdigest()
    )


def verify_github_signature(
    payload: bytes, signature: str | None, secret: str | None = None
) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(expected_signature(payload, secret), signature)
