"""Slack request signature verification (v0 scheme)."""

from __future__ import annotations

import hashlib
import hmac
import time

from app.config import settings

MAX_SKEW_SECONDS = 60 * 5


def _expected_signature(timestamp: str, body: bytes, secret: str) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def verify_slack_signature(
    body: bytes,
    timestamp: str | None,
    signature: str | None,
    *,
    now: int | None = None,
    secret: str | None = None,
) -> bool:
    if not timestamp or not signature:
        return False
    try:
        request_age = abs((int(time.time()) if now is None else now) - int(timestamp))
    except ValueError:
        return False
    if request_age > MAX_SKEW_SECONDS:
        return False
    expected = _expected_signature(timestamp, body, secret or settings.slack_signing_secret)
    return hmac.compare_digest(expected, signature)
