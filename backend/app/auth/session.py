"""Signed HttpOnly session cookies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from fastapi import Response

from app.config import settings


class SessionError(Exception):
    pass


@dataclass(frozen=True)
class SessionData:
    user_id: uuid.UUID
    workspace_id: uuid.UUID
    expires_at: int


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: bytes) -> bytes:
    return hmac.new(
        settings.session_secret.encode(), b"session:" + payload, hashlib.sha256
    ).digest()


def issue_session(user_id: uuid.UUID, workspace_id: uuid.UUID) -> str:
    now = int(time.time())
    payload = json.dumps(
        {
            "sub": str(user_id),
            "ws": str(workspace_id),
            "iat": now,
            "exp": now + settings.session_ttl_seconds,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"{_b64encode(payload)}.{_b64encode(_sign(payload))}"


def read_session(token: str) -> SessionData:
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = _b64decode(payload_b64)
        signature = _b64decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise SessionError("malformed session cookie") from exc
    if not hmac.compare_digest(signature, _sign(payload)):
        raise SessionError("bad session signature")
    try:
        data = json.loads(payload)
        session = SessionData(
            user_id=uuid.UUID(str(data["sub"])),
            workspace_id=uuid.UUID(str(data["ws"])),
            expires_at=int(data["exp"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionError("malformed session claims") from exc
    if session.expires_at <= int(time.time()):
        raise SessionError("session expired")
    return session


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.env == "production",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(settings.session_cookie_name, path="/")
