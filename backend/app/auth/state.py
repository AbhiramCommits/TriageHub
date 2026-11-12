"""Signed, TTL-stamped OAuth state tokens with replay protection."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Protocol, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ConsumedNonce


class StateError(Exception):
    """Base class for all state token failures."""


class MalformedState(StateError):
    pass


class BadSignature(StateError):
    pass


class ExpiredState(StateError):
    pass


class ReplayedState(StateError):
    pass


@dataclass(frozen=True)
class StateClaims:
    workspace_id: str
    provider: str
    nonce: str
    issued_at: int
    expires_at: int


class NonceStore(Protocol):
    def consume(self, nonce: str, expires_at: int) -> None:
        """Record a nonce, raising ReplayedState if it was already consumed."""


class InMemoryNonceStore:
    """Process-local nonce store; tests use a fresh instance per case."""

    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}

    def consume(self, nonce: str, expires_at: int) -> None:
        now = int(time.time())
        for key, exp in list(self._consumed.items()):
            if exp < now:
                del self._consumed[key]
        if nonce in self._consumed:
            raise ReplayedState("state token already used")
        self._consumed[nonce] = expires_at


class SqlNonceStore:
    """Database-backed nonce store shared by all API workers."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def consume(self, nonce: str, expires_at: int) -> None:
        with self._db.begin_nested():
            existing = self._db.scalars(
                select(ConsumedNonce).where(ConsumedNonce.nonce == nonce)
            ).first()
            if existing is not None:
                raise ReplayedState("state token already used")
            try:
                self._db.add(ConsumedNonce(nonce=nonce))
                self._db.flush()
            except IntegrityError as exc:
                raise ReplayedState("state token already used") from exc


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: bytes) -> bytes:
    return hmac.new(settings.state_secret.encode(), payload, hashlib.sha256).digest()


def issue_state(
    workspace_id: str,
    provider: str,
    nonce: str,
    ttl_seconds: int | None = None,
) -> str:
    if not workspace_id or not provider or not nonce:
        raise ValueError("workspace_id, provider and nonce are required")
    now = int(time.time())
    ttl = settings.state_ttl_seconds if ttl_seconds is None else ttl_seconds
    payload = json.dumps(
        {
            "workspace_id": workspace_id,
            "provider": provider,
            "nonce": nonce,
            "iat": now,
            "exp": now + ttl,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"{_b64encode(payload)}.{_b64encode(_sign(payload))}"


def _verify_signature(token: str) -> tuple[bytes, dict[str, object]]:
    try:
        payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise MalformedState("state token is not in payload.signature form") from exc
    try:
        payload = _b64decode(payload_b64)
        signature = _b64decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise MalformedState("state token is not valid base64") from exc
    if not hmac.compare_digest(signature, _sign(payload)):
        raise BadSignature("state token signature does not match")
    try:
        claims = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise MalformedState("state token payload is not JSON") from exc
    if not isinstance(claims, dict):
        raise MalformedState("state token payload is not an object")
    return payload, cast(dict[str, object], claims)


def verify_state(
    token: str, store: NonceStore | None = None, now: int | None = None
) -> StateClaims:
    """Verify signature, expiry and single-use nonce, in that order."""
    _, raw = _verify_signature(token)
    try:
        claims = StateClaims(
            workspace_id=str(raw["workspace_id"]),
            provider=str(raw["provider"]),
            nonce=str(raw["nonce"]),
            issued_at=int(cast(int | str, raw["iat"])),
            expires_at=int(cast(int | str, raw["exp"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MalformedState("state token is missing required claims") from exc

    current = int(time.time()) if now is None else now
    if claims.expires_at <= current:
        raise ExpiredState("state token has expired")

    (store or _DEFAULT_STORE).consume(claims.nonce, claims.expires_at)
    return claims


_DEFAULT_STORE = InMemoryNonceStore()
