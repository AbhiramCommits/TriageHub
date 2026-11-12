from __future__ import annotations

import time

import pytest

from app.auth.state import (
    BadSignature,
    ExpiredState,
    InMemoryNonceStore,
    MalformedState,
    ReplayedState,
    issue_state,
    verify_state,
)
from app.config import settings


def test_valid_state_roundtrip() -> None:
    token = issue_state("ws-1", "slack", "nonce-1")
    claims = verify_state(token, InMemoryNonceStore())
    assert claims.workspace_id == "ws-1"
    assert claims.provider == "slack"
    assert claims.nonce == "nonce-1"
    assert claims.expires_at > int(time.time())


def test_bad_signature_rejected() -> None:
    token = issue_state("ws-1", "slack", "nonce-1")
    payload, signature = token.split(".")
    tampered = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + signature
    with pytest.raises(BadSignature):
        verify_state(tampered, InMemoryNonceStore())


def test_expired_state_rejected() -> None:
    token = issue_state("ws-1", "slack", "nonce-1", ttl_seconds=-1)
    with pytest.raises(ExpiredState):
        verify_state(token, InMemoryNonceStore())


def test_replayed_state_rejected() -> None:
    token = issue_state("ws-1", "slack", "nonce-1")
    store = InMemoryNonceStore()
    verify_state(token, store)
    with pytest.raises(ReplayedState):
        verify_state(token, store)


def test_malformed_state_rejected() -> None:
    with pytest.raises(MalformedState):
        verify_state("not-a-token", InMemoryNonceStore())


def test_state_uses_configured_ttl() -> None:
    token = issue_state("ws-1", "github", "nonce-ttl")
    claims = verify_state(token, InMemoryNonceStore())
    assert claims.expires_at - claims.issued_at == settings.state_ttl_seconds
