"""Fernet wrapper for encrypting provider tokens at rest."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class TokenDecryptionError(Exception):
    pass


def _fernet() -> Fernet:
    return Fernet(settings.fernet_key)


def encrypt_token(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("refusing to encrypt an empty token")
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise TokenDecryptionError("token could not be decrypted with the configured key") from exc
