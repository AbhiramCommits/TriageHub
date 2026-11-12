"""Opaque cursor encoding for keyset pagination."""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime


class InvalidCursor(ValueError):
    pass


def encode_cursor(ts: datetime, row_id: uuid.UUID) -> str:
    raw = json.dumps({"t": ts.isoformat(), "id": str(row_id)}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return datetime.fromisoformat(raw["t"]), uuid.UUID(raw["id"])
    except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise InvalidCursor("malformed cursor") from exc
