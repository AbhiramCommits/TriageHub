"""Line fingerprinting used to detect when a finding's source line changed."""

from __future__ import annotations

import hashlib
import re

_WHITESPACE = re.compile(r"\s+")


def normalize_line(line: str) -> str:
    """Normalize an offending source line before hashing.

    Leading/trailing whitespace and internal whitespace runs are collapsed so
    that reformatting alone does not look like a code change.
    """
    return _WHITESPACE.sub(" ", line.strip())


def fingerprint_line(line: str) -> str:
    return hashlib.sha256(normalize_line(line).encode("utf-8")).hexdigest()
