"""Small shared utilities with no third-party dependencies."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: Path, chunk_size: int = 1_048_576) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def ip_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_global:
        return "global"
    return "special"


def counter_rows(
    counter: Counter[Any], limit: int = 20, key_name: str = "value"
) -> list[dict[str, Any]]:
    return [{key_name: str(key), "count": count} for key, count in counter.most_common(limit)]


def printable_preview(data: bytes, limit: int) -> str:
    return "".join(
        chr(byte) if 32 <= byte <= 126 or byte in (9, 10, 13) else "."
        for byte in data[:limit]
    )
