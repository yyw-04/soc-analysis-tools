"""Bounded, non-executing representation transforms for selected values."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

from .models import MAX_DECODE_INPUT


_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def identify_encoding(value: str) -> str | None:
    """Identify a likely encoded field using conservative SOC-oriented rules."""

    compact = "".join(value.split())
    if not 8 <= len(compact) <= MAX_DECODE_INPUT:
        return None
    if "%" in value and re.search(r"%[0-9A-Fa-f]{2}", value):
        return "url"
    if len(compact) >= 16 and len(compact) % 2 == 0 and _HEX.fullmatch(compact):
        return "hex"
    if len(compact) >= 12 and _BASE64.fullmatch(compact) and len(compact) % 4 in {0, 2, 3}:
        return "base64"
    if len(compact) >= 12 and _BASE64URL.fullmatch(compact) and len(compact) % 4 in {0, 2, 3}:
        return "base64url"
    return None


def decode_detected_layers(value: str, max_layers: int = 2) -> tuple[bytes, list[str]]:
    """Decode a detected value, including one confirmed URL wrapper.

    Only URL decoding may lead to a second automatic layer. This covers common
    URL-encoded Base64 while avoiding repeated speculative decoding.
    """

    if not 1 <= max_layers <= 3:
        raise ValueError("max_layers must be between 1 and 3")
    current = value
    decoded = b""
    chain: list[str] = []
    for _ in range(max_layers):
        encoding = identify_encoding(current)
        if encoding is None:
            break
        decoded = decode_value(current, encoding)
        chain.append(encoding)
        if encoding != "url":
            break
        try:
            current = decoded.decode("ascii")
        except UnicodeDecodeError:
            break
    return decoded, chain


def decode_value(value: str, encoding: str) -> bytes:
    if len(value.encode("utf-8")) > MAX_DECODE_INPUT:
        raise ValueError(f"Encoded input exceeds {MAX_DECODE_INPUT} bytes")
    compact = "".join(value.split())
    selected = encoding.lower()
    if selected == "raw":
        return value.encode("latin-1")
    if selected == "url":
        return urllib.parse.unquote_to_bytes(value)
    if selected == "hex":
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("Invalid hexadecimal input") from exc
    if selected in {"base64", "base64url"}:
        padding = "=" * (-len(compact) % 4)
        try:
            if selected == "base64url":
                return base64.urlsafe_b64decode(compact + padding)
            return base64.b64decode(compact + padding, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid {selected} input") from exc
    if selected == "auto":
        if "%" in value:
            return decode_value(value, "url")
        if re.fullmatch(r"[0-9a-fA-F]+", compact or "x") and len(compact) % 2 == 0:
            return decode_value(compact, "hex")
        for candidate in ("base64", "base64url"):
            try:
                return decode_value(compact, candidate)
            except ValueError:
                continue
        raise ValueError("Unable to identify encoding; specify --encoding")
    raise ValueError(f"Unsupported encoding: {encoding}")
