"""Bounded, non-executing representation transforms for selected values."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

from .models import MAX_DECODE_INPUT


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
