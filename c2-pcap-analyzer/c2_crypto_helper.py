#!/usr/bin/env python3
"""Compatibility launcher for optional offline RSA/AES/HMAC analysis."""

from soc_c2.crypto_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
