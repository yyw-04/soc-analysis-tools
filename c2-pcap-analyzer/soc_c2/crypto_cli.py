"""Command-line interface for offline C2 decryption helpers."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .crypto import aes_cbc_decrypt, rsa_decrypt, verify_hmac
from .transforms import decode_value
from .utils import printable_preview


MAX_BLOB_BYTES = 16 * 1024 * 1024


def _add_blob_arguments(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--value", help="Encoded ciphertext supplied directly")
    source.add_argument("--input-file", type=Path, help="File containing raw or encoded ciphertext")
    parser.add_argument(
        "--encoding",
        choices=("raw", "auto", "base64", "base64url", "hex", "url"),
        default="base64",
        help="Representation of the selected ciphertext",
    )
    parser.add_argument("--preview-bytes", type=int, default=256)


def _load_blob(args: argparse.Namespace) -> bytes:
    if args.value is not None:
        decoded = decode_value(args.value, args.encoding)
    else:
        input_path = args.input_file.expanduser().resolve(strict=True)
        if not input_path.is_file():
            raise ValueError(f"Input is not a file: {input_path}")
        if input_path.stat().st_size > MAX_BLOB_BYTES:
            raise ValueError("Input file exceeds the 16 MiB safety limit")
        if args.encoding == "raw":
            decoded = input_path.read_bytes()
        else:
            decoded = decode_value(input_path.read_text(encoding="utf-8"), args.encoding)
    if len(decoded) > MAX_BLOB_BYTES:
        raise ValueError("Decoded ciphertext exceeds the 16 MiB safety limit")
    return decoded


def _hex_value(value: str, name: str) -> bytes:
    try:
        result = bytes.fromhex("".join(value.split()))
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hexadecimal") from exc
    if not result:
        raise ValueError(f"{name} must not be empty")
    return result


def _print_preview(plaintext: bytes, limit: int) -> None:
    if not 1 <= limit <= 4096:
        raise ValueError("--preview-bytes must be between 1 and 4096")
    preview = plaintext[:limit]
    print(f"Decrypted length: {len(plaintext)} bytes")
    print(f"Hex preview: {preview.hex()}")
    print("Printable preview:")
    print(printable_preview(plaintext, limit))
    if len(plaintext) > limit:
        print(f"Preview truncated at {limit} bytes.")
    print("Safety: plaintext was displayed only; no payload was executed or written to disk.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline RSA/AES/HMAC helper for authorized defensive analysis. "
            "Requires exact analyst-supplied keys and layout."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    aes = subparsers.add_parser("aes-cbc", help="Verify optional HMAC, then decrypt AES-CBC")
    _add_blob_arguments(aes)
    aes.add_argument("--key-hex", required=True, help="16, 24, or 32-byte AES key in hex")
    aes.add_argument("--iv-hex", required=True, help="Exactly 16-byte CBC IV in hex")
    aes.add_argument("--no-unpad", action="store_true", help="Do not remove PKCS7 padding")
    aes.add_argument("--hmac-key-hex", help="Optional HMAC key in hex")
    aes.add_argument("--hmac-tag-hex", help="Expected full or truncated HMAC tag in hex")
    aes.add_argument(
        "--hmac-algorithm",
        choices=("sha1", "sha256", "sha384", "sha512"),
        default="sha256",
    )
    aes.add_argument(
        "--hmac-input",
        choices=("ciphertext", "iv-ciphertext"),
        default="ciphertext",
        help="Exact bytes covered by the supplied HMAC tag",
    )

    rsa = subparsers.add_parser("rsa", help="Decrypt one RSA ciphertext from an extracted field")
    _add_blob_arguments(rsa)
    rsa.add_argument("--private-key", type=Path, required=True)
    rsa.add_argument(
        "--padding",
        choices=("oaep-sha256", "pkcs1v15"),
        default="oaep-sha256",
        help="Use PKCS1v15 only when the protocol or lab explicitly requires it",
    )
    rsa.add_argument(
        "--key-password-env",
        help="Environment variable containing the PEM password; avoids placing it in command history",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ciphertext = _load_blob(args)
        if args.command == "aes-cbc":
            key = _hex_value(args.key_hex, "AES key")
            iv = _hex_value(args.iv_hex, "IV")
            if bool(args.hmac_key_hex) != bool(args.hmac_tag_hex):
                raise ValueError("Provide both --hmac-key-hex and --hmac-tag-hex, or neither")
            if args.hmac_key_hex:
                hmac_key = _hex_value(args.hmac_key_hex, "HMAC key")
                hmac_tag = _hex_value(args.hmac_tag_hex, "HMAC tag")
                authenticated = ciphertext if args.hmac_input == "ciphertext" else iv + ciphertext
                if not verify_hmac(authenticated, hmac_key, hmac_tag, args.hmac_algorithm):
                    raise ValueError("HMAC verification failed; decryption was not attempted")
                print("HMAC verification: passed")
            plaintext = aes_cbc_decrypt(ciphertext, key, iv, unpad=not args.no_unpad)
        else:
            password = None
            if args.key_password_env:
                password_text = os.environ.get(args.key_password_env)
                if password_text is None:
                    raise ValueError(
                        f"Environment variable {args.key_password_env!r} is not set"
                    )
                password = password_text.encode("utf-8")
            plaintext = rsa_decrypt(
                ciphertext,
                args.private_key,
                padding_mode=args.padding,
                password=password,
            )
        _print_preview(plaintext, args.preview_bytes)
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
