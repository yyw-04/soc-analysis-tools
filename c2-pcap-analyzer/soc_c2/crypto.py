"""Offline cryptographic primitives for authorized C2 analysis.

These helpers do not identify framework layouts or recover keys automatically;
the analyst must provide the correct algorithm, key, IV/nonce, padding,
authentication tag, and extracted ciphertext.
"""

from __future__ import annotations

import hmac as stdlib_hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def _hash_algorithm(name: str):
    choices = {
        "sha1": hashes.SHA1,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    try:
        return choices[name.lower()]()
    except KeyError as exc:
        raise ValueError(f"Unsupported HMAC algorithm: {name}") from exc


def verify_hmac(data: bytes, key: bytes, tag: bytes, algorithm: str = "sha256") -> bool:
    """Verify a full or explicitly truncated HMAC tag in constant time."""

    if not key:
        raise ValueError("HMAC key must not be empty")
    if not tag:
        raise ValueError("HMAC tag must not be empty")
    context = hmac.HMAC(key, _hash_algorithm(algorithm))
    context.update(data)
    calculated = context.finalize()
    if len(tag) > len(calculated):
        return False
    return stdlib_hmac.compare_digest(calculated[: len(tag)], tag)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, *, unpad: bool = True) -> bytes:
    """Decrypt AES-CBC bytes after strict key, IV, and block-size validation."""

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be exactly 16 bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("AES-CBC ciphertext must be non-empty and a multiple of 16 bytes")

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if not unpad:
        return plaintext
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(plaintext) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError(
            "PKCS7 unpadding failed; verify the key, IV, ciphertext, and padding mode"
        ) from exc


def rsa_decrypt(
    ciphertext: bytes,
    private_key_path: Path,
    *,
    padding_mode: str = "oaep-sha256",
    password: bytes | None = None,
) -> bytes:
    """Decrypt one RSA ciphertext using an analyst-supplied PEM private key."""

    if not ciphertext:
        raise ValueError("RSA ciphertext must not be empty")
    key_path = private_key_path.expanduser().resolve(strict=True)
    if not key_path.is_file():
        raise ValueError(f"Private key is not a file: {key_path}")
    if key_path.stat().st_size > 1_048_576:
        raise ValueError("Private key file exceeds the 1 MiB safety limit")

    try:
        private_key = load_pem_private_key(key_path.read_bytes(), password=password)
    except (TypeError, ValueError) as exc:
        raise ValueError("Unable to load the PEM private key or password") from exc
    if not hasattr(private_key, "decrypt"):
        raise ValueError("The supplied PEM does not contain an RSA private key")

    selected = padding_mode.lower()
    if selected == "oaep-sha256":
        selected_padding = asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    elif selected == "pkcs1v15":
        selected_padding = asymmetric_padding.PKCS1v15()
    else:
        raise ValueError(f"Unsupported RSA padding mode: {padding_mode}")
    try:
        return private_key.decrypt(ciphertext, selected_padding)
    except ValueError as exc:
        raise ValueError(
            "RSA decryption failed; verify the key, padding mode, and extracted ciphertext"
        ) from exc
