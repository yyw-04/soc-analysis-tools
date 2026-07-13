from __future__ import annotations

from pathlib import Path

import pytest

from soc_c2.crypto import aes_cbc_decrypt, rsa_decrypt, verify_hmac


cryptography = pytest.importorskip("cryptography")


def test_aes_cbc_decrypt_and_hmac_verification() -> None:
    from cryptography.hazmat.primitives import hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    hmac_key = bytes.fromhex("102132435465768798a9babbdcddfe0f")
    plaintext = b"authorized defensive test payload"

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    signer = hmac.HMAC(hmac_key, hashes.SHA256())
    signer.update(iv + ciphertext)
    tag = signer.finalize()[:16]

    assert verify_hmac(iv + ciphertext, hmac_key, tag, "sha256") is True
    assert verify_hmac(iv + ciphertext + b"x", hmac_key, tag, "sha256") is False
    assert aes_cbc_decrypt(ciphertext, key, iv) == plaintext


def test_aes_cbc_rejects_invalid_iv() -> None:
    with pytest.raises(ValueError, match="exactly 16 bytes"):
        aes_cbc_decrypt(b"0" * 16, b"1" * 16, b"short")


def test_rsa_oaep_and_pkcs1v15_decrypt(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_path = tmp_path / "test-private.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    plaintext = b"session metadata test"

    oaep_ciphertext = private_key.public_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    pkcs_ciphertext = private_key.public_key().encrypt(plaintext, padding.PKCS1v15())

    assert rsa_decrypt(oaep_ciphertext, private_key_path) == plaintext
    assert rsa_decrypt(
        pkcs_ciphertext, private_key_path, padding_mode="pkcs1v15"
    ) == plaintext
