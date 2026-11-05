"""
tests/test_crypto_engine.py — Unit tests for crypto_engine.py

Covers task 3.3: encrypt_text and decrypt_text (Requirements 2.2, 3.2).
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto_engine import (
    encrypt_text,
    decrypt_text,
    build_text_payload,
    parse_text_payload,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _key() -> bytes:
    """Generate a fresh 32-byte random key."""
    return os.urandom(32)


def _nonce() -> bytes:
    """Generate a fresh 12-byte random nonce."""
    return os.urandom(12)


# ---------------------------------------------------------------------------
# encrypt_text — happy-path unit tests
# ---------------------------------------------------------------------------

def test_encrypt_text_returns_tuple_of_bytes() -> None:
    """encrypt_text must return a (bytes, bytes) tuple."""
    ct, tag = encrypt_text("hello", _key(), _nonce())
    assert isinstance(ct, bytes)
    assert isinstance(tag, bytes)


def test_encrypt_text_tag_is_16_bytes() -> None:
    """GCM authentication tag must always be exactly 16 bytes."""
    _, tag = encrypt_text("hello world", _key(), _nonce())
    assert len(tag) == 16


def test_encrypt_text_ciphertext_length_matches_plaintext() -> None:
    """AES-GCM is a stream cipher: ciphertext length == plaintext byte length."""
    plaintext = "SecureCrypt rocks"
    ct, _ = encrypt_text(plaintext, _key(), _nonce())
    assert len(ct) == len(plaintext.encode("utf-8"))


def test_encrypt_text_ciphertext_differs_from_plaintext() -> None:
    """The ciphertext must not equal the raw UTF-8 plaintext bytes."""
    plaintext = "do not leak"
    key, nonce = _key(), _nonce()
    ct, _ = encrypt_text(plaintext, key, nonce)
    assert ct != plaintext.encode("utf-8")


def test_encrypt_text_nondeterministic_with_different_nonces() -> None:
    """Same plaintext + key with two different nonces must produce different ciphertexts."""
    plaintext = "same plaintext"
    key = _key()
    ct1, _ = encrypt_text(plaintext, key, _nonce())
    ct2, _ = encrypt_text(plaintext, key, _nonce())
    assert ct1 != ct2


# ---------------------------------------------------------------------------
# encrypt_text — validation error tests
# ---------------------------------------------------------------------------

def test_encrypt_text_raises_for_short_key() -> None:
    """encrypt_text must raise ValueError when key is shorter than 32 bytes."""
    with pytest.raises(ValueError):
        encrypt_text("hello", b"\x00" * 16, _nonce())


def test_encrypt_text_raises_for_long_key() -> None:
    """encrypt_text must raise ValueError when key is longer than 32 bytes."""
    with pytest.raises(ValueError):
        encrypt_text("hello", b"\x00" * 33, _nonce())


def test_encrypt_text_raises_for_empty_key() -> None:
    """encrypt_text must raise ValueError when key is empty."""
    with pytest.raises(ValueError):
        encrypt_text("hello", b"", _nonce())


def test_encrypt_text_raises_for_short_nonce() -> None:
    """encrypt_text must raise ValueError when nonce is shorter than 12 bytes."""
    with pytest.raises(ValueError):
        encrypt_text("hello", _key(), b"\x00" * 8)


def test_encrypt_text_raises_for_long_nonce() -> None:
    """encrypt_text must raise ValueError when nonce is longer than 12 bytes."""
    with pytest.raises(ValueError):
        encrypt_text("hello", _key(), b"\x00" * 16)


def test_encrypt_text_raises_for_empty_nonce() -> None:
    """encrypt_text must raise ValueError when nonce is empty."""
    with pytest.raises(ValueError):
        encrypt_text("hello", _key(), b"")


# ---------------------------------------------------------------------------
# decrypt_text — happy-path unit tests
# ---------------------------------------------------------------------------

def test_decrypt_text_round_trip() -> None:
    """encrypt then decrypt must recover the original plaintext."""
    plaintext = "The quick brown fox"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    result = decrypt_text(ct, tag, key, nonce)
    assert result == plaintext


def test_decrypt_text_round_trip_unicode() -> None:
    """encrypt/decrypt must handle full Unicode (emoji, CJK, accents)."""
    plaintext = "Héllo wörld 🌍 日本語"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    result = decrypt_text(ct, tag, key, nonce)
    assert result == plaintext


def test_decrypt_text_round_trip_empty_string() -> None:
    """encrypt/decrypt must round-trip an empty plaintext string."""
    plaintext = ""
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    result = decrypt_text(ct, tag, key, nonce)
    assert result == plaintext


def test_decrypt_text_round_trip_long_text() -> None:
    """encrypt/decrypt must handle large plaintexts (> 1 KB)."""
    plaintext = "A" * 10_000
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    result = decrypt_text(ct, tag, key, nonce)
    assert result == plaintext


# ---------------------------------------------------------------------------
# decrypt_text — authentication failure tests
# ---------------------------------------------------------------------------

def test_decrypt_text_raises_invalid_tag_for_wrong_key() -> None:
    """decrypt_text must raise InvalidTag when the key is wrong."""
    plaintext = "secret"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    with pytest.raises(InvalidTag):
        decrypt_text(ct, tag, _key(), nonce)  # different key


def test_decrypt_text_raises_invalid_tag_for_wrong_nonce() -> None:
    """decrypt_text must raise InvalidTag when the nonce is wrong."""
    plaintext = "secret"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    with pytest.raises(InvalidTag):
        decrypt_text(ct, tag, key, _nonce())  # different nonce


def test_decrypt_text_raises_invalid_tag_for_tampered_ciphertext() -> None:
    """decrypt_text must raise InvalidTag when a ciphertext byte is flipped."""
    plaintext = "tamper me"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    with pytest.raises(InvalidTag):
        decrypt_text(tampered, tag, key, nonce)


def test_decrypt_text_raises_invalid_tag_for_tampered_tag() -> None:
    """decrypt_text must raise InvalidTag when the authentication tag is flipped."""
    plaintext = "tamper the tag"
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text(plaintext, key, nonce)
    tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    with pytest.raises(InvalidTag):
        decrypt_text(ct, tampered_tag, key, nonce)


# ---------------------------------------------------------------------------
# decrypt_text — validation error tests
# ---------------------------------------------------------------------------

def test_decrypt_text_raises_for_short_key() -> None:
    """decrypt_text must raise ValueError when key is shorter than 32 bytes."""
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text("hello", key, nonce)
    with pytest.raises(ValueError):
        decrypt_text(ct, tag, b"\x00" * 16, nonce)


def test_decrypt_text_raises_for_long_key() -> None:
    """decrypt_text must raise ValueError when key is longer than 32 bytes."""
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text("hello", key, nonce)
    with pytest.raises(ValueError):
        decrypt_text(ct, tag, b"\x00" * 33, nonce)


def test_decrypt_text_raises_for_short_nonce() -> None:
    """decrypt_text must raise ValueError when nonce is shorter than 12 bytes."""
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text("hello", key, nonce)
    with pytest.raises(ValueError):
        decrypt_text(ct, tag, key, b"\x00" * 8)


def test_decrypt_text_raises_for_long_nonce() -> None:
    """decrypt_text must raise ValueError when nonce is longer than 12 bytes."""
    key, nonce = _key(), _nonce()
    ct, tag = encrypt_text("hello", key, nonce)
    with pytest.raises(ValueError):
        decrypt_text(ct, tag, key, b"\x00" * 16)
