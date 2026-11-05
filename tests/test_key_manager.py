"""
tests/test_key_manager.py — Unit tests and property-based tests for key_manager.py

Task 2.2: Property 5 — Encryption is non-deterministic (unique Salt and Nonce per operation)
Task 2.3: Unit tests for generate_salt, generate_nonce, and derive_key
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from key_manager import generate_salt, generate_nonce, derive_key


# ---------------------------------------------------------------------------
# Task 2.3 — Unit tests
# Requirements: 6.1, 6.2, 6.3, 11.7
# ---------------------------------------------------------------------------

def test_generate_salt_returns_32_bytes() -> None:
    """generate_salt() must return exactly 32 bytes."""
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == 32


def test_generate_nonce_returns_12_bytes() -> None:
    """generate_nonce() must return exactly 12 bytes."""
    nonce = generate_nonce()
    assert isinstance(nonce, bytes)
    assert len(nonce) == 12


def test_derive_key_returns_32_bytes() -> None:
    """derive_key() must return exactly 32 bytes."""
    salt = generate_salt()
    key = derive_key("correct horse battery staple", salt)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_key_is_deterministic_unit() -> None:
    """derive_key() with the same (password, salt) must produce the same key."""
    password = "my-secure-password"
    salt = generate_salt()
    key_a = derive_key(password, salt)
    key_b = derive_key(password, salt)
    assert key_a == key_b


def test_derive_key_raises_for_empty_password() -> None:
    """derive_key() must raise ValueError when password is empty."""
    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_key("", salt)


def test_derive_key_raises_for_short_salt() -> None:
    """derive_key() must raise ValueError when salt is shorter than 32 bytes."""
    with pytest.raises(ValueError):
        derive_key("password", b"tooshort")


def test_derive_key_raises_for_long_salt() -> None:
    """derive_key() must raise ValueError when salt is longer than 32 bytes."""
    with pytest.raises(ValueError):
        derive_key("password", b"x" * 33)


def test_derive_key_raises_for_empty_salt() -> None:
    """derive_key() must raise ValueError when salt is empty."""
    with pytest.raises(ValueError):
        derive_key("password", b"")


# ---------------------------------------------------------------------------
# Task 2.2 — Property-based tests
# Feature: secure-crypt, Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)
# Requirements: 2.7, 6.7, 11.7
# ---------------------------------------------------------------------------

# Feature: secure-crypt, Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)
@settings(max_examples=200)
@given(st.text(min_size=1))
def test_generate_salt_uniqueness(_unused: str) -> None:
    """Two consecutive generate_salt() calls must return different values.

    Validates: Requirements 2.7, 6.7, 11.7
    """
    salt_a = generate_salt()
    salt_b = generate_salt()
    assert salt_a != salt_b, (
        "generate_salt() returned the same value on two consecutive calls — "
        "salts must be unique per operation."
    )


# Feature: secure-crypt, Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)
@settings(max_examples=200)
@given(st.text(min_size=1))
def test_generate_nonce_uniqueness(_unused: str) -> None:
    """Two consecutive generate_nonce() calls must return different values.

    Validates: Requirements 2.7, 6.7, 11.7
    """
    nonce_a = generate_nonce()
    nonce_b = generate_nonce()
    assert nonce_a != nonce_b, (
        "generate_nonce() returned the same value on two consecutive calls — "
        "nonces must be unique per operation."
    )


# Feature: secure-crypt, Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)
@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1), st.binary(min_size=32, max_size=32))
def test_derive_key_is_deterministic(password: str, salt: bytes) -> None:
    """derive_key must be deterministic: same (password, salt) always yields the same key.

    deadline=None is required because Scrypt with N=131072 intentionally takes ~900ms per
    invocation — this is a security property of the KDF, not a bug.

    Validates: Requirements 2.7, 6.7, 11.7
    """
    key_a = derive_key(password, salt)
    key_b = derive_key(password, salt)
    assert key_a == key_b, (
        "derive_key() returned different keys for the same (password, salt) — "
        "key derivation must be deterministic."
    )


# Feature: secure-crypt, Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)
@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1), st.binary(min_size=32, max_size=32))
def test_derive_key_differs_for_different_salts(password: str, salt_a: bytes) -> None:
    """derive_key must produce different output when a different salt is used.

    Uses a freshly generated salt (via generate_salt) as the second salt to
    ensure the two salts are independent and almost certainly distinct.

    deadline=None is required because Scrypt with N=131072 intentionally takes ~900ms per
    invocation — this is a security property of the KDF, not a bug.

    Validates: Requirements 2.7, 6.7, 11.7
    """
    salt_b = generate_salt()
    # Salts must differ for the property to be meaningful; skip if equal (astronomically rare).
    assume(salt_a != salt_b)

    key_a = derive_key(password, salt_a)
    key_b = derive_key(password, salt_b)
    assert key_a != key_b, (
        "derive_key() returned the same key for two different salts — "
        "distinct salts must produce distinct derived keys."
    )
