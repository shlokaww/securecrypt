"""
key_manager.py — Salt/nonce generation and Scrypt key derivation for SecureCrypt.

All randomness is sourced from os.urandom(), which delegates to the OS CSPRNG
(getrandom on Linux, CryptGenRandom on Windows).
"""

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

SCRYPT_N: int = 131072   # 2^17 — CPU/memory cost factor
SCRYPT_R: int = 8        # block size parameter
SCRYPT_P: int = 1        # parallelisation parameter
SCRYPT_DKLEN: int = 32   # derived key length in bytes (256 bits)

SALT_BYTES: int = 32     # bytes per salt value
NONCE_BYTES: int = 12    # bytes per AES-GCM nonce (96 bits)
TAG_BYTES: int = 16      # bytes for GCM authentication tag

PAYLOAD_VERSION: int = 0x01  # current Encrypted_Text_Payload / Encrypted_Container version


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """Return 32 cryptographically random bytes from the OS CSPRNG.

    A fresh salt MUST be generated for every encryption operation; salts are
    never reused (Requirement 6.1, 6.7).
    """
    return os.urandom(SALT_BYTES)


def generate_nonce() -> bytes:
    """Return 12 cryptographically random bytes from the OS CSPRNG.

    A fresh nonce MUST be generated for every AES-GCM encryption operation;
    nonces are never reused (Requirement 6.2, 6.7).
    """
    return os.urandom(NONCE_BYTES)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from *password* and *salt* using Scrypt.

    Parameters
    ----------
    password:
        The user-supplied password.  Must be a non-empty string.
    salt:
        A 32-byte random salt.  Must be exactly SALT_BYTES (32) bytes long.

    Returns
    -------
    bytes
        A 32-byte (256-bit) derived key suitable for AES-256-GCM.

    Raises
    ------
    ValueError
        If *password* is empty or *salt* is not exactly 32 bytes.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if len(salt) != SALT_BYTES:
        raise ValueError(
            f"Salt must be exactly {SALT_BYTES} bytes; got {len(salt)} bytes."
        )

    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_DKLEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))
