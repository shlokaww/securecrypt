"""
crypto_engine.py — AES-256-GCM encryption/decryption and payload serialisation
for SecureCrypt.

This module provides:
  - Payload serialisation helpers for the Encrypted_Text_Payload binary format
  - Text encryption/decryption (encrypt_text, decrypt_text)
  - File encryption/decryption with streaming support (encrypt_file, decrypt_file)

Binary layout of Encrypted_Text_Payload (before Base64 encoding):

  Offset  Length  Field
  ------  ------  -----
  0       1       version (0x01)
  1       1       salt_len (0x20 = 32)
  2       32      salt
  34      1       nonce_len (0x0C = 12)
  35      12      nonce
  47      N       ciphertext  (N = plaintext byte length)
  47+N    16      authentication tag

Total fixed overhead: 63 bytes.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants (mirrors key_manager constants for local validation)
# ---------------------------------------------------------------------------

# Minimum total bytes a valid Encrypted_Text_Payload must contain:
#   1 (version) + 1 (salt_len) + salt + 1 (nonce_len) + nonce + tag
#   = 1 + 1 + 32 + 1 + 12 + 16 = 63 bytes
_MIN_PAYLOAD_BYTES: int = 63

_TAG_BYTES: int = 16  # GCM authentication tag length


# ---------------------------------------------------------------------------
# Payload serialisation helpers (Requirement 2.3, 6.6)
# ---------------------------------------------------------------------------

def build_text_payload(
    version: int,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Serialise an Encrypted_Text_Payload to bytes.

    Layout (length-prefixed):
        version (1 byte) | salt_len (1 byte) | salt | nonce_len (1 byte) | nonce
        | ciphertext | tag

    Parameters
    ----------
    version:
        1-byte unsigned integer version identifier (e.g. ``0x01``).
    salt:
        Random salt bytes (typically 32 bytes).
    nonce:
        Random nonce bytes (typically 12 bytes).
    ciphertext:
        Encrypted plaintext bytes.
    tag:
        16-byte GCM authentication tag.

    Returns
    -------
    bytes
        The concatenated binary payload ready for Base64 encoding.
    """
    return (
        bytes([version, len(salt)])
        + salt
        + bytes([len(nonce)])
        + nonce
        + ciphertext
        + tag
    )


def parse_text_payload(
    raw: bytes,
) -> tuple[int, bytes, bytes, bytes, bytes]:
    """Deserialise an Encrypted_Text_Payload from bytes.

    Parameters
    ----------
    raw:
        The raw binary payload (not Base64-encoded).

    Returns
    -------
    tuple[int, bytes, bytes, bytes, bytes]
        ``(version, salt, nonce, ciphertext, tag)``

    Raises
    ------
    ValueError
        If *raw* is too short to be a valid payload, if a length field
        would cause a read beyond the buffer, or if the remaining bytes
        after stripping ciphertext and tag are insufficient.
    """
    # --- Minimum structural check ----------------------------------------
    # Need at least: 1 (version) + 1 (salt_len) + 1 (nonce_len) + 16 (tag)
    # plus the actual salt and nonce bytes — the minimum is 63 bytes for
    # the standard salt=32 / nonce=12 case, but we validate dynamically.
    if len(raw) < 2:
        raise ValueError(
            f"Payload too short: need at least 2 bytes for version and "
            f"salt_len fields, got {len(raw)}."
        )

    # --- version & salt --------------------------------------------------
    version: int = raw[0]
    salt_len: int = raw[1]

    # Ensure the salt bytes are all present
    salt_end: int = 2 + salt_len
    if salt_end > len(raw):
        raise ValueError(
            f"Payload too short: salt_len={salt_len} but only "
            f"{len(raw) - 2} bytes remain after the salt_len field."
        )
    salt: bytes = raw[2:salt_end]

    # --- nonce_len & nonce ----------------------------------------------
    nonce_len_offset: int = salt_end
    if nonce_len_offset >= len(raw):
        raise ValueError(
            "Payload too short: missing nonce_len field."
        )

    nonce_len: int = raw[nonce_len_offset]
    nonce_start: int = nonce_len_offset + 1
    nonce_end: int = nonce_start + nonce_len

    if nonce_end > len(raw):
        raise ValueError(
            f"Payload too short: nonce_len={nonce_len} but only "
            f"{len(raw) - nonce_start} bytes remain after the nonce_len field."
        )
    nonce: bytes = raw[nonce_start:nonce_end]

    # --- ciphertext + tag -----------------------------------------------
    # Everything from nonce_end onwards is ciphertext || tag.
    # The tag is always the final TAG_BYTES (16) bytes.
    ct_and_tag: bytes = raw[nonce_end:]

    if len(ct_and_tag) < _TAG_BYTES:
        raise ValueError(
            f"Payload too short: need at least {_TAG_BYTES} bytes for the "
            f"authentication tag, got {len(ct_and_tag)} bytes after the nonce."
        )

    ciphertext: bytes = ct_and_tag[:-_TAG_BYTES]
    tag: bytes = ct_and_tag[-_TAG_BYTES:]

    return version, salt, nonce, ciphertext, tag


# ---------------------------------------------------------------------------
# Text encryption / decryption (Requirements 2.2, 3.2)
# ---------------------------------------------------------------------------

_KEY_BYTES: int = 32   # AES-256 requires a 32-byte key
_NONCE_BYTES: int = 12  # AES-GCM standard nonce length


def encrypt_text(plaintext: str, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Parameters
    ----------
    plaintext:
        The UTF-8 string to encrypt.
    key:
        A 32-byte AES-256 key (e.g. from ``key_manager.derive_key``).
    nonce:
        A 12-byte nonce (e.g. from ``key_manager.generate_nonce``).

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, tag)`` where *tag* is always 16 bytes.

    Raises
    ------
    ValueError
        If *key* is not exactly 32 bytes or *nonce* is not exactly 12 bytes.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(
            f"Key must be exactly {_KEY_BYTES} bytes; got {len(key)} bytes."
        )
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_BYTES} bytes; got {len(nonce)} bytes."
        )

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (tag is always the last 16 bytes)
    ct_and_tag: bytes = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    ciphertext: bytes = ct_and_tag[:-_TAG_BYTES]
    tag: bytes = ct_and_tag[-_TAG_BYTES:]
    return ciphertext, tag


def decrypt_text(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> str:
    """Decrypt and authenticate *ciphertext* with AES-256-GCM.

    Parameters
    ----------
    ciphertext:
        The encrypted bytes produced by :func:`encrypt_text`.
    tag:
        The 16-byte GCM authentication tag produced by :func:`encrypt_text`.
    key:
        A 32-byte AES-256 key.
    nonce:
        The 12-byte nonce used during encryption.

    Returns
    -------
    str
        The original plaintext string (UTF-8 decoded).

    Raises
    ------
    InvalidTag
        If GCM authentication fails (wrong key, wrong nonce, or tampered data).
    ValueError
        If *key* is not exactly 32 bytes or *nonce* is not exactly 12 bytes.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(
            f"Key must be exactly {_KEY_BYTES} bytes; got {len(key)} bytes."
        )
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_BYTES} bytes; got {len(nonce)} bytes."
        )

    aesgcm = AESGCM(key)
    # AESGCM.decrypt expects ciphertext || tag as a single buffer
    plaintext_bytes: bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# File encryption / decryption (Requirements 4.5, 5.2, 7.3, 7.4, 7.5)
# ---------------------------------------------------------------------------

from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    nonce: bytes,
    chunk_size: int = 1_048_576,
    streaming_threshold: int = 10_485_760,
) -> bytes:
    """Encrypt a file using AES-256-GCM via hazmat streaming context.

    For files whose size is at or below *streaming_threshold* the entire
    file is read in one shot and encrypted in a single ``update`` call.
    For larger files the content is processed in *chunk_size* chunks so
    that memory usage stays bounded.

    Parameters
    ----------
    src_path:
        Path to the plaintext source file.
    dst_path:
        Path where the ciphertext will be written (without the tag).
    key:
        A 32-byte AES-256 key.
    nonce:
        A 12-byte AES-GCM nonce.
    chunk_size:
        Number of bytes per read/write iteration (default 1 MB).
    streaming_threshold:
        File-size boundary in bytes above which streaming is used (default 10 MB).

    Returns
    -------
    bytes
        The 16-byte GCM authentication tag covering all ciphertext bytes.

    Raises
    ------
    ValueError
        If *key* is not exactly 32 bytes or *nonce* is not exactly 12 bytes.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(
            f"Key must be exactly {_KEY_BYTES} bytes; got {len(key)} bytes."
        )
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_BYTES} bytes; got {len(nonce)} bytes."
        )

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()

    src_path = Path(src_path)
    dst_path = Path(dst_path)

    file_size: int = src_path.stat().st_size

    with open(src_path, "rb") as src_fh, open(dst_path, "wb") as dst_fh:
        if file_size <= streaming_threshold:
            # Non-streaming path: read the whole file in one shot.
            plaintext_chunk = src_fh.read()
            dst_fh.write(encryptor.update(plaintext_chunk))
        else:
            # Streaming path: process in chunk_size increments.
            while True:
                plaintext_chunk = src_fh.read(chunk_size)
                if not plaintext_chunk:
                    break
                dst_fh.write(encryptor.update(plaintext_chunk))

        # Finalise the encryptor — flushes any remaining buffered bytes and
        # makes encryptor.tag available.
        dst_fh.write(encryptor.finalize())

    return encryptor.tag


def decrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    chunk_size: int = 1_048_576,
    streaming_threshold: int = 10_485_760,
) -> None:
    """Decrypt and authenticate a file using AES-256-GCM via hazmat streaming context.

    For files at or below *streaming_threshold* the ciphertext is read in
    one shot; larger files are streamed in *chunk_size* chunks.  All
    decrypted bytes are written to *dst_path* as they are produced by
    ``decryptor.update()``, but the decrypted content is not committed
    until ``decryptor.finalize_with_tag()`` succeeds.

    .. note::
        Because the hazmat GCM context buffers internally and
        ``finalize_with_tag`` raises ``InvalidTag`` before any plaintext
        is *authenticated*, callers should treat *dst_path* as
        uncommitted until this function returns normally.  If
        ``InvalidTag`` is raised, *dst_path* is deleted before the
        exception propagates so no unauthenticated bytes remain on disk.

    Parameters
    ----------
    src_path:
        Path to the encrypted source file (ciphertext without tag).
    dst_path:
        Path where the decrypted plaintext will be written.
    key:
        A 32-byte AES-256 key.
    nonce:
        A 12-byte AES-GCM nonce (must match the one used during encryption).
    tag:
        The 16-byte GCM authentication tag returned by :func:`encrypt_file`.
    chunk_size:
        Number of bytes per read/write iteration (default 1 MB).
    streaming_threshold:
        File-size boundary in bytes above which streaming is used (default 10 MB).

    Raises
    ------
    InvalidTag
        If GCM authentication fails — *dst_path* is deleted before raising.
    ValueError
        If *key* is not exactly 32 bytes or *nonce* is not exactly 12 bytes.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(
            f"Key must be exactly {_KEY_BYTES} bytes; got {len(key)} bytes."
        )
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_BYTES} bytes; got {len(nonce)} bytes."
        )

    # GCM(nonce, tag) tells the hazmat context which tag to verify during
    # finalize_with_tag().  We pass min_tag_length=16 implicitly via the
    # default — no extra argument needed.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()

    src_path = Path(src_path)
    dst_path = Path(dst_path)

    file_size: int = src_path.stat().st_size

    try:
        with open(src_path, "rb") as src_fh, open(dst_path, "wb") as dst_fh:
            if file_size <= streaming_threshold:
                # Non-streaming path.
                ciphertext_chunk = src_fh.read()
                dst_fh.write(decryptor.update(ciphertext_chunk))
            else:
                # Streaming path.
                while True:
                    ciphertext_chunk = src_fh.read(chunk_size)
                    if not ciphertext_chunk:
                        break
                    dst_fh.write(decryptor.update(ciphertext_chunk))

            # finalize() verifies the tag that was already supplied to
            # modes.GCM(nonce, tag) at construction time, and raises
            # InvalidTag if authentication fails.
            dst_fh.write(decryptor.finalize())

    except InvalidTag:
        # Remove partially-written output before re-raising so no
        # unauthenticated plaintext bytes are left on disk.
        if dst_path.exists():
            dst_path.unlink()
        raise
