"""
file_handler.py — Upload validation, temp-path helpers, and cleanup for SecureCrypt.

Responsibilities
----------------
- Enforce MIME-type allow-list and file-size limit before any content is read.
- Reject filenames that contain path-traversal patterns (/, \\, .., \\x00).
- Generate UUID-based temp paths under uploads/ and outputs/ so concurrent
  requests never collide and the names contain no user-supplied data.
- Silently delete temp files when callers are done; log failures to stderr only.

References: Requirements 4.3, 7.1, 8.1
"""

import os
import struct
import sys
import uuid
from pathlib import Path

from werkzeug.datastructures import FileStorage

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

ALLOWED_MIME_TYPES: frozenset[str] = frozenset({
    "text/plain",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/zip",
    "application/octet-stream",
})

MAX_UPLOAD_BYTES: int = 100 * 1024 * 1024  # 100 MB

UPLOADS_DIR: Path = Path("uploads")
OUTPUTS_DIR: Path = Path("outputs")


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when an uploaded file or filename fails a pre-processing check.

    The message is always human-readable and safe to return to the client
    (it must NOT contain key material, stack traces, or internal details).
    """


# ---------------------------------------------------------------------------
# Filename validation
# ---------------------------------------------------------------------------

def safe_filename(filename: str) -> str:
    """Validate *filename* against path-traversal patterns.

    Checks for the presence of ``/``, ``\\``, ``..``, or ``\\x00`` (null byte).
    These are the patterns that could allow an attacker to write files outside
    the intended directory (Requirement 8.1).

    Parameters
    ----------
    filename:
        The raw filename supplied by the client.

    Returns
    -------
    str
        The filename unchanged when it contains none of the forbidden patterns.

    Raises
    ------
    ValidationError
        If any forbidden pattern is detected.  The error message names the
        specific pattern so the caller can surface it to the user.
    """
    if "/" in filename:
        raise ValidationError(
            "Filename must not contain a forward slash ('/')."
        )
    if "\\" in filename:
        raise ValidationError(
            "Filename must not contain a backslash ('\\\\')."
        )
    if ".." in filename:
        raise ValidationError(
            "Filename must not contain a directory traversal sequence ('..')."
        )
    if "\x00" in filename:
        raise ValidationError(
            "Filename must not contain a null byte."
        )
    return filename


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

def validate_upload(file: FileStorage, max_bytes: int = MAX_UPLOAD_BYTES) -> None:
    """Validate an incoming upload for MIME type, filename safety, and size.

    Checks are performed in this order:

    1. **MIME type** — ``file.mimetype`` must be in :data:`ALLOWED_MIME_TYPES`.
    2. **Filename safety** — delegates to :func:`safe_filename`.
    3. **File size** — tries ``file.content_length`` (from the HTTP
       ``Content-Length`` header) first; falls back to ``os.fstat`` on the
       underlying stream.  File content is **never** read into memory.

    Parameters
    ----------
    file:
        A Werkzeug :class:`~werkzeug.datastructures.FileStorage` object
        representing the incoming upload.
    max_bytes:
        Maximum permitted file size in bytes.  Defaults to
        :data:`MAX_UPLOAD_BYTES` (100 MB).

    Raises
    ------
    ValidationError
        With a human-readable reason when any check fails.
    """
    # 1. MIME type check
    mime_type = (file.mimetype or "").split(";")[0].strip().lower()
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValidationError(
            f"Unsupported file type '{mime_type}'. "
            f"Allowed types: {', '.join(sorted(ALLOWED_MIME_TYPES))}."
        )

    # 2. Filename safety check
    filename = file.filename or ""
    safe_filename(filename)  # raises ValidationError if unsafe

    # 3. File size check — avoid reading content into memory (Requirement 7.1)
    size: int | None = None

    # Prefer the Content-Length header when available
    content_length = file.content_length
    if content_length is not None and content_length > 0:
        size = content_length
    else:
        # Fall back to fstat on the underlying stream file descriptor
        try:
            size = os.fstat(file.stream.fileno()).st_size
        except OSError:
            size = None

    if size is not None and size > max_bytes:
        limit_mb = max_bytes // (1024 * 1024)
        raise ValidationError(
            f"File size exceeds the {limit_mb} MB upload limit."
        )


# ---------------------------------------------------------------------------
# Temp-path helpers
# ---------------------------------------------------------------------------

def tmp_upload_path() -> Path:
    """Return a unique path under :data:`UPLOADS_DIR` for a new upload.

    The name is ``upload_<uuid4_hex>`` — no user-supplied data, no collisions.
    The directory is created if it does not exist.
    """
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    return UPLOADS_DIR / f"upload_{uuid.uuid4().hex}"


def tmp_output_path() -> Path:
    """Return a unique path under :data:`OUTPUTS_DIR` for a new output file.

    The name is ``output_<uuid4_hex>`` — no user-supplied data, no collisions.
    The directory is created if it does not exist.
    """
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUTS_DIR / f"output_{uuid.uuid4().hex}"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup(*paths: Path) -> None:
    """Silently delete each path if it exists.

    Failures are logged to ``stderr`` and swallowed so that a cleanup error
    in a teardown handler never masks the original exception or response
    (Requirements 8.3, 8.4).

    Parameters
    ----------
    *paths:
        Zero or more :class:`~pathlib.Path` objects to delete.
    """
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[file_handler] WARNING: could not delete temp file "
                f"'{path}': {exc}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Encrypted_Container assembly and parsing
# ---------------------------------------------------------------------------


def write_encrypted_container(
    enc_path: Path,
    version: int,
    salt: bytes,
    nonce: bytes,
    original_filename: str,
    ciphertext_path: Path,
    tag: bytes,
) -> None:
    """Assemble and write the Encrypted_Container binary format.

    Binary layout (offsets are zero-indexed)::

        0            1        version (0x01)
        1            1        salt_len (0x20 = 32)
        2            32       salt
        34           1        nonce_len (0x0C = 12)
        35           12       nonce
        47           2        fname_len (little-endian uint16)
        49           fname_len  original filename (UTF-8)
        49+fname_len  N        ciphertext (N = plaintext file size)
        49+fname_len+N  16    authentication tag

    The ciphertext bytes are streamed from *ciphertext_path* in 1 MB chunks
    so that large files do not require loading the entire ciphertext into
    memory.

    Parameters
    ----------
    enc_path:
        Destination path for the assembled container file.
    version:
        Format version byte (currently ``0x01``).
    salt:
        32-byte random salt produced by :func:`key_manager.generate_salt`.
    nonce:
        12-byte random nonce produced by :func:`key_manager.generate_nonce`.
    original_filename:
        Original upload filename to embed as UTF-8 metadata.
    ciphertext_path:
        Path to the file containing the raw encrypted bytes (without the
        authentication tag).
    tag:
        16-byte GCM authentication tag returned by
        :func:`crypto_engine.encrypt_file`.

    References: Requirements 4.5, 5.2, 6.6
    """
    fname_bytes = original_filename.encode("utf-8")
    fname_len = len(fname_bytes)

    with open(enc_path, "wb") as out:
        # version (1 byte)
        out.write(bytes([version]))
        # salt_len (1 byte) + salt (32 bytes)
        out.write(bytes([len(salt)]))
        out.write(salt)
        # nonce_len (1 byte) + nonce (12 bytes)
        out.write(bytes([len(nonce)]))
        out.write(nonce)
        # fname_len (2-byte little-endian uint16) + fname bytes
        out.write(struct.pack("<H", fname_len))
        out.write(fname_bytes)
        # ciphertext — streamed in 1 MB chunks
        with open(ciphertext_path, "rb") as ct_in:
            while True:
                chunk = ct_in.read(1_048_576)
                if not chunk:
                    break
                out.write(chunk)
        # authentication tag (16 bytes) — always the final bytes
        out.write(tag)


def parse_encrypted_container(
    enc_path: Path,
) -> tuple[int, bytes, bytes, str, bytes, bytes]:
    """Parse an Encrypted_Container file and return its fields.

    Reads the entire file into memory so that the structure can be fully
    validated before any field is returned to the caller.

    Returns
    -------
    tuple[int, bytes, bytes, str, bytes, bytes]
        ``(version, salt, nonce, original_filename, ciphertext, tag)``

    Raises
    ------
    ValidationError
        If the buffer is too short to contain the fixed-length header, if any
        length field points beyond the end of the buffer, or if the ciphertext
        section would be negative in length (i.e., the file is truncated).

    References: Requirements 4.5, 5.2, 6.6
    """
    data = enc_path.read_bytes()

    # Minimum fixed-length header: 1 (version) + 1 (salt_len) + 32 (salt)
    #   + 1 (nonce_len) + 12 (nonce) + 2 (fname_len) = 49 bytes
    # Plus at least 16 bytes for the tag.
    MINIMUM_SIZE = 49 + 16
    if len(data) < MINIMUM_SIZE:
        raise ValidationError(
            "Encrypted container is too short to be valid "
            f"(got {len(data)} bytes, need at least {MINIMUM_SIZE})."
        )

    offset = 0

    # version (1 byte)
    version = data[offset]
    offset += 1

    # salt_len (1 byte) + salt
    salt_len = data[offset]
    offset += 1
    if offset + salt_len > len(data):
        raise ValidationError(
            f"Container declares salt_len={salt_len} but the buffer is too short."
        )
    salt = data[offset: offset + salt_len]
    offset += salt_len

    # nonce_len (1 byte) + nonce
    if offset >= len(data):
        raise ValidationError("Container is truncated before nonce_len field.")
    nonce_len = data[offset]
    offset += 1
    if offset + nonce_len > len(data):
        raise ValidationError(
            f"Container declares nonce_len={nonce_len} but the buffer is too short."
        )
    nonce = data[offset: offset + nonce_len]
    offset += nonce_len

    # fname_len (2-byte little-endian uint16) + fname bytes
    if offset + 2 > len(data):
        raise ValidationError("Container is truncated before fname_len field.")
    (fname_len,) = struct.unpack_from("<H", data, offset)
    offset += 2
    if offset + fname_len > len(data):
        raise ValidationError(
            f"Container declares fname_len={fname_len} but the buffer is too short."
        )
    original_filename = data[offset: offset + fname_len].decode("utf-8")
    offset += fname_len

    # Everything remaining is ciphertext + 16-byte tag.
    # The tag is always the final 16 bytes.
    TAG_SIZE = 16
    remaining = len(data) - offset
    if remaining < TAG_SIZE:
        raise ValidationError(
            "Container is too short to contain a 16-byte authentication tag "
            f"(only {remaining} bytes remain after the header)."
        )

    ciphertext = data[offset: len(data) - TAG_SIZE]
    tag = data[len(data) - TAG_SIZE:]

    return version, salt, nonce, original_filename, ciphertext, tag
