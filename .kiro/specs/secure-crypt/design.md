# Design Document — SecureCrypt

## Overview

SecureCrypt is a browser-based symmetric encryption/decryption application. The Flask server acts purely as a cryptographic processing backend; no user data, keys, or plaintext are persisted between requests. Every page is server-rendered (Jinja2 templates + Bootstrap 5) so the application works without a JavaScript build step.

### Goals

- AES-256-GCM authenticated encryption for both text payloads and arbitrary files
- Scrypt key derivation (N=2¹⁷, r=8, p=1) turning user passwords into 256-bit keys
- Streaming I/O for files > 10 MB so memory use stays bounded regardless of file size
- Self-contained Docker deployment; zero host dependencies beyond Docker

### Non-Goals

- Multi-user accounts or session management
- Asymmetric (public-key) cryptography
- Key storage or key escrow

---

## Architecture

The application follows a thin-controller / rich-service pattern. Flask routes dispatch to domain-specific service modules; no cryptographic logic lives in `app.py`.

```
┌─────────────────────────────────────────────────────┐
│                     Browser                          │
│  Bootstrap 5 + Vanilla JS (main.js)                  │
└────────────────────┬───────────────────┬────────────┘
                     │ HTTP/multipart     │ JSON API
┌────────────────────▼───────────────────▼────────────┐
│                  Flask  (app.py)                      │
│  Routes: /  /encrypt  /decrypt  /about               │
│          /api/encrypt-text   /api/decrypt-text        │
│          /api/encrypt-file   /api/decrypt-file        │
└──────┬───────────────────┬────────────────┬──────────┘
       │                   │                │
┌──────▼──────┐  ┌─────────▼──────┐  ┌─────▼──────────┐
│ key_manager │  │ crypto_engine  │  │  file_handler  │
│             │  │                │  │                │
│ generate_   │  │ encrypt_text   │  │ validate_file  │
│   salt()    │  │ decrypt_text   │  │ safe_filename  │
│ generate_   │  │ encrypt_file   │  │ stream_encrypt │
│   nonce()   │  │ decrypt_file   │  │ stream_decrypt │
│ derive_key()│  │ (streaming)    │  │ cleanup_temps  │
└─────────────┘  └────────────────┘  └────────────────┘
```

### Request Lifecycle — Text Encryption

1. Browser POSTs `{plaintext, password}` to `/api/encrypt-text`
2. `app.py` validates non-empty fields, returns 400 on failure
3. Calls `key_manager.generate_salt()` → 32 random bytes
4. Calls `key_manager.generate_nonce()` → 12 random bytes
5. Calls `key_manager.derive_key(password, salt)` → 32-byte key
6. Calls `crypto_engine.encrypt_text(plaintext, key, nonce)` → `(ciphertext, tag)`
7. Serialises `Encrypted_Text_Payload` → Base64 string
8. Returns JSON `{payload: "<base64>"}` to browser

### Request Lifecycle — File Encryption (streaming path)

1. Browser POSTs multipart `{file, password}` to `/api/encrypt-file`
2. `file_handler.validate_upload(file)` checks MIME, filename safety, size ≤ 100 MB
3. Writes upload to a unique temp file under `uploads/`
4. `key_manager` generates salt + nonce + derived key
5. `crypto_engine.encrypt_file_streaming(src_path, dst_path, key, nonce)` processes in 1 MB chunks using `AESGCM` with accumulated AAD
6. `file_handler` assembles the `Encrypted_Container` binary around the encrypted temp file
7. Flask streams the container as an attachment response, naming it `<original>.enc`
8. `file_handler.cleanup(upload_tmp, output_tmp)` deletes both temp files

---

## Components and Interfaces

### `key_manager.py`

```python
def generate_salt() -> bytes:
    """Return 32 cryptographically random bytes (os.urandom)."""

def generate_nonce() -> bytes:
    """Return 12 cryptographically random bytes (os.urandom)."""

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password + salt using Scrypt.
    
    Parameters: N=131072 (2^17), r=8, p=1, dklen=32
    Raises: ValueError if password is empty or salt is not 32 bytes
    """
```

All randomness comes from `os.urandom()`, which delegates to the OS CSPRNG (getrandom on Linux, CryptGenRandom on Windows).

### `crypto_engine.py`

```python
def encrypt_text(plaintext: str, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext string with AES-256-GCM.
    
    Returns (ciphertext, tag) where tag is 16 bytes.
    Raises: ValueError for invalid key/nonce lengths.
    """

def decrypt_text(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> str:
    """Decrypt and authenticate ciphertext.
    
    Raises: InvalidTag on authentication failure.
    Raises: ValueError on structural errors.
    Returns: original plaintext string (UTF-8).
    """

def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    nonce: bytes,
    chunk_size: int = 1_048_576,        # 1 MB
    streaming_threshold: int = 10_485_760,  # 10 MB
) -> bytes:
    """Encrypt a file, streaming if it exceeds streaming_threshold.
    
    Returns the 16-byte GCM Authentication_Tag covering all content.
    Writes encrypted bytes (without tag) to dst_path.
    """

def decrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    chunk_size: int = 1_048_576,
    streaming_threshold: int = 10_485_760,
) -> None:
    """Decrypt and authenticate a file.
    
    Raises: InvalidTag if authentication fails — dst_path is deleted before raising.
    Raises: ValueError on structural errors.
    """
```

**Streaming construction**: AES-GCM does not natively support streaming. The implementation uses the `cryptography` library's `AEADEncryptionContext` / `AEADDecryptionContext` hazmat primitives (`Cipher(algorithms.AES(key), modes.GCM(nonce))`). For encryption, chunks are fed into `encryptor.update(chunk)` and the final `encryptor.finalize()` + `encryptor.tag` yields the tag that covers all bytes. For decryption, all encrypted bytes are fed into `decryptor.update(chunk)` and `decryptor.finalize_with_tag(tag)` performs the final authentication — if the tag does not match, `InvalidTag` is raised and no plaintext is committed to disk.

> **Rationale**: Using the hazmat low-level primitives from the `cryptography` library is the only way to stream AES-GCM while keeping a single tag covering the entire ciphertext. The alternative — splitting into independently-tagged chunks — would allow chunk-reordering attacks. This design matches GCM's security model (single tag, single context per operation).

### `file_handler.py`

```python
ALLOWED_MIME_TYPES: frozenset[str] = frozenset({
    "text/plain", "application/pdf",
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "application/zip", "application/octet-stream",
})
MAX_UPLOAD_BYTES: int = 100 * 1024 * 1024   # 100 MB
UPLOADS_DIR: Path = Path("uploads")
OUTPUTS_DIR: Path = Path("outputs")

def validate_upload(file: FileStorage, max_bytes: int = MAX_UPLOAD_BYTES) -> None:
    """Check MIME type, filename safety, and size.
    
    Raises: ValidationError with a human-readable reason on failure.
    Does NOT read file content into memory — uses Content-Length and os.fstat.
    """

def safe_filename(filename: str) -> str:
    """Sanitise a filename, rejecting path traversal patterns.
    
    Raises: ValidationError if '/', '\\', '..', or '\x00' are present.
    Returns: The filename unchanged if safe.
    """

def write_encrypted_container(
    enc_path: Path,
    version: int,
    salt: bytes,
    nonce: bytes,
    original_filename: str,
    ciphertext_path: Path,
    tag: bytes,
) -> None:
    """Assemble and write the Encrypted_Container binary format."""

def parse_encrypted_container(
    enc_path: Path,
) -> tuple[int, bytes, bytes, str, bytes, bytes]:
    """Parse the container, returning (version, salt, nonce, filename, ciphertext, tag).
    
    Raises: ValidationError on structural errors.
    """

def cleanup(*paths: Path) -> None:
    """Silently delete each path if it exists. Logs failures to stderr only."""
```

### `app.py`

Flask application factory pattern. Routes:

| Route | Method | Description |
|---|---|---|
| `/` | GET | Dashboard (index.html) |
| `/encrypt` | GET | Encrypt page |
| `/decrypt` | GET | Decrypt page |
| `/about` | GET | About page |
| `/api/encrypt-text` | POST | JSON: `{plaintext, password}` → `{payload}` |
| `/api/decrypt-text` | POST | JSON: `{payload, password}` → `{plaintext}` |
| `/api/encrypt-file` | POST | Multipart: `{file, password}` → file download |
| `/api/decrypt-file` | POST | Multipart: `{file, password}` → file download |

Error handling:
- `400` — validation errors (missing fields, bad Base64, unsafe filename, unsupported version)
- `413` — payload exceeds 100 MB
- `422` — authentication failure (wrong password, tampered ciphertext)
- `500` — unexpected internal errors (stack trace logged to stderr only, generic message to client)

### Frontend (`static/js/main.js`)

Vanilla JS with no bundler dependency:

- `initPasswordToggle()` — toggles `input[type]` between `password` and `text`
- `initDragDrop(dropzone, fileInput)` — handles `dragover` / `drop` events, populates the file input
- `submitWithSpinner(form, spinnerEl, btnEl)` — disables controls, shows spinner, submits via `fetch`, re-enables on completion
- `showNotification(message, type, durationMs)` — renders Bootstrap alert, auto-dismisses after `durationMs`
- `copyToClipboard(text, confirmEl)` — calls `navigator.clipboard.writeText`, shows confirmation

---

## Data Models

### Encrypted_Text_Payload (Base64-encoded binary)

The raw bytes before Base64 encoding follow a length-prefixed layout:

```
Offset  Length  Field
------  ------  -----
0       1       version (0x01)
1       1       salt_len (0x20 = 32)
2       32      salt
34      1       nonce_len (0x0C = 12)
35      12      nonce
47      N       ciphertext  (N = plaintext byte length)
47+N    16      authentication tag
```

Total fixed overhead: 63 bytes. Ciphertext length equals plaintext byte length (GCM is a stream cipher mode).

Serialisation helpers live in `crypto_engine.py`:

```python
def build_text_payload(version: int, salt: bytes, nonce: bytes,
                        ciphertext: bytes, tag: bytes) -> bytes:
    return bytes([version, len(salt)]) + salt + bytes([len(nonce)]) + nonce + ciphertext + tag

def parse_text_payload(raw: bytes) -> tuple[int, bytes, bytes, bytes, bytes]:
    version = raw[0]
    salt_len = raw[1]; salt = raw[2:2+salt_len]
    offset = 2 + salt_len
    nonce_len = raw[offset]; nonce = raw[offset+1:offset+1+nonce_len]
    offset = offset + 1 + nonce_len
    ct_and_tag = raw[offset:]
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return version, salt, nonce, ciphertext, tag
```

### Encrypted_Container (binary file — `.enc`)

```
Offset       Length   Field
-----------  -------  -----
0            1        version (0x01)
1            1        salt_len (0x20 = 32)
2            32       salt
34           1        nonce_len (0x0C = 12)
35           12       nonce
47           2        fname_len (little-endian uint16)
49           fname_len  original filename (UTF-8)
49+fname_len  N        ciphertext (N = plaintext file size)
49+fname_len+N  16    authentication tag
```

- `fname_len` is a 2-byte little-endian unsigned integer (supports filenames up to 65,535 bytes)
- The 16-byte GCM tag is always the final 16 bytes of the file
- There is no padding

### Supported MIME Types

```python
ALLOWED_MIME_TYPES = frozenset({
    "text/plain",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/zip",
    "application/octet-stream",
})
```

### Configuration Constants

```python
# key_manager.py
SCRYPT_N     = 131072   # 2^17
SCRYPT_R     = 8
SCRYPT_P     = 1
SCRYPT_DKLEN = 32
SALT_BYTES   = 32
NONCE_BYTES  = 12
TAG_BYTES    = 16
PAYLOAD_VERSION = 0x01

# file_handler.py
MAX_UPLOAD_BYTES    = 100 * 1024 * 1024   # 100 MB
STREAMING_THRESHOLD = 10  * 1024 * 1024   # 10 MB
CHUNK_SIZE          = 1   * 1024 * 1024   # 1 MB
```

### Temporary File Naming

```python
import uuid

def tmp_upload_path() -> Path:
    return UPLOADS_DIR / f"upload_{uuid.uuid4().hex}"

def tmp_output_path() -> Path:
    return OUTPUTS_DIR / f"output_{uuid.uuid4().hex}"
```

UUID-based names guarantee no two concurrent requests collide and contain no user-supplied data, preventing path traversal via the temp-file name itself.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Text encryption/decryption round-trip

*For any* non-empty UTF-8 plaintext string and any non-empty password string, encrypting the plaintext with the derived key and then decrypting the resulting payload with the same password SHALL recover the original plaintext exactly.

**Validates: Requirements 2.2, 2.3, 3.2, 3.3, 11.1**

---

### Property 2: File encryption/decryption round-trip

*For any* file whose byte contents and filename are given, encrypting the file and then decrypting the resulting Encrypted_Container with the same password SHALL recover the exact original byte contents and the exact original filename.

**Validates: Requirements 4.5, 5.2, 5.3, 11.2**

---

### Property 3: Wrong password always fails authentication

*For any* encrypted payload (text or file) and *for any* password that differs from the one used to encrypt it, the decryption operation SHALL raise an authentication error and SHALL NOT return any portion of the plaintext or plaintext bytes.

**Validates: Requirements 3.4, 5.4, 11.3**

---

### Property 4: Tampered ciphertext always fails authentication

*For any* valid encrypted payload (text or file), flipping any single bit in the ciphertext or tag portion SHALL cause decryption to raise an authentication error and SHALL NOT return any portion of the plaintext.

**Validates: Requirements 3.5, 5.5, 7.4, 11.4, 11.9**

---

### Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)

*For any* two separate encryption operations on the same plaintext with the same password, the resulting payloads SHALL contain different Salt values, different Nonce values, and therefore different ciphertext values.

**Validates: Requirements 2.7, 6.7, 11.7**

---

### Property 6: Empty or whitespace inputs are rejected before cryptographic invocation

*For any* submission where the plaintext field is empty or contains only whitespace, or where the password field is empty, the application SHALL return a validation error and SHALL NOT invoke any function in `crypto_engine` or `key_manager`.

**Validates: Requirements 2.6, 3.7, 4.6, 5.8, 11.6**

---

### Property 7: Invalid Base64 or non-conforming payload is rejected before decryption

*For any* byte sequence that is not valid Base64 or does not conform to the Encrypted_Text_Payload structure, submitting it to the text decryption path SHALL return a validation error and SHALL NOT invoke any decryption primitive.

**Validates: Requirements 3.6, 11.5**

---

### Property 8: Payload serialisation round-trip (structural integrity)

*For any* valid combination of (version, salt, nonce, ciphertext, tag), serialising to the `Encrypted_Text_Payload` binary layout and then deserialising SHALL recover every field exactly.

**Validates: Requirements 6.6, 2.3**

---

### Property 9: Encrypted_Container structural round-trip

*For any* valid combination of (version, salt, nonce, original_filename, ciphertext, tag), writing then parsing an `Encrypted_Container` file SHALL recover all fields exactly.

**Validates: Requirements 4.5, 5.2, 6.6**

---

### Property 10: Unsafe filenames are always rejected before disk write

*For any* filename string that contains `/`, `\`, `..`, or a null byte (`\x00`), submitting it as an upload SHALL cause `file_handler` to reject it and SHALL NOT write any bytes to disk.

**Validates: Requirements 4.3, 5.9, 8.1**

---

## Error Handling

### Validation Errors (HTTP 400)

Raised before any cryptographic work begins:
- Empty plaintext or empty password
- Non-Base64 or structurally invalid `Encrypted_Text_Payload`
- Unsupported payload version identifier
- Unsafe filename (path traversal patterns)
- Unsupported MIME type
- File too large (> 100 MB) — also triggers HTTP 413

All 400 responses return JSON: `{"error": "<human-readable reason>"}`. No key material, no stack trace.

### Authentication Errors (HTTP 422)

Raised after structural parsing succeeds but GCM tag verification fails:
- Wrong password supplied for decryption
- Ciphertext or tag has been modified

Response: `{"error": "Authentication failed. The password may be incorrect or the data may have been tampered with."}` — deliberately generic to avoid oracle attacks.

### Internal Errors (HTTP 500)

Unhandled exceptions are caught by a Flask `@app.errorhandler(Exception)` handler that:
1. Logs the full traceback to `stderr`
2. Calls `file_handler.cleanup()` on any temp paths registered in `flask.g.temp_files`
3. Returns `{"error": "An internal error occurred."}` to the client

### Temp File Cleanup Guarantee

A `teardown_request` signal handler iterates over `flask.g.temp_files` (a list populated by each request handler as temp paths are created) and calls `file_handler.cleanup()` for every registered path. This fires on both successful and failed requests, ensuring no orphaned files remain even if an exception escapes request handling.

---

## Testing Strategy

### Framework and Libraries

- **pytest** — test runner
- **hypothesis** — property-based testing library (generates arbitrary inputs, `@settings(max_examples=200)`)
- **pytest-flask** — Flask test client integration

### Test Layout

```
tests/
├── conftest.py              # fixtures: app client, sample files, known key vectors
├── test_key_manager.py      # unit tests for salt/nonce generation and key derivation
├── test_crypto_engine.py    # property tests + unit tests for encrypt/decrypt
├── test_file_handler.py     # unit tests for validation and container parsing
├── test_routes.py           # integration tests via Flask test client
└── test_streaming.py        # property tests for large-file streaming path
```

### Unit Tests

Concrete example-based tests covering:
- Key derivation produces exactly 32 bytes
- Same (password, salt) pair derives the same key deterministically
- Encrypt/decrypt with known test vectors
- File container parse/write for representative filenames and sizes
- All HTTP 400/413/422/500 error responses via the Flask test client
- Download response includes `Content-Disposition: attachment` with correct filename
- Unsupported version identifier returns HTTP 400

### Property-Based Tests (Hypothesis)

Each property test maps directly to a numbered Correctness Property above. All tests are annotated with the tag format `# Feature: secure-crypt, Property N: <property_text>` and run with `@settings(max_examples=200)`.

| Test function | Hypothesis strategies | Correctness Property |
|---|---|---|
| `test_text_round_trip` | `st.text(min_size=1)` × 2 | Property 1 |
| `test_file_round_trip` | `st.binary(min_size=1)`, `st.text(min_size=1)` | Property 2 |
| `test_wrong_password_text` | random text + two distinct passwords | Property 3 |
| `test_wrong_password_file` | random bytes + two distinct passwords | Property 3 |
| `test_bit_flip_text` | random payload, random bit index | Property 4 |
| `test_bit_flip_file` | random file bytes, random byte offset | Property 4 |
| `test_unique_salt_nonce` | same plaintext + password, two calls | Property 5 |
| `test_empty_inputs_rejected` | empty and whitespace-only strings | Property 6 |
| `test_invalid_payload_rejected` | `st.binary()` not conforming to schema | Property 7 |
| `test_payload_serialise_round_trip` | `st.binary(min_size=1)` for ciphertext | Property 8 |
| `test_container_round_trip` | `st.binary(min_size=1)`, `st.text()` | Property 9 |
| `test_unsafe_filename_rejected` | filenames with injected `/`, `\`, `..`, `\x00` | Property 10 |

### Integration Tests

- End-to-end encrypt → download → upload → decrypt cycle via Flask test client
- Verify HTTP status codes for every defined error condition
- Verify `Content-Disposition` header on file download responses
- Verify `flask.g.temp_files` cleanup fires on both success and failure paths

### Streaming Tests

- Encrypt/decrypt at exactly the 10 MB streaming threshold (boundary condition)
- Encrypt/decrypt at exactly the 100 MB size limit (boundary condition)
- Verify mid-stream authentication failure discards all output and deletes the temp output file
- Verify that files whose size is not a multiple of 1 MB encrypt and decrypt correctly (non-aligned chunk boundary)
