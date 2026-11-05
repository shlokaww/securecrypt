c# Implementation Plan: SecureCrypt

## Overview

Implement SecureCrypt as a Flask/Python AES-256-GCM encryption application using a thin-controller / rich-service architecture. Tasks follow the prescribed module dependency order: scaffolding → key_manager → crypto_engine → file_handler → app → templates → static assets → tests → Docker → README. Each task builds directly on the previous and ends with all components wired together.

---

## Tasks

- [x] 1. Project scaffolding
  - [x] 1.1 Create directory structure and configuration files
    - Create top-level directories: `tests/`, `templates/`, `static/css/`, `static/js/`, `uploads/`, `outputs/`
    - Create `uploads/.gitkeep` and `outputs/.gitkeep` so empty dirs are tracked
    - Create `.gitignore` excluding `__pycache__/`, `*.pyc`, `*.pyo`, `.env`, `uploads/*`, `outputs/*`, `!uploads/.gitkeep`, `!outputs/.gitkeep`, `.venv/`, `dist/`, `*.egg-info/`
    - Create `.dockerignore` excluding `uploads/`, `outputs/`, `tests/`, `.git/`, `__pycache__/`, `*.pyc`, `*.pyo`, `.env`, `*.md`
    - _Requirements: 10.4_

  - [x] 1.2 Create `requirements.txt`
    - Pin exact versions: `Flask==3.0.3`, `cryptography==42.0.8`, `hypothesis==6.103.1`, `pytest==8.2.2`, `pytest-flask==1.3.0`, `Werkzeug==3.0.3`, `gunicorn==22.0.0`
    - _Requirements: 10.1_

- [x] 2. Implement `key_manager.py`
  - [x] 2.1 Implement salt, nonce, and key derivation functions
    - Define module-level constants: `SCRYPT_N=131072`, `SCRYPT_R=8`, `SCRYPT_P=1`, `SCRYPT_DKLEN=32`, `SALT_BYTES=32`, `NONCE_BYTES=12`, `TAG_BYTES=16`, `PAYLOAD_VERSION=0x01`
    - Implement `generate_salt() -> bytes` using `os.urandom(32)`
    - Implement `generate_nonce() -> bytes` using `os.urandom(12)`
    - Implement `derive_key(password: str, salt: bytes) -> bytes` using `cryptography.hazmat.primitives.kdf.scrypt.Scrypt` with the above parameters; raise `ValueError` for empty password or salt not 32 bytes
    - _Requirements: 6.1, 6.2, 6.3_

  - [x] 2.2 Write property test for key derivation uniqueness
    - **Property 5: Encryption is non-deterministic (unique Salt and Nonce per operation)**
    - **Validates: Requirements 2.7, 6.7, 11.7**
    - Use `@given(st.text(min_size=1))` to confirm two `generate_salt()` calls return different values and two `generate_nonce()` calls return different values
    - Use `@given(st.text(min_size=1), st.binary(min_size=32, max_size=32))` to confirm `derive_key` is deterministic for the same (password, salt) but produces different output for different salts

  - [x] 2.3 Write unit tests for `key_manager.py` (`tests/test_key_manager.py`)
    - Verify `generate_salt()` returns exactly 32 bytes
    - Verify `generate_nonce()` returns exactly 12 bytes
    - Verify `derive_key` returns exactly 32 bytes
    - Verify `derive_key` is deterministic: same (password, salt) → same key
    - Verify `derive_key` raises `ValueError` for empty password
    - Verify `derive_key` raises `ValueError` for salt that is not 32 bytes
    - _Requirements: 6.1, 6.2, 6.3, 11.7_

- [x] 3. Implement `crypto_engine.py`
  - [x] 3.1 Implement payload serialisation helpers
    - Implement `build_text_payload(version, salt, nonce, ciphertext, tag) -> bytes` following the length-prefixed layout in the design
    - Implement `parse_text_payload(raw: bytes) -> tuple[int, bytes, bytes, bytes, bytes]` extracting (version, salt, nonce, ciphertext, tag); raise `ValueError` on structurally invalid input (buffer too short, lengths out of range)
    - _Requirements: 2.3, 6.6_

  - [x] 3.2 Write property test for payload serialisation round-trip
    - **Property 8: Payload serialisation round-trip (structural integrity)**
    - **Validates: Requirements 6.6, 2.3**
    - Use `@given(st.binary(min_size=1))` for ciphertext; fix version=1, salt=32 bytes, nonce=12 bytes, tag=16 bytes
    - Assert `parse_text_payload(build_text_payload(...))` recovers every field exactly

  - [x] 3.3 Implement `encrypt_text` and `decrypt_text`
    - Implement `encrypt_text(plaintext: str, key: bytes, nonce: bytes) -> tuple[bytes, bytes]` using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`; raise `ValueError` for key not 32 bytes or nonce not 12 bytes
    - Implement `decrypt_text(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> str` decoding the result as UTF-8; raise `InvalidTag` on authentication failure, `ValueError` on structural errors
    - _Requirements: 2.2, 3.2_

  - [x] 3.4 Write property test for text round-trip
    - **Property 1: Text encryption/decryption round-trip**
    - **Validates: Requirements 2.2, 2.3, 3.2, 3.3, 11.1**
    - Use `@given(st.text(min_size=1), st.text(min_size=1))` for (plaintext, password)
    - Derive key from password + fresh salt; assert decrypt(encrypt(plaintext)) == plaintext

  - [x] 3.5 Write property test for wrong password text decryption
    - **Property 3: Wrong password always fails authentication**
    - **Validates: Requirements 3.4, 5.4, 11.3**
    - Use `@given(st.text(min_size=1), st.text(min_size=1), st.text(min_size=1))` ensuring the two passwords differ
    - Assert `decrypt_text` raises `InvalidTag` and returns nothing

  - [x] 3.6 Write property test for tampered ciphertext (text)
    - **Property 4: Tampered ciphertext always fails authentication**
    - **Validates: Requirements 3.5, 5.5, 7.4, 11.4, 11.9**
    - Use `@given(st.text(min_size=1), st.text(min_size=1), st.integers())` to flip a byte in the ciphertext
    - Assert `decrypt_text` raises `InvalidTag`

  - [x] 3.7 Implement `encrypt_file` and `decrypt_file` (streaming via hazmat GCM context)
    - Implement `encrypt_file(src_path, dst_path, key, nonce, chunk_size=1_048_576, streaming_threshold=10_485_760) -> bytes` using `Cipher(algorithms.AES(key), modes.GCM(nonce))` from `cryptography.hazmat.primitives.ciphers`; feed chunks into `encryptor.update(chunk)`, finalise with `encryptor.finalize()`, return `encryptor.tag`
    - For files <= streaming_threshold, read entire file then encrypt; for files > streaming_threshold, stream in 1 MB chunks
    - Implement `decrypt_file(src_path, dst_path, key, nonce, tag, chunk_size=1_048_576, streaming_threshold=10_485_760) -> None` using `modes.GCM(nonce, tag)` hazmat context; feed chunks into `decryptor.update(chunk)`, call `decryptor.finalize_with_tag(tag)` at end; on `InvalidTag`, delete `dst_path` before re-raising
    - _Requirements: 4.5, 5.2, 7.3, 7.4, 7.5_

  - [x] 3.8 Write property test for file round-trip
    - **Property 2: File encryption/decryption round-trip**
    - **Validates: Requirements 4.5, 5.2, 5.3, 11.2**
    - Use `@given(st.binary(min_size=1), st.text(min_size=1))` for (file_bytes, password)
    - Write bytes to temp file; encrypt then decrypt; assert recovered bytes == original bytes

  - [x] 3.9 Write property test for wrong password file decryption
    - **Property 3: Wrong password always fails authentication (file path)**
    - **Validates: Requirements 3.4, 5.4, 11.3**
    - Use two distinct passwords; assert `decrypt_file` raises `InvalidTag`

  - [x] 3.10 Write property test for tampered ciphertext (file)
    - **Property 4: Tampered ciphertext always fails authentication (file path)**
    - **Validates: Requirements 3.5, 5.5, 7.4, 11.4, 11.9**
    - Flip a byte in the encrypted file bytes; assert `decrypt_file` raises `InvalidTag` and deletes temp output

- [~] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement `file_handler.py`
  - [x] 5.1 Implement validation, safe filename, and temp path helpers
    - Define module-level constants: `ALLOWED_MIME_TYPES`, `MAX_UPLOAD_BYTES=100*1024*1024`, `UPLOADS_DIR=Path("uploads")`, `OUTPUTS_DIR=Path("outputs")`
    - Implement `safe_filename(filename: str) -> str`; raise custom `ValidationError` if `/`, `\`, `..`, or `\x00` are present; return filename unchanged if safe
    - Implement `validate_upload(file: FileStorage, max_bytes=MAX_UPLOAD_BYTES) -> None`; check MIME type against `ALLOWED_MIME_TYPES`, call `safe_filename`, check size via `Content-Length` / `os.fstat` without reading content; raise `ValidationError` with specific reason
    - Implement `tmp_upload_path() -> Path` and `tmp_output_path() -> Path` using `uuid.uuid4().hex`
    - Implement `cleanup(*paths: Path) -> None`; silently delete each path if it exists; log failures to `stderr`
    - _Requirements: 4.3, 7.1, 8.1_

  - [x] 5.2 Write property test for unsafe filename rejection
    - **Property 10: Unsafe filenames are always rejected before disk write**
    - **Validates: Requirements 4.3, 5.9, 8.1**
    - Use `@given(st.text())` with injected `/`, `\`, `..`, `\x00` characters
    - Assert `safe_filename` raises `ValidationError` and no file is written to `UPLOADS_DIR`

  - [x] 5.3 Implement `write_encrypted_container` and `parse_encrypted_container`
    - Implement `write_encrypted_container(enc_path, version, salt, nonce, original_filename, ciphertext_path, tag) -> None` following the `Encrypted_Container` binary layout from the design (version, salt_len, salt, nonce_len, nonce, fname_len uint16-LE, fname bytes, ciphertext, tag)
    - Implement `parse_encrypted_container(enc_path) -> tuple[int, bytes, bytes, str, bytes, bytes]` returning (version, salt, nonce, filename, ciphertext, tag); raise `ValidationError` on structural errors
    - _Requirements: 4.5, 5.2, 6.6_

  - [x] 5.4 Write property test for Encrypted_Container structural round-trip
    - **Property 9: Encrypted_Container structural round-trip**
    - **Validates: Requirements 4.5, 5.2, 6.6**
    - Use `@given(st.binary(min_size=1), st.text(min_size=1, max_size=255))` for (ciphertext, filename)
    - Write container, parse it, assert all fields match exactly

  - [x] 5.5 Write unit tests for `file_handler.py` (`tests/test_file_handler.py`)
    - Test `safe_filename` allows normal filenames and rejects traversal patterns
    - Test `validate_upload` rejects unsupported MIME types, oversized files, and unsafe filenames with specific error messages
    - Test `write_encrypted_container` / `parse_encrypted_container` round-trip for representative filenames (ASCII, Unicode, filename with spaces)
    - Test `cleanup` silently succeeds for non-existent paths
    - _Requirements: 4.3, 5.9, 7.1, 8.1_

- [ ] 6. Implement `app.py`
  - [x] 6.1 Create Flask application factory with page routes
    - Create `app.py` with `create_app()` factory
    - Register GET routes: `/` -> `index.html`, `/encrypt` -> `encrypt.html`, `/decrypt` -> `decrypt.html`, `/about` -> `about.html`
    - Register `teardown_request` handler that calls `file_handler.cleanup()` on all paths in `flask.g.temp_files`
    - Register error handlers for 400, 413, 422, 500 returning JSON `{"error": "..."}` with no stack traces or key material
    - _Requirements: 1.2, 6.4, 6.5, 8.3, 8.4_

  - [-] 6.2 Implement `/api/encrypt-text` and `/api/decrypt-text`
    - `POST /api/encrypt-text`: validate non-empty `plaintext` and `password`; call `key_manager.generate_salt()`, `generate_nonce()`, `derive_key()`; call `crypto_engine.encrypt_text()`; call `build_text_payload()`; Base64-encode; return `{"payload": "<base64>"}`
    - `POST /api/decrypt-text`: validate non-empty `payload` and `password`; Base64-decode (return 400 on failure); call `parse_text_payload()` (return 400 on `ValueError`); check version (return 400 if unsupported); `derive_key()`; `decrypt_text()` (return 422 on `InvalidTag`); return `{"plaintext": "..."}`
    - _Requirements: 2.2, 2.3, 3.2, 3.4, 3.5, 3.6, 3.7, 3.8, 6.4, 6.5_

  - [ ] 6.3 Implement `/api/encrypt-file` and `/api/decrypt-file`
    - `POST /api/encrypt-file`: validate file and password presence; call `file_handler.validate_upload()`; write upload to `tmp_upload_path()` registered in `flask.g.temp_files`; generate salt/nonce/key; create `tmp_output_path()` for ciphertext; call `crypto_engine.encrypt_file()`; call `file_handler.write_encrypted_container()`; stream `.enc` file as attachment; register all temp paths in `flask.g.temp_files`
    - `POST /api/decrypt-file`: validate file and password presence; write upload to `tmp_upload_path()` registered in `flask.g.temp_files`; call `file_handler.parse_encrypted_container()` (return 400 on `ValidationError`); derive key; create `tmp_output_path()`; call `crypto_engine.decrypt_file()` (return 422 on `InvalidTag`); stream decrypted file as attachment using restored original filename; register all temp paths in `flask.g.temp_files`
    - _Requirements: 4.3, 4.5, 4.7, 5.2, 5.3, 5.4, 5.5, 5.7, 8.2_

- [~] 7. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement Jinja2 templates
  - [~] 8.1 Create `templates/base.html`
    - Bootstrap 5 CDN link, dark navy `#0a1628` background via inline CSS variable or class, white body text, responsive meta viewport tag
    - Navigation bar with links to Dashboard, Encrypt, Decrypt, About; active link highlighted
    - Block regions: `head_extra`, `content`, `scripts`
    - Ensure all link text has WCAG 2.1 AA contrast ratio >= 4.5:1 against the navbar background
    - _Requirements: 1.2, 1.4_

  - [~] 8.2 Create `templates/index.html`, `templates/encrypt.html`, `templates/decrypt.html`, `templates/about.html`
    - `index.html`: application name "SecureCrypt", algorithm name "AES-256-GCM", plain-language explanation of what AES-256-GCM does, what 256-bit key length means, and what authenticated encryption means; Quick-start cards linking to Encrypt and Decrypt pages
    - `encrypt.html`: text encryption panel (textarea <= 10,000 chars, password input <= 1,024 chars, password toggle button, submit button with spinner placeholder, copy-to-clipboard button, download button) and file encryption panel (file input with drag-drop zone, password input, submit button with spinner placeholder, download button)
    - `decrypt.html`: text decryption panel (payload textarea, password input, password toggle button, submit button) and file decryption panel (`.enc` file input, password input, submit button)
    - `about.html`: project description, cryptographic design details (AES-256-GCM, Scrypt parameters, streaming construction), format documentation
    - Body text minimum font size 14px; all body text contrast >= 4.5:1 on `#0a1628`
    - _Requirements: 1.1, 1.3, 1.4, 2.1, 2.4, 2.5, 2.8, 3.1, 4.1, 4.2, 5.1, 9.1, 9.5_

- [ ] 9. Implement static assets
  - [~] 9.1 Create `static/css/style.css`
    - Define CSS custom properties: `--bg-primary: #0a1628`, `--text-primary: #f0f4ff`
    - Style body, cards, inputs, buttons, dropzone, notification area, spinner using the dark navy palette
    - Responsive layout adjustments at 576px, 768px, 1200px breakpoints
    - Ensure all body text elements achieve WCAG 2.1 AA contrast ratio >= 4.5:1
    - _Requirements: 1.4_

  - [~] 9.2 Create `static/js/main.js`
    - Implement `initPasswordToggle()`: find all `[data-password-toggle]` buttons; toggle `input[type]` between `password` and `text` on click; update icon/label accordingly
    - Implement `initDragDrop(dropzone, fileInput)`: attach `dragover` (prevent default, add visual state) and `drop` event listeners; on drop, set `fileInput.files` via `DataTransfer`; call for each dropzone on the encrypt and decrypt pages
    - Implement `submitWithSpinner(form, spinnerEl, btnEl)`: intercept form submission via `fetch`; disable all inputs and button; show spinner; on response, re-enable controls; call `showNotification` with success/error message
    - Implement `showNotification(message, type, durationMs)`: create Bootstrap alert element; append to notification container; auto-dismiss after `durationMs` ms (>= 3000 for success per requirement 9.3)
    - Implement `copyToClipboard(text, confirmEl)`: call `navigator.clipboard.writeText(text)`; on success, briefly show `confirmEl` for 2 seconds
    - Wire all initialisers in a `DOMContentLoaded` listener
    - _Requirements: 2.4, 2.8, 9.1, 9.2, 9.3, 9.4, 9.6_

- [ ] 10. Write test suite
  - [~] 10.1 Create `tests/conftest.py`
    - Define `app` fixture using `create_app()` with `TESTING=True`
    - Define `client` fixture using `app.test_client()`
    - Define `sample_text` fixture returning a short ASCII string
    - Define `sample_binary` fixture returning known bytes
    - Define `known_key_vector` fixture with a precomputed (password, salt, expected_key) triple for determinism testing
    - _Requirements: 11.1, 11.2_

  - [~] 10.2 Complete `tests/test_key_manager.py` with Hypothesis property tests
    - Include all unit tests from task 2.3
    - Include property test from task 2.2
    - Annotate each property test: `# Feature: secure-crypt, Property 5: ...`; use `@settings(max_examples=200)`
    - _Requirements: 6.1, 6.2, 6.3, 11.7_

  - [~] 10.3 Complete `tests/test_crypto_engine.py` with Hypothesis property tests
    - Include property tests from tasks 3.2, 3.4, 3.5, 3.6
    - Include unit tests: encrypt/decrypt with known test vectors, key/nonce length validation, `InvalidTag` on wrong password, `ValueError` on invalid key length
    - Annotate each property test with `# Feature: secure-crypt, Property N: ...`; use `@settings(max_examples=200)`
    - _Requirements: 11.1, 11.3, 11.4, 11.5, 11.6_

  - [~] 10.4 Complete `tests/test_file_handler.py`
    - Include unit tests from task 5.5
    - Include property tests from tasks 5.2 and 5.4
    - Annotate property tests with `# Feature: secure-crypt, Property N: ...`; use `@settings(max_examples=200)`
    - _Requirements: 11.8_

  - [~] 10.5 Create `tests/test_routes.py` (integration tests via Flask test client)
    - Test `GET /`, `/encrypt`, `/decrypt`, `/about` all return HTTP 200
    - Test `POST /api/encrypt-text` with valid payload returns 200 with Base64 `payload`
    - Test `POST /api/decrypt-text` with correct password returns 200 with `plaintext`
    - Test `POST /api/decrypt-text` with wrong password returns 422
    - Test `POST /api/decrypt-text` with non-Base64 input returns 400
    - Test `POST /api/decrypt-text` with empty password returns 400
    - Test `POST /api/encrypt-text` with empty plaintext returns 400
    - Test `POST /api/encrypt-file` with valid multipart returns 200 and `Content-Disposition: attachment`
    - Test `POST /api/decrypt-file` with valid `.enc` file and correct password returns 200 with original filename in `Content-Disposition`
    - Test `POST /api/decrypt-file` with wrong password returns 422
    - Test `POST /api/decrypt-file` with non-conforming bytes returns 400
    - Test that `flask.g.temp_files` cleanup fires on both success and failure paths (assert no temp files remain after request)
    - Test `POST /api/encrypt-file` with oversized upload returns 413
    - Test that error responses contain no key material or stack trace
    - _Requirements: 3.4, 3.5, 3.6, 3.7, 5.4, 5.5, 5.6, 8.2, 8.3, 8.4, 9.4, 11.3, 11.8, 11.9_

  - [~] 10.6 Create `tests/test_streaming.py`
    - Include property tests from tasks 3.8, 3.9, 3.10
    - Boundary test: encrypt/decrypt file at exactly 10 MB (streaming threshold) — assert round-trip succeeds
    - Boundary test: encrypt/decrypt file at exactly 100 MB — assert round-trip succeeds
    - Boundary test: encrypt/decrypt file whose size is not a multiple of 1 MB — assert round-trip succeeds
    - Mid-stream auth failure test: corrupt the encrypted file after `encrypt_file`, call `decrypt_file`, assert `InvalidTag` is raised and the temp output file does not exist
    - Annotate property tests with `# Feature: secure-crypt, Property N: ...`; use `@settings(max_examples=200)`
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 11.2, 11.10_

- [~] 11. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Docker configuration
  - [~] 12.1 Create `Dockerfile`
    - Base image: `python:3.12-slim`
    - Create non-root user `securecrypt` with `adduser --disabled-password --gecos ''`
    - `COPY requirements.txt .` then `RUN pip install --no-cache-dir -r requirements.txt`
    - `COPY . .` (`.dockerignore` already excludes unnecessary paths)
    - Create `uploads/` and `outputs/` directories, `chown` them to `securecrypt`
    - `USER securecrypt`
    - `EXPOSE 5000`
    - `CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:create_app()"]`
    - _Requirements: 8.6, 10.1_

  - [~] 12.2 Create `docker-compose.yml`
    - Service `securecrypt` built from `Dockerfile`; ports `"5000:5000"`; `restart: unless-stopped`
    - Health check: `test: ["CMD", "curl", "-f", "http://localhost:5000/"]`; `interval: 10s`; `timeout: 5s`; `retries: 3`; `start_period: 15s`
    - _Requirements: 10.2, 10.3, 10.5_

- [ ] 13. Create `README.md`
  - [~] 13.1 Write all required README sections
    - Project introduction: what SecureCrypt is, key features
    - Prerequisites: Docker >= 24.x, Docker Compose >= 2.x
    - Commands: `docker compose build`, `docker compose up -d`, `docker compose down`, `docker compose logs -f`
    - Local execution without Docker: `pip install -r requirements.txt`, `flask --app app run`
    - `Encrypted_Container` binary format table (field, offset, length, description)
    - `Encrypted_Text_Payload` structure table
    - Cryptographic design: AES-256-GCM algorithm and authentication guarantee, Scrypt parameters (N=2^17, r=8, p=1, dklen=32) with rationale, streaming construction rationale (single tag via hazmat GCM context, why chunk-reorder attacks are prevented)
    - Testing: `pip install pytest hypothesis pytest-flask`, `pytest tests/`, expected output
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

- [~] 14. Final checkpoint — Ensure all tests pass
  - Run `pytest tests/` and confirm all tests pass. Ask the user if any questions arise before marking complete.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; all correctness properties are covered by both unit tests and property tests
- Each task references specific requirements for traceability
- The `flask.g.temp_files` pattern ensures cleanup fires via `teardown_request` even when exceptions escape route handlers
- The streaming threshold (10 MB) and chunk size (1 MB) are defined as module-level constants so tests can override them
- Property tests use `@settings(max_examples=200)` as specified in the design's testing strategy
- All property test functions are annotated with `# Feature: secure-crypt, Property N: <property text>` for traceability

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.1"] },
    { "id": 3, "tasks": ["3.2", "3.3"] },
    { "id": 4, "tasks": ["3.4", "3.5", "3.6", "3.7"] },
    { "id": 5, "tasks": ["3.8", "3.9", "3.10", "5.1"] },
    { "id": 6, "tasks": ["5.2", "5.3"] },
    { "id": 7, "tasks": ["5.4", "5.5", "6.1"] },
    { "id": 8, "tasks": ["6.2", "6.3"] },
    { "id": 9, "tasks": ["8.1"] },
    { "id": 10, "tasks": ["8.2", "9.1"] },
    { "id": 11, "tasks": ["9.2"] },
    { "id": 12, "tasks": ["10.1"] },
    { "id": 13, "tasks": ["10.2", "10.3", "10.4"] },
    { "id": 14, "tasks": ["10.5", "10.6"] },
    { "id": 15, "tasks": ["12.1"] },
    { "id": 16, "tasks": ["12.2", "13.1"] }
  ]
}
```
