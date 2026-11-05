# Requirements Document

## Introduction

SecureCrypt is a GUI-based encryption and decryption application built with Python/Flask and served through a web browser. It provides AES-256-GCM symmetric encryption for both text and files, deriving cryptographic keys from user-supplied passwords via Scrypt. The application is packaged with Docker so it can be deployed consistently across environments without manual dependency installation. All encryption operations produce authenticated ciphertext; decryption verifies the authentication tag before returning any plaintext.

## Glossary

- **Application**: The SecureCrypt Flask web application accessible at http://localhost:5000
- **Crypto_Engine**: The Python module responsible for all AES-256-GCM encryption and decryption operations
- **Key_Manager**: The Python module responsible for salt generation, Scrypt key derivation, and nonce generation
- **File_Handler**: The Python module responsible for file upload validation, encrypted-container assembly/parsing, and temporary file lifecycle management
- **Encrypted_Container**: The structured binary format that stores version, salt, nonce, original filename, and ciphertext+tag for encrypted files
- **Encrypted_Text_Payload**: The structured data (version, salt, nonce, ciphertext, tag) serialised as a single Base64 string for text encryption
- **AES-256-GCM**: Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode, providing authenticated encryption
- **Scrypt**: A password-based key derivation function used to derive a 256-bit key from a user password and a random salt
- **Salt**: A cryptographically secure random 32-byte value generated fresh for each encryption operation
- **Nonce**: A cryptographically secure random 12-byte (96-bit) value generated fresh for each AES-GCM encryption operation
- **Authentication_Tag**: The 16-byte GCM tag appended to ciphertext that enables integrity and authenticity verification on decryption
- **User**: A human operating the Application through a web browser

---

## Requirements

### Requirement 1: Dashboard

**User Story:** As a User, I want a clear dashboard landing page, so that I can understand what SecureCrypt does and navigate to encryption or decryption features.

#### Acceptance Criteria

1. THE Application SHALL display the text "SecureCrypt" as the application name and the text "AES-256-GCM" as the algorithm name on the dashboard page, each visible without scrolling on a 1280×720 viewport.
2. THE Application SHALL provide navigation links to Dashboard, Encrypt, Decrypt, and About pages such that each link, when activated, loads the corresponding page and returns an HTTP 200 response.
3. THE Application SHALL display an explanation of AES-256-GCM on the dashboard page that includes at minimum: what the algorithm does, what the 256-bit key length means, and what "authenticated encryption" means — written in plain language without cryptographic jargon.
4. THE Application SHALL render all pages using a dark navy background colour (hex #0a1628 or equivalent with luminance ≤ 0.05) and white or near-white body text (luminance ≥ 0.85), with a minimum body font size of 14px, and SHALL pass WCAG 2.1 AA contrast ratio (≥ 4.5:1) for all body text elements; all pages SHALL use responsive layout with breakpoints at 576px, 768px, and 1200px.

---

### Requirement 2: Text Encryption

**User Story:** As a User, I want to encrypt plaintext using a password, so that I can protect sensitive text and share it securely.

#### Acceptance Criteria

1. THE Application SHALL provide a textarea accepting up to 10,000 characters for plaintext and a password input field accepting up to 1,024 characters that masks the entered password by default on the encrypt page.
2. WHEN the User submits a non-empty plaintext and a non-empty password for text encryption, THE Crypto_Engine SHALL derive a 256-bit key using Scrypt with a freshly generated Salt and encrypt the plaintext using AES-256-GCM with a freshly generated Nonce.
3. WHEN text encryption completes successfully, THE Application SHALL display the result as a single Base64-encoded Encrypted_Text_Payload containing the version identifier, Salt, Nonce, ciphertext, and Authentication_Tag.
4. WHEN text encryption completes successfully, THE Application SHALL provide a copy-to-clipboard button for the Base64 output that, when clicked, copies the full payload to the system clipboard and displays a visible confirmation message within 2 seconds.
5. WHEN text encryption completes successfully, THE Application SHALL provide a download button that saves the Base64 output as a text file named `encrypted_text_<ISO8601_timestamp>.txt`.
6. IF the User submits an empty plaintext field, THEN THE Application SHALL display a validation error identifying the plaintext field specifically and SHALL NOT perform any encryption operation; IF the User submits an empty password field, THEN THE Application SHALL display a validation error identifying the password field specifically and SHALL NOT perform any encryption operation.
7. THE Application SHALL generate a different Salt and a different Nonce for each encryption operation, such that two separate encryptions of the same plaintext with the same password produce different Base64 outputs.
8. WHILE a text encryption operation is in progress, THE Application SHALL display a loading indicator and SHALL disable the submission control until the operation completes or fails.

---

### Requirement 3: Text Decryption

**User Story:** As a User, I want to decrypt an Encrypted_Text_Payload using the original password, so that I can recover the original plaintext.

#### Acceptance Criteria

1. THE Application SHALL provide a text input field for the Base64 Encrypted_Text_Payload and a password input field on the decrypt page.
2. WHEN the User submits a valid Base64 Encrypted_Text_Payload and the correct password, THE Crypto_Engine SHALL extract the version identifier, Salt, Nonce, ciphertext, and Authentication_Tag from the payload, derive the key using Scrypt and the stored Salt, and decrypt and verify the ciphertext using AES-256-GCM.
3. WHEN decryption and authentication succeed, THE Application SHALL display the recovered plaintext to the User.
4. IF the User supplies an incorrect password, THEN THE Application SHALL display a visible, non-empty error message indicating authentication failure; the error message SHALL NOT contain any portion of the plaintext and SHALL NOT reveal the Salt, Nonce, or derived key.
5. IF the Base64 Encrypted_Text_Payload has been modified or is corrupted, THEN THE Application SHALL detect the authentication tag mismatch, display a visible, non-empty error message indicating integrity verification failure, and SHALL NOT return any portion of the plaintext.
6. IF the User submits input that is not valid Base64 or does not conform to the Encrypted_Text_Payload structure, THEN THE Application SHALL display a validation error and SHALL NOT attempt decryption.
7. IF the User submits an empty ciphertext field or an empty password field, THEN THE Application SHALL display a validation error and SHALL NOT attempt decryption.
8. IF the User submits a structurally valid Encrypted_Text_Payload whose version identifier is not supported by the current Crypto_Engine, THEN THE Application SHALL display a validation error stating the version is unsupported and SHALL NOT attempt decryption.

---

### Requirement 4: File Encryption

**User Story:** As a User, I want to encrypt an uploaded file using a password, so that I can protect file contents and download the encrypted result.

#### Acceptance Criteria

1. THE Application SHALL provide a file upload control and a password input field accepting up to 1,024 characters on the file encryption panel.
2. THE Application SHALL accept drag-and-drop file upload in addition to the standard file-browse control.
3. WHEN a User uploads a file, THE File_Handler SHALL validate that the file's MIME type is one of the supported types (plain text, PDF, PNG, JPEG, GIF, WebP, ZIP, application/octet-stream), that the filename contains no path separators, null bytes, or `..` sequences, and that the file size does not exceed the configured upload size limit defined in Requirement 7.
4. IF an uploaded file fails validation, THEN THE Application SHALL display an error message indicating the specific reason for rejection (unsupported type, unsafe filename, or file too large) and SHALL NOT proceed with encryption.
5. WHEN a User submits a valid file and a non-empty password for file encryption, THE Key_Manager SHALL derive a 256-bit key using Scrypt with a freshly generated Salt, THE Crypto_Engine SHALL encrypt the file contents using AES-256-GCM with a freshly generated Nonce, and THE File_Handler SHALL embed the original filename and extension as metadata within the Encrypted_Container.
6. IF the User submits a valid file and an empty password, THEN THE Application SHALL display a validation error and SHALL NOT proceed with encryption.
7. WHEN file encryption completes successfully, THE Application SHALL provide a download link for the Encrypted_Container named `<original_filename>.enc` (for example, `report.pdf.enc`).
8. WHEN the download response for the Encrypted_Container is sent, THE File_Handler SHALL delete all temporary files created during that encryption operation from disk.
9. THE File_Handler SHALL NOT modify the original uploaded file during encryption.

---

### Requirement 5: File Decryption

**User Story:** As a User, I want to decrypt a previously encrypted `.enc` file using the original password, so that I can recover the original file with its original filename and extension.

#### Acceptance Criteria

1. THE Application SHALL provide a file upload control for `.enc` files and a password input field on the file decryption panel.
2. WHEN the User uploads a valid `.enc` file and provides the correct password, THE Crypto_Engine SHALL verify the Authentication_Tag before reading any plaintext, then decrypt the file contents using the Salt and Nonce stored in the Encrypted_Container.
3. WHEN file decryption and authentication succeed, THE Application SHALL restore the original filename and extension from the Encrypted_Container metadata and provide a download link for the decrypted file using the restored original filename.
4. IF the User supplies an incorrect password for file decryption, THEN THE Application SHALL display an error message indicating authentication failure and SHALL NOT provide any decrypted output.
5. IF the uploaded `.enc` file is corrupted or has been tampered with, THEN THE Application SHALL detect the authentication failure, display an error message indicating integrity verification failure, and SHALL NOT provide any decrypted output.
6. IF the uploaded file does not conform to the Encrypted_Container format, THEN THE Application SHALL display a validation error and SHALL NOT attempt decryption.
7. WHEN the download response for the decrypted file is sent, THE File_Handler SHALL delete all temporary files created during that decryption operation from disk; IF an error response is returned instead, THE File_Handler SHALL delete those temporary files before returning the error response.
8. IF the User submits an empty file field or an empty password field for file decryption, THEN THE Application SHALL display a validation error and SHALL NOT attempt decryption.
9. WHEN a User uploads a `.enc` file for decryption, THE File_Handler SHALL validate that the filename contains no path separators, null bytes, or `..` sequences and that the file size does not exceed the configured upload size limit; IF validation fails, THE Application SHALL display an error message indicating the specific reason and SHALL NOT proceed with decryption.

---

### Requirement 6: Key Management and Cryptographic Hygiene

**User Story:** As a security-conscious User, I want the application to follow cryptographic best practices, so that my data is protected even if an attacker captures encrypted output.

#### Acceptance Criteria

1. THE Key_Manager SHALL generate a cryptographically secure random 32-byte Salt for each encryption operation using the operating system's secure random source.
2. THE Key_Manager SHALL generate a cryptographically secure random 12-byte Nonce for each AES-GCM encryption operation using the operating system's secure random source.
3. THE Key_Manager SHALL derive encryption keys exclusively via Scrypt using parameters N=2^17 (131072), r=8, p=1, and dklen=32, with the Salt supplied to each invocation; derived keys SHALL be 256 bits (32 bytes) in length.
4. THE Application SHALL NOT log, store, or transmit passwords, derived keys, or plaintext content.
5. THE Application SHALL NOT expose Salt, Nonce, derived key values, or internal cryptographic details in error messages returned to the User.
6. THE Encrypted_Container and Encrypted_Text_Payload formats SHALL include a 1-byte unsigned integer version identifier as the first byte of the format, with the current version encoded as 0x01.
7. THE Key_Manager SHALL NOT reuse a Salt or Nonce value across any two encryption operations.

---

### Requirement 7: Large File Handling

**User Story:** As a User, I want to encrypt and decrypt large files without the application running out of memory, so that I can protect files of practical sizes.

#### Acceptance Criteria

1. THE File_Handler SHALL enforce a configurable maximum upload size with a default of 100 MB and SHALL evaluate the file size before loading any file content into memory.
2. IF an uploaded file exceeds the configured maximum upload size, THEN THE Application SHALL return an error response indicating the file is too large and SHALL NOT load the file content into memory or proceed with any cryptographic operation.
3. WHEN encrypting or decrypting files whose size exceeds a configurable streaming threshold (default 10 MB), THE Crypto_Engine SHALL process the file in chunks of at most 1 MB, writing each encrypted or decrypted chunk to a temporary output file rather than accumulating the entire output in memory.
4. THE Application SHALL use an authenticated encryption design for streaming such that the Authentication_Tag covers the complete file contents; an attacker who substitutes, reorders, or truncates any chunk SHALL cause authentication to fail and the Application SHALL return an error without providing any decrypted output.
5. IF a streaming decryption operation fails mid-stream due to authentication failure or I/O error, THEN THE Application SHALL discard all partially decrypted output, delete any temporary output file, and return an error response without providing any portion of the plaintext.
6. WHEN file encryption or decryption completes successfully for a file processed via streaming, THE Application SHALL verify that the temporary output file exists and is non-empty before providing the download link.

---

### Requirement 8: Security Controls

**User Story:** As a User, I want the application to prevent common web and file-handling vulnerabilities, so that the server and my data remain safe.

#### Acceptance Criteria

1. WHEN a User uploads a file, THE File_Handler SHALL evaluate the filename for path separators (`/`, `\`), null bytes (`\x00`), and `..` sequences before writing any file to disk; IF any such pattern is detected, THE Application SHALL reject the upload with an error message and SHALL NOT write any file to disk.
2. WHEN a request body exceeds 100 MB, THE Application SHALL return an HTTP 413 response and SHALL NOT process the request body further.
3. WHEN an encryption or decryption operation completes successfully, THE File_Handler SHALL delete all temporary upload and output files created during that operation before returning the response.
4. IF an encryption or decryption operation fails at any point, THE File_Handler SHALL delete all temporary upload and output files created during that operation; the obligation to return an error response is governed by the application's error-handling logic and is not a conjunct of this criterion.
5. THE Application SHALL NOT write passwords, derived key material, or uploaded file content to any log file or persistent storage location.
6. WHERE a non-root user is available within the Docker container, THE Application SHALL run as that non-root user; IF the application is found running as root, THEN THE Application SHALL log a warning to stderr and SHALL continue to start rather than blocking deployment.

---

### Requirement 9: User Interface Controls

**User Story:** As a User, I want a clean, intuitive interface with helpful feedback during operations, so that I can use the application confidently without technical knowledge.

#### Acceptance Criteria

1. THE Application SHALL provide a password visibility toggle on all password input fields such that when toggled to visible, the input type changes from `password` to `text`, and when toggled back, the input type returns to `password`.
2. WHILE an encryption or decryption operation is in progress, THE Application SHALL display a visible loading indicator (spinner or progress bar) within the active panel.
3. WHEN an operation completes successfully, THE Application SHALL display a success notification that remains visible for at least 3 seconds before dismissing.
4. IF an operation fails, THE Application SHALL display an error notification that does not include key material, algorithm parameters, or internal stack traces.
5. THE Application SHALL provide a download button for each encrypted or decrypted output; THE Application SHALL NOT display a download button when no output is available.
6. WHILE an encryption or decryption operation is in progress, THE Application SHALL disable all input controls and the submission button within the active panel to prevent concurrent submissions.

---

### Requirement 10: Containerisation and Deployment

**User Story:** As a deployer, I want to run SecureCrypt using Docker Compose without manual dependency installation, so that the application works consistently across different host environments.

#### Acceptance Criteria

1. THE Application SHALL include a Dockerfile that builds a runnable image using the official `python:3.12-slim` base image and installs all dependencies listed in requirements.txt using `pip install --no-cache-dir -r requirements.txt`.
2. THE Application SHALL include a docker-compose.yml that maps port 5000 on the host to port 5000 in the container, sets `restart: unless-stopped`, and starts the Flask application process; the compose file SHALL declare a health check that confirms the Flask process is listening on port 5000 before the service is marked healthy.
3. WHEN the container is started via `docker compose up`, THE Application SHALL respond to an HTTP GET request to `http://localhost:5000/` with an HTTP 200 status code within 30 seconds of container startup.
4. THE Application SHALL include a .dockerignore file that explicitly excludes the following paths from the Docker build context: `uploads/`, `outputs/`, `tests/`, `.git/`, `__pycache__/`, `*.pyc`, `*.pyo`, `.env`, and `*.md`.
5. WHEN the Docker container exits unexpectedly, Docker Compose SHALL restart the container automatically due to the `restart: unless-stopped` policy.

---

### Requirement 11: Testing

**User Story:** As a developer, I want a comprehensive automated test suite, so that I can verify the correctness and security properties of the cryptographic operations and file handling.

#### Acceptance Criteria

1. THE Application SHALL include Pytest tests that verify successful text encryption followed by decryption recovers the original plaintext exactly (round-trip property).
2. THE Application SHALL include Pytest tests that verify successful file encryption followed by decryption recovers the original file contents exactly and the original filename exactly (round-trip property).
3. THE Application SHALL include Pytest tests that verify decryption with an incorrect password raises an exception or returns an error indicator and does not return any plaintext value.
4. THE Application SHALL include Pytest tests that verify decryption of a ciphertext where one byte has been flipped raises an exception or returns an error indicator and does not return any plaintext value.
5. THE Application SHALL include Pytest tests that verify submitting a non-Base64 string to the text decryption path raises a validation error before any cryptographic operation is invoked.
6. THE Application SHALL include Pytest tests that verify submitting an empty plaintext or an empty password to the text encryption path raises a validation error and does not invoke any cryptographic operation.
7. THE Application SHALL include Pytest tests that verify two separate encryption operations on the same plaintext and the same password produce different Salt values, different Nonce values, and different ciphertext values.
8. THE Application SHALL include Pytest tests that verify submitting a byte sequence that does not conform to the Encrypted_Container format to the file decryption path raises a validation error.
9. THE Application SHALL include Pytest tests that verify submitting a structurally valid Encrypted_Container whose ciphertext has been tampered with raises an authentication error and does not return any file content.
10. THE Application SHALL include Pytest tests that verify file encryption and decryption of a file exactly at the configured maximum size limit completes successfully and the round-trip property holds; and that submitting a file whose plaintext input size strictly exceeds the configured maximum size limit is rejected before any file content is read into memory or any cryptographic operation is attempted.

---

### Requirement 12: Documentation

**User Story:** As a developer or deployer, I want comprehensive README documentation, so that I can set up, run, and understand the application without needing to read the source code.

#### Acceptance Criteria

1. THE Application SHALL include a README.md that contains all of the following sections: project introduction, prerequisites (Docker version, Docker Compose version), build command (`docker compose build`), run command (`docker compose up -d`), stop command (`docker compose down`), log command (`docker compose logs -f`), and local execution instructions without Docker.
2. THE Application SHALL include a README.md that documents the Encrypted_Container binary format specifying the byte layout of each field (version, salt length, salt bytes, nonce length, nonce bytes, filename length, filename bytes, ciphertext+tag bytes), and the Encrypted_Text_Payload structure specifying the fields encoded into the Base64 string.
3. THE Application SHALL include a README.md that documents the cryptographic design choices including: the AES-256-GCM algorithm and its authentication guarantee, the Scrypt parameters used (N, r, p, dklen), the rationale for authenticated streaming and the specific construction used to preserve integrity across chunks.
4. THE Application SHALL include a README.md that documents how to run the test suite including: the command to install test dependencies, the command to execute all tests (`pytest tests/`), and the expected output indicating all tests passed.
