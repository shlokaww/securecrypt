# SecureCrypt

SecureCrypt is a Flask application for password-based text and file encryption using AES-256-GCM. It derives keys with Scrypt and packages files with their original filename. Keep your password safe: it cannot be recovered if lost.

## Prerequisites

- Docker 24.x or newer
- Docker Compose v2 or newer

## Build and run with Docker

```sh
docker compose build
docker compose up -d
docker compose logs -f
docker compose down
```

Open <http://localhost:5000/> after startup.

## Public hosting

The project includes a Render Blueprint in `render.yaml`. Connect this repository to Render and create the `securecrypt` web service from the Blueprint. Render supplies a public `onrender.com` address and HTTPS, so a separately purchased domain is optional. The configured Free compute plan has limited CPU and sleeps when idle. Set `WEB_CONCURRENCY=1` to limit simultaneous Scrypt operations on the small instance.

For a free preview, change the service plan to `free`. Free web services sleep after 15 minutes without traffic and can take about a minute to wake; Render describes this plan as intended for testing and hobby projects rather than production.

## Run locally without Docker

Use Python 3.10 or newer. From the project directory:

```sh
python -m venv .venv
# Activate the environment, then:
pip install -r requirements.txt
flask --app app run
```

## Cryptographic design

AES-256-GCM provides confidentiality and an authentication tag that detects incorrect passwords and modified ciphertext. The 256-bit key is derived from the user's password using Scrypt (N=2^17 / 131072, r=8, p=1, dklen=32). Each encryption gets a random 32-byte salt and 12-byte nonce. Passwords and plaintext are not deliberately logged or persisted.

Large files are encrypted through a single GCM context while reading and writing chunks of up to 1 MiB. The single final tag authenticates the complete ordered stream, so reordered, truncated, or changed content fails verification. Decryption output is discarded on authentication failure.

## Binary formats

### Encrypted_Container

| Field | Offset | Length | Description |
|---|---:|---:|---|
| Version | 0 | 1 byte | Currently `0x01` |
| Salt length | 1 | 1 byte | Currently 32 |
| Salt | 2 | 32 bytes | Random Scrypt salt |
| Nonce length | 34 | 1 byte | Currently 12 |
| Nonce | 35 | 12 bytes | AES-GCM nonce |
| Filename length | 47 | 2 bytes | Unsigned little-endian byte count |
| Filename | 49 | Variable | Original filename encoded as UTF-8 |
| Ciphertext | After filename | Variable | Encrypted original file bytes |
| Authentication tag | Final 16 bytes | 16 bytes | AES-GCM tag |

### Encrypted_Text_Payload

Binary fields in order: version (1 byte), salt length (1 byte), salt, nonce length (1 byte), nonce, ciphertext, and the final 16-byte authentication tag. The ciphertext length is inferred from the remaining bytes. The complete binary structure is Base64 encoded for transport.

## Tests

Install test dependencies and run the suite:

```sh
pip install pytest hypothesis pytest-flask
pytest tests/
```

Expected result: pytest reports all collected tests passed (e.g. `N passed`).
