"""
app.py — Flask application factory for SecureCrypt.

Responsibilities
----------------
- Expose ``create_app()`` for use by the WSGI entry-point, tests, and Docker.
- Register GET page routes for the four HTML pages.
- Stub POST API routes (to be implemented in later tasks).
- Register a ``teardown_request`` handler that cleans up any temp files
  registered in ``flask.g.temp_files`` during the request.
- Register error handlers for 400, 413, 422, and 500 that return JSON with
  no key material and no stack traces in the response body.

References: Requirements 1.2, 6.4, 6.5, 8.3, 8.4
"""

from __future__ import annotations

import base64
import sys
import traceback

from cryptography.exceptions import InvalidTag
from flask import Flask, g, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

import crypto_engine
import file_handler
import key_manager


def create_app(config: dict | None = None) -> Flask:
    """Application factory.

    Parameters
    ----------
    config:
        Optional dict of Flask config overrides (e.g. ``{"TESTING": True}``).
        When *None*, production defaults are used.

    Returns
    -------
    Flask
        A fully configured Flask application instance.
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Core configuration
    # ------------------------------------------------------------------
    # Flask enforces this limit and automatically raises a 413 when the
    # incoming request body exceeds it (Requirement 7.1, 8.2).
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

    if config:
        app.config.update(config)

    # ------------------------------------------------------------------
    # Teardown handler — temp-file cleanup (Requirements 8.3, 8.4)
    # ------------------------------------------------------------------

    @app.teardown_request
    def _cleanup_temp_files(exc: BaseException | None) -> None:  # noqa: ANN001
        """Delete every temp path registered in ``g.temp_files``.

        Fires on *both* successful and failed requests, ensuring no orphaned
        temporary files remain on disk regardless of how the request ended.
        ``getattr`` is used because ``g`` may not have the attribute if the
        request handler never created any temp files.
        """
        for path in getattr(g, "temp_files", []):
            file_handler.cleanup(path)

    def _send_temp_download(path, download_name: str):
        """Keep generated download files alive until the response is closed.

        WSGI servers stream a ``send_file`` response after request teardown.
        Deferring cleanup to response close prevents teardown from deleting the
        file before Gunicorn has finished sending it.
        """
        response = send_file(
            str(path),
            as_attachment=True,
            download_name=download_name,
        )
        temp_paths = tuple(getattr(g, "temp_files", ()))
        g.temp_files = []

        def _stream_and_cleanup(iterable):
            try:
                yield from iterable
            finally:
                close = getattr(iterable, "close", None)
                if close is not None:
                    close()
                file_handler.cleanup(*temp_paths)

        response.response = _stream_and_cleanup(response.response)
        return response

    # ------------------------------------------------------------------
    # Page routes (GET)  — Requirements 1.2
    # ------------------------------------------------------------------

    @app.route("/")
    def index():  # type: ignore[return]
        """Dashboard page."""
        return render_template("index.html")

    @app.route("/encrypt")
    def encrypt_page():  # type: ignore[return]
        """Encrypt page."""
        return render_template("encrypt.html")

    @app.route("/decrypt")
    def decrypt_page():  # type: ignore[return]
        """Decrypt page."""
        return render_template("decrypt.html")

    @app.route("/about")
    def about():  # type: ignore[return]
        """About page."""
        return render_template("about.html")

    # ------------------------------------------------------------------
    # API route stubs (POST) — to be implemented in later tasks
    # ------------------------------------------------------------------

    @app.route("/api/encrypt-text", methods=["POST"])
    def api_encrypt_text():
        """Encrypt plaintext with a password and return a Base64 payload.

        Request JSON: {plaintext, password}
        Response JSON: {payload: "<base64>"}

        Requirements: 2.2, 2.3, 3.2, 3.4, 3.5, 3.6, 3.7, 3.8, 6.4, 6.5
        """
        data = request.get_json(silent=True) or {}

        plaintext = data.get("plaintext", "")
        password = data.get("password", "")

        if not plaintext:
            return jsonify({"error": "plaintext is required"}), 400
        if not password:
            return jsonify({"error": "password is required"}), 400

        salt = key_manager.generate_salt()
        nonce = key_manager.generate_nonce()
        derived_key = key_manager.derive_key(password, salt)

        ciphertext, tag = crypto_engine.encrypt_text(plaintext, derived_key, nonce)

        raw_payload = crypto_engine.build_text_payload(
            key_manager.PAYLOAD_VERSION, salt, nonce, ciphertext, tag
        )
        encoded = base64.b64encode(raw_payload).decode()

        return jsonify({"payload": encoded}), 200

    @app.route("/api/decrypt-text", methods=["POST"])
    def api_decrypt_text():
        """Decrypt a Base64 Encrypted_Text_Payload with a password.

        Request JSON: {payload, password}
        Response JSON: {plaintext: "..."}

        Requirements: 2.2, 2.3, 3.2, 3.4, 3.5, 3.6, 3.7, 3.8, 6.4, 6.5
        """
        data = request.get_json(silent=True) or {}

        payload_b64 = data.get("payload", "")
        password = data.get("password", "")

        if not payload_b64:
            return jsonify({"error": "payload is required"}), 400
        if not password:
            return jsonify({"error": "password is required"}), 400

        # Decode Base64 — return 400 on any decoding failure
        try:
            raw_payload = base64.b64decode(payload_b64)
        except Exception:
            return jsonify({"error": "Invalid payload encoding"}), 400

        # Parse the binary payload structure — return 400 on structural errors
        try:
            version, salt, nonce, ciphertext, tag = crypto_engine.parse_text_payload(raw_payload)
        except ValueError:
            return jsonify({"error": "Invalid payload structure"}), 400

        # Version check — only 0x01 is supported
        if version != key_manager.PAYLOAD_VERSION:
            return jsonify({"error": "Unsupported payload version"}), 400

        derived_key = key_manager.derive_key(password, salt)

        # Decrypt and authenticate — return 422 on GCM tag mismatch
        try:
            plaintext = crypto_engine.decrypt_text(ciphertext, tag, derived_key, nonce)
        except InvalidTag:
            return (
                jsonify(
                    {
                        "error": (
                            "Authentication failed. The password may be incorrect "
                            "or the data may have been tampered with."
                        )
                    }
                ),
                422,
            )

        return jsonify({"plaintext": plaintext}), 200

    @app.route("/api/encrypt-file", methods=["POST"])
    def api_encrypt_file():
        """Encrypt an uploaded file with a password and return an Encrypted_Container.

        Request: multipart/form-data {file, password}
        Response: binary .enc file attachment

        Requirements: 4.3, 4.5, 4.7, 5.2, 5.3, 5.4, 5.5, 5.7, 8.2
        """
        if not hasattr(g, "temp_files"):
            g.temp_files = []

        # --- Validate presence of file and password ----------------------
        uploaded_file = request.files.get("file")
        password = request.form.get("password", "")

        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "file is required"}), 400
        if not password:
            return jsonify({"error": "password is required"}), 400

        try:
            file_handler.validate_upload(uploaded_file)
        except file_handler.ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        # --- Validate upload (MIME type, filename safety, size) ----------
        try:
            file_handler.validate_upload(uploaded_file)
        except file_handler.ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        original_filename = uploaded_file.filename

        # --- Write upload to a temp path ---------------------------------
        upload_path = file_handler.tmp_upload_path()
        g.temp_files.append(upload_path)
        uploaded_file.save(str(upload_path))

        # --- Generate salt, nonce, and derived key -----------------------
        salt = key_manager.generate_salt()
        nonce = key_manager.generate_nonce()
        derived_key = key_manager.derive_key(password, salt)

        # --- Encrypt the file; ciphertext written to an intermediate temp -
        ciphertext_path = file_handler.tmp_output_path()
        g.temp_files.append(ciphertext_path)
        tag = crypto_engine.encrypt_file(upload_path, ciphertext_path, derived_key, nonce)

        # --- Assemble the Encrypted_Container into a final .enc temp -----
        container_path = file_handler.tmp_output_path()
        g.temp_files.append(container_path)
        file_handler.write_encrypted_container(
            container_path,
            key_manager.PAYLOAD_VERSION,
            salt,
            nonce,
            original_filename,
            ciphertext_path,
            tag,
        )

        # --- Stream the .enc container as a file attachment --------------
        download_name = f"{original_filename}.enc"
        return _send_temp_download(container_path, download_name)

    @app.route("/api/decrypt-file", methods=["POST"])
    def api_decrypt_file():
        """Decrypt an Encrypted_Container .enc file with a password.

        Request: multipart/form-data {file, password}
        Response: binary file attachment with the original filename restored

        Requirements: 4.3, 4.5, 4.7, 5.2, 5.3, 5.4, 5.5, 5.7, 8.2
        """
        if not hasattr(g, "temp_files"):
            g.temp_files = []

        # --- Validate presence of file and password ----------------------
        uploaded_file = request.files.get("file")
        password = request.form.get("password", "")

        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "file is required"}), 400
        if not password:
            return jsonify({"error": "password is required"}), 400

        try:
            file_handler.validate_upload(uploaded_file)
        except file_handler.ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        # --- Write the .enc upload to a temp path -----------------------
        upload_path = file_handler.tmp_upload_path()
        g.temp_files.append(upload_path)
        uploaded_file.save(str(upload_path))

        # --- Parse the Encrypted_Container; return 400 on ValidationError -
        try:
            version, salt, nonce, original_filename, ciphertext_bytes, tag = (
                file_handler.parse_encrypted_container(upload_path)
            )
        except file_handler.ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        if version != key_manager.PAYLOAD_VERSION:
            return jsonify({"error": "Unsupported encrypted file version"}), 400
        try:
            file_handler.safe_filename(original_filename)
        except file_handler.ValidationError:
            return jsonify({"error": "Encrypted container contains an unsafe filename"}), 400

        # --- Derive the key from the password and stored salt -----------
        derived_key = key_manager.derive_key(password, salt)

        # --- Write raw ciphertext bytes to a temp file for decrypt_file --
        ciphertext_path = file_handler.tmp_output_path()
        g.temp_files.append(ciphertext_path)
        ciphertext_path.write_bytes(ciphertext_bytes)

        # --- Decrypt; return 422 on InvalidTag (wrong password/tampered) -
        output_path = file_handler.tmp_output_path()
        g.temp_files.append(output_path)
        try:
            crypto_engine.decrypt_file(ciphertext_path, output_path, derived_key, nonce, tag)
        except InvalidTag:
            return (
                jsonify(
                    {
                        "error": (
                            "Authentication failed. The password may be incorrect "
                            "or the data may have been tampered with."
                        )
                    }
                ),
                422,
            )

        # --- Stream the decrypted file using the restored original filename -
        return _send_temp_download(output_path, original_filename)

    # ------------------------------------------------------------------
    # Error handlers (Requirements 6.4, 6.5)
    # ------------------------------------------------------------------

    @app.errorhandler(400)
    def bad_request(exc):
        """Validation errors — missing fields, bad Base64, unsafe filename, etc."""
        return jsonify({"error": "Bad request. Please check your input and try again."}), 400

    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(exc):
        """HTTP 413 — request body exceeds 100 MB (Requirement 8.2)."""
        return jsonify({"error": "File too large. Maximum upload size is 100 MB."}), 413

    @app.errorhandler(422)
    def unprocessable_entity(exc):
        """Authentication failure — wrong password or tampered ciphertext."""
        return (
            jsonify(
                {
                    "error": (
                        "Authentication failed. The password may be incorrect "
                        "or the data may have been tampered with."
                    )
                }
            ),
            422,
        )

    @app.errorhandler(500)
    def internal_server_error(exc):
        """Unexpected internal errors — full traceback to stderr only."""
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "An internal error occurred."}), 500

    @app.errorhandler(Exception)
    def unhandled_exception(exc):
        """Catch-all for any unhandled non-HTTP exception.

        Logs the traceback to stderr and returns a generic JSON error so that
        no key material or stack traces ever reach the client
        (Requirements 6.4, 6.5).

        HTTPExceptions (e.g. 404, 405) are passed through to Flask's own
        default handler by returning the exception's native response, so they
        are handled normally (including by any more-specific registered
        handlers above).
        """
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            # Let Flask handle standard HTTP errors with its own response.
            return exc
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "An internal error occurred."}), 500

    return app


# ------------------------------------------------------------------
# WSGI entry-point
# ------------------------------------------------------------------

if __name__ == "__main__":
    create_app().run(debug=False)
