import base64
import io


def test_pages(client):
    for path in ("/", "/encrypt", "/decrypt", "/about"):
        assert client.get(path).status_code == 200


def test_text_round_trip(client):
    encrypted = client.post("/api/encrypt-text", json={"plaintext": "hello", "password": "pw"})
    assert encrypted.status_code == 200
    assert base64.b64decode(encrypted.json["payload"])
    decrypted = client.post("/api/decrypt-text", json={"payload": encrypted.json["payload"], "password": "pw"})
    assert decrypted.json["plaintext"] == "hello"


def test_text_errors(client):
    assert client.post("/api/encrypt-text", json={"plaintext": "", "password": "pw"}).status_code == 400
    assert client.post("/api/decrypt-text", json={"payload": "!", "password": "pw"}).status_code == 400
    encrypted = client.post("/api/encrypt-text", json={"plaintext": "hello", "password": "pw"}).json["payload"]
    assert client.post("/api/decrypt-text", json={"payload": encrypted, "password": "wrong"}).status_code == 422


def test_file_round_trip(client):
    encrypted = client.post("/api/encrypt-file", data={"password": "pw", "file": (io.BytesIO(b"file contents"), "hello.txt", "text/plain")}, content_type="multipart/form-data")
    assert encrypted.status_code == 200
    decrypted = client.post("/api/decrypt-file", data={"password": "pw", "file": (io.BytesIO(encrypted.data), "hello.txt.enc", "application/octet-stream")}, content_type="multipart/form-data")
    assert decrypted.status_code == 200
    assert decrypted.data == b"file contents"
    assert "hello.txt" in decrypted.headers["Content-Disposition"]


def test_file_invalid_container(client):
    response = client.post("/api/decrypt-file", data={"password": "pw", "file": (io.BytesIO(b"bad"), "bad.enc", "application/octet-stream")}, content_type="multipart/form-data")
    assert response.status_code == 400


def test_download_temp_files_are_cleaned_when_response_closes(client):
    import file_handler

    response = client.post(
        "/api/encrypt-file",
        data={"password": "pw", "file": (io.BytesIO(b"download check"), "check.txt", "text/plain")},
        content_type="multipart/form-data",
        buffered=False,
    )
    assert response.status_code == 200
    assert list(file_handler.OUTPUTS_DIR.iterdir())
    assert response.get_data()
    response.close()
    assert list(file_handler.OUTPUTS_DIR.iterdir()) == []
    assert list(file_handler.UPLOADS_DIR.iterdir()) == []
