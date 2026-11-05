import pytest

from app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    import file_handler
    monkeypatch.setattr(file_handler, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(file_handler, "OUTPUTS_DIR", tmp_path / "outputs")
    return create_app({"TESTING": True})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_text():
    return "SecureCrypt round trip"


@pytest.fixture
def sample_binary():
    return b"\x00\x01securecrypt\xff"


@pytest.fixture
def known_key_vector():
    from key_manager import derive_key
    salt = bytes(range(32))
    password = "known vector password"
    return password, salt, derive_key(password, salt)
