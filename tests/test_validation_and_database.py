import os
import sqlite3
import tempfile
import uuid

import pytest

from chat import Database, safe_filename, validate_file_id, validate_label, validate_public_key


def test_validate_public_key_enforces_hex_and_expected_length():
    assert validate_public_key("AAff", expected_bytes=2) == "aaff"
    with pytest.raises(ValueError):
        validate_public_key("xyz")
    with pytest.raises(ValueError):
        validate_public_key("aaff", expected_bytes=3)


def test_validate_file_id_requires_canonical_uuid():
    file_id = str(uuid.uuid4())
    assert validate_file_id(file_id) == file_id
    for bad in ["../escape", "", file_id.upper(), "not-a-uuid"]:
        with pytest.raises(ValueError):
            validate_file_id(bad)


def test_labels_and_filenames_are_bounded_and_basename_only():
    assert validate_label("  Alice  ", "Nickname", 20) == "Alice"
    assert safe_filename("../secret.txt") == "secret.txt"
    with pytest.raises(ValueError):
        validate_label("x" * 21, "Nickname", 20)


def test_database_encrypts_identity_session_and_message_at_rest():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    key = b"k" * 32
    try:
        db = Database(path, master_key=key)
        db.save_identity("aa", b"secret-key")
        db.save_session("bb", "session", b"session-key", initiator=True)
        inserted = db.save_message("m1", "aa", "hello", "out", recipient="bb")
        assert inserted is True
        assert db.load_identity() == ("aa", b"secret-key")
        assert db.get_session("bb")["key"] == b"session-key"
        assert db.recent_messages()[0]["body"] == "hello"
        conn = sqlite3.connect(path)
        raw_secret, secret_nonce = conn.execute("SELECT secret_key, secret_nonce FROM identity").fetchone()
        raw_message, body_nonce = conn.execute("SELECT body, body_nonce FROM messages").fetchone()
        conn.close()
        assert secret_nonce is not None and raw_secret != b"secret-key"
        assert body_nonce is not None and raw_message != "hello"
        assert db.save_message("m1", "aa", "hello", "out", recipient="bb") is False
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass
