import asyncio
import os
import sqlite3
import tempfile
import uuid
from types import SimpleNamespace

import pytest

from chat import (
    ChatHTTPHandler,
    Database,
    safe_filename,
    validate_file_id,
    validate_label,
    validate_public_key,
)


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

def test_replay_window_accepts_out_of_order_and_rejects_duplicates():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.save_session("bb", "session", b"session-key", initiator=True)
        db.mark_recv_counter("bb", 2)
        db.mark_recv_counter("bb", 1)
        with pytest.raises(ValueError):
            db.mark_recv_counter("bb", 1)
        assert db.get_session("bb")["recv_counter"] == 2
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_group_keys_chunks_metrics_and_friend_verification_persist():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        gid = str(uuid.uuid4())
        db.create_group(gid, "Team", "aa")
        db.save_group_key(gid, 1, b"g" * 32, "aa")
        assert db.get_group_key(gid)["key"] == b"g" * 32
        db.add_friend("bb", "Bob")
        db.verify_friend("bb")
        db.set_friend_transport("bb", "alias", "ws://127.0.0.1:9999")
        friend = db.get_friends()[0]
        assert friend["verified"] == 1
        assert friend["direct_url"] == "ws://127.0.0.1:9999"
        file_id = str(uuid.uuid4())
        assert db.save_file_chunk(file_id, 0, 1, "/tmp/chunk") is True
        assert db.save_file_chunk(file_id, 0, 1, "/tmp/chunk") is False
        db.metric_inc("relay_sent", 2)
        assert db.metrics()["relay_sent"] == 2
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_http_auth_required_for_root_when_remote_mode_enabled():
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/"
    handler.require_http_auth = True
    handler._http_authenticated = lambda parsed: False
    called = []
    handler.send_error = lambda code, msg="": called.append((code, msg))
    handler._send = lambda *_args, **_kwargs: called.append(("sent", "ok"))
    handler.send_response = lambda *_args, **_kwargs: None
    handler.send_header = lambda *_args, **_kwargs: None
    handler.end_headers = lambda: None
    handler.wfile = SimpleNamespace(write=lambda _data: None)
    ChatHTTPHandler.do_GET(handler)
    assert called and called[0][0] == 401


def test_remote_mode_csp_includes_dynamic_host():
    headers = {}
    handler = object.__new__(ChatHTTPHandler)
    handler.require_http_auth = True
    handler.headers = {"Host": "chat.example.com:8443"}
    handler.send_header = lambda k, v: headers.__setitem__(k, v)
    ChatHTTPHandler._security_headers(handler)
    csp = headers["Content-Security-Policy"]
    assert "ws://chat.example.com:8443" in csp
    assert "wss://chat.example.com:8443" in csp


def test_remote_mode_ui_url_prints_token(monkeypatch):
    printed = []

    class FakeNode:
        def __init__(self, *_args, **_kwargs):
            self.public_key = "ab" * 8
            self.ui_token = "token123"
            self.db = SimpleNamespace(close=lambda: None)
            self.allow_remote_ui = False

        async def connect_signaling_loop(self):
            return None

    async def fake_start_ui_ws(*_args, **_kwargs):
        return None

    async def fake_start_direct_peer(*_args, **_kwargs):
        return None

    def fake_start_http(*_args, **_kwargs):
        return SimpleNamespace(shutdown=lambda: None)

    monkeypatch.setattr("chat.QuantumNode", FakeNode)
    monkeypatch.setattr("chat.start_http", fake_start_http)
    monkeypatch.setattr("chat.start_ui_ws", fake_start_ui_ws)
    monkeypatch.setattr("chat.start_direct_peer", fake_start_direct_peer)
    monkeypatch.setattr("chat.key_fingerprint", lambda _k: "ff:ff")
    monkeypatch.setattr("builtins.print", lambda *args, **_kwargs: printed.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr("chat.webbrowser.open", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("chat.asyncio.create_task", lambda coro: coro)
    monkeypatch.setattr("chat.asyncio.gather", lambda *tasks: (_ for _ in ()).throw(asyncio.CancelledError()))
    monkeypatch.setattr("chat.asyncio.Future", lambda: None)

    args = SimpleNamespace(
        db=":memory:",
        signaling_url="ws://127.0.0.1:8766",
        enable_direct=False,
        direct_advertise_host=None,
        direct_host="127.0.0.1",
        direct_port=8768,
        allow_remote_ui=True,
        http_host="0.0.0.0",
        http_port=9000,
        ui_ws_port=8765,
        open_browser=False,
        with_signaling=False,
        signaling_host="0.0.0.0",
        signaling_port=8766,
        ui_ws_host="0.0.0.0",
    )
    with pytest.raises(asyncio.CancelledError):
        import chat
        asyncio.run(chat.run_node(args))
    assert any("UI:        http://0.0.0.0:9000?token=token123" in line for line in printed)
