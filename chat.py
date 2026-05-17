#!/usr/bin/env python3
"""
Quantum Chat: production-oriented post-quantum, end-to-end encrypted P2P chat.

One-file application with:
- local browser UI served over HTTP
- local UI WebSocket API
- optional built-in signaling/relay WebSocket server
- post-quantum session setup (ML-DSA/Dilithium signatures + Kyber KEM)
- AES-256-GCM encrypted messages/files
- SQLite identity, friends, sessions, groups, and message/file metadata
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import logging
import time
import uuid
import webbrowser
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import quote, urlparse, parse_qs
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional, Set, Tuple

APP_NAME = "Quantum Chat"
DB_FILE = "quantum_chat.db"
FILES_DIR = "files"
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8000
UI_WS_HOST = "127.0.0.1"
UI_WS_PORT = 8765
SIGNALING_HOST = "0.0.0.0"
SIGNALING_PORT = 8766
DEFAULT_SIGNALING_URL = "ws://127.0.0.1:8766"
MAX_TEXT_BYTES = 64 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
PENDING_OFFER_TTL = 5 * 60
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_NICKNAME_CHARS = 80
MAX_GROUP_NAME_CHARS = 120
MAX_FILENAME_CHARS = 180
MAX_GROUP_MEMBERS = 128
SCHEMA_VERSION = 2
LOG = logging.getLogger("quantum_chat")


def validate_public_key(pubkey: str, expected_bytes: Optional[int] = None) -> str:
    value = (pubkey or "").strip().lower()
    if not value or len(value) % 2 or not HEX_RE.fullmatch(value):
        raise ValueError("Public key must be a non-empty hexadecimal string")
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        raise ValueError(f"Public key must be {expected_bytes} bytes ({expected_bytes * 2} hex characters)")
    return value


def validate_file_id(file_id: str) -> str:
    value = (file_id or "").strip()
    if not UUID_RE.fullmatch(value):
        raise ValueError("File id must be a canonical UUID")
    return str(uuid.UUID(value))


def validate_label(value: Any, field: str, max_chars: int, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_chars:
        raise ValueError(f"{field} is too long; maximum is {max_chars} characters")
    return text


def safe_filename(filename: Any) -> str:
    name = os.path.basename(str(filename or "").replace("\\", "/")).strip() or "download.bin"
    name = name[:MAX_FILENAME_CHARS]
    return name or "download.bin"


def utc_ts() -> int:
    return int(time.time())


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def short_key(pubkey: str) -> str:
    return f"{pubkey[:12]}…{pubkey[-8:]}" if len(pubkey) > 24 else pubkey


def require_websockets():
    try:
        import websockets  # type: ignore
        return websockets
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: websockets. Install with `python -m pip install -r requirements.txt`.") from exc


def require_cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        return AESGCM, HKDF, hashes
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: cryptography. Install with `python -m pip install -r requirements.txt`.") from exc


class PQModule:
    """Small compatibility wrapper for pqcrypto import/API drift."""

    def __init__(self) -> None:
        try:
            from pqcrypto.sign import dilithium3 as sign_mod  # type: ignore
        except ModuleNotFoundError:
            try:
                from pqcrypto.dilithium import Dilithium3 as sign_mod  # type: ignore
            except ModuleNotFoundError as exc:
                raise SystemExit("Missing dependency: pqcrypto. Install with `python -m pip install -r requirements.txt`.") from exc
        try:
            from pqcrypto.kem import kyber512 as kem_mod  # type: ignore
        except ModuleNotFoundError:
            try:
                from pqcrypto.kyber import Kyber512 as kem_mod  # type: ignore
            except ModuleNotFoundError as exc:
                raise SystemExit("Missing dependency: pqcrypto. Install with `python -m pip install -r requirements.txt`.") from exc
        self.sign_mod = sign_mod
        self.kem_mod = kem_mod
        pk, _ = self.sign_keypair()
        self.sign_public_key_bytes = len(pk)

    def sign_keypair(self) -> Tuple[bytes, bytes]:
        return self.sign_mod.generate_keypair() if hasattr(self.sign_mod, "generate_keypair") else self.sign_mod.keypair()

    def kem_keypair(self) -> Tuple[bytes, bytes]:
        return self.kem_mod.generate_keypair() if hasattr(self.kem_mod, "generate_keypair") else self.kem_mod.keypair()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        try:
            return self.sign_mod.sign(secret_key, message)
        except TypeError:
            return self.sign_mod.sign(message, secret_key)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            self.sign_mod.verify(public_key, message, signature)
            return True
        except TypeError:
            try:
                self.sign_mod.verify(message, signature, public_key)
                return True
            except Exception:
                return False
        except Exception:
            return False

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return self.kem_mod.encrypt(public_key) if hasattr(self.kem_mod, "encrypt") else self.kem_mod.encapsulate(public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        try:
            return self.kem_mod.decrypt(secret_key, ciphertext)
        except TypeError:
            return self.kem_mod.decapsulate(secret_key, ciphertext)


class QuantumCrypto:
    def __init__(self) -> None:
        self.pq = PQModule()
        self.AESGCM, self.HKDF, self.hashes = require_cryptography()
        self.sign_public_key_bytes = self.pq.sign_public_key_bytes

    def new_identity(self) -> Tuple[bytes, bytes]:
        return self.pq.sign_keypair()

    def new_kem_keypair(self) -> Tuple[bytes, bytes]:
        return self.pq.kem_keypair()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return self.pq.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self.pq.verify(public_key, message, signature)

    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return self.pq.encapsulate(public_key)

    def kem_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self.pq.decapsulate(secret_key, ciphertext)

    def derive_session_key(self, shared_secret: bytes, a_pub: str, b_pub: str, session_id: str, transcript: Optional[Dict[str, Any]] = None) -> bytes:
        transcript_hash = hashlib.sha256(canonical_json(transcript or {})).hexdigest()
        salt = hashlib.sha256("|".join(sorted([a_pub, b_pub]) + [session_id, transcript_hash]).encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt, info=b"quantum-chat-v4-session-transcript")
        return hkdf.derive(shared_secret)

    def derive_message_key(self, session_key: bytes, peer_pubkey: str, counter: int, purpose: str) -> bytes:
        salt = hashlib.sha256(f"{peer_pubkey}:{counter}:{purpose}".encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt, info=b"quantum-chat-v1-message-key")
        return hkdf.derive(session_key)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.AESGCM(key).encrypt(nonce, plaintext, aad)
        return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

    def decrypt(self, key: bytes, packet: Dict[str, str], aad: bytes = b"") -> bytes:
        return self.AESGCM(key).decrypt(b64d(packet["nonce"]), b64d(packet["ciphertext"]), aad)


class LocalKeyStore:
    """Small local key store used to encrypt data at rest.

    The key is stored beside the database with owner-only permissions. This is
    not a substitute for an OS keychain or user passphrase, but it prevents
    casual plaintext disclosure from the SQLite database and files directory.
    """

    def __init__(self, db_path: str) -> None:
        self.path = Path(f"{db_path}.key")

    def load_or_create(self) -> bytes:
        if self.path.exists():
            raw = self.path.read_bytes().strip()
            try:
                key = b64d(raw.decode("ascii"))
            except Exception as exc:
                raise RuntimeError(f"Invalid local key file: {self.path}") from exc
            if len(key) != 32:
                raise RuntimeError(f"Invalid local key length in {self.path}")
            return key
        key = secrets.token_bytes(32)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(b64e(key), encoding="ascii")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)
        return key


class Database:
    def __init__(self, db_path: str = DB_FILE, master_key: Optional[bytes] = None) -> None:
        self.path = db_path
        self.master_key = master_key
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self._init_tables()

    def _init_tables(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    public_key TEXT NOT NULL,
                    secret_key BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    secret_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS friends (
                    pubkey TEXT PRIMARY KEY,
                    nickname TEXT,
                    trusted INTEGER NOT NULL DEFAULT 1,
                    added_at INTEGER NOT NULL,
                    last_seen INTEGER
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    peer_pubkey TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    key BLOB NOT NULL,
                    established_at INTEGER NOT NULL,
                    initiator INTEGER NOT NULL DEFAULT 0,
                    key_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0,
                    send_counter INTEGER NOT NULL DEFAULT 0,
                    recv_counter INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    owner_pubkey TEXT,
                    epoch INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    pubkey TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, pubkey),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT UNIQUE NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    recipient_pubkey TEXT,
                    group_id TEXT,
                    body TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'sent',
                    body_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    recipient_pubkey TEXT,
                    group_id TEXT,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    file_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_pubkey TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_messages_target ON messages(sender_pubkey, recipient_pubkey, group_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_outbox_target_status ON outbox(target_pubkey, status);
                """
            )
            self._ensure_columns()
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.conn.commit()

    def _columns(self, table: str) -> Set[str]:
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def _ensure_columns(self) -> None:
        additions = {
            "identity": [("secret_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
            "sessions": [("key_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0"), ("send_counter", "INTEGER NOT NULL DEFAULT 0"), ("recv_counter", "INTEGER NOT NULL DEFAULT 0")],
            "groups": [("owner_pubkey", "TEXT"), ("epoch", "INTEGER NOT NULL DEFAULT 1")],
            "group_members": [("role", "TEXT NOT NULL DEFAULT 'member'")],
            "messages": [("status", "TEXT NOT NULL DEFAULT 'sent'"), ("body_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
            "files": [("file_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
        }
        for table, cols in additions.items():
            existing = self._columns(table)
            for name, ddl in cols:
                if name not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def _aead(self):
        if not self.master_key:
            return None
        AESGCM, _, _ = require_cryptography()
        return AESGCM(self.master_key)

    def encrypt_blob(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, Optional[bytes], int]:
        aead = self._aead()
        if not aead:
            return plaintext, None, 0
        nonce = secrets.token_bytes(12)
        return aead.encrypt(nonce, plaintext, aad), nonce, 1

    def decrypt_blob(self, ciphertext: bytes, nonce: Optional[bytes], aad: bytes = b"") -> bytes:
        if not nonce:
            return ciphertext
        aead = self._aead()
        if not aead:
            raise RuntimeError("Encrypted database value cannot be decrypted without a master key")
        return aead.decrypt(nonce, ciphertext, aad)

    def load_identity(self) -> Optional[Tuple[str, bytes]]:
        with self.lock:
            row = self.conn.execute("SELECT public_key, secret_key, secret_nonce FROM identity WHERE id=1").fetchone()
            if not row:
                return None
            secret = self.decrypt_blob(row["secret_key"], row["secret_nonce"], f"identity:{row['public_key']}".encode())
            return (row["public_key"], secret)

    def save_identity(self, public_key: str, secret_key: bytes) -> None:
        blob, nonce, version = self.encrypt_blob(secret_key, f"identity:{public_key}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO identity (id, public_key, secret_key, created_at, secret_nonce, key_version) VALUES (1, ?, ?, ?, ?, ?)",
                (public_key, blob, utc_ts(), nonce, version),
            )
            self.conn.commit()

    def add_friend(self, pubkey: str, nickname: Optional[str] = None) -> None:
        nickname = validate_label(nickname, "Nickname", MAX_NICKNAME_CHARS) or None
        with self.lock:
            self.conn.execute(
                "INSERT INTO friends (pubkey, nickname, added_at) VALUES (?, ?, ?) "
                "ON CONFLICT(pubkey) DO UPDATE SET nickname=COALESCE(excluded.nickname, friends.nickname), trusted=1",
                (pubkey, nickname, utc_ts()),
            )
            self.conn.commit()

    def remove_friend(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM friends WHERE pubkey=?", (pubkey,))
            self.conn.execute("DELETE FROM sessions WHERE peer_pubkey=?", (pubkey,))
            self.conn.commit()

    def get_friends(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT pubkey, nickname, last_seen FROM friends ORDER BY added_at DESC")]

    def is_friend(self, pubkey: str) -> bool:
        with self.lock:
            return self.conn.execute("SELECT 1 FROM friends WHERE pubkey=?", (pubkey,)).fetchone() is not None

    def session_summary(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT peer_pubkey, session_id, established_at, initiator, send_counter, recv_counter FROM sessions")
            return {r["peer_pubkey"]: {"session_id": r["session_id"], "established_at": r["established_at"], "initiator": bool(r["initiator"]), "send_counter": r["send_counter"], "recv_counter": r["recv_counter"]} for r in rows}

    def touch_friend(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET last_seen=? WHERE pubkey=?", (utc_ts(), pubkey))
            self.conn.commit()

    def save_session(self, peer_pubkey: str, session_id: str, key: bytes, initiator: bool) -> None:
        blob, nonce, version = self.encrypt_blob(key, f"session:{peer_pubkey}:{session_id}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions (peer_pubkey, session_id, key, established_at, initiator, key_nonce, key_version, send_counter, recv_counter) VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT send_counter FROM sessions WHERE peer_pubkey=?),0), COALESCE((SELECT recv_counter FROM sessions WHERE peer_pubkey=?),0))",
                (peer_pubkey, session_id, blob, utc_ts(), int(initiator), nonce, version, peer_pubkey, peer_pubkey),
            )
            self.conn.commit()

    def get_session(self, peer_pubkey: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)).fetchone()
            if not row:
                return None
            data = dict(row)
            data["key"] = self.decrypt_blob(data["key"], data.get("key_nonce"), f"session:{peer_pubkey}:{data['session_id']}".encode())
            return data

    def next_send_counter(self, peer_pubkey: str) -> int:
        with self.lock:
            row = self.conn.execute("SELECT send_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)).fetchone()
            counter = int(row["send_counter"] if row else 0) + 1
            self.conn.execute("UPDATE sessions SET send_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey))
            self.conn.commit()
            return counter

    def mark_recv_counter(self, peer_pubkey: str, counter: int) -> None:
        with self.lock:
            row = self.conn.execute("SELECT recv_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)).fetchone()
            if row and counter <= int(row["recv_counter"]):
                raise ValueError("Replay or out-of-order message detected")
            self.conn.execute("UPDATE sessions SET recv_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey))
            self.conn.commit()

    def create_group(self, group_id: str, name: str, owner_pubkey: str) -> None:
        name = validate_label(name, "Group name", MAX_GROUP_NAME_CHARS, required=True)
        with self.lock:
            self.conn.execute("INSERT OR IGNORE INTO groups (group_id, name, created_at, owner_pubkey, epoch) VALUES (?, ?, ?, ?, 1)", (group_id, name, utc_ts(), owner_pubkey))
            self.conn.execute("INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) VALUES (?, ?, ?, ?)", (group_id, owner_pubkey, "owner", utc_ts()))
            self.conn.commit()

    def add_group_member(self, group_id: str, pubkey: str, role: str = "member") -> None:
        with self.lock:
            self.conn.execute("INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) VALUES (?, ?, ?, ?)", (group_id, pubkey, role, utc_ts()))
            self.conn.commit()

    def groups_for(self, pubkey: str) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT g.group_id, g.name, g.created_at, g.owner_pubkey, g.epoch FROM groups g JOIN group_members gm ON g.group_id=gm.group_id WHERE gm.pubkey=? ORDER BY g.created_at DESC",
                (pubkey,),
            )
            return [dict(r) for r in rows]

    def group_members(self, group_id: str) -> List[str]:
        with self.lock:
            return [r["pubkey"] for r in self.conn.execute("SELECT pubkey FROM group_members WHERE group_id=?", (group_id,))]

    def group_details_for(self, pubkey: str) -> List[Dict[str, Any]]:
        groups = self.groups_for(pubkey)
        for group in groups:
            group["members"] = self.group_members(group["group_id"])
        return groups

    def save_message(self, msg_id: str, sender: str, body: str, direction: str, recipient: Optional[str] = None, group_id: Optional[str] = None, delivered: bool = False, status: str = "sent") -> bool:
        plaintext = body.encode("utf-8")
        aad = f"message:{msg_id}:{sender}:{recipient or ''}:{group_id or ''}".encode()
        blob, nonce, version = self.encrypt_blob(plaintext, aad)
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO messages (msg_id, sender_pubkey, recipient_pubkey, group_id, body, direction, timestamp, delivered, status, body_nonce, key_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (msg_id, sender, recipient, group_id, blob.decode("utf-8", "surrogateescape") if not nonce else sqlite3.Binary(blob), direction, utc_ts(), int(delivered), status, nonce, version),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def update_message_status(self, msg_id: str, status: str, delivered: bool = False) -> None:
        with self.lock:
            self.conn.execute("UPDATE messages SET status=?, delivered=? WHERE msg_id=?", (status, int(delivered), msg_id))
            self.conn.commit()

    def recent_messages(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM messages ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)).fetchall()
        out: List[Dict[str, Any]] = []
        for r in reversed(rows):
            d = dict(r)
            raw = d["body"]
            if isinstance(raw, str):
                raw_b = raw.encode("utf-8", "surrogateescape")
            else:
                raw_b = raw
            aad = f"message:{d['msg_id']}:{d['sender_pubkey']}:{d.get('recipient_pubkey') or ''}:{d.get('group_id') or ''}".encode()
            d["body"] = self.decrypt_blob(raw_b, d.get("body_nonce"), aad).decode("utf-8")
            out.append(d)
        return out

    def recent_files(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]

    def save_file(self, file_id: str, filename: str, sender: str, size: int, sha256: str, path: str, recipient: Optional[str] = None, group_id: Optional[str] = None, file_nonce: Optional[bytes] = None, replace: bool = False) -> bool:
        file_id = validate_file_id(file_id)
        filename = safe_filename(filename)
        sql = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        with self.lock:
            cur = self.conn.execute(
                f"{sql} INTO files (file_id, filename, sender_pubkey, recipient_pubkey, group_id, size, sha256, storage_path, uploaded_at, file_nonce, key_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, filename, sender, recipient, group_id, size, sha256, path, utc_ts(), file_nonce, 1 if file_nonce else 0),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        file_id = validate_file_id(file_id)
        with self.lock:
            row = self.conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
            return dict(row) if row else None

    def queue_outbox(self, target_pubkey: str, payload: Dict[str, Any]) -> None:
        now = utc_ts()
        with self.lock:
            self.conn.execute("INSERT INTO outbox (target_pubkey, payload, status, retry_count, created_at, updated_at) VALUES (?, ?, 'queued', 0, ?, ?)", (target_pubkey, json.dumps(payload), now, now))
            self.conn.commit()

    def queued_outbox(self, target_pubkey: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM outbox WHERE target_pubkey=? AND status='queued' ORDER BY created_at ASC LIMIT ?", (target_pubkey, limit)).fetchall()
            return [dict(r) for r in rows]

    def mark_outbox_sent(self, outbox_id: int) -> None:
        with self.lock:
            self.conn.execute("UPDATE outbox SET status='sent', updated_at=? WHERE id=?", (utc_ts(), outbox_id))
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.close()


@dataclass
class PendingOffer:
    peer_pubkey: str
    session_id: str
    kem_secret_key: bytes
    created_at: int
    offer_payload: Dict[str, Any]


class QuantumNode:
    def __init__(self, db_path: str = DB_FILE, signaling_url: str = DEFAULT_SIGNALING_URL) -> None:
        self.crypto = QuantumCrypto()
        self.local_master_key = LocalKeyStore(db_path).load_or_create()
        self.db = Database(db_path, master_key=self.local_master_key)
        identity = self.db.load_identity()
        if identity:
            self.public_key, self.secret_key = identity
        else:
            pk, sk = self.crypto.new_identity()
            self.public_key, self.secret_key = pk.hex(), sk
            self.db.save_identity(self.public_key, self.secret_key)
        self.signaling_url = signaling_url
        self.signaling_ws: Any = None
        self.ui_clients: Set[Any] = set()
        self.online_peers: Set[str] = set()
        self.pending_offers: Dict[str, PendingOffer] = {}
        self.sessions: Dict[str, bytes] = {}
        self.group_members: Dict[str, Set[str]] = {}
        self.ui_token = secrets.token_urlsafe(32)
        self.expected_public_key_bytes = self.crypto.sign_public_key_bytes
        self._load_state()

    def _load_state(self) -> None:
        for friend in self.db.get_friends():
            session = self.db.get_session(friend["pubkey"])
            if session:
                self.sessions[friend["pubkey"]] = session["key"]
        for group in self.db.groups_for(self.public_key):
            self.group_members[group["group_id"]] = set(self.db.group_members(group["group_id"]))

    async def broadcast_ui(self, event: Dict[str, Any]) -> None:
        payload = json.dumps(event)
        dead = []
        for ws in self.ui_clients:
            try:
                await ws.send(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ui_clients.discard(ws)

    def state_payload(self) -> Dict[str, Any]:
        return {
            "type": "state",
            "public_key": self.public_key,
            "signaling_url": self.signaling_url,
            "online": sorted(self.online_peers),
            "friends": self.db.get_friends(),
            "groups": self.db.group_details_for(self.public_key),
            "messages": self.db.recent_messages(),
            "files": self.db.recent_files(),
            "sessions": self.db.session_summary(),
        }

    async def send_relay(self, peer_pubkey: str, payload: Dict[str, Any], queue_on_failure: bool = False) -> None:
        envelope = {"type": "relay", "to": peer_pubkey, "payload": payload}
        if not self.signaling_ws:
            if queue_on_failure:
                self.db.queue_outbox(peer_pubkey, envelope)
                return
            raise RuntimeError("Not connected to signaling server")
        await self.signaling_ws.send(json.dumps(envelope))

    async def flush_outbox(self, peer_pubkey: str) -> None:
        if not self.signaling_ws:
            return
        for item in self.db.queued_outbox(peer_pubkey):
            await self.signaling_ws.send(item["payload"])
            self.db.mark_outbox_sent(item["id"])

    def validate_peer_key(self, pubkey: str) -> str:
        return validate_public_key(pubkey, self.expected_public_key_bytes)

    def encrypt_for_disk(self, raw: bytes, file_id: str) -> Tuple[bytes, Optional[bytes]]:
        encrypted, nonce, _ = self.db.encrypt_blob(raw, f"file:{file_id}".encode())
        return encrypted, nonce

    def decrypt_from_disk(self, raw: bytes, file_id: str, nonce: Optional[bytes]) -> bytes:
        return self.db.decrypt_blob(raw, nonce, f"file:{file_id}".encode())

    def signed_payload(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = {"kind": kind, "payload": payload}
        sig = self.crypto.sign(self.secret_key, canonical_json(envelope))
        return {"kind": kind, "payload": payload, "signature": b64e(sig)}

    def verify_signed(self, peer_pubkey: str, data: Dict[str, Any]) -> bool:
        sig = b64d(data.get("signature", ""))
        envelope = {"kind": data.get("kind"), "payload": data.get("payload")}
        return self.crypto.verify(bytes.fromhex(peer_pubkey), canonical_json(envelope), sig)

    def cleanup_pending_offers(self) -> None:
        now = utc_ts()
        expired = [peer for peer, offer in self.pending_offers.items() if now - offer.created_at > PENDING_OFFER_TTL]
        for peer in expired:
            self.pending_offers.pop(peer, None)

    async def connect_peer(self, peer_pubkey: str) -> None:
        self.cleanup_pending_offers()
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey == self.public_key:
            raise ValueError("You cannot connect to your own public key")
        if not self.db.is_friend(peer_pubkey):
            raise ValueError("Add this public key as a friend before connecting")
        kem_pk, kem_sk = self.crypto.new_kem_keypair()
        session_id = str(uuid.uuid4())
        payload = {"protocol": "quantum-chat-v4", "from": self.public_key, "to": peer_pubkey, "session_id": session_id, "kem_pk": b64e(kem_pk), "created_at": utc_ts()}
        self.pending_offers[peer_pubkey] = PendingOffer(peer_pubkey, session_id, kem_sk, utc_ts(), payload)
        await self.send_relay(peer_pubkey, self.signed_payload("session_offer", payload))
        await self.broadcast_ui({"type": "notice", "level": "info", "text": f"Session offer sent to {short_key(peer_pubkey)}"})

    async def handle_session_offer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.db.is_friend(peer_pubkey):
            await self.broadcast_ui({"type": "notice", "level": "warning", "text": f"Rejected untrusted session offer from {short_key(peer_pubkey)}"})
            return
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session offer signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Session offer routing metadata mismatch")
        if utc_ts() - int(payload.get("created_at", 0)) > PENDING_OFFER_TTL:
            raise ValueError("Session offer expired")
        if payload.get("protocol") != "quantum-chat-v4":
            raise ValueError("Unsupported session protocol")
        ciphertext, secret = self.crypto.kem_encapsulate(b64d(payload["kem_pk"]))
        transcript = {"offer": payload, "ciphertext": b64e(ciphertext), "roles": {"initiator": peer_pubkey, "responder": self.public_key}}
        key = self.crypto.derive_session_key(secret, self.public_key, peer_pubkey, payload["session_id"], transcript)
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=False)
        self.db.touch_friend(peer_pubkey)
        accept = {"protocol": "quantum-chat-v4", "from": self.public_key, "to": peer_pubkey, "session_id": payload["session_id"], "ciphertext": b64e(ciphertext), "accepted_at": utc_ts()}
        await self.send_relay(peer_pubkey, self.signed_payload("session_accept", accept))
        await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Secure session established with {short_key(peer_pubkey)}"})
        await self.broadcast_ui(self.state_payload())

    async def handle_session_accept(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session accept signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Session accept routing metadata mismatch")
        pending = self.pending_offers.pop(peer_pubkey, None)
        if not pending or pending.session_id != payload["session_id"]:
            raise ValueError("Session accept does not match an active offer")
        if payload.get("protocol") != "quantum-chat-v4":
            raise ValueError("Unsupported session protocol")
        secret = self.crypto.kem_decapsulate(pending.kem_secret_key, b64d(payload["ciphertext"]))
        transcript = {"offer": pending.offer_payload, "ciphertext": payload["ciphertext"], "roles": {"initiator": self.public_key, "responder": peer_pubkey}}
        key = self.crypto.derive_session_key(secret, self.public_key, peer_pubkey, payload["session_id"], transcript)
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=True)
        self.db.touch_friend(peer_pubkey)
        await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Secure session established with {short_key(peer_pubkey)}"})
        await self.broadcast_ui(self.state_payload())

    async def send_chat(self, peer_pubkey: str, text: str, group_id: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        text = (text or "").strip()
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        if peer_pubkey not in self.sessions:
            await self.connect_peer(peer_pubkey)
            raise ValueError("Secure session is not ready yet; retry after handshake completes")
        msg_id = str(uuid.uuid4())
        counter = self.db.next_send_counter(peer_pubkey)
        payload = {"msg_id": msg_id, "from": self.public_key, "to": peer_pubkey, "group_id": group_id, "counter": counter, "sent_at": utc_ts()}
        msg_key = self.crypto.derive_message_key(self.sessions[peer_pubkey], peer_pubkey, counter, "chat")
        packet = self.crypto.encrypt(msg_key, text.encode(), canonical_json(payload))
        await self.send_relay(peer_pubkey, {"kind": "chat", "payload": payload, "packet": packet}, queue_on_failure=True)
        self.db.save_message(msg_id, self.public_key, text, "out", recipient=peer_pubkey, group_id=group_id, delivered=False, status="sent_to_relay")
        await self.broadcast_ui({"type": "message", "message": {"msg_id": msg_id, "sender_pubkey": self.public_key, "recipient_pubkey": peer_pubkey, "group_id": group_id, "body": text, "direction": "out", "timestamp": utc_ts(), "delivered": 0, "status": "sent_to_relay"}})

    async def handle_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if peer_pubkey not in self.sessions:
            raise ValueError("Encrypted chat received without a session")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Chat routing metadata mismatch")
        counter = int(payload.get("counter", 0))
        msg_key = self.crypto.derive_message_key(self.sessions[peer_pubkey], peer_pubkey, counter, "chat")
        text = self.crypto.decrypt(msg_key, data["packet"], canonical_json(payload)).decode("utf-8")
        self.db.mark_recv_counter(peer_pubkey, counter)
        inserted = self.db.save_message(payload["msg_id"], peer_pubkey, text, "in", recipient=self.public_key, group_id=payload.get("group_id"), delivered=True, status="delivered")
        if inserted:
            await self.send_relay(peer_pubkey, self.signed_payload("delivery_ack", {"from": self.public_key, "to": peer_pubkey, "msg_id": payload["msg_id"], "delivered_at": utc_ts()}), queue_on_failure=True)
            await self.broadcast_ui({"type": "message", "message": {"msg_id": payload["msg_id"], "sender_pubkey": peer_pubkey, "recipient_pubkey": self.public_key, "group_id": payload.get("group_id"), "body": text, "direction": "in", "timestamp": utc_ts(), "delivered": 1, "status": "delivered"}})

    async def send_group_chat(self, group_id: str, text: str) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                await self.send_chat(peer, text, group_id=group_id)

    async def send_group_file(self, group_id: str, filename: str, encoded: str) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        sent = 0
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                await self.send_file(peer, filename, encoded, group_id=group_id)
                sent += 1
        if not sent:
            raise ValueError("No group members with active friend records were available for file delivery")

    async def send_file(self, peer_pubkey: str, filename: str, encoded: str, group_id: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        raw = b64d(encoded)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
        if peer_pubkey not in self.sessions:
            await self.connect_peer(peer_pubkey)
            raise ValueError("Secure session is not ready yet; retry after handshake completes")
        file_id = str(uuid.uuid4())
        safe_name = safe_filename(filename)
        sha = hashlib.sha256(raw).hexdigest()
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        Path(storage).write_bytes(stored)
        self.db.save_file(file_id, safe_name, self.public_key, len(raw), sha, storage, recipient=peer_pubkey, group_id=group_id, file_nonce=file_nonce, replace=False)
        counter = self.db.next_send_counter(peer_pubkey)
        meta = {"file_id": file_id, "filename": safe_name, "size": len(raw), "sha256": sha, "from": self.public_key, "to": peer_pubkey, "group_id": group_id, "counter": counter, "sent_at": utc_ts()}
        msg_key = self.crypto.derive_message_key(self.sessions[peer_pubkey], peer_pubkey, counter, "file")
        packet = self.crypto.encrypt(msg_key, raw, canonical_json(meta))
        await self.send_relay(peer_pubkey, {"kind": "file", "payload": meta, "packet": packet}, queue_on_failure=True)
        await self.broadcast_ui({"type": "file", "file": {**meta, "direction": "out", "url": f"/files/{file_id}"}})

    async def handle_file(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if peer_pubkey not in self.sessions:
            raise ValueError("Encrypted file received without a session")
        meta = data["payload"]
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File routing metadata mismatch")
        file_id = validate_file_id(meta.get("file_id", ""))
        counter = int(meta.get("counter", 0))
        msg_key = self.crypto.derive_message_key(self.sessions[peer_pubkey], peer_pubkey, counter, "file")
        raw = self.crypto.decrypt(msg_key, data["packet"], canonical_json(meta))
        self.db.mark_recv_counter(peer_pubkey, counter)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("File exceeds configured limit")
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError("File checksum mismatch")
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        inserted = self.db.save_file(file_id, safe_filename(meta.get("filename") or "download.bin"), peer_pubkey, len(raw), meta["sha256"], storage, recipient=self.public_key, group_id=meta.get("group_id"), file_nonce=file_nonce, replace=False)
        if inserted:
            Path(storage).write_bytes(stored)
            await self.broadcast_ui({"type": "file", "file": {**meta, "file_id": file_id, "direction": "in", "url": f"/files/{file_id}"}})

    async def handle_relay_payload(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if not isinstance(payload, dict):
            raise ValueError("Relay payload must be an object")
        kind = payload.get("kind")
        if kind == "session_offer":
            await self.handle_session_offer(peer_pubkey, payload)
        elif kind == "session_accept":
            await self.handle_session_accept(peer_pubkey, payload)
        elif kind == "chat":
            await self.handle_chat(peer_pubkey, payload)
        elif kind == "file":
            await self.handle_file(peer_pubkey, payload)
        elif kind == "delivery_ack":
            if not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid delivery acknowledgement")
            data = payload.get("payload", {})
            if data.get("from") != peer_pubkey or data.get("to") != self.public_key:
                raise ValueError("Delivery acknowledgement routing mismatch")
            self.db.update_message_status(str(data.get("msg_id", "")), "delivered_to_peer", delivered=True)
            await self.broadcast_ui(self.state_payload())
        elif kind == "group_invite":
            if not self.db.is_friend(peer_pubkey) or not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid group invite")
            data = payload.get("payload", {})
            if data.get("from") != peer_pubkey or data.get("to") != self.public_key or self.public_key not in data.get("members", []):
                raise ValueError("Group invite metadata mismatch")
            self.db.create_group(data["group_id"], data.get("name") or f"Group {data['group_id'][:8]}", self.public_key)
            for member in data.get("members", []):
                self.db.add_group_member(data["group_id"], self.validate_peer_key(member))
            await self.broadcast_ui(self.state_payload())

    def _ui_authenticated(self, ws: Any) -> bool:
        path = getattr(ws, "path", "/") or "/"
        token = parse_qs(urlparse(path).query).get("token", [""])[0]
        if not secrets.compare_digest(token, self.ui_token):
            return False
        origin = None
        headers = getattr(ws, "request_headers", None)
        if headers:
            origin = headers.get("Origin")
        if origin:
            host = (urlparse(origin).hostname or "").lower()
            if host not in {"127.0.0.1", "localhost", "::1"}:
                return False
        return True

    async def handle_ui(self, ws: Any) -> None:
        if not self._ui_authenticated(ws):
            await ws.close(code=1008, reason="Unauthorized UI socket")
            return
        self.ui_clients.add(ws)
        await ws.send(json.dumps(self.state_payload()))
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                    typ = msg.get("type")
                    if typ == "add_friend":
                        pubkey = self.validate_peer_key(msg["pubkey"])
                        if pubkey == self.public_key:
                            raise ValueError("You cannot add your own public key as a friend")
                        self.db.add_friend(pubkey, msg.get("nickname"))
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "remove_friend":
                        self.db.remove_friend(self.validate_peer_key(msg["pubkey"]))
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "connect":
                        await self.connect_peer(msg["pubkey"])
                    elif typ == "send_message":
                        if msg.get("group_id"):
                            await self.send_group_chat(str(msg["group_id"]), str(msg.get("text", "")))
                        else:
                            await self.send_chat(msg["pubkey"], str(msg.get("text", "")))
                    elif typ == "send_file":
                        filename = safe_filename(msg.get("filename"))
                        data = str(msg.get("data", ""))
                        if msg.get("group_id"):
                            await self.send_group_file(str(msg["group_id"]), filename, data)
                        else:
                            await self.send_file(msg["pubkey"], filename, data, msg.get("group_id"))
                    elif typ == "create_group":
                        group_id = str(uuid.uuid4())
                        name = validate_label(msg.get("name"), "Group name", MAX_GROUP_NAME_CHARS) or f"Group {group_id[:8]}"
                        members_raw = msg.get("members", [])
                        if not isinstance(members_raw, list) or len(members_raw) > MAX_GROUP_MEMBERS:
                            raise ValueError(f"Group members must be a list of at most {MAX_GROUP_MEMBERS}")
                        self.db.create_group(group_id, name, self.public_key)
                        for member in members_raw:
                            member = self.validate_peer_key(member)
                            if self.db.is_friend(member):
                                self.db.add_group_member(group_id, member)
                                if member in self.sessions:
                                    invite = {"group_id": group_id, "name": name, "members": self.db.group_members(group_id), "from": self.public_key, "to": member, "epoch": 1}
                                    await self.send_relay(member, self.signed_payload("group_invite", invite), queue_on_failure=True)
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "refresh":
                        await ws.send(json.dumps(self.state_payload()))
                    else:
                        raise ValueError(f"Unknown command: {typ}")
                except Exception as exc:
                    LOG.warning("UI command rejected: %s", exc)
                    await ws.send(json.dumps({"type": "notice", "level": "error", "text": str(exc)}))
        finally:
            self.ui_clients.discard(ws)


    async def connect_signaling_loop(self) -> None:
        websockets = require_websockets()
        while True:
            try:
                async with websockets.connect(self.signaling_url, max_size=MAX_FILE_BYTES * 2) as ws:
                    self.signaling_ws = ws
                    try:
                        first_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                        first = json.loads(first_raw)
                        if first.get("type") == "register_challenge":
                            challenge = {"type": "register_challenge", "nonce": first["nonce"], "pubkey": self.public_key}
                            sig = b64e(self.crypto.sign(self.secret_key, canonical_json(challenge)))
                            await ws.send(json.dumps({"type": "register", "pubkey": self.public_key, "signature": sig, "challenge": first["nonce"]}))
                        else:
                            await ws.send(json.dumps({"type": "register", "pubkey": self.public_key}))
                            await self._handle_signaling_message(first)
                    except asyncio.TimeoutError:
                        await ws.send(json.dumps({"type": "register", "pubkey": self.public_key}))
                    await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Connected to signaling server {self.signaling_url}"})
                    async for raw in ws:
                        try:
                            await self._handle_signaling_message(json.loads(raw))
                        except Exception as exc:
                            LOG.warning("Ignored malformed signaling message: %s", exc)
                            await self.broadcast_ui({"type": "notice", "level": "warning", "text": f"Ignored malformed signaling payload: {exc}"})
            except Exception as exc:
                self.signaling_ws = None
                await self.broadcast_ui({"type": "notice", "level": "warning", "text": f"Signaling disconnected: {exc}. Reconnecting…"})
                await asyncio.sleep(3)

    async def _handle_signaling_message(self, msg: Dict[str, Any]) -> None:
        if msg.get("type") == "peers":
            self.online_peers = set(msg.get("peers", [])) - {self.public_key}
            await self.broadcast_ui(self.state_payload())
            for peer in list(self.online_peers):
                await self.flush_outbox(peer)
        elif msg.get("type") == "relay":
            await self.handle_relay_payload(msg["from"], msg["payload"])
        elif msg.get("type") == "error":
            await self.broadcast_ui({"type": "notice", "level": "error", "text": msg.get("text", "signaling error")})



class SignalingServer:
    def __init__(self) -> None:
        self.clients: Dict[str, Any] = {}
        self.crypto = QuantumCrypto()
        self.rate: Dict[Any, List[int]] = {}

    def _rate_ok(self, ws: Any, limit: int = 120, window: int = 60) -> bool:
        now = utc_ts()
        events = [t for t in self.rate.get(ws, []) if now - t < window]
        events.append(now)
        self.rate[ws] = events
        return len(events) <= limit

    async def broadcast_peers(self) -> None:
        payload = json.dumps({"type": "peers", "peers": list(self.clients)})
        for ws in list(self.clients.values()):
            try:
                await ws.send(payload)
            except Exception:
                pass

    async def handle(self, ws: Any) -> None:
        pubkey = None
        nonce = secrets.token_urlsafe(32)
        await ws.send(json.dumps({"type": "register_challenge", "nonce": nonce}))
        try:
            async for raw in ws:
                if not self._rate_ok(ws):
                    await ws.send(json.dumps({"type": "error", "text": "Rate limit exceeded"}))
                    continue
                try:
                    msg = json.loads(raw)
                    if msg.get("type") == "register":
                        candidate = validate_public_key(msg["pubkey"], self.crypto.sign_public_key_bytes)
                        sig = msg.get("signature")
                        if sig:
                            challenge = {"type": "register_challenge", "nonce": msg.get("challenge"), "pubkey": candidate}
                            if msg.get("challenge") != nonce or not self.crypto.verify(bytes.fromhex(candidate), canonical_json(challenge), b64d(sig)):
                                await ws.send(json.dumps({"type": "error", "text": "Invalid registration signature"}))
                                continue
                        elif candidate in self.clients:
                            await ws.send(json.dumps({"type": "error", "text": "Duplicate unsigned registration rejected"}))
                            continue
                        pubkey = candidate
                        old = self.clients.get(pubkey)
                        if old and old is not ws:
                            await old.close(code=1008, reason="Replaced by a signed registration")
                        self.clients[pubkey] = ws
                        await self.broadcast_peers()
                    elif msg.get("type") == "relay":
                        if not pubkey:
                            await ws.send(json.dumps({"type": "error", "text": "Register before relaying"}))
                            continue
                        target = validate_public_key(msg.get("to", ""), self.crypto.sign_public_key_bytes)
                        payload = msg.get("payload")
                        if not isinstance(payload, dict) or len(json.dumps(payload)) > MAX_FILE_BYTES * 2:
                            await ws.send(json.dumps({"type": "error", "text": "Invalid relay payload"}))
                            continue
                        if target in self.clients:
                            await self.clients[target].send(json.dumps({"type": "relay", "from": pubkey, "payload": payload}))
                        else:
                            await ws.send(json.dumps({"type": "error", "text": "Peer is offline"}))
                except Exception as exc:
                    LOG.warning("Rejected signaling frame: %s", exc)
                    await ws.send(json.dumps({"type": "error", "text": str(exc)}))
        finally:
            self.rate.pop(ws, None)
            if pubkey and self.clients.get(pubkey) is ws:
                del self.clients[pubkey]
                await self.broadcast_peers()



class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ChatHTTPHandler(BaseHTTPRequestHandler):
    node: QuantumNode = None  # type: ignore
    ui_ws_port: int = UI_WS_PORT

    def do_GET(self) -> None:
        if self.path == "/":
            body = HTML.replace("__UI_WS_PORT__", str(self.ui_ws_port)).replace("__UI_TOKEN__", self.node.ui_token if self.node else "").encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if self.path.startswith("/files/"):
            try:
                file_id = validate_file_id(urlparse(self.path).path.rsplit("/", 1)[-1])
            except ValueError:
                self.send_error(404, "File not found")
                return
            meta = self.node.db.get_file(file_id) if self.node else None
            if not meta or not Path(meta["storage_path"]).exists():
                self.send_error(404, "File not found")
                return
            ctype = mimetypes.guess_type(meta["filename"])[0] or "application/octet-stream"
            stored = Path(meta["storage_path"]).read_bytes()
            data = self.node.decrypt_from_disk(stored, file_id, meta.get("file_nonce")) if self.node else stored
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(meta['filename'])}")
            self._security_headers(download=True)
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def _security_headers(self, download: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws://127.0.0.1:* ws://localhost:*; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[http] " + fmt % args + "\n")


HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quantum Chat</title>
<style>
:root{color-scheme:dark;--bg:#06101d;--panel:#0f1c2e;--panel2:#13243a;--muted:#96a9c4;--line:#274061;--accent:#67e8a5;--danger:#ff6b81;--warn:#ffd166;--text:#edf5ff;--blue:#79abff}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 18% 0,#203b6c 0,#0a1627 38%,var(--bg) 100%);color:var(--text);font:15px/1.45 Inter,system-ui,Segoe UI,sans-serif}.app{max-width:1360px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.top h1{margin:.1rem 0;font-size:34px}.top p{margin:.25rem 0;color:var(--muted)}.badge{border:1px solid var(--line);padding:7px 12px;border-radius:999px;color:var(--accent);white-space:nowrap}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}.stat{background:rgba(15,28,46,.85);border:1px solid var(--line);border-radius:16px;padding:12px}.stat b{display:block;font-size:24px}.stat span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.grid{display:grid;grid-template-columns:340px 1fr 290px;gap:16px}.card{background:rgba(15,28,46,.9);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:0 12px 30px #0005}.card h3{margin:0 0 10px}.key{font-family:ui-monospace,monospace;word-break:break-all;color:#d2e5ff;background:#07111f;border:1px solid var(--line);border-radius:12px;padding:10px;max-height:112px;overflow:auto}.row{display:flex;gap:8px;margin-top:10px;align-items:center}input,select,textarea{width:100%;background:#07111f;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:10px}button{background:linear-gradient(135deg,#326bff,#715aff);border:0;border-radius:12px;color:#fff;font-weight:750;padding:10px 13px;cursor:pointer}button.secondary{background:#223656}button.danger{background:#7f1d35}button:disabled{opacity:.48;cursor:not-allowed}.list{display:flex;flex-direction:column;gap:8px;margin-top:10px;max-height:330px;overflow:auto}.item{border:1px solid var(--line);border-radius:14px;padding:10px;background:#0b1627;cursor:pointer}.item.active{border-color:var(--accent);box-shadow:0 0 0 1px #67e8a555}.item small{display:block;color:var(--muted);font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis}.pill{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--muted);font-size:12px}.pill.secure{border-color:var(--accent);color:var(--accent)}.pill.online{border-color:var(--blue);color:var(--blue)}.chat-head{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center}.chat{height:565px;overflow:auto;display:flex;flex-direction:column;gap:10px;background:#07111f;border:1px solid var(--line);border-radius:16px;padding:14px}.empty{margin:auto;color:var(--muted);text-align:center}.msg{max-width:76%;padding:10px 12px;border-radius:16px;background:#162845}.msg.out{align-self:flex-end;background:#214c70}.msg .meta{font-size:12px;color:var(--muted);margin-bottom:4px}.composer{display:grid;grid-template-columns:1fr auto auto;gap:8px;margin-top:12px}.hint{color:var(--muted);font-size:12px;margin-top:6px}.files a{color:var(--accent);text-decoration:none}.toast{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:10}.toast div{padding:12px 14px;border-radius:12px;background:#15233a;border:1px solid var(--line);max-width:420px}.toast .error{border-color:var(--danger)}.toast .warning{border-color:var(--warn)}.toast .success{border-color:var(--accent)}@media(max-width:1100px){.grid{grid-template-columns:330px 1fr}.right{grid-column:1/-1}.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:760px){.grid,.stats,.composer{grid-template-columns:1fr}.top{display:block}.app{padding:14px}}
</style>
</head>
<body>
<div class="app">
  <div class="top"><div><h1>⚛ Quantum Chat</h1><p>Post-quantum end-to-end encrypted chat with friend trust, session health, encrypted files, and group fan-out.</p></div><div class="badge" id="status">connecting UI…</div></div>
  <section class="stats"><div class="stat"><b id="statFriends">0</b><span>friends</span></div><div class="stat"><b id="statOnline">0</b><span>online</span></div><div class="stat"><b id="statSessions">0</b><span>secure sessions</span></div><div class="stat"><b id="statFiles">0</b><span>files</span></div></section>
  <div class="grid">
    <aside>
      <div class="card"><h3>Your identity</h3><div class="key" id="myKey">loading…</div><div class="row"><button class="secondary" onclick="copyKey()">Copy public key</button><button class="secondary" onclick="refresh()">Refresh</button></div></div>
      <div class="card"><h3>Friends</h3><input id="friendKey" placeholder="Friend public key"><input id="friendName" placeholder="Nickname (optional)" style="margin-top:8px"><div class="row"><button onclick="addFriend()">Add</button><button class="secondary" onclick="connectSelected()">Connect selected</button></div><div class="list" id="friends"></div></div>
      <div class="card"><h3>Groups</h3><input id="groupName" placeholder="Group name"><input id="groupMembers" placeholder="Member public keys, comma-separated" style="margin-top:8px"><button style="margin-top:8px" onclick="createGroup()">Create group</button><p class="hint">Tip: leave members empty to use the selected friend.</p><div class="list" id="groups"></div></div>
    </aside>
    <main class="card">
      <div class="chat-head"><div><select id="target"></select><div class="hint" id="targetHint">Choose a friend or group.</div></div><select id="mode"><option value="friend">Friend</option><option value="group">Group</option></select></div>
      <input id="search" placeholder="Filter visible messages…" style="margin-top:10px" oninput="renderMessages()">
      <div class="chat" id="chat"></div>
      <div class="composer"><textarea id="text" rows="2" placeholder="Type encrypted message…" oninput="updateComposer()" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}"></textarea><button id="sendBtn" onclick="sendMessage()">Send</button><label><button type="button" onclick="document.getElementById('file').click()">File</button><input id="file" type="file" hidden onchange="sendFile()"></label></div><div class="hint" id="charCount">0 / 65536 bytes</div>
    </main>
    <aside class="right">
      <div class="card"><h3>Session health</h3><div class="list" id="sessions"></div></div>
      <div class="card files"><h3>Encrypted files</h3><div class="list" id="files"></div></div>
    </aside>
  </div>
</div><div class="toast" id="toast"></div>
<script>
let ws,state={friends:[],groups:[],messages:[],files:[],online:[],sessions:{}},selectedFriend=null;
const UI_WS_PORT = __UI_WS_PORT__;
const UI_TOKEN = "__UI_TOKEN__";
function $(id){return document.getElementById(id)}
function connect(){let scheme=location.protocol==='https:'?'wss':'ws';ws=new WebSocket(`${scheme}://${location.hostname}:${UI_WS_PORT}/?token=${encodeURIComponent(UI_TOKEN)}`);ws.onopen=()=>status('UI connected');ws.onclose=()=>{status('UI disconnected · retrying');setTimeout(connect,1500)};ws.onmessage=e=>handle(JSON.parse(e.data));}
function status(t){$('status').textContent=t}
function handle(d){if(d.type==='state'){state=d;render()}else if(d.type==='notice'){toast(d.text,d.level)}else if(d.type==='message'){state.messages.push(d.message);renderMessages()}else if(d.type==='file'){state.files.unshift(d.file);renderFiles();toast(`File ${d.file.filename} received/sent`,'success')}}
function render(){ $('myKey').textContent=state.public_key||'';$('statFriends').textContent=state.friends.length;$('statOnline').textContent=state.online.length;$('statSessions').textContent=Object.keys(state.sessions||{}).length;$('statFiles').textContent=(state.files||[]).length;renderFriends();renderGroups();renderTargets();renderSessions();renderFiles();renderMessages();updateComposer();}
function renderFriends(){let el=$('friends');el.innerHTML='';state.friends.forEach(f=>{let online=state.online.includes(f.pubkey), secure=state.sessions&&state.sessions[f.pubkey], div=document.createElement('div');div.className='item '+(selectedFriend===f.pubkey?'active':'');div.onclick=()=>{selectedFriend=f.pubkey;$('mode').value='friend';renderTargets();renderFriends();renderMessages()};div.innerHTML=`<b>${online?'🟢':'⚪'} ${escapeHtml(f.nickname||short(f.pubkey))}</b><small>${f.pubkey}</small><div class="row"><span class="pill ${online?'online':''}">${online?'online':'offline'}</span><span class="pill ${secure?'secure':''}">${secure?'secure':'no session'}</span></div><div class="row"><button onclick="event.stopPropagation();selectedFriend='${f.pubkey}';connectSelected()">Connect</button><button class="danger" onclick="event.stopPropagation();removeFriend('${f.pubkey}')">Remove</button></div>`;el.appendChild(div)});if(!state.friends.length)el.innerHTML='<div class="hint">Add a friend public key to start.</div>'}
function renderGroups(){let el=$('groups');el.innerHTML='';state.groups.forEach(g=>{let div=document.createElement('div');div.className='item';div.onclick=()=>{$('mode').value='group';renderTargets(g.group_id);renderMessages()};div.innerHTML=`<b>${escapeHtml(g.name)}</b><small>${g.group_id}</small><span class="pill">${(g.members||[]).length} members</span>`;el.appendChild(div)});if(!state.groups.length)el.innerHTML='<div class="hint">Create a group for pairwise encrypted fan-out.</div>'}
function renderTargets(preferred){let t=$('target'),mode=$('mode').value,current=preferred||t.value;t.innerHTML='';let rows=mode==='friend'?state.friends:state.groups;rows.forEach(x=>{let o=document.createElement('option');o.value=mode==='friend'?x.pubkey:x.group_id;o.textContent=mode==='friend'?(x.nickname||short(x.pubkey)):x.name;t.appendChild(o)});if(selectedFriend&&mode==='friend')t.value=selectedFriend;else if(current)t.value=current;let target=currentTarget();$('targetHint').textContent=target?targetHint(target):'No target available yet.';updateComposer();}
function renderMessages(){let el=$('chat'),target=currentTarget(),q=$('search').value.toLowerCase();el.innerHTML='';let rows=(state.messages||[]).filter(m=>matchesTarget(m,target)).filter(m=>!q||(m.body||'').toLowerCase().includes(q));rows.forEach(m=>{let div=document.createElement('div');div.className='msg '+(m.direction==='out'?'out':'in');div.innerHTML=`<div class="meta">${m.direction==='out'?'You':short(m.sender_pubkey)} · ${new Date((m.timestamp||Date.now()/1000)*1000).toLocaleString()}${m.group_id?' · group':''}</div><div></div>`;div.lastChild.textContent=m.body;el.appendChild(div)});if(!rows.length)el.innerHTML='<div class="empty">No messages for this view yet.</div>';el.scrollTop=el.scrollHeight;}
function renderSessions(){let el=$('sessions');el.innerHTML='';let entries=Object.entries(state.sessions||{});entries.forEach(([peer,s])=>{let f=state.friends.find(x=>x.pubkey===peer), div=document.createElement('div');div.className='item';div.innerHTML=`<b>${escapeHtml(f?.nickname||short(peer))}</b><small>${peer}</small><span class="pill secure">established ${new Date(s.established_at*1000).toLocaleString()}</span>`;el.appendChild(div)});if(!entries.length)el.innerHTML='<div class="hint">Connect to a friend to establish a secure Kyber session.</div>'}
function renderFiles(){let el=$('files');el.innerHTML='';(state.files||[]).forEach(f=>{let div=document.createElement('div');div.className='item';div.innerHTML=`<b>${escapeHtml(f.filename)}</b><small>${formatBytes(f.size)} · ${new Date(f.uploaded_at*1000).toLocaleString()}</small><a href="/files/${f.file_id}">Download</a>`;el.appendChild(div)});if(!(state.files||[]).length)el.innerHTML='<div class="hint">Encrypted file transfers appear here.</div>'}
function currentTarget(){return {mode:$('mode').value,id:$('target').value}}
function targetHint(t){if(t.mode==='friend'){let f=state.friends.find(x=>x.pubkey===t.id);return f?`${state.online.includes(t.id)?'Online':'Offline'} · ${state.sessions?.[t.id]?'secure session ready':'connect before sending'}`:'Choose a friend.'}let g=state.groups.find(x=>x.group_id===t.id);return g?`${(g.members||[]).length} members · encrypted separately to each reachable member`:'Choose a group.'}
function matchesTarget(m,t){if(!t.id)return true;if(t.mode==='group')return m.group_id===t.id;return !m.group_id&&(m.sender_pubkey===t.id||m.recipient_pubkey===t.id)}
function short(k){return k?`${k.slice(0,12)}…${k.slice(-8)}`:''}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function formatBytes(n){if(!Number.isFinite(n))return '0 B';let u=['B','KB','MB','GB'],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
function send(o){if(!ws||ws.readyState!==1){toast('UI socket is not connected yet','warning');return}ws.send(JSON.stringify(o))}
function addFriend(){send({type:'add_friend',pubkey:$('friendKey').value.trim(),nickname:$('friendName').value.trim()});$('friendKey').value='';$('friendName').value=''}
function removeFriend(pubkey){if(confirm('Remove this friend and local session?'))send({type:'remove_friend',pubkey})}
function connectSelected(){let pubkey=selectedFriend||$('target').value||$('friendKey').value.trim();if(pubkey)send({type:'connect',pubkey})}
function sendMessage(){let text=$('text').value;if(!text.trim())return;let t=currentTarget();if(t.mode==='group')send({type:'send_message',group_id:t.id,text});else send({type:'send_message',pubkey:t.id,text});$('text').value='';updateComposer()}
function sendFile(){let f=$('file').files[0],t=currentTarget();if(!f||!t.id)return;let r=new FileReader();r.onload=()=>{let data=r.result.split(',')[1];if(t.mode==='group')send({type:'send_file',group_id:t.id,filename:f.name,data});else send({type:'send_file',pubkey:t.id,filename:f.name,data})};r.readAsDataURL(f);$('file').value=''}
function createGroup(){let typed=$('groupMembers').value.split(',').map(x=>x.trim()).filter(Boolean),members=typed.length?typed:(selectedFriend?[selectedFriend]:[]);send({type:'create_group',name:$('groupName').value.trim(),members});$('groupName').value='';$('groupMembers').value=''}
function refresh(){send({type:'refresh'})}
function copyKey(){navigator.clipboard.writeText(state.public_key||'');toast('Copied public key','success')}
function updateComposer(){let bytes=new TextEncoder().encode($('text').value).length;$('charCount').textContent=`${bytes} / 65536 bytes`;$('sendBtn').disabled=!$('text').value.trim()||!$('target').value}
function toast(t,l='info'){let e=document.createElement('div');e.className=l;e.textContent=t;$('toast').appendChild(e);setTimeout(()=>e.remove(),5500)}
$('mode').onchange=()=>{renderTargets();renderMessages()};$('target').onchange=()=>{if($('mode').value==='friend')selectedFriend=$('target').value;renderMessages();renderTargets()};connect();
</script>
</body>
</html>
"""


def start_http(node: QuantumNode, host: str, port: int, ui_ws_port: int = UI_WS_PORT) -> ThreadedHTTPServer:
    ChatHTTPHandler.node = node
    ChatHTTPHandler.ui_ws_port = ui_ws_port
    httpd = ThreadedHTTPServer((host, port), ChatHTTPHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


async def start_ui_ws(node: QuantumNode, host: str, port: int) -> None:
    websockets = require_websockets()
    async with websockets.serve(node.handle_ui, host, port, max_size=MAX_FILE_BYTES * 2):
        await asyncio.Future()


async def start_signaling(host: str, port: int) -> None:
    websockets = require_websockets()
    server = SignalingServer()
    async with websockets.serve(server.handle, host, port, max_size=MAX_FILE_BYTES * 2):
        print(f"Signaling server listening on ws://{host}:{port}")
        await asyncio.Future()


async def run_node(args: argparse.Namespace) -> None:
    node = QuantumNode(args.db, args.signaling_url)
    httpd = start_http(node, args.http_host, args.http_port, args.ui_ws_port)
    print(f"{APP_NAME} identity: {node.public_key}")
    print(f"UI: http://{args.http_host}:{args.http_port}")
    if args.open_browser:
        webbrowser.open(f"http://{args.http_host}:{args.http_port}")
    tasks = [asyncio.create_task(start_ui_ws(node, args.ui_ws_host, args.ui_ws_port)), asyncio.create_task(node.connect_signaling_loop())]
    if args.with_signaling:
        tasks.append(asyncio.create_task(start_signaling(args.signaling_host, args.signaling_port)))
    try:
        await asyncio.gather(*tasks)
    finally:
        httpd.shutdown()
        node.db.close()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Post-quantum P2P chat")
    sub = parser.add_subparsers(dest="command")
    signal = sub.add_parser("signal", help="run only the signaling/relay server")
    signal.add_argument("--host", default=SIGNALING_HOST)
    signal.add_argument("--port", type=int, default=SIGNALING_PORT)
    parser.add_argument("--db", default=DB_FILE)
    parser.add_argument("--signaling-url", default=DEFAULT_SIGNALING_URL)
    parser.add_argument("--with-signaling", action="store_true", help="also start a local signaling server")
    parser.add_argument("--signaling-host", default=SIGNALING_HOST)
    parser.add_argument("--signaling-port", type=int, default=SIGNALING_PORT)
    parser.add_argument("--http-host", default=HTTP_HOST)
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--ui-ws-host", default=UI_WS_HOST)
    parser.add_argument("--ui-ws-port", type=int, default=UI_WS_PORT)
    parser.add_argument("--no-browser", dest="open_browser", action="store_false")
    parser.set_defaults(open_browser=True)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    if args.command == "signal":
        asyncio.run(start_signaling(args.host, args.port))
    else:
        asyncio.run(run_node(args))


if __name__ == "__main__":
    main()
