#!/usr/bin/env python3
"""
Quantum Chat v2.0 — production-oriented post-quantum end-to-end encrypted P2P chat.

New in v2.0:
- Typing indicators (ephemeral relay)
- Read receipts (signed, persisted)
- Emoji reactions (signed, persisted)
- Per-friend unread message counts
- Session TTL tracking and expiry warnings
- Exponential backoff reconnection
- /health HTTP endpoint
- Configurable log level (--log-level)
- Completely redesigned dark UI with image previews, drag-drop, notifications
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import quote, urlparse, parse_qs
from typing import Any, Dict, List, Optional, Set, Tuple

APP_NAME = "Quantum Chat"
VERSION = "2.0.0"
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
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_CHUNK_BYTES = 512 * 1024
DIRECT_PEER_HOST = "127.0.0.1"
DIRECT_PEER_PORT = 8768
PENDING_OFFER_TTL = 5 * 60
SESSION_TTL = 24 * 3600           # 24-hour session key lifetime
SESSION_WARN_SECS = 3600          # warn when < 1 hour left
TYPING_INACTIVITY_TTL = 6         # clear typing indicator after N seconds silence
MAX_RECONNECT_DELAY = 60          # cap exponential backoff
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_NICKNAME_CHARS = 80
MAX_GROUP_NAME_CHARS = 120
MAX_FILENAME_CHARS = 180
MAX_GROUP_MEMBERS = 128
MAX_REACTION_EMOJI_BYTES = 8
ALLOWED_REACTIONS = {"👍", "❤️", "😂", "😮", "😢", "🔥"}
SCHEMA_VERSION = 4
LOG = logging.getLogger("quantum_chat")


# ─── Utilities ────────────────────────────────────────────────────────────────

def validate_public_key(pubkey: str, expected_bytes: Optional[int] = None) -> str:
    value = (pubkey or "").strip().lower()
    if not value or len(value) % 2 or not HEX_RE.fullmatch(value):
        raise ValueError("Public key must be a non-empty hexadecimal string")
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        raise ValueError(f"Public key must be {expected_bytes} bytes ({expected_bytes * 2} hex chars)")
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


def validate_emoji(emoji: str) -> str:
    emoji = (emoji or "").strip()
    if emoji not in ALLOWED_REACTIONS:
        raise ValueError(f"Reaction must be one of: {', '.join(sorted(ALLOWED_REACTIONS))}")
    return emoji


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


def key_fingerprint(pubkey: str) -> str:
    """Return a colon-separated SHA-256 fingerprint (first 8 bytes) of the key."""
    digest = hashlib.sha256(bytes.fromhex(pubkey)).hexdigest()[:16]
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))


def require_websockets():
    try:
        import websockets  # type: ignore
        return websockets
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: websockets. Run `pip install -r requirements.txt`.") from exc


def require_cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        return AESGCM, HKDF, hashes
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: cryptography. Run `pip install -r requirements.txt`.") from exc


# ─── Post-Quantum Crypto ──────────────────────────────────────────────────────

class PQModule:
    """Compatibility wrapper for pqcrypto import/API variance."""

    def __init__(self) -> None:
        try:
            from pqcrypto.sign import ml_dsa_65 as sign_mod  # type: ignore
        except ImportError:
            try:
                from pqcrypto.sign import dilithium3 as sign_mod  # type: ignore
            except ModuleNotFoundError:
                try:
                    from pqcrypto.dilithium import Dilithium3 as sign_mod  # type: ignore
                except ModuleNotFoundError as exc:
                    raise SystemExit("Missing dependency: pqcrypto. Run `pip install -r requirements.txt`.") from exc
        try:
            from pqcrypto.kem import ml_kem_512 as kem_mod  # type: ignore
        except ImportError:
            try:
                from pqcrypto.kem import kyber512 as kem_mod  # type: ignore
            except ModuleNotFoundError:
                try:
                    from pqcrypto.kyber import Kyber512 as kem_mod  # type: ignore
                except ModuleNotFoundError as exc:
                    raise SystemExit("Missing dependency: pqcrypto. Run `pip install -r requirements.txt`.") from exc
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

    def derive_session_key(self, shared_secret: bytes, a_pub: str, b_pub: str,
                           session_id: str, transcript: Optional[Dict[str, Any]] = None) -> bytes:
        transcript_hash = hashlib.sha256(canonical_json(transcript or {})).hexdigest()
        salt = hashlib.sha256("|".join(sorted([a_pub, b_pub]) + [session_id, transcript_hash]).encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt,
                         info=b"quantum-chat-v4-session-transcript")
        return hkdf.derive(shared_secret)

    def derive_message_key(self, session_key: bytes, peer_pubkey: str, counter: int, purpose: str) -> bytes:
        salt = hashlib.sha256(f"{peer_pubkey}:{counter}:{purpose}".encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt,
                         info=b"quantum-chat-v1-message-key")
        return hkdf.derive(session_key)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.AESGCM(key).encrypt(nonce, plaintext, aad)
        return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

    def decrypt(self, key: bytes, packet: Dict[str, str], aad: bytes = b"") -> bytes:
        return self.AESGCM(key).decrypt(b64d(packet["nonce"]), b64d(packet["ciphertext"]), aad)


# ─── Local Key Store ──────────────────────────────────────────────────────────

class LocalKeyStore:
    """Load or create the local database encryption key.

    By default the app remains backward compatible with the existing raw
    ``*.db.key`` file.  Operators can set QUANTUM_CHAT_PASSPHRASE to store a
    wrapped key instead; the passphrase never becomes the data-encryption key
    and the file beside the database is not directly usable without it.
    """

    def __init__(self, db_path: str) -> None:
        self.path = Path(f"{db_path}.key")
        self.mode = os.environ.get("QUANTUM_CHAT_KEY_MODE", "passphrase" if os.environ.get("QUANTUM_CHAT_PASSPHRASE") else "file")
        self.passphrase = os.environ.get("QUANTUM_CHAT_PASSPHRASE")

    def _wrap_key(self, key: bytes, salt: bytes) -> bytes:
        AESGCM, HKDF, hashes = require_cryptography()
        wrapping = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                        info=b"quantum-chat-local-key-wrap-v1").derive(self.passphrase.encode("utf-8"))
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(wrapping).encrypt(nonce, key, b"quantum-chat-local-key")

    def _unwrap_key(self, blob: bytes, salt: bytes) -> bytes:
        AESGCM, HKDF, hashes = require_cryptography()
        wrapping = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                        info=b"quantum-chat-local-key-wrap-v1").derive(self.passphrase.encode("utf-8"))
        return AESGCM(wrapping).decrypt(blob[:12], blob[12:], b"quantum-chat-local-key")

    def load_or_create(self) -> bytes:
        if self.path.exists():
            raw = self.path.read_bytes().strip()
            try:
                text = raw.decode("ascii")
                if text.startswith("QCWRAP1:"):
                    if not self.passphrase:
                        raise RuntimeError("QUANTUM_CHAT_PASSPHRASE is required for this wrapped key file")
                    _, salt_b64, blob_b64 = text.split(":", 2)
                    key = self._unwrap_key(b64d(blob_b64), b64d(salt_b64))
                else:
                    key = b64d(text)
                    if self.mode == "passphrase" and self.passphrase:
                        # One-way compatibility migration: protect the raw key file
                        # without rewriting any existing database ciphertext.
                        self._write_wrapped(key)
            except Exception as exc:
                raise RuntimeError(f"Invalid local key file: {self.path}") from exc
            if len(key) != 32:
                raise RuntimeError(f"Invalid local key length in {self.path}")
            return key
        key = secrets.token_bytes(32)
        if self.mode == "passphrase":
            if not self.passphrase:
                raise RuntimeError("QUANTUM_CHAT_PASSPHRASE must be set when QUANTUM_CHAT_KEY_MODE=passphrase")
            self._write_wrapped(key)
        else:
            self._write_raw(key)
        return key

    def _write_raw(self, key: bytes) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(b64e(key), encoding="ascii")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)

    def _write_wrapped(self, key: bytes) -> None:
        salt = secrets.token_bytes(16)
        blob = self._wrap_key(key, salt)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(f"QCWRAP1:{b64e(salt)}:{b64e(blob)}", encoding="ascii")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)


# ─── Database ─────────────────────────────────────────────────────────────────

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
            self.conn.executescript("""
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
                    verified INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    relay_alias TEXT,
                    direct_url TEXT,
                    added_at INTEGER NOT NULL,
                    last_seen INTEGER,
                    unread INTEGER NOT NULL DEFAULT 0
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
                    key_version INTEGER NOT NULL DEFAULT 0,
                    read_at INTEGER
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
                CREATE TABLE IF NOT EXISTS reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT NOT NULL,
                    peer_pubkey TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    direction TEXT NOT NULL DEFAULT 'in',
                    added_at INTEGER NOT NULL,
                    UNIQUE(msg_id, peer_pubkey, emoji)
                );
                CREATE TABLE IF NOT EXISTS read_receipts (
                    msg_id TEXT PRIMARY KEY,
                    reader_pubkey TEXT NOT NULL,
                    read_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recv_counters (
                    peer_pubkey TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    seen_at INTEGER NOT NULL,
                    PRIMARY KEY (peer_pubkey, session_id, counter)
                );
                CREATE TABLE IF NOT EXISTS group_epochs (
                    group_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    key BLOB NOT NULL,
                    key_nonce BLOB,
                    created_at INTEGER NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY (group_id, epoch)
                );
                CREATE TABLE IF NOT EXISTS file_chunks (
                    file_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    storage_path TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY (file_id, chunk_index)
                );
                CREATE TABLE IF NOT EXISTS metrics (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_messages_target
                    ON messages(sender_pubkey, recipient_pubkey, group_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_outbox_target_status
                    ON outbox(target_pubkey, status);
                CREATE INDEX IF NOT EXISTS idx_reactions_msg
                    ON reactions(msg_id);
                CREATE INDEX IF NOT EXISTS idx_recv_counters_peer
                    ON recv_counters(peer_pubkey, session_id, counter);
                CREATE INDEX IF NOT EXISTS idx_file_chunks_file
                    ON file_chunks(file_id, chunk_index);
            """)
            self._ensure_columns()
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.conn.commit()

    def _columns(self, table: str) -> Set[str]:
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def _ensure_columns(self) -> None:
        additions: Dict[str, List[Tuple[str, str]]] = {
            "identity": [("secret_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
            "sessions": [("key_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0"),
                         ("send_counter", "INTEGER NOT NULL DEFAULT 0"),
                         ("recv_counter", "INTEGER NOT NULL DEFAULT 0")],
            "groups": [("owner_pubkey", "TEXT"), ("epoch", "INTEGER NOT NULL DEFAULT 1")],
            "group_members": [("role", "TEXT NOT NULL DEFAULT 'member'")],
            "messages": [("status", "TEXT NOT NULL DEFAULT 'sent'"), ("body_nonce", "BLOB"),
                         ("key_version", "INTEGER NOT NULL DEFAULT 0"), ("read_at", "INTEGER")],
            "files": [("file_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
            "friends": [("unread", "INTEGER NOT NULL DEFAULT 0"),
                        ("verified", "INTEGER NOT NULL DEFAULT 0"),
                        ("blocked", "INTEGER NOT NULL DEFAULT 0"),
                        ("relay_alias", "TEXT"), ("direct_url", "TEXT")],
        }
        for table, cols in additions.items():
            existing = self._columns(table)
            for name, ddl in cols:
                if name not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    # ── AEAD helpers ──────────────────────────────────────────────────────────

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
            raise RuntimeError("Encrypted database value cannot be decrypted without master key")
        return aead.decrypt(nonce, ciphertext, aad)

    # ── Identity ──────────────────────────────────────────────────────────────

    def load_identity(self) -> Optional[Tuple[str, bytes]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT public_key, secret_key, secret_nonce FROM identity WHERE id=1"
            ).fetchone()
            if not row:
                return None
            secret = self.decrypt_blob(row["secret_key"], row["secret_nonce"],
                                       f"identity:{row['public_key']}".encode())
            return (row["public_key"], secret)

    def save_identity(self, public_key: str, secret_key: bytes) -> None:
        blob, nonce, version = self.encrypt_blob(secret_key, f"identity:{public_key}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO identity "
                "(id, public_key, secret_key, created_at, secret_nonce, key_version) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                (public_key, blob, utc_ts(), nonce, version),
            )
            self.conn.commit()

    # ── Friends ───────────────────────────────────────────────────────────────

    def add_friend(self, pubkey: str, nickname: Optional[str] = None) -> None:
        nickname = validate_label(nickname, "Nickname", MAX_NICKNAME_CHARS) or None
        with self.lock:
            self.conn.execute(
                "INSERT INTO friends (pubkey, nickname, added_at, unread, verified, blocked) VALUES (?, ?, ?, 0, 0, 0) "
                "ON CONFLICT(pubkey) DO UPDATE SET "
                "nickname=COALESCE(excluded.nickname, friends.nickname), trusted=1, blocked=0",
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
            friends = []
            for r in self.conn.execute(
                "SELECT pubkey, nickname, last_seen, unread, verified, blocked, relay_alias, direct_url FROM friends ORDER BY added_at DESC"
            ):
                d = dict(r)
                d["fingerprint"] = key_fingerprint(d["pubkey"])
                friends.append(d)
            return friends

    def is_friend(self, pubkey: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM friends WHERE pubkey=? AND blocked=0", (pubkey,)
            ).fetchone() is not None

    def touch_friend(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET last_seen=? WHERE pubkey=?", (utc_ts(), pubkey)
            )
            self.conn.commit()

    def set_friend_transport(self, pubkey: str, relay_alias: Optional[str] = None,
                             direct_url: Optional[str] = None) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET relay_alias=COALESCE(?, relay_alias), direct_url=COALESCE(?, direct_url) WHERE pubkey=?",
                (relay_alias, direct_url, pubkey)
            )
            self.conn.commit()

    def verify_friend(self, pubkey: str, verified: bool = True) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET verified=? WHERE pubkey=?", (int(verified), pubkey))
            self.conn.commit()

    def block_friend(self, pubkey: str, blocked: bool = True) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET blocked=? WHERE pubkey=?", (int(blocked), pubkey))
            self.conn.commit()

    def increment_unread(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET unread=unread+1 WHERE pubkey=?", (pubkey,)
            )
            self.conn.commit()

    def clear_unread(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET unread=0 WHERE pubkey=?", (pubkey,))
            self.conn.commit()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def session_summary(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT peer_pubkey, session_id, established_at, initiator, "
                "send_counter, recv_counter FROM sessions"
            )
            return {
                r["peer_pubkey"]: {
                    "session_id": r["session_id"],
                    "established_at": r["established_at"],
                    "initiator": bool(r["initiator"]),
                    "send_counter": r["send_counter"],
                    "recv_counter": r["recv_counter"],
                    "age_secs": utc_ts() - r["established_at"],
                    "expires_in": max(0, SESSION_TTL - (utc_ts() - r["established_at"])),
                }
                for r in rows
            }

    def save_session(self, peer_pubkey: str, session_id: str, key: bytes, initiator: bool) -> None:
        blob, nonce, version = self.encrypt_blob(key, f"session:{peer_pubkey}:{session_id}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions "
                "(peer_pubkey, session_id, key, established_at, initiator, key_nonce, key_version, "
                "send_counter, recv_counter) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, "
                "COALESCE((SELECT send_counter FROM sessions WHERE peer_pubkey=?),0), "
                "COALESCE((SELECT recv_counter FROM sessions WHERE peer_pubkey=?),0))",
                (peer_pubkey, session_id, blob, utc_ts(), int(initiator), nonce, version,
                 peer_pubkey, peer_pubkey),
            )
            self.conn.commit()

    def get_session(self, peer_pubkey: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["key"] = self.decrypt_blob(
                data["key"], data.get("key_nonce"),
                f"session:{peer_pubkey}:{data['session_id']}".encode()
            )
            return data

    def next_send_counter(self, peer_pubkey: str) -> int:
        with self.lock:
            row = self.conn.execute(
                "SELECT send_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            counter = int(row["send_counter"] if row else 0) + 1
            self.conn.execute(
                "UPDATE sessions SET send_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey)
            )
            self.conn.commit()
            return counter

    def mark_recv_counter(self, peer_pubkey: str, counter: int) -> None:
        """Record a received counter with a replay window.

        Older out-of-order messages are accepted if they have not been seen and
        are within REPLAY_WINDOW of the highest observed counter.
        """
        REPLAY_WINDOW = 2048
        with self.lock:
            row = self.conn.execute(
                "SELECT session_id, recv_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            if not row:
                raise ValueError("No session for replay validation")
            highest = int(row["recv_counter"])
            if counter <= max(0, highest - REPLAY_WINDOW):
                raise ValueError("Message counter is outside the replay window")
            try:
                self.conn.execute(
                    "INSERT INTO recv_counters (peer_pubkey, session_id, counter, seen_at) VALUES (?, ?, ?, ?)",
                    (peer_pubkey, row["session_id"], counter, utc_ts())
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Replay duplicate message detected") from exc
            if counter > highest:
                self.conn.execute(
                    "UPDATE sessions SET recv_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey)
                )
            self.conn.execute(
                "DELETE FROM recv_counters WHERE peer_pubkey=? AND session_id=? AND counter<=?",
                (peer_pubkey, row["session_id"], max(0, max(highest, counter) - REPLAY_WINDOW))
            )
            self.conn.commit()

    # ── Groups ────────────────────────────────────────────────────────────────

    def create_group(self, group_id: str, name: str, owner_pubkey: str) -> None:
        name = validate_label(name, "Group name", MAX_GROUP_NAME_CHARS, required=True)
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO groups (group_id, name, created_at, owner_pubkey, epoch) "
                "VALUES (?, ?, ?, ?, 1)",
                (group_id, name, utc_ts(), owner_pubkey)
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) "
                "VALUES (?, ?, ?, ?)",
                (group_id, owner_pubkey, "owner", utc_ts())
            )
            self.conn.commit()

    def add_group_member(self, group_id: str, pubkey: str, role: str = "member") -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) "
                "VALUES (?, ?, ?, ?)",
                (group_id, pubkey, role, utc_ts())
            )
            self.conn.commit()

    def groups_for(self, pubkey: str) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT g.group_id, g.name, g.created_at, g.owner_pubkey, g.epoch "
                "FROM groups g JOIN group_members gm ON g.group_id=gm.group_id "
                "WHERE gm.pubkey=? ORDER BY g.created_at DESC",
                (pubkey,),
            )
            return [dict(r) for r in rows]

    def group_members(self, group_id: str) -> List[str]:
        with self.lock:
            return [r["pubkey"] for r in self.conn.execute(
                "SELECT pubkey FROM group_members WHERE group_id=?", (group_id,)
            )]

    def group_details_for(self, pubkey: str) -> List[Dict[str, Any]]:
        groups = self.groups_for(pubkey)
        for group in groups:
            group["members"] = self.group_members(group["group_id"])
            group["fingerprint"] = key_fingerprint(group["group_id"])
        return groups

    def save_group_key(self, group_id: str, epoch: int, key: bytes, created_by: str) -> None:
        blob, nonce, _ = self.encrypt_blob(key, f"group:{group_id}:{epoch}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO group_epochs (group_id, epoch, key, key_nonce, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (group_id, epoch, blob, nonce, utc_ts(), created_by)
            )
            self.conn.execute("UPDATE groups SET epoch=? WHERE group_id=?", (epoch, group_id))
            self.conn.commit()

    def get_group_key(self, group_id: str, epoch: Optional[int] = None) -> Optional[Dict[str, Any]]:
        with self.lock:
            if epoch is None:
                row = self.conn.execute(
                    "SELECT ge.* FROM group_epochs ge JOIN groups g ON ge.group_id=g.group_id AND ge.epoch=g.epoch WHERE ge.group_id=?",
                    (group_id,)
                ).fetchone()
            else:
                row = self.conn.execute(
                    "SELECT * FROM group_epochs WHERE group_id=? AND epoch=?", (group_id, epoch)
                ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["key"] = self.decrypt_blob(d["key"], d.get("key_nonce"), f"group:{group_id}:{d['epoch']}".encode())
            return d

    # ── Messages ──────────────────────────────────────────────────────────────

    def save_message(self, msg_id: str, sender: str, body: str, direction: str,
                     recipient: Optional[str] = None, group_id: Optional[str] = None,
                     delivered: bool = False, status: str = "sent") -> bool:
        plaintext = body.encode("utf-8")
        aad = f"message:{msg_id}:{sender}:{recipient or ''}:{group_id or ''}".encode()
        blob, nonce, version = self.encrypt_blob(plaintext, aad)
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO messages "
                "(msg_id, sender_pubkey, recipient_pubkey, group_id, body, direction, "
                "timestamp, delivered, status, body_nonce, key_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (msg_id, sender, recipient, group_id,
                 blob.decode("utf-8", "surrogateescape") if not nonce else sqlite3.Binary(blob),
                 direction, utc_ts(), int(delivered), status, nonce, version),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def update_message_status(self, msg_id: str, status: str, delivered: bool = False) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE messages SET status=?, delivered=? WHERE msg_id=?",
                (status, int(delivered), msg_id)
            )
            self.conn.commit()

    def mark_message_read(self, msg_id: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE messages SET read_at=? WHERE msg_id=? AND read_at IS NULL",
                (utc_ts(), msg_id)
            )
            self.conn.commit()

    def recent_messages(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM messages ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in reversed(rows):
            d = dict(r)
            raw = d["body"]
            raw_b = raw.encode("utf-8", "surrogateescape") if isinstance(raw, str) else raw
            aad = (f"message:{d['msg_id']}:{d['sender_pubkey']}:"
                   f"{d.get('recipient_pubkey') or ''}:{d.get('group_id') or ''}").encode()
            d["body"] = self.decrypt_blob(raw_b, d.get("body_nonce"), aad).decode("utf-8")
            out.append(d)
        return out

    # ── Reactions ─────────────────────────────────────────────────────────────

    def add_reaction(self, msg_id: str, peer_pubkey: str, emoji: str,
                     direction: str = "in") -> bool:
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO reactions (msg_id, peer_pubkey, emoji, direction, added_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (msg_id, peer_pubkey, emoji, direction, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def remove_reaction(self, msg_id: str, peer_pubkey: str, emoji: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM reactions WHERE msg_id=? AND peer_pubkey=? AND emoji=?",
                (msg_id, peer_pubkey, emoji)
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_reactions(self, msg_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        if not msg_ids:
            return {}
        with self.lock:
            placeholders = ",".join("?" * len(msg_ids))
            rows = self.conn.execute(
                f"SELECT msg_id, peer_pubkey, emoji, direction, added_at "
                f"FROM reactions WHERE msg_id IN ({placeholders})",
                msg_ids
            ).fetchall()
        result: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            result.setdefault(r["msg_id"], []).append(dict(r))
        return result

    # ── Read Receipts ─────────────────────────────────────────────────────────

    def save_read_receipt(self, msg_id: str, reader_pubkey: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO read_receipts (msg_id, reader_pubkey, read_at) "
                "VALUES (?, ?, ?)",
                (msg_id, reader_pubkey, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_read_receipts(self, msg_ids: List[str]) -> Dict[str, int]:
        if not msg_ids:
            return {}
        with self.lock:
            placeholders = ",".join("?" * len(msg_ids))
            rows = self.conn.execute(
                f"SELECT msg_id, read_at FROM read_receipts WHERE msg_id IN ({placeholders})",
                msg_ids
            ).fetchall()
        return {r["msg_id"]: r["read_at"] for r in rows}

    # ── Files ─────────────────────────────────────────────────────────────────

    def recent_files(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM files ORDER BY uploaded_at DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in rows]

    def save_file(self, file_id: str, filename: str, sender: str, size: int, sha256: str,
                  path: str, recipient: Optional[str] = None, group_id: Optional[str] = None,
                  file_nonce: Optional[bytes] = None, replace: bool = False) -> bool:
        file_id = validate_file_id(file_id)
        filename = safe_filename(filename)
        sql = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        with self.lock:
            cur = self.conn.execute(
                f"{sql} INTO files "
                "(file_id, filename, sender_pubkey, recipient_pubkey, group_id, "
                "size, sha256, storage_path, uploaded_at, file_nonce, key_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, filename, sender, recipient, group_id, size, sha256, path,
                 utc_ts(), file_nonce, 1 if file_nonce else 0),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        file_id = validate_file_id(file_id)
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM files WHERE file_id=?", (file_id,)
            ).fetchone()
            return dict(row) if row else None

    # ── Outbox ────────────────────────────────────────────────────────────────

    def queue_outbox(self, target_pubkey: str, payload: Dict[str, Any]) -> None:
        now = utc_ts()
        with self.lock:
            self.conn.execute(
                "INSERT INTO outbox (target_pubkey, payload, status, retry_count, created_at, updated_at) "
                "VALUES (?, ?, 'queued', 0, ?, ?)",
                (target_pubkey, json.dumps(payload), now, now)
            )
            self.conn.commit()

    def queued_outbox(self, target_pubkey: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM outbox WHERE target_pubkey=? AND status='queued' "
                "ORDER BY created_at ASC LIMIT ?",
                (target_pubkey, limit)
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_outbox_sent(self, outbox_id: int) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE outbox SET status='sent', updated_at=? WHERE id=?", (utc_ts(), outbox_id)
            )
            self.conn.commit()

    def save_file_chunk(self, file_id: str, chunk_index: int, total_chunks: int, path: str) -> bool:
        file_id = validate_file_id(file_id)
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO file_chunks (file_id, chunk_index, total_chunks, storage_path, received_at) VALUES (?, ?, ?, ?, ?)",
                (file_id, chunk_index, total_chunks, path, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def file_chunks(self, file_id: str) -> List[Dict[str, Any]]:
        file_id = validate_file_id(file_id)
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM file_chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)
            )]

    def metric_inc(self, name: str, amount: int = 1) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO metrics (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                (name, amount)
            )
            self.conn.commit()

    def metrics(self) -> Dict[str, int]:
        with self.lock:
            return {r["name"]: int(r["value"]) for r in self.conn.execute("SELECT name, value FROM metrics")}

    def outbox_depth(self) -> int:
        with self.lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM outbox WHERE status='queued'").fetchone()[0])

    def close(self) -> None:
        with self.lock:
            self.conn.close()


# ─── Node ─────────────────────────────────────────────────────────────────────

@dataclass
class PendingOffer:
    peer_pubkey: str
    session_id: str
    kem_secret_key: bytes
    created_at: int
    offer_payload: Dict[str, Any]


class QuantumNode:
    def __init__(self, db_path: str = DB_FILE, signaling_url: str = DEFAULT_SIGNALING_URL,
                 direct_url: Optional[str] = None, enable_direct: bool = True) -> None:
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
        self.relay_alias = hashlib.sha256((self.public_key + ":relay-alias").encode()).hexdigest()
        self.direct_url = direct_url
        self.enable_direct = enable_direct
        self.peer_direct: Dict[str, str] = {}
        self._typing_timers: Dict[str, asyncio.TimerHandle] = {}
        self._load_state()

    def _load_state(self) -> None:
        for friend in self.db.get_friends():
            if friend.get("direct_url"):
                self.peer_direct[friend["pubkey"]] = friend["direct_url"]
            session = self.db.get_session(friend["pubkey"])
            if session:
                self.sessions[friend["pubkey"]] = session["key"]
        for group in self.db.groups_for(self.public_key):
            self.group_members[group["group_id"]] = set(
                self.db.group_members(group["group_id"])
            )

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
        msgs = self.db.recent_messages()
        msg_ids = [m["msg_id"] for m in msgs]
        reactions = self.db.get_reactions(msg_ids)
        read_receipts = self.db.get_read_receipts(msg_ids)
        for m in msgs:
            m["reactions"] = reactions.get(m["msg_id"], [])
            m["read_at"] = read_receipts.get(m["msg_id"])
        return {
            "type": "state",
            "public_key": self.public_key,
            "fingerprint": key_fingerprint(self.public_key),
            "signaling_url": self.signaling_url,
            "online": sorted(self.online_peers),
            "relay_alias": self.relay_alias,
            "direct_url": self.direct_url,
            "friends": self.db.get_friends(),
            "groups": self.db.group_details_for(self.public_key),
            "messages": msgs,
            "files": self.db.recent_files(),
            "sessions": self.db.session_summary(),
            "version": VERSION,
        }

    async def send_relay(self, peer_pubkey: str, payload: Dict[str, Any],
                         queue_on_failure: bool = False) -> None:
        envelope = {"type": "relay", "to": peer_pubkey, "payload": payload}
        if self.enable_direct and peer_pubkey in self.peer_direct:
            try:
                await self.send_direct(peer_pubkey, payload)
                self.db.metric_inc("direct_sent")
                return
            except Exception as exc:
                LOG.debug("Direct delivery to %s failed, falling back to relay: %s", short_key(peer_pubkey), exc)
                self.db.metric_inc("direct_fallback")
        if not self.signaling_ws:
            if queue_on_failure:
                self.db.queue_outbox(peer_pubkey, envelope)
                return
            raise RuntimeError("Not connected to signaling server")
        await self.signaling_ws.send(json.dumps(envelope))
        self.db.metric_inc("relay_sent")

    async def send_direct(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        websockets = require_websockets()
        direct_url = self.peer_direct[peer_pubkey]
        hello = {"from": self.public_key, "to": peer_pubkey, "sent_at": utc_ts(), "payload": payload}
        sig = b64e(self.crypto.sign(self.secret_key, canonical_json(hello)))
        async with websockets.connect(direct_url, max_size=MAX_FILE_BYTES * 2) as ws:
            await ws.send(json.dumps({"type": "direct", **hello, "signature": sig}))
            ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            if ack.get("type") != "direct_ack":
                raise RuntimeError("Direct peer did not acknowledge payload")

    async def handle_direct_peer(self, ws: Any) -> None:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = json.loads(raw)
            if msg.get("type") != "direct" or msg.get("to") != self.public_key:
                raise ValueError("Invalid direct peer frame")
            peer = self.validate_peer_key(msg.get("from", ""))
            sig = b64d(msg.get("signature", ""))
            hello = {"from": peer, "to": self.public_key, "sent_at": msg.get("sent_at"), "payload": msg.get("payload")}
            if not self.crypto.verify(bytes.fromhex(peer), canonical_json(hello), sig):
                raise ValueError("Invalid direct peer signature")
            if not self.db.is_friend(peer):
                raise ValueError("Direct peer is not a trusted friend")
            await self.handle_relay_payload(peer, msg.get("payload"))
            await ws.send(json.dumps({"type": "direct_ack"}))
            self.db.metric_inc("direct_received")
        except Exception as exc:
            self.db.metric_inc("direct_rejected")
            await ws.send(json.dumps({"type": "error", "text": str(exc)}))

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
        expired = [
            peer for peer, offer in self.pending_offers.items()
            if now - offer.created_at > PENDING_OFFER_TTL
        ]
        for peer in expired:
            self.pending_offers.pop(peer, None)

    def health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": VERSION,
            "public_key": self.public_key,
            "fingerprint": key_fingerprint(self.public_key),
            "signaling_connected": self.signaling_ws is not None,
            "online_peers": len(self.online_peers),
            "active_sessions": len(self.sessions),
            "friends": len(self.db.get_friends()),
            "ui_clients": len(self.ui_clients),
            "direct_enabled": self.enable_direct,
            "direct_url": self.direct_url,
            "outbox_depth": self.db.outbox_depth(),
            "metrics": self.db.metrics(),
            "file_storage_bytes": sum(p.stat().st_size for p in Path(FILES_DIR).glob("**/*") if p.is_file()) if Path(FILES_DIR).exists() else 0,
            "timestamp": utc_ts(),
        }

    # ── Session management ────────────────────────────────────────────────────

    def session_fresh(self, peer_pubkey: str) -> bool:
        session = self.db.get_session(peer_pubkey)
        return bool(session and utc_ts() - int(session["established_at"]) < SESSION_TTL)

    async def require_fresh_session(self, peer_pubkey: str, outgoing: bool = True) -> bytes:
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            self.sessions.pop(peer_pubkey, None)
            if outgoing:
                await self.connect_peer(peer_pubkey)
                raise ValueError("Secure session expired or missing; rekeying started, retry after handshake completes")
            raise ValueError("Encrypted payload received for an expired or missing session")
        return self.sessions[peer_pubkey]

    async def connect_peer(self, peer_pubkey: str) -> None:
        self.cleanup_pending_offers()
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey == self.public_key:
            raise ValueError("You cannot connect to your own public key")
        if not self.db.is_friend(peer_pubkey):
            raise ValueError("Add this public key as a friend before connecting")
        kem_pk, kem_sk = self.crypto.new_kem_keypair()
        session_id = str(uuid.uuid4())
        payload = {
            "protocol": "quantum-chat-v4",
            "from": self.public_key,
            "to": peer_pubkey,
            "session_id": session_id,
            "kem_pk": b64e(kem_pk),
            "created_at": utc_ts(),
        }
        self.pending_offers[peer_pubkey] = PendingOffer(
            peer_pubkey, session_id, kem_sk, utc_ts(), payload
        )
        await self.send_relay(peer_pubkey, self.signed_payload("session_offer", payload))
        await self.broadcast_ui({
            "type": "notice", "level": "info",
            "text": f"Session offer sent to {short_key(peer_pubkey)}"
        })

    async def handle_session_offer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.db.is_friend(peer_pubkey):
            await self.broadcast_ui({
                "type": "notice", "level": "warning",
                "text": f"Rejected untrusted session offer from {short_key(peer_pubkey)}"
            })
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
        transcript = {
            "offer": payload,
            "ciphertext": b64e(ciphertext),
            "roles": {"initiator": peer_pubkey, "responder": self.public_key},
        }
        key = self.crypto.derive_session_key(
            secret, self.public_key, peer_pubkey, payload["session_id"], transcript
        )
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=False)
        self.db.touch_friend(peer_pubkey)
        accept = {
            "protocol": "quantum-chat-v4",
            "from": self.public_key,
            "to": peer_pubkey,
            "session_id": payload["session_id"],
            "ciphertext": b64e(ciphertext),
            "accepted_at": utc_ts(),
        }
        await self.send_relay(peer_pubkey, self.signed_payload("session_accept", accept))
        await self.broadcast_ui({
            "type": "notice", "level": "success",
            "text": f"Secure session established with {short_key(peer_pubkey)}"
        })
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
        transcript = {
            "offer": pending.offer_payload,
            "ciphertext": payload["ciphertext"],
            "roles": {"initiator": self.public_key, "responder": peer_pubkey},
        }
        key = self.crypto.derive_session_key(
            secret, self.public_key, peer_pubkey, payload["session_id"], transcript
        )
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=True)
        self.db.touch_friend(peer_pubkey)
        await self.broadcast_ui({
            "type": "notice", "level": "success",
            "text": f"Secure session established with {short_key(peer_pubkey)}"
        })
        await self.broadcast_ui(self.state_payload())

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def send_chat(self, peer_pubkey: str, text: str,
                        group_id: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        text = (text or "").strip()
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        msg_id = str(uuid.uuid4())
        counter = self.db.next_send_counter(peer_pubkey)
        payload = {
            "msg_id": msg_id,
            "from": self.public_key,
            "to": peer_pubkey,
            "group_id": group_id,
            "counter": counter,
            "sent_at": utc_ts(),
        }
        msg_key = self.crypto.derive_message_key(
            session_key, peer_pubkey, counter, "chat"
        )
        packet = self.crypto.encrypt(msg_key, text.encode(), canonical_json(payload))
        await self.send_relay(
            peer_pubkey,
            {"kind": "chat", "payload": payload, "packet": packet},
            queue_on_failure=True
        )
        self.db.save_message(
            msg_id, self.public_key, text, "out",
            recipient=peer_pubkey, group_id=group_id,
            delivered=False, status="sent_to_relay"
        )
        await self.broadcast_ui({
            "type": "message",
            "message": {
                "msg_id": msg_id, "sender_pubkey": self.public_key,
                "recipient_pubkey": peer_pubkey, "group_id": group_id,
                "body": text, "direction": "out",
                "timestamp": utc_ts(), "delivered": 0,
                "status": "sent_to_relay", "reactions": [], "read_at": None,
            }
        })

    async def handle_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Chat routing metadata mismatch")
        counter = int(payload.get("counter", 0))
        msg_key = self.crypto.derive_message_key(
            session_key, peer_pubkey, counter, "chat"
        )
        text = self.crypto.decrypt(
            msg_key, data["packet"], canonical_json(payload)
        ).decode("utf-8")
        self.db.mark_recv_counter(peer_pubkey, counter)
        inserted = self.db.save_message(
            payload["msg_id"], peer_pubkey, text, "in",
            recipient=self.public_key, group_id=payload.get("group_id"),
            delivered=True, status="delivered"
        )
        if inserted:
            self.db.increment_unread(peer_pubkey)
            ack = self.signed_payload("delivery_ack", {
                "from": self.public_key, "to": peer_pubkey,
                "msg_id": payload["msg_id"], "delivered_at": utc_ts(),
            })
            await self.send_relay(peer_pubkey, ack, queue_on_failure=True)
            await self.broadcast_ui({
                "type": "message",
                "message": {
                    "msg_id": payload["msg_id"], "sender_pubkey": peer_pubkey,
                    "recipient_pubkey": self.public_key,
                    "group_id": payload.get("group_id"),
                    "body": text, "direction": "in",
                    "timestamp": utc_ts(), "delivered": 1,
                    "status": "delivered", "reactions": [], "read_at": None,
                }
            })

    # ── Typing Indicators ─────────────────────────────────────────────────────

    async def send_typing(self, peer_pubkey: str, active: bool) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            return  # silently skip, session may not exist yet
        try:
            await self.send_relay(peer_pubkey, {
                "kind": "typing",
                "from": self.public_key,
                "to": peer_pubkey,
                "active": active,
            })
        except Exception:
            pass  # typing indicators are ephemeral — failures are acceptable

    async def handle_typing(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if data.get("from") != peer_pubkey or data.get("to") != self.public_key:
            return
        active = bool(data.get("active"))
        # Cancel any pending clear timer
        if peer_pubkey in self._typing_timers:
            self._typing_timers[peer_pubkey].cancel()
            del self._typing_timers[peer_pubkey]
        await self.broadcast_ui({"type": "typing", "peer": peer_pubkey, "active": active})
        if active:
            loop = asyncio.get_event_loop()
            handle = loop.call_later(
                TYPING_INACTIVITY_TTL,
                lambda: asyncio.ensure_future(
                    self.broadcast_ui({"type": "typing", "peer": peer_pubkey, "active": False})
                )
            )
            self._typing_timers[peer_pubkey] = handle

    # ── Read Receipts ─────────────────────────────────────────────────────────

    async def send_read_receipt(self, peer_pubkey: str, msg_id: str) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            return
        try:
            await self.send_relay(peer_pubkey, self.signed_payload("read_receipt", {
                "from": self.public_key, "to": peer_pubkey,
                "msg_id": msg_id, "read_at": utc_ts(),
            }), queue_on_failure=True)
        except Exception as exc:
            LOG.debug("Failed to send read receipt: %s", exc)

    async def handle_read_receipt(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid read receipt signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Read receipt routing mismatch")
        msg_id = str(payload.get("msg_id", ""))
        if self.db.save_read_receipt(msg_id, peer_pubkey):
            self.db.update_message_status(msg_id, "read", delivered=True)
            await self.broadcast_ui({
                "type": "read_receipt",
                "msg_id": msg_id,
                "peer": peer_pubkey,
                "read_at": payload.get("read_at", utc_ts()),
            })

    # ── Reactions ─────────────────────────────────────────────────────────────

    async def send_reaction(self, peer_pubkey: str, msg_id: str,
                            emoji: str, action: str = "add") -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        emoji = validate_emoji(emoji)
        if action not in ("add", "remove"):
            raise ValueError("Reaction action must be 'add' or 'remove'")
        await self.require_fresh_session(peer_pubkey, outgoing=True)
        await self.send_relay(peer_pubkey, self.signed_payload("reaction", {
            "from": self.public_key, "to": peer_pubkey,
            "msg_id": msg_id, "emoji": emoji, "action": action,
        }), queue_on_failure=True)
        if action == "add":
            self.db.add_reaction(msg_id, self.public_key, emoji, direction="out")
        else:
            self.db.remove_reaction(msg_id, self.public_key, emoji)
        await self.broadcast_ui({
            "type": "reaction",
            "msg_id": msg_id, "peer": self.public_key,
            "emoji": emoji, "action": action,
        })

    async def handle_reaction(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid reaction signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Reaction routing mismatch")
        emoji = validate_emoji(payload.get("emoji", ""))
        action = payload.get("action", "add")
        if action not in ("add", "remove"):
            raise ValueError("Invalid reaction action")
        msg_id = str(payload.get("msg_id", ""))
        if action == "add":
            self.db.add_reaction(msg_id, peer_pubkey, emoji, direction="in")
        else:
            self.db.remove_reaction(msg_id, peer_pubkey, emoji)
        await self.broadcast_ui({
            "type": "reaction",
            "msg_id": msg_id, "peer": peer_pubkey,
            "emoji": emoji, "action": action,
        })

    async def send_group_invite(self, peer_pubkey: str, invite: Dict[str, Any], group_key: bytes) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        counter = self.db.next_send_counter(peer_pubkey)
        invite = {**invite, "counter": counter}
        key_packet = self.crypto.encrypt(
            self.crypto.derive_message_key(session_key, peer_pubkey, counter, "group-key"),
            group_key, canonical_json(invite)
        )
        await self.send_relay(peer_pubkey, self.signed_payload("group_invite", invite) | {"packet": key_packet}, queue_on_failure=True)

    # ── Group messaging ───────────────────────────────────────────────────────

    async def send_group_chat(self, group_id: str, text: str) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        text = (text or "").strip()
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        group_key = self.db.get_group_key(group_id)
        if not group_key:
            key = secrets.token_bytes(32)
            self.db.save_group_key(group_id, 1, key, self.public_key)
            group_key = self.db.get_group_key(group_id)
        epoch = int(group_key["epoch"])
        msg_id = str(uuid.uuid4())
        meta = {"msg_id": msg_id, "from": self.public_key, "group_id": group_id,
                "epoch": epoch, "sent_at": utc_ts()}
        packet = self.crypto.encrypt(group_key["key"], text.encode(), canonical_json(meta))
        envelope = self.signed_payload("group_chat", {"meta": meta, "packet": packet})
        delivered = 0
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                await self.send_relay(peer, envelope, queue_on_failure=True)
                delivered += 1
        self.db.save_message(msg_id, self.public_key, text, "out", group_id=group_id,
                             delivered=delivered > 0, status="sent_to_group")
        await self.broadcast_ui({"type": "message", "message": {
            "msg_id": msg_id, "sender_pubkey": self.public_key, "recipient_pubkey": None,
            "group_id": group_id, "body": text, "direction": "out", "timestamp": utc_ts(),
            "delivered": int(delivered > 0), "status": "sent_to_group", "reactions": [], "read_at": None,
        }})

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
            raise ValueError("No group members with active friend records available")

    # ── File transfer ─────────────────────────────────────────────────────────

    async def send_file(self, peer_pubkey: str, filename: str, encoded: str,
                        group_id: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        raw = b64d(encoded)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        file_id = str(uuid.uuid4())
        safe_name = safe_filename(filename)
        sha = hashlib.sha256(raw).hexdigest()
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        Path(storage).write_bytes(stored)
        self.db.save_file(file_id, safe_name, self.public_key, len(raw), sha, storage,
                          recipient=peer_pubkey, group_id=group_id,
                          file_nonce=file_nonce, replace=False)
        total_chunks = max(1, (len(raw) + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES)
        manifest = {"file_id": file_id, "filename": safe_name, "size": len(raw), "sha256": sha,
                    "from": self.public_key, "to": peer_pubkey, "group_id": group_id,
                    "total_chunks": total_chunks, "chunk_size": MAX_CHUNK_BYTES, "sent_at": utc_ts()}
        await self.send_relay(peer_pubkey, self.signed_payload("file_manifest", manifest), queue_on_failure=True)
        for idx in range(total_chunks):
            chunk = raw[idx * MAX_CHUNK_BYTES:(idx + 1) * MAX_CHUNK_BYTES]
            counter = self.db.next_send_counter(peer_pubkey)
            meta = {**manifest, "chunk_index": idx, "counter": counter,
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest()}
            msg_key = self.crypto.derive_message_key(session_key, peer_pubkey, counter, "file-chunk")
            packet = self.crypto.encrypt(msg_key, chunk, canonical_json(meta))
            await self.send_relay(peer_pubkey, {"kind": "file_chunk", "payload": meta, "packet": packet}, queue_on_failure=True)
        await self.broadcast_ui({
            "type": "file",
            "file": {**manifest, "direction": "out", "url": f"/files/{file_id}"}
        })

    async def handle_file(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        # Backward-compatible single-packet file receiver.
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        meta = data["payload"]
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File routing metadata mismatch")
        file_id = validate_file_id(meta.get("file_id", ""))
        counter = int(meta.get("counter", 0))
        msg_key = self.crypto.derive_message_key(session_key, peer_pubkey, counter, "file")
        raw = self.crypto.decrypt(msg_key, data["packet"], canonical_json(meta))
        self.db.mark_recv_counter(peer_pubkey, counter)
        await self._store_complete_file(peer_pubkey, meta, raw, file_id)

    async def handle_file_manifest(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid file manifest signature")
        meta = data.get("payload", {})
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File manifest routing mismatch")
        validate_file_id(meta.get("file_id", ""))
        if int(meta.get("size", 0)) > MAX_FILE_BYTES:
            raise ValueError("File exceeds configured limit")
        self.db.metric_inc("file_manifests_received")

    async def handle_file_chunk(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        meta = data["payload"]
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File chunk routing metadata mismatch")
        file_id = validate_file_id(meta.get("file_id", ""))
        counter = int(meta.get("counter", 0))
        msg_key = self.crypto.derive_message_key(session_key, peer_pubkey, counter, "file-chunk")
        chunk = self.crypto.decrypt(msg_key, data["packet"], canonical_json(meta))
        self.db.mark_recv_counter(peer_pubkey, counter)
        if hashlib.sha256(chunk).hexdigest() != meta.get("chunk_sha256"):
            raise ValueError("File chunk checksum mismatch")
        total_chunks = int(meta.get("total_chunks", 1))
        chunk_index = int(meta.get("chunk_index", 0))
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise ValueError("Invalid file chunk index")
        Path(FILES_DIR).mkdir(exist_ok=True)
        chunk_dir = Path(FILES_DIR) / f"{file_id}.chunks"
        chunk_dir.mkdir(exist_ok=True)
        chunk_path = chunk_dir / str(chunk_index)
        chunk_path.write_bytes(chunk)
        self.db.save_file_chunk(file_id, chunk_index, total_chunks, str(chunk_path))
        chunks = self.db.file_chunks(file_id)
        if len(chunks) == total_chunks:
            raw = b"".join(Path(c["storage_path"]).read_bytes() for c in chunks)
            await self._store_complete_file(peer_pubkey, meta, raw, file_id)

    async def _store_complete_file(self, peer_pubkey: str, meta: Dict[str, Any], raw: bytes, file_id: str) -> None:
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("File exceeds configured limit")
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError("File checksum mismatch")
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        inserted = self.db.save_file(
            file_id, safe_filename(meta.get("filename") or "download.bin"),
            peer_pubkey, len(raw), meta["sha256"], storage,
            recipient=self.public_key, group_id=meta.get("group_id"),
            file_nonce=file_nonce, replace=False
        )
        if inserted:
            Path(storage).write_bytes(stored)
            await self.broadcast_ui({"type": "file", "file": {**meta, "file_id": file_id, "direction": "in", "url": f"/files/{file_id}"}})

    async def handle_group_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid group message signature")
        payload = data.get("payload", {})
        meta = payload.get("meta", {})
        if meta.get("from") != peer_pubkey:
            raise ValueError("Group message sender mismatch")
        group_id = str(meta.get("group_id", ""))
        if self.public_key not in self.db.group_members(group_id):
            raise ValueError("Group message for unknown group")
        group_key = self.db.get_group_key(group_id, int(meta.get("epoch", 0)))
        if not group_key:
            raise ValueError("Missing group epoch key")
        text = self.crypto.decrypt(group_key["key"], payload["packet"], canonical_json(meta)).decode("utf-8")
        inserted = self.db.save_message(meta["msg_id"], peer_pubkey, text, "in", group_id=group_id,
                                        delivered=True, status="delivered")
        if inserted:
            self.db.increment_unread(peer_pubkey)
            await self.broadcast_ui({"type": "message", "message": {
                "msg_id": meta["msg_id"], "sender_pubkey": peer_pubkey,
                "recipient_pubkey": None, "group_id": group_id, "body": text,
                "direction": "in", "timestamp": utc_ts(), "delivered": 1,
                "status": "delivered", "reactions": [], "read_at": None,
            }})

    # ── Relay dispatch ────────────────────────────────────────────────────────

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
        elif kind == "file_manifest":
            await self.handle_file_manifest(peer_pubkey, payload)
        elif kind == "file_chunk":
            await self.handle_file_chunk(peer_pubkey, payload)
        elif kind == "group_chat":
            await self.handle_group_chat(peer_pubkey, payload)
        elif kind == "typing":
            await self.handle_typing(peer_pubkey, payload)
        elif kind == "read_receipt":
            await self.handle_read_receipt(peer_pubkey, payload)
        elif kind == "reaction":
            await self.handle_reaction(peer_pubkey, payload)
        elif kind == "delivery_ack":
            if not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid delivery acknowledgement")
            data = payload.get("payload", {})
            if data.get("from") != peer_pubkey or data.get("to") != self.public_key:
                raise ValueError("Delivery ack routing mismatch")
            self.db.update_message_status(str(data.get("msg_id", "")),
                                          "delivered_to_peer", delivered=True)
            await self.broadcast_ui({
                "type": "status_update",
                "msg_id": str(data.get("msg_id", "")),
                "status": "delivered_to_peer",
            })
        elif kind == "group_invite":
            if not self.db.is_friend(peer_pubkey) or not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid group invite")
            data = payload.get("payload", {})
            if (data.get("from") != peer_pubkey or data.get("to") != self.public_key
                    or self.public_key not in data.get("members", [])):
                raise ValueError("Group invite metadata mismatch")
            group_id = validate_file_id(data["group_id"])
            self.db.create_group(group_id, data.get("name") or f"Group {group_id[:8]}", self.public_key)
            for member in data.get("members", []):
                self.db.add_group_member(group_id, self.validate_peer_key(member))
            if payload.get("packet"):
                session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
                group_key = self.crypto.decrypt(
                    self.crypto.derive_message_key(session_key, peer_pubkey, int(data.get("counter", 0)), "group-key"),
                    payload["packet"], canonical_json(data)
                )
                self.db.mark_recv_counter(peer_pubkey, int(data.get("counter", 0)))
                self.db.save_group_key(group_id, int(data.get("epoch", 1)), group_key, peer_pubkey)
            await self.broadcast_ui(self.state_payload())

    # ── UI WebSocket ──────────────────────────────────────────────────────────

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
            if host not in {"127.0.0.1", "localhost", "::1"} and not getattr(self, "allow_remote_ui", False):
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
                    await self._dispatch_ui(msg)
                except Exception as exc:
                    LOG.warning("UI command rejected: %s", exc)
                    await ws.send(json.dumps({
                        "type": "notice", "level": "error", "text": str(exc)
                    }))
        finally:
            self.ui_clients.discard(ws)

    async def _dispatch_ui(self, msg: Dict[str, Any]) -> None:
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
        elif typ == "verify_friend":
            self.db.verify_friend(self.validate_peer_key(msg["pubkey"]), bool(msg.get("verified", True)))
            await self.broadcast_ui(self.state_payload())
        elif typ == "block_friend":
            self.db.block_friend(self.validate_peer_key(msg["pubkey"]), bool(msg.get("blocked", True)))
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
            name = (validate_label(msg.get("name"), "Group name", MAX_GROUP_NAME_CHARS)
                    or f"Group {group_id[:8]}")
            members_raw = msg.get("members", [])
            if not isinstance(members_raw, list) or len(members_raw) > MAX_GROUP_MEMBERS:
                raise ValueError(f"Group members must be a list of at most {MAX_GROUP_MEMBERS}")
            self.db.create_group(group_id, name, self.public_key)
            group_key = secrets.token_bytes(32)
            self.db.save_group_key(group_id, 1, group_key, self.public_key)
            for member in members_raw:
                member = self.validate_peer_key(member)
                if self.db.is_friend(member):
                    self.db.add_group_member(group_id, member)
                    if member in self.sessions:
                        invite = {
                            "group_id": group_id, "name": name,
                            "members": self.db.group_members(group_id),
                            "from": self.public_key, "to": member, "epoch": 1,
                        }
                        await self.send_group_invite(member, invite, group_key)
            await self.broadcast_ui(self.state_payload())
        elif typ == "typing":
            await self.send_typing(msg["pubkey"], bool(msg.get("active", True)))
        elif typ == "read_receipt":
            await self.send_read_receipt(msg["pubkey"], str(msg["msg_id"]))
            self.db.clear_unread(msg["pubkey"])
            await self.broadcast_ui(self.state_payload())
        elif typ == "reaction":
            await self.send_reaction(
                msg["pubkey"], str(msg["msg_id"]),
                str(msg["emoji"]), str(msg.get("action", "add"))
            )
        elif typ == "clear_unread":
            self.db.clear_unread(self.validate_peer_key(msg["pubkey"]))
            await self.broadcast_ui(self.state_payload())
        elif typ == "refresh":
            await self.broadcast_ui(self.state_payload())
        else:
            raise ValueError(f"Unknown command: {typ}")

    # ── Signaling loop ────────────────────────────────────────────────────────

    async def connect_signaling_loop(self) -> None:
        websockets = require_websockets()
        delay = 1.0
        while True:
            try:
                async with websockets.connect(
                    self.signaling_url, max_size=MAX_FILE_BYTES * 2
                ) as ws:
                    self.signaling_ws = ws
                    delay = 1.0  # reset backoff on success
                    try:
                        first_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                        first = json.loads(first_raw)
                        if first.get("type") == "register_challenge":
                            challenge = {
                                "type": "register_challenge",
                                "nonce": first["nonce"],
                                "pubkey": self.public_key,
                            }
                            sig = b64e(self.crypto.sign(self.secret_key, canonical_json(challenge)))
                            await ws.send(json.dumps({
                                "type": "register", "pubkey": self.public_key,
                                "signature": sig, "challenge": first["nonce"],
                                "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                            }))
                        else:
                            await ws.send(json.dumps({
                                "type": "register", "pubkey": self.public_key,
                                "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                            }))
                            await self._handle_signaling_message(first)
                    except asyncio.TimeoutError:
                        await ws.send(json.dumps({
                            "type": "register", "pubkey": self.public_key,
                            "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                        }))
                    await self.broadcast_ui({
                        "type": "notice", "level": "success",
                        "text": "Connected to signaling server"
                    })
                    async for raw in ws:
                        try:
                            await self._handle_signaling_message(json.loads(raw))
                        except Exception as exc:
                            LOG.warning("Ignored malformed signaling message: %s", exc)
            except Exception as exc:
                self.signaling_ws = None
                LOG.warning("Signaling disconnected: %s", exc)
                await self.broadcast_ui({
                    "type": "notice", "level": "warning",
                    "text": f"Disconnected from relay — reconnecting in {delay:.0f}s…"
                })
                await asyncio.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)

    async def _handle_signaling_message(self, msg: Dict[str, Any]) -> None:
        if msg.get("type") == "peers":
            raw_peers = msg.get("peers", [])
            if isinstance(raw_peers, dict):
                self.online_peers = set(raw_peers) - {self.public_key}
                for peer, meta in raw_peers.items():
                    if peer != self.public_key and isinstance(meta, dict):
                        if meta.get("direct_url"):
                            self.peer_direct[peer] = meta["direct_url"]
                        self.db.set_friend_transport(peer, meta.get("relay_alias"), meta.get("direct_url"))
            else:
                self.online_peers = set(raw_peers) - {self.public_key}
            await self.broadcast_ui(self.state_payload())
            for peer in list(self.online_peers):
                await self.flush_outbox(peer)
        elif msg.get("type") == "relay":
            await self.handle_relay_payload(msg["from"], msg["payload"])
        elif msg.get("type") == "error":
            await self.broadcast_ui({
                "type": "notice", "level": "error",
                "text": msg.get("text", "signaling error")
            })


# ─── Signaling Server ─────────────────────────────────────────────────────────

class SignalingServer:
    def __init__(self) -> None:
        self.clients: Dict[str, Any] = {}
        self.aliases: Dict[str, str] = {}
        self.peer_meta: Dict[str, Dict[str, Any]] = {}
        self.offline: Dict[str, List[Dict[str, Any]]] = {}
        self.relay_db = sqlite3.connect(os.environ.get("QUANTUM_CHAT_RELAY_DB", "quantum_chat_relay.db"), check_same_thread=False)
        self.relay_db.execute("CREATE TABLE IF NOT EXISTS offline_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, envelope TEXT NOT NULL, created_at INTEGER NOT NULL)")
        self.relay_db.commit()
        self.crypto = QuantumCrypto()
        self.rate: Dict[Any, List[int]] = {}

    def _rate_ok(self, ws: Any, limit: int = 120, window: int = 60) -> bool:
        now = utc_ts()
        events = [t for t in self.rate.get(ws, []) if now - t < window]
        events.append(now)
        self.rate[ws] = events
        return len(events) <= limit

    async def broadcast_peers(self) -> None:
        payload = json.dumps({"type": "peers", "peers": self.peer_meta})
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
                        candidate = validate_public_key(
                            msg["pubkey"], self.crypto.sign_public_key_bytes
                        )
                        sig = msg.get("signature")
                        if sig:
                            challenge = {
                                "type": "register_challenge",
                                "nonce": msg.get("challenge"),
                                "pubkey": candidate,
                            }
                            if (msg.get("challenge") != nonce
                                    or not self.crypto.verify(
                                        bytes.fromhex(candidate),
                                        canonical_json(challenge), b64d(sig)
                                    )):
                                await ws.send(json.dumps({
                                    "type": "error", "text": "Invalid registration signature"
                                }))
                                continue
                        elif candidate in self.clients:
                            await ws.send(json.dumps({
                                "type": "error",
                                "text": "Duplicate unsigned registration rejected"
                            }))
                            continue
                        pubkey = candidate
                        relay_alias = str(msg.get("relay_alias") or hashlib.sha256(candidate.encode()).hexdigest())
                        if not HEX_RE.match(relay_alias) or len(relay_alias) > 128:
                            raise ValueError("Invalid relay alias")
                        direct_url = msg.get("direct_url") if isinstance(msg.get("direct_url"), str) else None
                        old = self.clients.get(pubkey)
                        if old and old is not ws:
                            await old.close(code=1008, reason="Replaced by signed registration")
                        self.clients[pubkey] = ws
                        self.aliases[relay_alias] = pubkey
                        self.peer_meta[pubkey] = {"relay_alias": relay_alias, "direct_url": direct_url}
                        for queued in self.offline.pop(pubkey, []):
                            await ws.send(json.dumps(queued))
                        rows = self.relay_db.execute("SELECT id, envelope FROM offline_queue WHERE target=? ORDER BY id LIMIT 500", (pubkey,)).fetchall()
                        for qid, envelope in rows:
                            await ws.send(envelope)
                            self.relay_db.execute("DELETE FROM offline_queue WHERE id=?", (qid,))
                        self.relay_db.commit()
                        await self.broadcast_peers()
                    elif msg.get("type") == "relay":
                        if not pubkey:
                            await ws.send(json.dumps({
                                "type": "error", "text": "Register before relaying"
                            }))
                            continue
                        raw_target = str(msg.get("to", ""))
                        try:
                            target = validate_public_key(raw_target, self.crypto.sign_public_key_bytes)
                        except ValueError:
                            target = self.aliases.get(raw_target, "")
                            if not target:
                                raise
                        payload = msg.get("payload")
                        if (not isinstance(payload, dict)
                                or len(json.dumps(payload)) > MAX_FILE_BYTES * 2):
                            await ws.send(json.dumps({
                                "type": "error", "text": "Invalid relay payload"
                            }))
                            continue
                        if target in self.clients:
                            await self.clients[target].send(json.dumps({
                                "type": "relay", "from": pubkey, "payload": payload
                            }))
                        else:
                            queue = self.offline.setdefault(target, [])
                            if len(queue) >= 500:
                                await ws.send(json.dumps({"type": "error", "text": "Peer offline queue is full"}))
                            else:
                                queued = {"type": "relay", "from": pubkey, "payload": payload, "offline": True}
                                queue.append(queued)
                                self.relay_db.execute(
                                    "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
                                    (target, json.dumps(queued), utc_ts())
                                )
                                self.relay_db.commit()
                                await ws.send(json.dumps({"type": "queued", "to": target}))
                except Exception as exc:
                    LOG.warning("Rejected signaling frame: %s", exc)
                    await ws.send(json.dumps({"type": "error", "text": str(exc)}))
        finally:
            self.rate.pop(ws, None)
            if pubkey and self.clients.get(pubkey) is ws:
                del self.clients[pubkey]
                self.peer_meta.pop(pubkey, None)
                for alias, owner in list(self.aliases.items()):
                    if owner == pubkey:
                        self.aliases.pop(alias, None)
                await self.broadcast_peers()


# ─── HTTP Server ──────────────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ChatHTTPHandler(BaseHTTPRequestHandler):
    node: QuantumNode = None  # type: ignore
    ui_ws_port: int = UI_WS_PORT
    require_http_auth: bool = False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if self.require_http_auth and not self._http_authenticated(parsed):
            self.send_error(401, "Unauthorized")
            return

        if path == "/":
            body = (
                HTML
                .replace("__UI_WS_PORT__", str(self.ui_ws_port))
                .replace("__UI_TOKEN__", self.node.ui_token if self.node else "")
                .replace("__VERSION__", VERSION)
            ).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return

        if path == "/health":
            body = json.dumps(self.node.health() if self.node else {"status": "no node"}).encode()
            self._send(200, body, "application/json")
            return

        if path.startswith("/files/"):
            try:
                file_id = validate_file_id(path.rsplit("/", 1)[-1])
            except ValueError:
                self.send_error(404, "File not found")
                return
            meta = self.node.db.get_file(file_id) if self.node else None
            if not meta or not Path(meta["storage_path"]).exists():
                self.send_error(404, "File not found")
                return
            ctype = mimetypes.guess_type(meta["filename"])[0] or "application/octet-stream"
            stored = Path(meta["storage_path"]).read_bytes()
            data = (self.node.decrypt_from_disk(stored, file_id, meta.get("file_nonce"))
                    if self.node else stored)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8''{quote(meta['filename'])}"
            )
            self._security_headers(download=True)
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(404)

    def _http_authenticated(self, parsed: Any) -> bool:
        token = parse_qs(parsed.query).get("token", [""])[0]
        auth = self.headers.get("Authorization", "")
        expected = self.node.ui_token if self.node else ""
        bearer = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        return bool(expected and (secrets.compare_digest(token, expected) or secrets.compare_digest(bearer, expected)))

    def _security_headers(self, download: bool = False) -> None:
        connect_src = "connect-src 'self' ws://127.0.0.1:* ws://localhost:* ws://[::1]:* wss://127.0.0.1:* wss://localhost:* wss://[::1]:*;"
        if self.require_http_auth:
            host = (self.headers.get("Host", "") or "").strip()
            if host:
                host = host.split("/", 1)[0]
                connect_src = (
                    f"connect-src 'self' ws://{host} wss://{host} "
                    "ws://127.0.0.1:* ws://localhost:* ws://[::1]:* "
                    "wss://127.0.0.1:* wss://localhost:* wss://[::1]:*;"
                )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"{connect_src} "
            "style-src 'unsafe-inline' 'self'; "
            "script-src 'unsafe-inline' 'self'; "
            "img-src 'self' data: blob:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.debug("[http] " + fmt, *args)


# ─── Embedded UI ──────────────────────────────────────────────────────────────

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚛ Quantum Chat</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
  --bg: #030508;
  --glass-bg: rgba(12, 18, 30, 0.65);
  --glass-border: rgba(255, 255, 255, 0.07);
  --glass-border-hover: rgba(255, 255, 255, 0.15);
  --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  
  --s1: var(--glass-bg);
  --s2: rgba(18, 25, 40, 0.5);
  --s3: rgba(25, 35, 55, 0.6);
  --s4: rgba(35, 50, 75, 0.7);
  --border: var(--glass-border);
  --border2: var(--glass-border-hover);
  
  --accent: #00d2ff;
  --accent-glow: rgba(0, 210, 255, 0.4);
  --accent2: #3a86ff;
  --accent2-glow: rgba(58, 134, 255, 0.4);
  --danger: #ff3366;
  --warn: #ffcc00;
  
  --text1: #f8f9fa;
  --text2: #adb5bd;
  --text3: #6c757d;
  
  --out-bg: linear-gradient(135deg, var(--accent2), var(--accent));
  --out-border: transparent;
  --in-bg: var(--s3);
  
  --rad: 16px;
  --font: 'Outfit', system-ui, sans-serif;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  background-color: var(--bg);
  background-image: 
    radial-gradient(circle at 15% 50%, rgba(58, 134, 255, 0.15), transparent 40%),
    radial-gradient(circle at 85% 30%, rgba(0, 210, 255, 0.15), transparent 40%),
    radial-gradient(circle at 50% 100%, rgba(255, 51, 102, 0.05), transparent 40%);
  background-attachment: fixed;
  color: var(--text1);
  height: 100vh;
  overflow: hidden;
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ── Layout ── */
#app { display: flex; height: 100vh; }

#sidebar {
  width: 320px;
  min-width: 320px;
  display: flex;
  flex-direction: column;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-right: 1px solid var(--border);
  box-shadow: var(--glass-shadow);
  z-index: 10;
}

#main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: transparent;
}

#panel {
  width: 290px;
  min-width: 290px;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-left: 1px solid var(--border);
  box-shadow: var(--glass-shadow);
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  z-index: 10;
}

/* ── Sidebar ── */
.sidebar-head {
  padding: 20px;
  border-bottom: 1px solid var(--border);
  background: rgba(0,0,0,0.1);
}

.app-logo {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.app-logo .icon {
  font-size: 26px;
  line-height: 1;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 8px var(--accent-glow));
}

.app-logo h1 {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--text1);
}

.app-logo .ver {
  font-size: 11px;
  color: var(--text3);
  font-family: var(--mono);
  margin-top: 2px;
}

.conn-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 500;
  padding: 6px 12px;
  border-radius: 999px;
  background: var(--s3);
  border: 1px solid var(--border);
  color: var(--text2);
  transition: all 0.3s ease;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.conn-badge.connected { 
  border-color: rgba(58, 134, 255, 0.4); 
  color: #fff;
  background: rgba(58, 134, 255, 0.1);
}
.conn-badge.connected .dot { background: var(--accent); box-shadow: 0 0 10px var(--accent); }
.conn-badge .dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--text3);
  transition: all 0.3s;
}
.conn-badge.connected .dot { animation: pulse 2s infinite; }
@keyframes pulse {
  0%,100% { opacity: 1; transform: scale(1); box-shadow: 0 0 10px var(--accent); }
  50% { opacity: 0.5; transform: scale(0.8); box-shadow: 0 0 2px var(--accent); }
}

/* Identity card */
.id-card {
  margin: 16px;
  padding: 16px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border);
  border-radius: var(--rad);
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
  position: relative;
  overflow: hidden;
}
.id-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--accent2), var(--accent));
  opacity: 0;
  transition: opacity 0.3s;
}
.id-card:hover {
  transform: translateY(-2px);
  background: rgba(255, 255, 255, 0.05);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3);
  border-color: var(--border2);
}
.id-card:hover::before { opacity: 1; }

.id-card-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.id-avatar {
  width: 42px; height: 42px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  box-shadow: 0 4px 12px var(--accent-glow);
  display: flex; align-items: center; justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
  color: white;
}
.id-name { font-weight: 600; font-size: 15px; }
.id-fp {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  letter-spacing: 0.05em;
}
.id-key {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text2);
  word-break: break-all;
  padding: 10px;
  background: rgba(0,0,0,0.3);
  border-radius: 10px;
  border: 1px solid var(--border);
  display: none;
  margin-top: 12px;
  line-height: 1.6;
}
.id-key.visible { display: block; animation: fadeIn 0.3s; }
.id-actions { display: flex; gap: 8px; margin-top: 12px; }

/* Search */
.search-wrap {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.search-input {
  width: 100%;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 10px 14px 10px 36px;
  color: var(--text1);
  font-size: 14px;
  font-family: var(--font);
  outline: none;
  transition: all 0.2s;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%236c757d' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: 12px center;
}
.search-input:focus { 
  border-color: var(--accent); 
  background: rgba(0,0,0,0.4);
  box-shadow: 0 0 0 2px rgba(0, 210, 255, 0.1);
}
.search-input::placeholder { color: var(--text3); }

/* Friend / group lists */
.list-section { flex: 1; overflow-y: auto; padding: 12px 0; }
.section-label {
  padding: 8px 20px 6px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text3);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.section-label button {
  font-size: 20px;
  color: var(--text3);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
  transition: all 0.2s;
}
.section-label button:hover { 
  color: var(--accent); 
  transform: scale(1.1);
  filter: drop-shadow(0 0 4px var(--accent-glow));
}

.friend-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 20px;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.25, 0.8, 0.25, 1);
  position: relative;
  margin: 2px 8px;
  border-radius: 12px;
}
.friend-item:hover { background: rgba(255, 255, 255, 0.03); }
.friend-item.active { 
  background: rgba(255, 255, 255, 0.06); 
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
.friend-item.active::before {
  content: '';
  position: absolute;
  left: 0; top: 12px; bottom: 12px;
  width: 4px;
  background: linear-gradient(180deg, var(--accent2), var(--accent));
  border-radius: 0 4px 4px 0;
  box-shadow: 2px 0 8px var(--accent-glow);
}

.friend-avatar {
  position: relative;
  flex-shrink: 0;
}
.avatar-circle {
  width: 42px; height: 42px;
  border-radius: 50%;
  background: linear-gradient(135deg, #1e293b, #334155);
  display: flex; align-items: center; justify-content: center;
  font-size: 16px;
  font-weight: 600;
  color: #fff;
  border: 1px solid var(--border);
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}
.online-dot {
  position: absolute;
  bottom: 0px; right: -2px;
  width: 14px; height: 14px;
  border-radius: 50%;
  background: var(--bg);
  display: flex; align-items: center; justify-content: center;
}
.online-dot::after {
  content: '';
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--text3);
  transition: all 0.3s;
}
.online-dot.online::after { 
  background: #34d39a; 
  box-shadow: 0 0 8px #34d39a;
}

.friend-info { flex: 1; min-width: 0; }
.friend-name {
  font-size: 15px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 2px;
}
.friend-preview {
  font-size: 13px;
  color: var(--text2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.friend-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 6px;
  flex-shrink: 0;
}
.unread-badge {
  background: linear-gradient(135deg, var(--danger), #ff5e62);
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 999px;
  min-width: 22px;
  text-align: center;
  box-shadow: 0 2px 8px rgba(255, 51, 102, 0.4);
  animation: popIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
@keyframes popIn {
  0% { transform: scale(0.5); opacity: 0; }
  100% { transform: scale(1); opacity: 1; }
}

.secure-tag {
  font-size: 11px;
  color: var(--accent);
  font-family: var(--mono);
  display: flex;
  align-items: center;
  gap: 4px;
}
.time-tag {
  font-size: 11px;
  color: var(--text3);
}

/* ── Main chat area ── */
.chat-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: rgba(10, 15, 25, 0.6);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  min-height: 72px;
  z-index: 5;
}
.chat-header-avatar {
  width: 44px; height: 44px;
  border-radius: 50%;
  background: linear-gradient(135deg, #1e293b, #334155);
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
  font-weight: 600;
  flex-shrink: 0;
  border: 1px solid var(--border);
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}
.chat-header-info { flex: 1; min-width: 0; }
.chat-header-name { font-size: 17px; font-weight: 700; margin-bottom: 2px; }
.chat-header-sub {
  font-size: 13px;
  color: var(--text2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.chat-header-actions { display: flex; gap: 10px; }

.messages-wrap {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  scroll-behavior: smooth;
}

/* Drop overlay */
.drop-overlay {
  display: none;
  position: absolute;
  inset: 0;
  background: rgba(3, 5, 8, 0.85);
  backdrop-filter: blur(10px);
  border: 2px dashed var(--accent);
  border-radius: var(--rad);
  z-index: 20;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 12px;
  font-size: 20px;
  font-weight: 600;
  color: var(--accent);
  pointer-events: none;
  animation: fadeIn 0.2s;
}
.drop-overlay.active { display: flex; }
#main { position: relative; }

/* Date divider */
.date-divider {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 16px 0;
  color: var(--text3);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.date-divider::before, .date-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--border), transparent);
}

/* Messages */
.msg-group { display: flex; flex-direction: column; margin: 4px 0; }
.msg-group.out { align-items: flex-end; }
.msg-group.in { align-items: flex-start; }

.msg-bubble {
  max-width: 70%;
  padding: 12px 16px;
  border-radius: 20px;
  position: relative;
  word-break: break-word;
  line-height: 1.6;
  font-size: 15px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.15);
  animation: slideUp 0.3s cubic-bezier(0.2, 0.8, 0.2, 1);
}
@keyframes slideUp {
  from { opacity: 0; transform: translateY(12px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}

.msg-group.out .msg-bubble {
  background: var(--out-bg);
  border: none;
  border-bottom-right-radius: 6px;
  color: #fff;
  box-shadow: 0 4px 16px rgba(0, 210, 255, 0.2);
}
.msg-group.in .msg-bubble {
  background: var(--s3);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid var(--border);
  border-bottom-left-radius: 6px;
}

.msg-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  font-size: 11px;
  color: var(--text3);
  padding: 0 6px;
}
.msg-group.out .msg-meta { flex-direction: row-reverse; }

.msg-status { display: flex; align-items: center; }
.check { color: var(--text3); font-size: 14px; }
.check.delivered { color: var(--text2); }
.check.read { color: var(--accent); filter: drop-shadow(0 0 2px var(--accent-glow)); }

.msg-image {
  max-width: 320px;
  max-height: 240px;
  border-radius: 12px;
  display: block;
  cursor: pointer;
  object-fit: cover;
  border: 1px solid rgba(255,255,255,0.1);
  transition: transform 0.2s;
}
.msg-image:hover {
  transform: scale(1.02);
}

/* Reactions */
.reactions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: -6px;
  margin-bottom: 4px;
  z-index: 2;
  position: relative;
}
.reaction-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: 999px;
  background: var(--s2);
  backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.reaction-chip:hover { 
  border-color: var(--accent); 
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.25);
}
.reaction-chip.mine { 
  border-color: var(--accent); 
  background: rgba(0, 210, 255, 0.1); 
}

.reaction-bar {
  display: none;
  position: absolute;
  bottom: calc(100% + 8px);
  background: var(--s2);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 6px;
  gap: 4px;
  z-index: 10;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  animation: fadeInDown 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
}
@keyframes fadeInDown {
  from { opacity: 0; transform: translateY(10px) scale(0.95); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.msg-group.out .reaction-bar { right: 0; }
.msg-group.in .reaction-bar { left: 0; }
.msg-bubble:hover .reaction-bar { display: flex; }
.reaction-btn {
  width: 36px; height: 36px;
  border-radius: 10px;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 18px;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s;
}
.reaction-btn:hover { background: rgba(255,255,255,0.1); transform: scale(1.1); }

/* Typing indicator */
#typing-indicator {
  padding: 0 24px 12px;
  min-height: 32px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: var(--text2);
}
.typing-dots {
  display: flex;
  gap: 4px;
  align-items: center;
  background: var(--s3);
  padding: 8px 12px;
  border-radius: 16px;
  border: 1px solid var(--border);
}
.typing-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--accent);
  animation: bounce 1.4s infinite ease-in-out;
  box-shadow: 0 0 4px var(--accent-glow);
}
.typing-dot:nth-child(2) { animation-delay: 0.2s; }
.typing-dot:nth-child(3) { animation-delay: 0.4s; }
@keyframes bounce {
  0%,80%,100% { transform: translateY(0); opacity: 0.4; }
  40% { transform: translateY(-4px); opacity: 1; }
}

/* Composer */
.composer {
  padding: 16px 24px 20px;
  border-top: 1px solid var(--border);
  background: rgba(10, 15, 25, 0.6);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  z-index: 5;
}
.composer-inner {
  display: flex;
  gap: 12px;
  align-items: flex-end;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 10px 14px;
  transition: all 0.3s;
  box-shadow: inset 0 2px 8px rgba(0,0,0,0.2);
}
.composer-inner:focus-within { 
  border-color: var(--accent); 
  box-shadow: 0 0 0 3px rgba(0, 210, 255, 0.15), inset 0 2px 8px rgba(0,0,0,0.2);
}
#text {
  flex: 1;
  background: none;
  border: none;
  outline: none;
  color: var(--text1);
  font-family: var(--font);
  font-size: 15px;
  resize: none;
  max-height: 140px;
  min-height: 24px;
  line-height: 1.5;
  padding-bottom: 4px;
}
#text::placeholder { color: var(--text3); }
.composer-actions { display: flex; align-items: center; gap: 6px; }
.icon-btn {
  width: 38px; height: 38px;
  display: flex; align-items: center; justify-content: center;
  background: none; border: none; cursor: pointer;
  color: var(--text2);
  border-radius: 10px;
  font-size: 20px;
  transition: all 0.2s;
}
.icon-btn:hover { 
  background: rgba(255,255,255,0.05); 
  color: var(--accent); 
  transform: translateY(-1px);
}
.send-btn {
  width: 40px; height: 40px;
  display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  border: none; cursor: pointer;
  color: #fff;
  border-radius: 12px;
  font-size: 18px;
  transition: all 0.2s;
  flex-shrink: 0;
  box-shadow: 0 4px 12px var(--accent-glow);
}
.send-btn:hover { 
  transform: translateY(-2px);
  box-shadow: 0 6px 16px var(--accent-glow);
}
.send-btn:active { transform: scale(0.95); }
.send-btn:disabled { 
  opacity: 0.4; 
  cursor: not-allowed; 
  background: var(--s4); 
  box-shadow: none;
  transform: none;
}

.char-hint {
  font-size: 11px;
  color: var(--text3);
  text-align: right;
  margin-top: 6px;
  font-family: var(--mono);
}

/* ── Right panel ── */
.panel-section {
  padding: 18px 20px;
  border-bottom: 1px solid var(--border);
}
.panel-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text3);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.panel-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--border), transparent);
}

.stat-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.stat-box {
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px;
  text-align: center;
  transition: all 0.2s;
}
.stat-box:hover {
  background: rgba(255,255,255,0.03);
  border-color: var(--border2);
  transform: translateY(-2px);
}
.stat-box b { 
  display: block; 
  font-size: 24px; 
  font-weight: 700; 
  margin-bottom: 4px;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.stat-box span { font-size: 11px; color: var(--text2); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }

.session-item {
  padding: 12px;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 8px;
  font-size: 13px;
  transition: all 0.2s;
}
.session-item:hover {
  border-color: var(--border2);
  background: rgba(255,255,255,0.02);
}
.session-item-name { font-weight: 600; margin-bottom: 4px; font-size: 14px; }
.session-item-meta { color: var(--text2); font-family: var(--mono); font-size: 11px; }
.session-age {
  font-size: 11px;
  margin-top: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.session-age .bar {
  flex: 1;
  height: 4px;
  background: rgba(255,255,255,0.1);
  border-radius: 2px;
  overflow: hidden;
}
.session-age .fill {
  height: 100%;
  background: linear-gradient(90deg, #34d39a, #10b981);
  border-radius: 2px;
  transition: width 0.3s;
  box-shadow: 0 0 6px rgba(16, 185, 129, 0.4);
}
.session-age .fill.warn { background: linear-gradient(90deg, #fbbf24, #f59e0b); box-shadow: 0 0 6px rgba(245, 158, 11, 0.4); }
.session-age .fill.danger { background: linear-gradient(90deg, #fb7185, #e11d48); box-shadow: 0 0 6px rgba(225, 29, 72, 0.4); }

.file-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 8px;
  transition: all 0.2s;
}
.file-item:hover {
  transform: translateY(-2px);
  border-color: var(--border2);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}
.file-icon { 
  font-size: 24px; 
  flex-shrink: 0; 
  background: rgba(255,255,255,0.05);
  width: 40px; height: 40px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 10px;
}
.file-info { flex: 1; min-width: 0; }
.file-name {
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 2px;
}
.file-meta { font-size: 11px; color: var(--text2); }
.file-dl {
  font-size: 20px;
  color: var(--text3);
  text-decoration: none;
  transition: all 0.2s;
  flex-shrink: 0;
  width: 32px; height: 32px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 8px;
}
.file-dl:hover { 
  color: var(--accent); 
  background: rgba(0, 210, 255, 0.1);
}

/* ── Add friend / group panels ── */
.slide-panel {
  background: rgba(0,0,0,0.15);
  border-bottom: 1px solid var(--border);
  overflow: hidden;
  max-height: 0;
  transition: max-height 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
}
.slide-panel.open { max-height: 400px; }
.slide-panel-inner { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }

/* ── Buttons ── */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 18px;
  border-radius: 12px;
  font-family: var(--font);
  font-size: 14px;
  font-weight: 600;
  border: none;
  cursor: pointer;
  transition: all 0.2s;
}
.btn:active { transform: scale(0.96); }
.btn-primary { 
  background: linear-gradient(135deg, var(--accent2), var(--accent)); 
  color: #fff; 
  box-shadow: 0 4px 12px var(--accent-glow);
}
.btn-primary:hover { 
  box-shadow: 0 6px 16px var(--accent-glow); 
  filter: brightness(1.1);
}
.btn-secondary { 
  background: rgba(255,255,255,0.05); 
  color: var(--text1); 
  border: 1px solid var(--border); 
}
.btn-secondary:hover { 
  border-color: var(--border2); 
  background: rgba(255,255,255,0.08);
}
.btn-danger { 
  background: rgba(255, 51, 102, 0.1); 
  color: var(--danger); 
  border: 1px solid rgba(255, 51, 102, 0.2); 
}
.btn-danger:hover { 
  background: rgba(255, 51, 102, 0.2); 
  box-shadow: 0 4px 12px rgba(255, 51, 102, 0.2);
}
.btn-sm { padding: 6px 12px; font-size: 13px; border-radius: 8px; }

/* ── Inputs ── */
.field {
  width: 100%;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 12px 16px;
  color: var(--text1);
  font-family: var(--font);
  font-size: 14px;
  outline: none;
  transition: all 0.2s;
}
.field:focus { 
  border-color: var(--accent); 
  background: rgba(0,0,0,0.4);
  box-shadow: 0 0 0 3px rgba(0, 210, 255, 0.1);
}
.field::placeholder { color: var(--text3); }

/* ── Toast ── */
#toasts {
  position: fixed;
  bottom: 24px;
  right: 24px;
  display: flex;
  flex-direction: column-reverse;
  gap: 12px;
  z-index: 100;
  max-width: 380px;
}
.toast {
  padding: 16px 20px;
  border-radius: 16px;
  background: rgba(18, 25, 40, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  font-size: 14px;
  animation: slideIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  box-shadow: 0 12px 32px rgba(0,0,0,0.5);
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.toast.info { border-left: 4px solid var(--accent); }
.toast.success { border-left: 4px solid #34d39a; }
.toast.error { border-left: 4px solid var(--danger); }
.toast.warning { border-left: 4px solid var(--warn); }
.toast-icon { flex-shrink: 0; font-size: 18px; margin-top: 2px; }
@keyframes slideIn {
  from { transform: translateX(120%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
@keyframes fadeOut {
  from { opacity: 1; transform: scale(1); }
  to { opacity: 0; transform: scale(0.9); }
}

/* ── Empty states ── */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex: 1;
  gap: 16px;
  color: var(--text3);
  text-align: center;
  padding: 40px;
}
.empty-state .emo { 
  font-size: 48px; 
  margin-bottom: 8px;
  filter: drop-shadow(0 8px 16px rgba(0,0,0,0.2));
}
.empty-state h3 { font-size: 18px; color: var(--text1); font-weight: 600; }
.empty-state p { font-size: 14px; max-width: 280px; line-height: 1.6; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { 
  background: rgba(255,255,255,0.1); 
  border-radius: 6px; 
}
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

/* ── Mode selector ── */
.mode-tabs {
  display: flex;
  gap: 4px;
  margin: 12px 16px;
  border-radius: 12px;
  overflow: hidden;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  padding: 4px;
}
.mode-tab {
  flex: 1;
  padding: 8px;
  text-align: center;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  background: transparent;
  color: var(--text2);
  border: none;
  border-radius: 8px;
  transition: all 0.2s;
}
.mode-tab:hover { color: var(--text1); background: rgba(255,255,255,0.05); }
.mode-tab.active { 
  background: rgba(255,255,255,0.1); 
  color: #fff; 
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

/* ── Misc ── */
.muted { color: var(--text2); }
.mono { font-family: var(--mono); }

@media (max-width: 960px) {
  #panel { display: none; }
}
@media (max-width: 768px) {
  #sidebar { width: 280px; min-width: 280px; }
}
@media (max-width: 640px) {
  #sidebar { width: 72px; min-width: 72px; }
  .friend-info, .id-key, .search-wrap, .mode-tabs,
  .section-label span, .friend-name, .unread-badge { display: none; }
  .friend-avatar { margin: 0 auto; }
  .sidebar-head .conn-badge span { display: none; }
  .app-logo h1, .app-logo .ver { display: none; }
  .app-logo { justify-content: center; }
  .section-label { justify-content: center; padding: 12px 0; }
  .id-card { padding: 12px; }
  .id-card-head { justify-content: center; }
  .id-card-head > div:last-child { display: none; }
}
</style>
</head>
<body>
<div id="app">
  <!-- ── Sidebar ─────────────────────────── -->
  <aside id="sidebar">
    <div class="sidebar-head">
      <div class="app-logo">
        <span class="icon">⚛</span>
        <div>
          <h1>Quantum Chat</h1>
          <div class="ver">v__VERSION__</div>
        </div>
      </div>
      <div class="conn-badge" id="connBadge">
        <span class="dot"></span>
        <span id="connText">connecting…</span>
      </div>
    </div>

    <!-- Identity card -->
    <div class="id-card" onclick="toggleId()">
      <div class="id-card-head">
        <div class="id-avatar">⚛</div>
        <div>
          <div class="id-name">Your Identity</div>
          <div class="id-fp mono" id="myFp">loading…</div>
        </div>
      </div>
      <div class="id-key" id="myKey">loading…</div>
      <div class="id-actions" id="idActions" style="display:none">
        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();copyKey()">Copy key</button>
      </div>
    </div>

    <!-- Mode tabs -->
    <div class="mode-tabs">
      <button class="mode-tab active" id="tabFriends" onclick="setMode('friends')">Friends</button>
      <button class="mode-tab" id="tabGroups" onclick="setMode('groups')">Groups</button>
    </div>

    <!-- Search -->
    <div class="search-wrap">
      <input class="search-input" id="sideSearch" placeholder="Search…" oninput="renderSidebar()">
    </div>

    <!-- Add Friend panel -->
    <div class="slide-panel" id="addPanel">
      <div class="slide-panel-inner">
        <input class="field" id="friendKey" placeholder="Friend public key">
        <input class="field" id="friendName" placeholder="Nickname (optional)">
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" style="flex:1" onclick="addFriend()">Add friend</button>
          <button class="btn btn-secondary" onclick="toggleAdd()">Cancel</button>
        </div>
      </div>
    </div>

    <!-- Add Group panel -->
    <div class="slide-panel" id="groupPanel">
      <div class="slide-panel-inner">
        <input class="field" id="groupName" placeholder="Group name">
        <input class="field" id="groupMembers" placeholder="Member keys, comma-separated (or leave empty)">
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" style="flex:1" onclick="createGroup()">Create</button>
          <button class="btn btn-secondary" onclick="toggleGroup()">Cancel</button>
        </div>
      </div>
    </div>

    <div class="list-section" id="listSection"></div>
  </aside>

  <!-- ── Main chat ───────────────────────── -->
  <main id="main">
    <!-- Chat header -->
    <div class="chat-header" id="chatHeader">
      <div class="empty-state" style="flex-direction:row;padding:0;flex:1">
        <span style="color:var(--text3);font-size:13px">← Select a friend or group to start chatting</span>
      </div>
    </div>

    <!-- Messages -->
    <div class="messages-wrap" id="messages">
      <div class="empty-state">
        <div class="emo">🔐</div>
        <h3>Post-quantum encrypted</h3>
        <p>All messages are encrypted with Kyber-512 + AES-256-GCM. Select a contact to start.</p>
      </div>
    </div>

    <!-- Typing indicator -->
    <div id="typing-indicator"></div>

    <!-- Drop overlay -->
    <div class="drop-overlay" id="dropOverlay">
      <div style="font-size:36px">📎</div>
      <div>Drop file to send encrypted</div>
    </div>

    <!-- Composer -->
    <div class="composer">
      <div class="composer-inner">
        <textarea id="text" rows="1" placeholder="Type an encrypted message…"
          oninput="onTextInput()" onkeydown="onTextKey(event)"></textarea>
        <div class="composer-actions">
          <label class="icon-btn" title="Attach file">
            📎
            <input id="fileInput" type="file" hidden onchange="sendFile()">
          </label>
          <button class="send-btn" id="sendBtn" onclick="sendMessage()" disabled title="Send">➤</button>
        </div>
      </div>
      <div class="char-hint" id="charHint">0 / 65536</div>
    </div>
  </main>

  <!-- ── Right panel ─────────────────────── -->
  <aside id="panel">
    <div class="panel-section">
      <div class="panel-title">Overview</div>
      <div class="stat-row">
        <div class="stat-box"><b id="statFriends">0</b><span>friends</span></div>
        <div class="stat-box"><b id="statOnline">0</b><span>online</span></div>
        <div class="stat-box"><b id="statSessions">0</b><span>sessions</span></div>
        <div class="stat-box"><b id="statFiles">0</b><span>files</span></div>
      </div>
    </div>
    <div class="panel-section" id="panelSessions">
      <div class="panel-title">Secure sessions</div>
      <div id="sessionList"><span class="muted" style="font-size:12px">No sessions yet</span></div>
    </div>
    <div class="panel-section" id="panelFiles">
      <div class="panel-title">Recent files</div>
      <div id="fileList"><span class="muted" style="font-size:12px">No files yet</span></div>
    </div>
  </aside>
</div>

<!-- Toasts -->
<div id="toasts"></div>

<script>
// ─── State ──────────────────────────────────────────────────────────────────
const UI_WS_PORT = __UI_WS_PORT__;
const UI_TOKEN = "__UI_TOKEN__";
const MAX_FILE_BYTES_UI = 512*1024*1024;

let state = {
  public_key: '', fingerprint: '', signaling_url: '',
  online: [], friends: [], groups: [], messages: [],
  files: [], sessions: {},
};
let ws = null;
let mode = 'friends';          // 'friends' | 'groups'
let selectedTarget = null;     // {type:'friend'|'group', id:string}
let typing = {};               // peer_pubkey -> timestamp
let typingTimer = null;
let myTypingActive = false;
let myTypingTimeout = null;
let notificationsGranted = false;
let unreadTitle = 0;
let titleTimer = null;

// ─── Utils ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short = k => k ? k.slice(0,10)+'…'+k.slice(-6) : '';
const fmt = n => {
  if(!Number.isFinite(+n)) return '0 B';
  let u=['B','KB','MB','GB'],i=0; n=+n;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return `${n.toFixed(i?1:0)} ${u[i]}`;
};
const relTime = ts => {
  if(!ts) return '';
  const d = Date.now()/1000 - ts, m = Math.floor(d/60), h = Math.floor(d/3600), day = Math.floor(d/86400);
  if(d < 60) return 'just now';
  if(m < 60) return `${m}m ago`;
  if(h < 24) return `${h}h ago`;
  if(day < 7) return `${day}d ago`;
  return new Date(ts*1000).toLocaleDateString();
};
const fullTime = ts => ts ? new Date(ts*1000).toLocaleString() : '';
const dateLabel = ts => {
  if(!ts) return '';
  const d = new Date(ts*1000), today = new Date();
  if(d.toDateString() === today.toDateString()) return 'Today';
  const yesterday = new Date(today); yesterday.setDate(today.getDate()-1);
  if(d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString(undefined, {weekday:'long',month:'short',day:'numeric'});
};
const fileIcon = name => {
  const ext = (name||'').split('.').pop().toLowerCase();
  const map = {png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',webp:'🖼️',svg:'🖼️',
               mp4:'🎬',mov:'🎬',avi:'🎬',webm:'🎬',mkv:'🎬',
               mp3:'🎵',wav:'🎵',ogg:'🎵',flac:'🎵',aac:'🎵',
               pdf:'📄',doc:'📄',docx:'📄',txt:'📄',md:'📄',
               zip:'📦',tar:'📦',gz:'📦',rar:'📦',
               py:'💻',js:'💻',ts:'💻',html:'💻',css:'💻',sh:'💻',
  };
  return map[ext] || '📎';
};
const isImage = name => /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(name||'');
const avatarLetter = name => (name||'?').trim()[0].toUpperCase();
const avatarColor = key => {
  let h = 0;
  for(let c of (key||'')) h = ((h<<5)-h) + c.charCodeAt(0);
  const colors = ['#1a3a8f','#2a1a8f','#1a6a5f','#5a1a6f','#8f3a1a','#1a5a8f'];
  return colors[Math.abs(h) % colors.length];
};

// ─── WebSocket ───────────────────────────────────────────────────────────────
function wsConnect() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${scheme}://${location.hostname}:${UI_WS_PORT}/?token=${encodeURIComponent(UI_TOKEN)}`);
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(wsConnect, 1500); };
  ws.onerror = () => {};
  ws.onmessage = e => handle(JSON.parse(e.data));
}

function setConn(connected) {
  const b = $('connBadge'), t = $('connText');
  b.className = 'conn-badge' + (connected ? ' connected' : '');
  t.textContent = connected ? 'connected' : 'disconnected';
}

function send(obj) {
  if(ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
  else toast('UI socket not connected', 'warning');
}

// ─── Message handler ─────────────────────────────────────────────────────────
function handle(d) {
  if(d.type === 'state') {
    state = d;
    render();
  } else if(d.type === 'notice') {
    toast(d.text, d.level || 'info');
  } else if(d.type === 'message') {
    state.messages.push(d.message);
    const isSelected = selectedTarget &&
      (selectedTarget.type === 'friend'
        ? !d.message.group_id && (d.message.sender_pubkey === selectedTarget.id || d.message.recipient_pubkey === selectedTarget.id)
        : d.message.group_id === selectedTarget.id);
    if(!isSelected && d.message.direction === 'in') {
      const friend = state.friends.find(f => f.pubkey === d.message.sender_pubkey);
      const name = friend?.nickname || short(d.message.sender_pubkey);
      notify(name, d.message.body);
      bumpUnread(d.message.sender_pubkey);
    }
    renderMessages();
    renderSidebar();
    scrollBottom(false);
    if(isSelected && d.message.direction === 'in') {
      send({type:'clear_unread', pubkey: d.message.sender_pubkey});
    }
  } else if(d.type === 'file') {
    state.files.unshift(d.file);
    $('statFiles').textContent = state.files.length;
    renderFiles();
    toast(`${d.file.direction === 'in' ? '📥' : '📤'} ${d.file.filename}`, 'success');
  } else if(d.type === 'typing') {
    if(d.active) {
      typing[d.peer] = Date.now();
      setTimeout(() => {
        delete typing[d.peer];
        renderTyping();
      }, 6000);
    } else {
      delete typing[d.peer];
    }
    renderTyping();
  } else if(d.type === 'status_update') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) { m.status = d.status; renderMessages(); }
  } else if(d.type === 'read_receipt') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) { m.status = 'read'; m.read_at = d.read_at; renderMessages(); }
  } else if(d.type === 'reaction') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) {
      if(!m.reactions) m.reactions = [];
      if(d.action === 'add') {
        if(!m.reactions.find(r => r.peer_pubkey === d.peer && r.emoji === d.emoji))
          m.reactions.push({peer_pubkey: d.peer, emoji: d.emoji});
      } else {
        m.reactions = m.reactions.filter(r => !(r.peer_pubkey === d.peer && r.emoji === d.emoji));
      }
      renderMessages();
    }
  }
}

// ─── Render ──────────────────────────────────────────────────────────────────
function render() {
  $('myKey').textContent = state.public_key || '';
  $('myFp').textContent = state.fingerprint || '';
  $('statFriends').textContent = state.friends.length;
  $('statOnline').textContent = state.online.length;
  $('statSessions').textContent = Object.keys(state.sessions||{}).length;
  $('statFiles').textContent = (state.files||[]).length;
  renderSidebar();
  renderMessages();
  renderSessions();
  renderFiles();
  updateSendBtn();
}

function renderSidebar() {
  const q = ($('sideSearch').value||'').toLowerCase();
  const el = $('listSection');
  el.innerHTML = '';

  if(mode === 'friends') {
    const friends = state.friends.filter(f =>
      !q || (f.nickname||'').toLowerCase().includes(q) || f.pubkey.toLowerCase().includes(q)
    );
    const addBtn = `<button onclick="toggleAdd()" title="Add friend">＋</button>`;
    const label = document.createElement('div');
    label.className = 'section-label';
    label.innerHTML = `<span>Friends (${friends.length})</span>${addBtn}`;
    el.appendChild(label);
    if(!friends.length) {
      el.innerHTML += '<div style="padding:16px;color:var(--text3);font-size:12px;text-align:center">No friends yet — add one above</div>';
      return;
    }
    friends.forEach(f => {
      const online = state.online.includes(f.pubkey);
      const secure = !!(state.sessions&&state.sessions[f.pubkey]);
      const isSelected = selectedTarget?.type === 'friend' && selectedTarget?.id === f.pubkey;
      const lastMsg = [...state.messages].reverse().find(m =>
        !m.group_id && (m.sender_pubkey === f.pubkey || m.recipient_pubkey === f.pubkey)
      );
      const unread = f.unread || 0;
      const div = document.createElement('div');
      div.className = 'friend-item' + (isSelected ? ' active' : '');
      div.onclick = () => selectFriend(f.pubkey);
      const bgColor = avatarColor(f.pubkey);
      div.innerHTML = `
        <div class="friend-avatar">
          <div class="avatar-circle" style="background:${bgColor}">${esc(avatarLetter(f.nickname||f.pubkey))}</div>
          <div class="online-dot ${online?'online':''}"></div>
        </div>
        <div class="friend-info">
          <div class="friend-name">${esc(f.nickname||short(f.pubkey))}</div>
          <div class="friend-preview">${lastMsg ? esc(lastMsg.body.slice(0,40)) : secure?'🔒 secure session':(f.verified?'✅ verified':'⚠️ unverified')}</div>
        </div>
        <div class="friend-meta">
          ${unread ? `<div class="unread-badge">${unread}</div>` : ''}
          ${f.verified ? '<div class="secure-tag">✅</div>' : '<div class="secure-tag">⚠️</div>'} ${secure ? '<div class="secure-tag">🔒</div>' : ''}
          ${lastMsg ? `<div class="time-tag">${relTime(lastMsg.timestamp)}</div>` : ''}
        </div>
      `;
      el.appendChild(div);
    });
  } else {
    const groups = state.groups.filter(g =>
      !q || (g.name||'').toLowerCase().includes(q)
    );
    const addBtn = `<button onclick="toggleGroup()" title="Create group">＋</button>`;
    const label = document.createElement('div');
    label.className = 'section-label';
    label.innerHTML = `<span>Groups (${groups.length})</span>${addBtn}`;
    el.appendChild(label);
    if(!groups.length) {
      el.innerHTML += '<div style="padding:16px;color:var(--text3);font-size:12px;text-align:center">No groups yet</div>';
      return;
    }
    groups.forEach(g => {
      const isSelected = selectedTarget?.type === 'group' && selectedTarget?.id === g.group_id;
      const div = document.createElement('div');
      div.className = 'friend-item' + (isSelected ? ' active' : '');
      div.onclick = () => selectGroup(g.group_id);
      div.innerHTML = `
        <div class="friend-avatar">
          <div class="avatar-circle" style="background:#1a3a8f">👥</div>
        </div>
        <div class="friend-info">
          <div class="friend-name">${esc(g.name)}</div>
          <div class="friend-preview">${(g.members||[]).length} members</div>
        </div>
      `;
      el.appendChild(div);
    });
  }
}

function renderMessages() {
  const el = $('messages');
  if(!selectedTarget) return;

  const msgs = (state.messages||[]).filter(m => matchTarget(m));
  if(!msgs.length) {
    el.innerHTML = '<div class="empty-state"><div class="emo">🔒</div><h3>No messages yet</h3><p>Send the first encrypted message!</p></div>';
    return;
  }

  let html = '';
  let lastDate = '';
  let lastSender = '';

  msgs.forEach((m, idx) => {
    const thisDate = dateLabel(m.timestamp);
    if(thisDate !== lastDate) {
      html += `<div class="date-divider">${thisDate}</div>`;
      lastDate = thisDate;
      lastSender = '';
    }

    const isOut = m.direction === 'out';
    const sameGroup = m.sender_pubkey === lastSender && idx > 0;
    lastSender = m.sender_pubkey;

    const statusIcon = isOut ? msgStatus(m) : '';

    // Reactions HTML
    const reactMap = {};
    (m.reactions||[]).forEach(r => {
      if(!reactMap[r.emoji]) reactMap[r.emoji] = {count:0, mine:false};
      reactMap[r.emoji].count++;
      if(r.peer_pubkey === state.public_key) reactMap[r.emoji].mine = true;
    });
    const reactHtml = Object.entries(reactMap).map(([emoji, info]) =>
      `<span class="reaction-chip ${info.mine?'mine':''}" onclick="toggleReaction('${esc(m.msg_id)}','${esc(m.recipient_pubkey||m.sender_pubkey)}','${emoji}')">${emoji} ${info.count}</span>`
    ).join('');

    // Image body
    let bodyHtml;
    if(m._imgSrc) {
      bodyHtml = `<img class="msg-image" src="${esc(m._imgSrc)}" onclick="window.open(this.src)" loading="lazy">`;
    } else {
      bodyHtml = `<span>${esc(m.body)}</span>`;
    }

    // Reaction bar
    const reactionBar = `<div class="reaction-bar">
      ${['👍','❤️','😂','😮','😢','🔥'].map(e=>`<button class="reaction-btn" onclick="event.stopPropagation();toggleReaction('${esc(m.msg_id)}','${esc(isOut?m.recipient_pubkey:m.sender_pubkey)}','${e}')">${e}</button>`).join('')}
    </div>`;

    html += `
      <div class="msg-group ${isOut?'out':'in'}">
        <div class="msg-bubble" style="${sameGroup?'margin-top:1px':''}">
          ${reactionBar}
          ${bodyHtml}
        </div>
        ${reactHtml ? `<div class="reactions" style="padding:0 4px">${reactHtml}</div>` : ''}
        <div class="msg-meta">
          <span title="${fullTime(m.timestamp)}">${relTime(m.timestamp)}</span>
          ${statusIcon}
          ${!isOut && !m.read_at ? `<button style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:10px;padding:0" onclick="markRead('${esc(m.msg_id)}','${esc(m.sender_pubkey)}')">mark read</button>` : ''}
        </div>
      </div>
    `;
  });

  el.innerHTML = html;
}

function msgStatus(m) {
  const s = m.status || '';
  if(s === 'read') return `<span class="check read" title="Read">✓✓</span>`;
  if(s === 'delivered_to_peer' || s === 'delivered') return `<span class="check delivered" title="Delivered">✓✓</span>`;
  if(s === 'sent_to_relay') return `<span class="check" title="Sent">✓</span>`;
  return `<span style="font-size:10px;color:var(--text3)" title="Sending">🕐</span>`;
}

function renderTyping() {
  const el = $('typing-indicator');
  const target = selectedTarget;
  if(!target || target.type !== 'friend') { el.innerHTML = ''; return; }
  if(typing[target.id]) {
    const f = state.friends.find(x=>x.pubkey===target.id);
    const name = f?.nickname || short(target.id);
    el.innerHTML = `<span style="color:var(--text2);font-size:12px">${esc(name)} is typing</span><div class="typing-dots"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div>`;
  } else {
    el.innerHTML = '';
  }
}

function renderSessions() {
  const el = $('sessionList');
  const entries = Object.entries(state.sessions||{});
  if(!entries.length) {
    el.innerHTML = '<span class="muted" style="font-size:12px">No sessions yet</span>';
    return;
  }
  const SESSION_TTL = 86400;
  el.innerHTML = entries.map(([peer, s]) => {
    const f = state.friends.find(x=>x.pubkey===peer);
    const name = f?.nickname || short(peer);
    const pct = Math.min(100, Math.round((s.expires_in/SESSION_TTL)*100));
    const cls = pct > 50 ? '' : pct > 20 ? 'warn' : 'danger';
    const expiresLabel = s.expires_in > 3600
      ? `${Math.floor(s.expires_in/3600)}h remaining`
      : s.expires_in > 60
      ? `${Math.floor(s.expires_in/60)}m remaining`
      : `Expired`;
    return `<div class="session-item">
      <div class="session-item-name">${esc(name)}</div>
      <div class="session-item-meta">${short(peer)}</div>
      <div class="session-age">
        <span style="font-size:10px;color:var(--text3)">${expiresLabel}</span>
        <div class="bar"><div class="fill ${cls}" style="width:${pct}%"></div></div>
      </div>
    </div>`;
  }).join('');
}

function renderFiles() {
  const el = $('fileList');
  if(!state.files.length) {
    el.innerHTML = '<span class="muted" style="font-size:12px">No files yet</span>';
    return;
  }
  el.innerHTML = state.files.slice(0,10).map(f => `
    <div class="file-item">
      <div class="file-icon">${fileIcon(f.filename)}</div>
      <div class="file-info">
        <div class="file-name" title="${esc(f.filename)}">${esc(f.filename)}</div>
        <div class="file-meta">${fmt(f.size)} · ${relTime(f.uploaded_at)}</div>
      </div>
      <a class="file-dl" href="/files/${f.file_id}" download title="Download">⬇</a>
    </div>
  `).join('');
}

function renderChatHeader() {
  const el = $('chatHeader');
  if(!selectedTarget) {
    el.innerHTML = '<div style="flex:1;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:13px">← Select a friend or group to start chatting</div>';
    return;
  }
  if(selectedTarget.type === 'friend') {
    const f = state.friends.find(x=>x.pubkey===selectedTarget.id);
    const name = f?.nickname || short(selectedTarget.id);
    const online = state.online.includes(selectedTarget.id);
    const secure = !!(state.sessions&&state.sessions[selectedTarget.id]);
    const bgColor = avatarColor(selectedTarget.id);
    el.innerHTML = `
      <div class="chat-header-avatar" style="background:${bgColor}">${esc(avatarLetter(f?.nickname||selectedTarget.id))}</div>
      <div class="chat-header-info">
        <div class="chat-header-name">${esc(name)}</div>
        <div class="chat-header-sub">
          ${online?'🟢 Online':'⚫ Offline'} · ${secure?'🔒 Secure session':'🔓 No session'} · ${f?.verified?'✅ Verified':'⚠️ Unverified'} · ${f?.direct_url?'🌐 Direct-capable':'relay'}
          ${f?.fingerprint?` · Safety ${esc(f.fingerprint)}`:''}${f?.last_seen?` · Last seen ${relTime(f.last_seen)}`:''}
        </div>
      </div>
      <div class="chat-header-actions">
        ${!secure?`<button class="btn btn-primary btn-sm" onclick="connectPeer()">Connect</button>`:''}
        ${f?.verified?`<button class="btn btn-secondary btn-sm" onclick="verifyFriend(false)">Unverify</button>`:`<button class="btn btn-primary btn-sm" onclick="verifyFriend(true)">Verify safety</button>`}
        <button class="btn btn-secondary btn-sm" onclick="removeFriend('${esc(selectedTarget.id)}')">Remove</button>
      </div>
    `;
  } else {
    const g = state.groups.find(x=>x.group_id===selectedTarget.id);
    const name = g?.name || 'Group';
    el.innerHTML = `
      <div class="chat-header-avatar">👥</div>
      <div class="chat-header-info">
        <div class="chat-header-name">${esc(name)}</div>
        <div class="chat-header-sub">${(g?.members||[]).length} members · group epoch key · ${esc(g?.fingerprint||'')}</div>
      </div>
    `;
  }
}

// ─── Selection ────────────────────────────────────────────────────────────────
function selectFriend(pubkey) {
  selectedTarget = {type:'friend', id:pubkey};
  delete typing[pubkey];
  renderTyping();
  renderSidebar();
  renderChatHeader();
  renderMessages();
  scrollBottom(true);
  send({type:'clear_unread', pubkey});
  updateSendBtn();
  // Request browser notification permission lazily
  if(Notification.permission === 'default') Notification.requestPermission();
}

function selectGroup(group_id) {
  selectedTarget = {type:'group', id:group_id};
  renderSidebar();
  renderChatHeader();
  renderMessages();
  scrollBottom(true);
  updateSendBtn();
}

function matchTarget(m) {
  if(!selectedTarget) return false;
  if(selectedTarget.type === 'group') return m.group_id === selectedTarget.id;
  return !m.group_id && (m.sender_pubkey === selectedTarget.id || m.recipient_pubkey === selectedTarget.id);
}

// ─── Mode ─────────────────────────────────────────────────────────────────────
function setMode(m) {
  mode = m;
  $('tabFriends').className = 'mode-tab' + (m==='friends'?' active':'');
  $('tabGroups').className  = 'mode-tab' + (m==='groups' ?' active':'');
  selectedTarget = null;
  renderSidebar();
  renderChatHeader();
  renderMessages();
  updateSendBtn();
}

// ─── Actions ──────────────────────────────────────────────────────────────────
function toggleId() {
  const k = $('myKey'), a = $('idActions');
  const show = !k.classList.contains('visible');
  k.classList.toggle('visible', show);
  a.style.display = show ? 'flex' : 'none';
}

function copyKey() {
  navigator.clipboard.writeText(state.public_key||'').then(()=>toast('Public key copied','success'));
}

function toggleAdd() {
  const p = $('addPanel');
  p.classList.toggle('open');
  if(p.classList.contains('open')) $('friendKey').focus();
}

function toggleGroup() {
  const p = $('groupPanel');
  p.classList.toggle('open');
  if(p.classList.contains('open')) $('groupName').focus();
}

function addFriend() {
  const pk = $('friendKey').value.trim(), nick = $('friendName').value.trim();
  if(!pk) return;
  send({type:'add_friend', pubkey:pk, nickname:nick||undefined});
  $('friendKey').value=''; $('friendName').value='';
  $('addPanel').classList.remove('open');
  setMode('friends');
}

function removeFriend(pubkey) {
  if(!confirm('Remove this friend and their local session?')) return;
  send({type:'remove_friend', pubkey});
  selectedTarget = null;
  renderChatHeader();
  renderMessages();
}

function connectPeer() {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  send({type:'connect', pubkey: selectedTarget.id});
}

function verifyFriend(verified) {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  const f = state.friends.find(x=>x.pubkey===selectedTarget.id);
  if(verified && !confirm(`Verify this safety fingerprint?

${f?.fingerprint||selectedTarget.id}`)) return;
  send({type:'verify_friend', pubkey:selectedTarget.id, verified});
}

function sendMessage() {
  const text = $('text').value.trim();
  if(!text || !selectedTarget) return;
  if(selectedTarget.type === 'group') {
    send({type:'send_message', group_id:selectedTarget.id, text});
  } else {
    send({type:'send_message', pubkey:selectedTarget.id, text});
  }
  $('text').value = '';
  onTextInput();
  stopTyping();
}

function sendFile() {
  const f = $('fileInput').files[0];
  if(!f || !selectedTarget) return;
  if(f.size > MAX_FILE_BYTES_UI) { toast('File exceeds 512 MB limit','error'); return; }
  const r = new FileReader();
  r.onload = () => {
    const data = r.result.split(',')[1];
    if(selectedTarget.type === 'group') {
      send({type:'send_file', group_id:selectedTarget.id, filename:f.name, data});
    } else {
      send({type:'send_file', pubkey:selectedTarget.id, filename:f.name, data});
    }
  };
  r.readAsDataURL(f);
  $('fileInput').value = '';
}

function createGroup() {
  const name = $('groupName').value.trim();
  const raw = $('groupMembers').value.trim();
  const members = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean)
    : (selectedTarget?.type==='friend' ? [selectedTarget.id] : []);
  send({type:'create_group', name, members});
  $('groupName').value=''; $('groupMembers').value='';
  $('groupPanel').classList.remove('open');
  setMode('groups');
}

function markRead(msg_id, peer_pubkey) {
  send({type:'read_receipt', pubkey:peer_pubkey, msg_id});
}

function toggleReaction(msg_id, peer_pubkey, emoji) {
  if(!peer_pubkey || peer_pubkey === state.public_key) return;
  const m = state.messages.find(x=>x.msg_id===msg_id);
  if(!m) return;
  const existing = (m.reactions||[]).find(r=>r.peer_pubkey===state.public_key&&r.emoji===emoji);
  const action = existing ? 'remove' : 'add';
  send({type:'reaction', pubkey:peer_pubkey, msg_id, emoji, action});
}

// ─── Typing ───────────────────────────────────────────────────────────────────
function startTyping() {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  if(!myTypingActive) {
    myTypingActive = true;
    send({type:'typing', pubkey:selectedTarget.id, active:true});
  }
  clearTimeout(myTypingTimeout);
  myTypingTimeout = setTimeout(stopTyping, 3000);
}

function stopTyping() {
  if(myTypingActive && selectedTarget?.type==='friend') {
    myTypingActive = false;
    send({type:'typing', pubkey:selectedTarget.id, active:false});
  }
  clearTimeout(myTypingTimeout);
}

function onTextInput() {
  const v = $('text').value;
  const bytes = new TextEncoder().encode(v).length;
  $('charHint').textContent = `${bytes.toLocaleString()} / 65,536`;
  updateSendBtn();
  autoResize($('text'));
  if(v.trim()) startTyping(); else stopTyping();
}

function onTextKey(e) {
  if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

function updateSendBtn() {
  const hasText = !!$('text').value.trim();
  const hasTarget = !!selectedTarget;
  $('sendBtn').disabled = !(hasText && hasTarget);
}

// ─── Scroll ───────────────────────────────────────────────────────────────────
function scrollBottom(instant) {
  const el = $('messages');
  if(instant) el.scrollTop = el.scrollHeight;
  else setTimeout(() => el.scrollTop = el.scrollHeight, 50);
}

// ─── Unread ───────────────────────────────────────────────────────────────────
function bumpUnread(pubkey) {
  unreadTitle++;
  updateTitle();
}

function updateTitle() {
  document.title = unreadTitle > 0 ? `(${unreadTitle}) ⚛ Quantum Chat` : '⚛ Quantum Chat';
}

// ─── Notifications ────────────────────────────────────────────────────────────
function notify(title, body) {
  if(Notification.permission === 'granted') {
    try {
      new Notification(`⚛ ${title}`, {body: body.slice(0,120), icon: ''});
    } catch(_) {}
  }
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function toast(text, level='info') {
  const icons = {info:'ℹ️', success:'✅', error:'❌', warning:'⚠️'};
  const div = document.createElement('div');
  div.className = `toast ${level}`;
  div.innerHTML = `<span class="toast-icon">${icons[level]||'ℹ️'}</span><span>${esc(text)}</span>`;
  $('toasts').appendChild(div);
  setTimeout(() => div.remove(), 4500);
}

// ─── Drag & Drop ─────────────────────────────────────────────────────────────
const mainEl = $('main');
mainEl.addEventListener('dragover', e => {
  e.preventDefault();
  if(selectedTarget) $('dropOverlay').classList.add('active');
});
mainEl.addEventListener('dragleave', e => {
  if(!mainEl.contains(e.relatedTarget)) $('dropOverlay').classList.remove('active');
});
mainEl.addEventListener('drop', e => {
  e.preventDefault();
  $('dropOverlay').classList.remove('active');
  if(!selectedTarget) { toast('Select a contact first', 'warning'); return; }
  const file = e.dataTransfer.files[0];
  if(!file) return;
  if(file.size > MAX_FILE_BYTES_UI) { toast('File exceeds 512 MB limit', 'error'); return; }
  const r = new FileReader();
  r.onload = () => {
    const data = r.result.split(',')[1];
    if(selectedTarget.type === 'group')
      send({type:'send_file', group_id:selectedTarget.id, filename:file.name, data});
    else
      send({type:'send_file', pubkey:selectedTarget.id, filename:file.name, data});
  };
  r.readAsDataURL(file);
});

// Focus on window return — clear title unread
window.addEventListener('focus', () => {
  unreadTitle = 0;
  updateTitle();
});

wsConnect();
</script>
</body>
</html>
"""


# ─── Entry point ──────────────────────────────────────────────────────────────

def start_http(node: QuantumNode, host: str, port: int,
               ui_ws_port: int = UI_WS_PORT, require_http_auth: bool = False) -> ThreadedHTTPServer:
    ChatHTTPHandler.node = node
    ChatHTTPHandler.ui_ws_port = ui_ws_port
    ChatHTTPHandler.require_http_auth = require_http_auth
    httpd = ThreadedHTTPServer((host, port), ChatHTTPHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


async def start_ui_ws(node: QuantumNode, host: str, port: int) -> None:
    websockets = require_websockets()
    async with websockets.serve(node.handle_ui, host, port, max_size=MAX_FILE_BYTES * 2):
        await asyncio.Future()


async def start_direct_peer(node: QuantumNode, host: str, port: int) -> None:
    websockets = require_websockets()
    async with websockets.serve(node.handle_direct_peer, host, port, max_size=MAX_FILE_BYTES * 2):
        LOG.info("Direct peer listener on ws://%s:%d", host, port)
        await asyncio.Future()


async def start_signaling(host: str, port: int) -> None:
    websockets = require_websockets()
    server = SignalingServer()
    async with websockets.serve(server.handle, host, port, max_size=MAX_FILE_BYTES * 2):
        LOG.info("Signaling server listening on ws://%s:%d", host, port)
        print(f"Signaling server listening on ws://{host}:{port}")
        await asyncio.Future()


def _is_local_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


async def run_node(args: argparse.Namespace) -> None:
    if (not _is_local_host(args.http_host) or not _is_local_host(args.ui_ws_host)) and not args.allow_remote_ui:
        raise SystemExit("Refusing to expose the UI on a non-local interface without --allow-remote-ui")
    direct_url = None
    if args.enable_direct:
        advertised_host = args.direct_advertise_host or args.direct_host
        direct_url = f"ws://{advertised_host}:{args.direct_port}"
    node = QuantumNode(args.db, args.signaling_url, direct_url=direct_url, enable_direct=args.enable_direct)
    node.allow_remote_ui = args.allow_remote_ui
    ui_url = f"http://{args.http_host}:{args.http_port}"
    if args.allow_remote_ui:
        ui_url = f"{ui_url}?token={quote(node.ui_token)}"
    httpd = start_http(node, args.http_host, args.http_port, args.ui_ws_port,
                       require_http_auth=args.allow_remote_ui)
    LOG.info("%s v%s — identity: %s", APP_NAME, VERSION, node.public_key)
    print(f"{APP_NAME} v{VERSION}")
    print(f"Identity:  {node.public_key}")
    print(f"Fingerprint: {key_fingerprint(node.public_key)}")
    print(f"UI:        {ui_url}")
    print(f"Health:    http://{args.http_host}:{args.http_port}/health")
    if args.open_browser:
        webbrowser.open(ui_url)
    tasks = [
        asyncio.create_task(start_ui_ws(node, args.ui_ws_host, args.ui_ws_port)),
        asyncio.create_task(node.connect_signaling_loop()),
    ]
    if args.enable_direct:
        tasks.append(asyncio.create_task(start_direct_peer(node, args.direct_host, args.direct_port)))
    if args.with_signaling:
        tasks.append(asyncio.create_task(start_signaling(args.signaling_host, args.signaling_port)))
    try:
        await asyncio.gather(*tasks)
    finally:
        httpd.shutdown()
        node.db.close()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"Quantum Chat v{VERSION} — post-quantum P2P encrypted chat"
    )
    sub = parser.add_subparsers(dest="command")
    signal_cmd = sub.add_parser("signal", help="run only the signaling/relay server")
    signal_cmd.add_argument("--host", default=SIGNALING_HOST)
    signal_cmd.add_argument("--port", type=int, default=SIGNALING_PORT)

    parser.add_argument("--db", default=DB_FILE)
    parser.add_argument("--signaling-url", default=DEFAULT_SIGNALING_URL)
    parser.add_argument("--with-signaling", action="store_true",
                        help="also start a local signaling server")
    parser.add_argument("--signaling-host", default=SIGNALING_HOST)
    parser.add_argument("--signaling-port", type=int, default=SIGNALING_PORT)
    parser.add_argument("--http-host", default=HTTP_HOST)
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--ui-ws-host", default=UI_WS_HOST)
    parser.add_argument("--ui-ws-port", type=int, default=UI_WS_PORT)
    parser.add_argument("--allow-remote-ui", action="store_true",
                        help="allow binding HTTP/UI WebSocket to non-local interfaces and require token auth for non-root HTTP routes")
    parser.add_argument("--enable-direct", action="store_true", default=True,
                        help="enable direct peer WebSocket listener and direct delivery fallback")
    parser.add_argument("--no-direct", dest="enable_direct", action="store_false")
    parser.add_argument("--direct-host", default=DIRECT_PEER_HOST)
    parser.add_argument("--direct-port", type=int, default=DIRECT_PEER_PORT)
    parser.add_argument("--direct-advertise-host", default=None,
                        help="host/IP peers should use to reach this node's direct listener")
    parser.add_argument("--no-browser", dest="open_browser", action="store_false")
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging verbosity (default: WARNING)"
    )
    parser.set_defaults(open_browser=True)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level, logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if args.command == "signal":
        asyncio.run(start_signaling(args.host, args.port))
    else:
        asyncio.run(run_node(args))


if __name__ == "__main__":
    main()
