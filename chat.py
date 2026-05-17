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
import secrets
import sqlite3
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
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

    def derive_session_key(self, shared_secret: bytes, a_pub: str, b_pub: str, session_id: str) -> bytes:
        salt = hashlib.sha256("|".join(sorted([a_pub, b_pub]) + [session_id]).encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt, info=b"quantum-chat-v3-session")
        return hkdf.derive(shared_secret)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.AESGCM(key).encrypt(nonce, plaintext, aad)
        return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

    def decrypt(self, key: bytes, packet: Dict[str, str], aad: bytes = b"") -> bytes:
        return self.AESGCM(key).decrypt(b64d(packet["nonce"]), b64d(packet["ciphertext"]), aad)


class Database:
    def __init__(self, db_path: str = DB_FILE) -> None:
        self.path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_tables()

    def _init_tables(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key TEXT NOT NULL,
                secret_key BLOB NOT NULL,
                created_at INTEGER NOT NULL
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
                initiator INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                pubkey TEXT NOT NULL,
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
                delivered INTEGER NOT NULL DEFAULT 0
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
                uploaded_at INTEGER NOT NULL
            );
            """
        )
        self.conn.commit()

    def load_identity(self) -> Optional[Tuple[str, bytes]]:
        row = self.conn.execute("SELECT public_key, secret_key FROM identity WHERE id=1").fetchone()
        return (row["public_key"], row["secret_key"]) if row else None

    def save_identity(self, public_key: str, secret_key: bytes) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO identity (id, public_key, secret_key, created_at) VALUES (1, ?, ?, ?)",
            (public_key, secret_key, utc_ts()),
        )
        self.conn.commit()

    def add_friend(self, pubkey: str, nickname: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO friends (pubkey, nickname, added_at) VALUES (?, ?, ?) "
            "ON CONFLICT(pubkey) DO UPDATE SET nickname=COALESCE(excluded.nickname, friends.nickname), trusted=1",
            (pubkey, nickname, utc_ts()),
        )
        self.conn.commit()

    def remove_friend(self, pubkey: str) -> None:
        self.conn.execute("DELETE FROM friends WHERE pubkey=?", (pubkey,))
        self.conn.execute("DELETE FROM sessions WHERE peer_pubkey=?", (pubkey,))
        self.conn.commit()

    def get_friends(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT pubkey, nickname, last_seen FROM friends ORDER BY added_at DESC")]

    def is_friend(self, pubkey: str) -> bool:
        return self.conn.execute("SELECT 1 FROM friends WHERE pubkey=?", (pubkey,)).fetchone() is not None

    def touch_friend(self, pubkey: str) -> None:
        self.conn.execute("UPDATE friends SET last_seen=? WHERE pubkey=?", (utc_ts(), pubkey))
        self.conn.commit()

    def save_session(self, peer_pubkey: str, session_id: str, key: bytes, initiator: bool) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (peer_pubkey, session_id, key, established_at, initiator) VALUES (?, ?, ?, ?, ?)",
            (peer_pubkey, session_id, key, utc_ts(), int(initiator)),
        )
        self.conn.commit()

    def get_session(self, peer_pubkey: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)).fetchone()
        return dict(row) if row else None

    def create_group(self, group_id: str, name: str, owner_pubkey: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO groups (group_id, name, created_at) VALUES (?, ?, ?)", (group_id, name, utc_ts()))
        self.add_group_member(group_id, owner_pubkey)
        self.conn.commit()

    def add_group_member(self, group_id: str, pubkey: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO group_members (group_id, pubkey, joined_at) VALUES (?, ?, ?)", (group_id, pubkey, utc_ts()))
        self.conn.commit()

    def groups_for(self, pubkey: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT g.group_id, g.name, g.created_at FROM groups g JOIN group_members gm ON g.group_id=gm.group_id WHERE gm.pubkey=? ORDER BY g.created_at DESC",
            (pubkey,),
        )
        return [dict(r) for r in rows]

    def group_members(self, group_id: str) -> List[str]:
        return [r["pubkey"] for r in self.conn.execute("SELECT pubkey FROM group_members WHERE group_id=?", (group_id,))]

    def save_message(self, msg_id: str, sender: str, body: str, direction: str, recipient: Optional[str] = None, group_id: Optional[str] = None, delivered: bool = False) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (msg_id, sender_pubkey, recipient_pubkey, group_id, body, direction, timestamp, delivered) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (msg_id, sender, recipient, group_id, body, direction, utc_ts(), int(delivered)),
        )
        self.conn.commit()

    def recent_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM messages ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))
        return [dict(r) for r in reversed(rows.fetchall())]

    def save_file(self, file_id: str, filename: str, sender: str, size: int, sha256: str, path: str, recipient: Optional[str] = None, group_id: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO files (file_id, filename, sender_pubkey, recipient_pubkey, group_id, size, sha256, storage_path, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, filename, sender, recipient, group_id, size, sha256, path, utc_ts()),
        )
        self.conn.commit()

    def get_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()


@dataclass
class PendingOffer:
    peer_pubkey: str
    session_id: str
    kem_secret_key: bytes
    created_at: int


class QuantumNode:
    def __init__(self, db_path: str = DB_FILE, signaling_url: str = DEFAULT_SIGNALING_URL) -> None:
        self.db = Database(db_path)
        self.crypto = QuantumCrypto()
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
            "groups": self.db.groups_for(self.public_key),
            "messages": self.db.recent_messages(),
        }

    async def send_relay(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        if not self.signaling_ws:
            raise RuntimeError("Not connected to signaling server")
        await self.signaling_ws.send(json.dumps({"type": "relay", "to": peer_pubkey, "payload": payload}))

    def signed_payload(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = {"kind": kind, "payload": payload}
        sig = self.crypto.sign(self.secret_key, canonical_json(envelope))
        return {"kind": kind, "payload": payload, "signature": b64e(sig)}

    def verify_signed(self, peer_pubkey: str, data: Dict[str, Any]) -> bool:
        sig = b64d(data.get("signature", ""))
        envelope = {"kind": data.get("kind"), "payload": data.get("payload")}
        return self.crypto.verify(bytes.fromhex(peer_pubkey), canonical_json(envelope), sig)

    async def connect_peer(self, peer_pubkey: str) -> None:
        if not self.db.is_friend(peer_pubkey):
            raise ValueError("Add this public key as a friend before connecting")
        kem_pk, kem_sk = self.crypto.new_kem_keypair()
        session_id = str(uuid.uuid4())
        self.pending_offers[peer_pubkey] = PendingOffer(peer_pubkey, session_id, kem_sk, utc_ts())
        payload = {"from": self.public_key, "session_id": session_id, "kem_pk": b64e(kem_pk), "created_at": utc_ts()}
        await self.send_relay(peer_pubkey, self.signed_payload("session_offer", payload))
        await self.broadcast_ui({"type": "notice", "level": "info", "text": f"Session offer sent to {short_key(peer_pubkey)}"})

    async def handle_session_offer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.db.is_friend(peer_pubkey):
            await self.broadcast_ui({"type": "notice", "level": "warning", "text": f"Rejected untrusted session offer from {short_key(peer_pubkey)}"})
            return
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session offer signature")
        payload = data["payload"]
        ciphertext, secret = self.crypto.kem_encapsulate(b64d(payload["kem_pk"]))
        key = self.crypto.derive_session_key(secret, self.public_key, peer_pubkey, payload["session_id"])
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=False)
        self.db.touch_friend(peer_pubkey)
        accept = {"from": self.public_key, "session_id": payload["session_id"], "ciphertext": b64e(ciphertext), "accepted_at": utc_ts()}
        await self.send_relay(peer_pubkey, self.signed_payload("session_accept", accept))
        await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Secure session established with {short_key(peer_pubkey)}"})
        await self.broadcast_ui(self.state_payload())

    async def handle_session_accept(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session accept signature")
        payload = data["payload"]
        pending = self.pending_offers.pop(peer_pubkey, None)
        if not pending or pending.session_id != payload["session_id"]:
            raise ValueError("Session accept does not match an active offer")
        secret = self.crypto.kem_decapsulate(pending.kem_secret_key, b64d(payload["ciphertext"]))
        key = self.crypto.derive_session_key(secret, self.public_key, peer_pubkey, payload["session_id"])
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=True)
        self.db.touch_friend(peer_pubkey)
        await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Secure session established with {short_key(peer_pubkey)}"})
        await self.broadcast_ui(self.state_payload())

    async def send_chat(self, peer_pubkey: str, text: str, group_id: Optional[str] = None) -> None:
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        if peer_pubkey not in self.sessions:
            await self.connect_peer(peer_pubkey)
            raise ValueError("Secure session is not ready yet; retry after handshake completes")
        msg_id = str(uuid.uuid4())
        payload = {"msg_id": msg_id, "from": self.public_key, "to": peer_pubkey, "group_id": group_id, "sent_at": utc_ts()}
        packet = self.crypto.encrypt(self.sessions[peer_pubkey], text.encode(), canonical_json(payload))
        await self.send_relay(peer_pubkey, {"kind": "chat", "payload": payload, "packet": packet})
        self.db.save_message(msg_id, self.public_key, text, "out", recipient=peer_pubkey, group_id=group_id, delivered=True)
        await self.broadcast_ui({"type": "message", "message": {"msg_id": msg_id, "sender_pubkey": self.public_key, "recipient_pubkey": peer_pubkey, "group_id": group_id, "body": text, "direction": "out", "timestamp": utc_ts(), "delivered": 1}})

    async def handle_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if peer_pubkey not in self.sessions:
            raise ValueError("Encrypted chat received without a session")
        payload = data["payload"]
        text = self.crypto.decrypt(self.sessions[peer_pubkey], data["packet"], canonical_json(payload)).decode("utf-8")
        self.db.save_message(payload["msg_id"], peer_pubkey, text, "in", recipient=self.public_key, group_id=payload.get("group_id"), delivered=True)
        await self.broadcast_ui({"type": "message", "message": {"msg_id": payload["msg_id"], "sender_pubkey": peer_pubkey, "recipient_pubkey": self.public_key, "group_id": payload.get("group_id"), "body": text, "direction": "in", "timestamp": utc_ts(), "delivered": 1}})

    async def send_group_chat(self, group_id: str, text: str) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                await self.send_chat(peer, text, group_id=group_id)

    async def send_file(self, peer_pubkey: str, filename: str, encoded: str, group_id: Optional[str] = None) -> None:
        raw = b64d(encoded)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
        if peer_pubkey not in self.sessions:
            await self.connect_peer(peer_pubkey)
            raise ValueError("Secure session is not ready yet; retry after handshake completes")
        file_id = str(uuid.uuid4())
        safe_name = os.path.basename(filename) or "download.bin"
        sha = hashlib.sha256(raw).hexdigest()
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / file_id)
        Path(storage).write_bytes(raw)
        self.db.save_file(file_id, safe_name, self.public_key, len(raw), sha, storage, recipient=peer_pubkey, group_id=group_id)
        meta = {"file_id": file_id, "filename": safe_name, "size": len(raw), "sha256": sha, "from": self.public_key, "to": peer_pubkey, "group_id": group_id, "sent_at": utc_ts()}
        packet = self.crypto.encrypt(self.sessions[peer_pubkey], raw, canonical_json(meta))
        await self.send_relay(peer_pubkey, {"kind": "file", "payload": meta, "packet": packet})
        await self.broadcast_ui({"type": "file", "file": {**meta, "direction": "out", "url": f"/files/{file_id}"}})

    async def handle_file(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if peer_pubkey not in self.sessions:
            raise ValueError("Encrypted file received without a session")
        meta = data["payload"]
        raw = self.crypto.decrypt(self.sessions[peer_pubkey], data["packet"], canonical_json(meta))
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError("File checksum mismatch")
        Path(FILES_DIR).mkdir(exist_ok=True)
        storage = str(Path(FILES_DIR) / meta["file_id"])
        Path(storage).write_bytes(raw)
        self.db.save_file(meta["file_id"], os.path.basename(meta["filename"]), peer_pubkey, len(raw), meta["sha256"], storage, recipient=self.public_key, group_id=meta.get("group_id"))
        await self.broadcast_ui({"type": "file", "file": {**meta, "direction": "in", "url": f"/files/{meta['file_id']}"}})

    async def handle_relay_payload(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        kind = payload.get("kind")
        if kind == "session_offer":
            await self.handle_session_offer(peer_pubkey, payload)
        elif kind == "session_accept":
            await self.handle_session_accept(peer_pubkey, payload)
        elif kind == "chat":
            await self.handle_chat(peer_pubkey, payload)
        elif kind == "file":
            await self.handle_file(peer_pubkey, payload)
        elif kind == "group_invite":
            data = payload.get("payload", {})
            self.db.create_group(data["group_id"], data.get("name") or f"Group {data['group_id'][:8]}", self.public_key)
            for member in data.get("members", []):
                self.db.add_group_member(data["group_id"], member)
            await self.broadcast_ui(self.state_payload())

    async def handle_ui(self, ws: Any) -> None:
        self.ui_clients.add(ws)
        await ws.send(json.dumps(self.state_payload()))
        try:
            async for raw in ws:
                msg = json.loads(raw)
                typ = msg.get("type")
                try:
                    if typ == "add_friend":
                        self.db.add_friend(msg["pubkey"].strip(), msg.get("nickname") or None)
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "remove_friend":
                        self.db.remove_friend(msg["pubkey"])
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "connect":
                        await self.connect_peer(msg["pubkey"])
                    elif typ == "send_message":
                        if msg.get("group_id"):
                            await self.send_group_chat(msg["group_id"], msg["text"])
                        else:
                            await self.send_chat(msg["pubkey"], msg["text"])
                    elif typ == "send_file":
                        await self.send_file(msg["pubkey"], msg["filename"], msg["data"], msg.get("group_id"))
                    elif typ == "create_group":
                        group_id = str(uuid.uuid4())
                        name = msg.get("name") or f"Group {group_id[:8]}"
                        self.db.create_group(group_id, name, self.public_key)
                        for member in msg.get("members", []):
                            if self.db.is_friend(member):
                                self.db.add_group_member(group_id, member)
                                if member in self.sessions:
                                    invite = {"group_id": group_id, "name": name, "members": self.db.group_members(group_id), "from": self.public_key}
                                    await self.send_relay(member, self.signed_payload("group_invite", invite))
                        await self.broadcast_ui(self.state_payload())
                    elif typ == "refresh":
                        await ws.send(json.dumps(self.state_payload()))
                    else:
                        raise ValueError(f"Unknown command: {typ}")
                except Exception as exc:
                    await ws.send(json.dumps({"type": "notice", "level": "error", "text": str(exc)}))
        finally:
            self.ui_clients.discard(ws)

    async def connect_signaling_loop(self) -> None:
        websockets = require_websockets()
        while True:
            try:
                async with websockets.connect(self.signaling_url, max_size=MAX_FILE_BYTES * 2) as ws:
                    self.signaling_ws = ws
                    await ws.send(json.dumps({"type": "register", "pubkey": self.public_key}))
                    await self.broadcast_ui({"type": "notice", "level": "success", "text": f"Connected to signaling server {self.signaling_url}"})
                    async for raw in ws:
                        msg = json.loads(raw)
                        if msg.get("type") == "peers":
                            self.online_peers = set(msg.get("peers", [])) - {self.public_key}
                            await self.broadcast_ui(self.state_payload())
                        elif msg.get("type") == "relay":
                            await self.handle_relay_payload(msg["from"], msg["payload"])
                        elif msg.get("type") == "error":
                            await self.broadcast_ui({"type": "notice", "level": "error", "text": msg.get("text", "signaling error")})
            except Exception as exc:
                self.signaling_ws = None
                await self.broadcast_ui({"type": "notice", "level": "warning", "text": f"Signaling disconnected: {exc}. Reconnecting…"})
                await asyncio.sleep(3)


class SignalingServer:
    def __init__(self) -> None:
        self.clients: Dict[str, Any] = {}

    async def broadcast_peers(self) -> None:
        payload = json.dumps({"type": "peers", "peers": list(self.clients)})
        for ws in list(self.clients.values()):
            try:
                await ws.send(payload)
            except Exception:
                pass

    async def handle(self, ws: Any) -> None:
        pubkey = None
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "register":
                    pubkey = msg["pubkey"]
                    self.clients[pubkey] = ws
                    await self.broadcast_peers()
                elif msg.get("type") == "relay":
                    target = msg.get("to")
                    if target in self.clients:
                        await self.clients[target].send(json.dumps({"type": "relay", "from": pubkey, "payload": msg.get("payload")}))
                    else:
                        await ws.send(json.dumps({"type": "error", "text": "Peer is offline"}))
        finally:
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
            body = HTML.replace("__UI_WS_PORT__", str(self.ui_ws_port)).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if self.path.startswith("/files/"):
            file_id = self.path.rsplit("/", 1)[-1]
            meta = self.node.db.get_file(file_id) if self.node else None
            if not meta or not Path(meta["storage_path"]).exists():
                self.send_error(404, "File not found")
                return
            ctype = mimetypes.guess_type(meta["filename"])[0] or "application/octet-stream"
            data = Path(meta["storage_path"]).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{meta["filename"]}"')
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
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
:root{color-scheme:dark;--bg:#07111f;--panel:#101d2f;--muted:#91a4bd;--line:#223656;--accent:#69e6a6;--danger:#ff6b81;--warn:#ffd166;--text:#eaf2ff;--blue:#73a7ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#142545,var(--bg));color:var(--text);font:15px/1.45 Inter,system-ui,Segoe UI,sans-serif}.app{max-width:1200px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center}.badge{border:1px solid var(--line);padding:6px 10px;border-radius:999px;color:var(--accent)}.grid{display:grid;grid-template-columns:330px 1fr;gap:16px;margin-top:18px}.card{background:rgba(16,29,47,.88);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 12px 30px #0004}.key{font-family:ui-monospace,monospace;word-break:break-all;color:#cfe1ff;background:#07111f;border:1px solid var(--line);border-radius:10px;padding:10px;max-height:104px;overflow:auto}.row{display:flex;gap:8px;margin-top:10px}input,select,textarea{width:100%;background:#07111f;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px}button{background:linear-gradient(135deg,#326bff,#715aff);border:0;border-radius:10px;color:#fff;font-weight:700;padding:10px 13px;cursor:pointer}button.secondary{background:#223656}button.danger{background:#7f1d35}.list{display:flex;flex-direction:column;gap:8px;margin-top:10px}.item{border:1px solid var(--line);border-radius:12px;padding:10px;background:#0b1627}.item small{display:block;color:var(--muted);font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis}.chat{height:560px;overflow:auto;display:flex;flex-direction:column;gap:10px;background:#07111f;border:1px solid var(--line);border-radius:16px;padding:14px}.msg{max-width:76%;padding:10px 12px;border-radius:14px;background:#162845}.msg.out{align-self:flex-end;background:#214c70}.msg .meta{font-size:12px;color:var(--muted);margin-bottom:4px}.composer{display:grid;grid-template-columns:1fr 140px auto auto;gap:8px;margin-top:12px}.toast{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px}.toast div{padding:12px 14px;border-radius:12px;background:#15233a;border:1px solid var(--line)}.toast .error{border-color:var(--danger)}.toast .warning{border-color:var(--warn)}.toast .success{border-color:var(--accent)}@media(max-width:850px){.grid{grid-template-columns:1fr}.composer{grid-template-columns:1fr}.top{display:block}}
</style>
</head>
<body>
<div class="app">
  <div class="top"><div><h1>⚛ Quantum Chat</h1><p>Post-quantum E2EE P2P chat with ML-DSA signatures, Kyber session setup, and AES-256-GCM payload encryption.</p></div><div class="badge" id="status">connecting UI…</div></div>
  <div class="grid">
    <aside>
      <div class="card"><h3>Your identity</h3><div class="key" id="myKey">loading…</div><button class="secondary" onclick="copyKey()">Copy public key</button></div>
      <div class="card"><h3>Friends</h3><input id="friendKey" placeholder="Friend public key"><input id="friendName" placeholder="Nickname (optional)" style="margin-top:8px"><div class="row"><button onclick="addFriend()">Add</button><button class="secondary" onclick="connectSelected()">Connect selected</button></div><div class="list" id="friends"></div></div>
      <div class="card"><h3>Groups</h3><input id="groupName" placeholder="Group name"><button style="margin-top:8px" onclick="createGroup()">Create group with selected friend</button><div class="list" id="groups"></div></div>
    </aside>
    <main class="card"><div class="row"><select id="target"></select><button class="secondary" onclick="refresh()">Refresh</button></div><div class="chat" id="chat"></div><div class="composer"><input id="text" placeholder="Type encrypted message…" onkeydown="if(event.key==='Enter')sendMessage()"><select id="mode"><option value="friend">Friend</option><option value="group">Group</option></select><button onclick="sendMessage()">Send</button><label><button type="button" onclick="document.getElementById('file').click()">File</button><input id="file" type="file" hidden onchange="sendFile()"></label></div></main>
  </div>
</div><div class="toast" id="toast"></div>
<script>
let ws,state={friends:[],groups:[],messages:[],online:[]},selectedFriend=null;
const UI_WS_PORT = __UI_WS_PORT__;
function connect(){ws=new WebSocket(`ws://${location.hostname}:${UI_WS_PORT}`);ws.onopen=()=>status('UI connected');ws.onclose=()=>{status('UI disconnected');setTimeout(connect,1500)};ws.onmessage=e=>handle(JSON.parse(e.data));}
function status(t){document.getElementById('status').textContent=t}
function handle(d){if(d.type==='state'){state=d;render()}else if(d.type==='notice'){toast(d.text,d.level)}else if(d.type==='message'){state.messages.push(d.message);renderMessages()}else if(d.type==='file'){toast(`File ${d.file.filename} received/sent`,'success')}}
function render(){document.getElementById('myKey').textContent=state.public_key||'';renderFriends();renderGroups();renderTargets();renderMessages();}
function renderFriends(){let el=document.getElementById('friends');el.innerHTML='';state.friends.forEach(f=>{let online=state.online.includes(f.pubkey)?'🟢':'⚪';let div=document.createElement('div');div.className='item';div.onclick=()=>{selectedFriend=f.pubkey;document.getElementById('mode').value='friend';renderTargets()};div.innerHTML=`<b>${online} ${f.nickname||short(f.pubkey)}</b><small>${f.pubkey}</small><div class="row"><button onclick="event.stopPropagation();selectedFriend='${f.pubkey}';connectSelected()">Connect</button><button class="danger" onclick="event.stopPropagation();removeFriend('${f.pubkey}')">Remove</button></div>`;el.appendChild(div)});}
function renderGroups(){let el=document.getElementById('groups');el.innerHTML='';state.groups.forEach(g=>{let div=document.createElement('div');div.className='item';div.onclick=()=>{document.getElementById('mode').value='group';document.getElementById('target').value=g.group_id};div.innerHTML=`<b>${g.name}</b><small>${g.group_id}</small>`;el.appendChild(div)});}
function renderTargets(){let t=document.getElementById('target'),mode=document.getElementById('mode').value;t.innerHTML='';(mode==='friend'?state.friends:state.groups).forEach(x=>{let o=document.createElement('option');o.value=mode==='friend'?x.pubkey:x.group_id;o.textContent=mode==='friend'?(x.nickname||short(x.pubkey)):x.name;t.appendChild(o)});if(selectedFriend&&mode==='friend')t.value=selectedFriend;}
function renderMessages(){let el=document.getElementById('chat');el.innerHTML='';state.messages.forEach(m=>{let div=document.createElement('div');div.className='msg '+(m.direction==='out'?'out':'in');div.innerHTML=`<div class="meta">${m.direction==='out'?'You':short(m.sender_pubkey)} · ${new Date((m.timestamp||Date.now()/1000)*1000).toLocaleString()}</div><div></div>`;div.lastChild.textContent=m.body;el.appendChild(div)});el.scrollTop=el.scrollHeight;}
function short(k){return k?`${k.slice(0,12)}…${k.slice(-8)}`:''}
function send(o){ws.send(JSON.stringify(o))}function addFriend(){send({type:'add_friend',pubkey:friendKey.value.trim(),nickname:friendName.value.trim()});friendKey.value='';friendName.value=''}function removeFriend(pubkey){send({type:'remove_friend',pubkey})}function connectSelected(){let pubkey=selectedFriend||target.value||friendKey.value.trim();if(pubkey)send({type:'connect',pubkey})}function sendMessage(){let text=document.getElementById('text').value;if(!text.trim())return;let mode=document.getElementById('mode').value;if(mode==='group')send({type:'send_message',group_id:target.value,text});else send({type:'send_message',pubkey:target.value,text});document.getElementById('text').value=''}function sendFile(){let f=file.files[0];if(!f)return;let r=new FileReader();r.onload=()=>send({type:'send_file',pubkey:target.value,filename:f.name,data:r.result.split(',')[1]});r.readAsDataURL(f);file.value=''}function createGroup(){let members=selectedFriend?[selectedFriend]:[];send({type:'create_group',name:groupName.value.trim(),members})}function refresh(){send({type:'refresh'})}function copyKey(){navigator.clipboard.writeText(state.public_key||'');toast('Copied public key','success')}function toast(t,l='info'){let e=document.createElement('div');e.className=l;e.textContent=t;document.getElementById('toast').appendChild(e);setTimeout(()=>e.remove(),5000)}document.getElementById('mode').onchange=renderTargets;connect();
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
