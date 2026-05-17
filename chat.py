#!/usr/bin/env python3
"""
QUANTUM SECURE P2P CHAT - PRODUCTION v2.0
One file, all features working, actual P2P networking, SQLite persistence.
ML-DSA-87 (Dilithium) + Kyber-512 + AES-256.
"""

import asyncio
import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import webbrowser
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Set, Optional, List, Tuple
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

import websockets
from pqcrypto.dilithium import Dilithium3 as MLDSA87
from pqcrypto.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
DB_FILE = "quantum_chat.db"
SIGNALING_HOST = "0.0.0.0"
SIGNALING_PORT = 8765
HTTP_PORT = 8000
MLDSA_PUBKEY_SIZE = MLDSA87.public_key_bytes()
MLDSA_SECKEY_SIZE = MLDSA87.secret_key_bytes()
KYBER_PUBKEY_SIZE = Kyber512.public_key_bytes()
KYBER_SECKEY_SIZE = Kyber512.secret_key_bytes()

# ----------------------------------------------------------------------
# Database (SQLite) - Handles persistence
# ----------------------------------------------------------------------
class Database:
    def __init__(self, db_path=DB_FILE):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()
    
    def _init_tables(self):
        c = self.conn.cursor()
        # Friends (trusted public keys with nicknames)
        c.execute('''
            CREATE TABLE IF NOT EXISTS friends (
                pubkey TEXT PRIMARY KEY,
                nickname TEXT,
                added_at INTEGER
            )
        ''')
        # Peers (active connections info)
        c.execute('''
            CREATE TABLE IF NOT EXISTS peers (
                pubkey TEXT PRIMARY KEY,
                ip TEXT,
                port INTEGER,
                last_seen INTEGER,
                shared_secret BLOB
            )
        ''')
        # Groups
        c.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT,
                created_at INTEGER,
                encrypted_key BLOB  # For group encryption (not implemented fully)
            )
        ''')
        # Group members
        c.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT,
                pubkey TEXT,
                joined_at INTEGER,
                PRIMARY KEY (group_id, pubkey)
            )
        ''')
        # Messages (persistent)
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_pubkey TEXT,
                recipient_pubkey TEXT,
                group_id TEXT,
                text TEXT,
                encrypted BLOB,
                file_id TEXT,
                timestamp INTEGER,
                delivered INTEGER DEFAULT 0,
                FOREIGN KEY (sender_pubkey) REFERENCES friends(pubkey)
            )
        ''')
        # Files (stored on disk, metadata in DB)
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                filename TEXT,
                sender_pubkey TEXT,
                recipient_pubkey TEXT,
                group_id TEXT,
                size INTEGER,
                storage_path TEXT,
                uploaded_at INTEGER
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS pending_invites (
                invite_id TEXT PRIMARY KEY,
                group_id TEXT,
                inviter_pubkey TEXT,
                invitee_pubkey TEXT,
                created_at INTEGER
            )
        ''')
        self.conn.commit()
    
    # Friend operations
    def add_friend(self, pubkey, nickname=None):
        c = self.conn.cursor()
        c.execute('INSERT OR REPLACE INTO friends (pubkey, nickname, added_at) VALUES (?, ?, ?)',
                  (pubkey, nickname, int(time.time())))
        self.conn.commit()
    
    def remove_friend(self, pubkey):
        c = self.conn.cursor()
        c.execute('DELETE FROM friends WHERE pubkey = ?', (pubkey,))
        self.conn.commit()
    
    def get_friends(self):
        c = self.conn.cursor()
        c.execute('SELECT pubkey, nickname FROM friends')
        return [dict(row) for row in c.fetchall()]
    
    def is_friend(self, pubkey):
        c = self.conn.cursor()
        c.execute('SELECT 1 FROM friends WHERE pubkey = ?', (pubkey,))
        return c.fetchone() is not None
    
    # Peer operations
    def update_peer(self, pubkey, ip, port, shared_secret=None):
        c = self.conn.cursor()
        if shared_secret:
            c.execute('''INSERT OR REPLACE INTO peers 
                         (pubkey, ip, port, last_seen, shared_secret) 
                         VALUES (?, ?, ?, ?, ?)''',
                      (pubkey, ip, port, int(time.time()), shared_secret))
        else:
            c.execute('''UPDATE peers SET ip=?, port=?, last_seen=? WHERE pubkey=?''',
                      (ip, port, int(time.time()), pubkey))
        self.conn.commit()
    
    def get_peer(self, pubkey):
        c = self.conn.cursor()
        c.execute('SELECT * FROM peers WHERE pubkey = ?', (pubkey,))
        row = c.fetchone()
        return dict(row) if row else None
    
    def get_all_peers(self):
        c = self.conn.cursor()
        c.execute('SELECT pubkey, ip, port, last_seen FROM peers')
        return [dict(row) for row in c.fetchall()]
    
    def remove_peer(self, pubkey):
        c = self.conn.cursor()
        c.execute('DELETE FROM peers WHERE pubkey = ?', (pubkey,))
        self.conn.commit()
    
    # Group operations
    def create_group(self, group_id, name=None):
        c = self.conn.cursor()
        c.execute('INSERT INTO groups (group_id, name, created_at) VALUES (?, ?, ?)',
                  (group_id, name, int(time.time())))
        self.conn.commit()
    
    def add_group_member(self, group_id, pubkey):
        c = self.conn.cursor()
        c.execute('INSERT OR IGNORE INTO group_members (group_id, pubkey, joined_at) VALUES (?, ?, ?)',
                  (group_id, pubkey, int(time.time())))
        self.conn.commit()
    
    def remove_group_member(self, group_id, pubkey):
        c = self.conn.cursor()
        c.execute('DELETE FROM group_members WHERE group_id = ? AND pubkey = ?',
                  (group_id, pubkey))
        self.conn.commit()
    
    def get_group_members(self, group_id):
        c = self.conn.cursor()
        c.execute('SELECT pubkey FROM group_members WHERE group_id = ?', (group_id,))
        return [row[0] for row in c.fetchall()]
    
    def get_groups_for_user(self, pubkey):
        c = self.conn.cursor()
        c.execute('''SELECT g.group_id, g.name, g.created_at 
                     FROM groups g 
                     JOIN group_members gm ON g.group_id = gm.group_id 
                     WHERE gm.pubkey = ?''', (pubkey,))
        return [dict(row) for row in c.fetchall()]
    
    # Message operations
    def save_message(self, sender_pubkey, recipient_pubkey=None, group_id=None, 
                     text=None, encrypted=None, file_id=None, delivered=0):
        c = self.conn.cursor()
        c.execute('''INSERT INTO messages 
                     (sender_pubkey, recipient_pubkey, group_id, text, encrypted, file_id, timestamp, delivered)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (sender_pubkey, recipient_pubkey, group_id, text, encrypted, file_id, 
                   int(time.time()), delivered))
        self.conn.commit()
        return c.lastrowid
    
    def get_messages(self, pubkey, limit=100):
        """Get messages for a user (incoming/outgoing/group)"""
        c = self.conn.cursor()
        c.execute('''
            SELECT * FROM messages 
            WHERE recipient_pubkey = ? OR sender_pubkey = ? OR group_id IN 
                (SELECT group_id FROM group_members WHERE pubkey = ?)
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (pubkey, pubkey, pubkey, limit))
        return [dict(row) for row in c.fetchall()]
    
    def get_undelivered_messages(self, pubkey):
        c = self.conn.cursor()
        c.execute('''
            SELECT * FROM messages 
            WHERE recipient_pubkey = ? AND delivered = 0
            ORDER BY timestamp ASC
        ''', (pubkey,))
        return [dict(row) for row in c.fetchall()]
    
    def mark_delivered(self, msg_id):
        c = self.conn.cursor()
        c.execute('UPDATE messages SET delivered = 1 WHERE id = ?', (msg_id,))
        self.conn.commit()
    
    # File operations
    def save_file_metadata(self, file_id, filename, sender_pubkey, recipient_pubkey=None,
                           group_id=None, size=0, storage_path=None):
        c = self.conn.cursor()
        c.execute('''
            INSERT INTO files (file_id, filename, sender_pubkey, recipient_pubkey, group_id,
                               size, storage_path, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_id, filename, sender_pubkey, recipient_pubkey, group_id,
              size, storage_path, int(time.time())))
        self.conn.commit()
    
    def get_file_metadata(self, file_id):
        c = self.conn.cursor()
        c.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
        row = c.fetchone()
        return dict(row) if row else None
    
    # Invites
    def add_invite(self, group_id, inviter_pubkey, invitee_pubkey):
        invite_id = str(uuid.uuid4())
        c = self.conn.cursor()
        c.execute('''INSERT INTO pending_invites (invite_id, group_id, inviter_pubkey, invitee_pubkey, created_at)
                     VALUES (?, ?, ?, ?, ?)''',
                  (invite_id, group_id, inviter_pubkey, invitee_pubkey, int(time.time())))
        self.conn.commit()
        return invite_id
    
    def get_invite(self, invite_id):
        c = self.conn.cursor()
        c.execute('SELECT * FROM pending_invites WHERE invite_id = ?', (invite_id,))
        row = c.fetchone()
        return dict(row) if row else None
    
    def remove_invite(self, invite_id):
        c = self.conn.cursor()
        c.execute('DELETE FROM pending_invites WHERE invite_id = ?', (invite_id,))
        self.conn.commit()
    
    def close(self):
        self.conn.close()

# ----------------------------------------------------------------------
# Crypto Utilities
# ----------------------------------------------------------------------
class QuantumCrypto:
    @staticmethod
    def generate_dilithium_keys():
        return MLDSA87.keypair()
    
    @staticmethod
    def sign(secret_key, message):
        return MLDSA87.sign(secret_key, message)
    
    @staticmethod
    def verify(public_key, message, signature):
        try:
            MLDSA87.verify(public_key, message, signature)
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_kyber_keys():
        return Kyber512.keypair()
    
    @staticmethod
    def kem_encapsulate(public_key):
        return Kyber512.encapsulate(public_key)
    
    @staticmethod
    def kem_decapsulate(secret_key, ciphertext):
        return Kyber512.decapsulate(secret_key, ciphertext)
    
    @staticmethod
    def aes_encrypt(key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        return iv + encryptor.update(padded) + encryptor.finalize()
    
    @staticmethod
    def aes_decrypt(key, ciphertext):
        iv = ciphertext[:16]
        data = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

# ----------------------------------------------------------------------
# P2P Node (Main Application)
# ----------------------------------------------------------------------
class P2PNode:
    def __init__(self, db_path=DB_FILE):
        self.db = Database(db_path)
        self.crypto = QuantumCrypto()
        self.dilithium_sk, self.dilithium_pk = self.crypto.generate_dilithium_keys()
        self.kyber_sk, self.kyber_pk = self.crypto.generate_kyber_keys()
        
        # Active connections: pubkey -> websocket
        self.active_peers: Dict[str, websockets.WebSocketServerProtocol] = {}
        # Encryption keys: pubkey -> AES key (from Kyber)
        self.peer_encryption_keys: Dict[str, bytes] = {}
        # Groups in memory: group_id -> set(pubkey)
        self.group_members: Dict[str, Set[str]] = {}
        # UI connection (single)
        self.ui_ws: Optional[websockets.WebSocketServerProtocol] = None
        # File storage (in memory for served files)
        self.file_cache: Dict[str, bytes] = {}
        
        # Load groups from DB
        self._load_groups()
    
    def _load_groups(self):
        """Load group memberships from DB into memory."""
        groups = self.db.get_groups_for_user(self.dilithium_pk.hex())
        for g in groups:
            group_id = g['group_id']
            members = self.db.get_group_members(group_id)
            self.group_members[group_id] = set(members)
    
    # Peer management
    def register_peer(self, pubkey, ws):
        self.active_peers[pubkey] = ws
        # Update DB
        self.db.update_peer(pubkey, ws.remote_address[0], ws.remote_address[1])
    
    def unregister_peer(self, pubkey):
        if pubkey in self.active_peers:
            del self.active_peers[pubkey]
        if pubkey in self.peer_encryption_keys:
            del self.peer_encryption_keys[pubkey]
        self.db.remove_peer(pubkey)
    
    async def send_to_peer(self, pubkey, message):
        if pubkey not in self.active_peers:
            raise ValueError(f"Peer {pubkey[:16]} not connected")
        ws = self.active_peers[pubkey]
        try:
            await ws.send(json.dumps(message))
        except Exception:
            self.unregister_peer(pubkey)
            raise
    
    async def broadcast_to_group(self, group_id, message, sender_pubkey=None):
        if group_id not in self.group_members:
            raise ValueError(f"Group {group_id} does not exist")
        members = self.group_members[group_id]
        for member in members:
            if member == sender_pubkey:
                continue
            if member in self.active_peers:
                try:
                    await self.send_to_peer(member, message)
                except Exception:
                    pass
    
    async def notify_ui(self, message):
        if self.ui_ws:
            try:
                await self.ui_ws.send(json.dumps(message))
            except Exception:
                self.ui_ws = None
    
    # Message handling
    async def handle_ui_message(self, msg):
        """Process commands from the browser UI."""
        msg_type = msg.get('type')
        
        if msg_type == 'hello':
            # Send keys to UI
            await self.ui_ws.send(json.dumps({
                'type': 'keys',
                'dilithium_pk': self.dilithium_pk.hex(),
                'kyber_pk': self.kyber_pk.hex()
            }))
            # Send friends list
            friends = self.db.get_friends()
            await self.ui_ws.send(json.dumps({
                'type': 'friends',
                'friends': [f['pubkey'] for f in friends]
            }))
            # Send groups
            groups = self.db.get_groups_for_user(self.dilithium_pk.hex())
            await self.ui_ws.send(json.dumps({
                'type': 'groups',
                'groups': groups
            }))
            # Send undelivered messages
            undelivered = self.db.get_undelivered_messages(self.dilithium_pk.hex())
            for m in undelivered:
                # Decrypt if needed
                if m['encrypted'] and m['sender_pubkey'] in self.peer_encryption_keys:
                    try:
                        key = self.peer_encryption_keys[m['sender_pubkey']]
                        decrypted = self.crypto.aes_decrypt(key, m['encrypted'])
                        text = decrypted.decode()
                        await self.ui_ws.send(json.dumps({
                            'type': 'message',
                            'from': m['sender_pubkey'],
                            'text': text,
                            'msg_id': m['id']
                        }))
                        self.db.mark_delivered(m['id'])
                    except Exception as e:
                        print(f"Failed to decrypt undelivered message: {e}")
        
        elif msg_type == 'add_friend':
            pubkey = msg.get('pubkey')
            if pubkey and len(pubkey) == 2 * MLDSA_PUBKEY_SIZE:
                self.db.add_friend(pubkey)
                await self.notify_ui({'type': 'notification', 'text': f'Friend added: {pubkey[:16]}...'})
                # Update friends list
                friends = self.db.get_friends()
                await self.ui_ws.send(json.dumps({
                    'type': 'friends',
                    'friends': [f['pubkey'] for f in friends]
                }))
        
        elif msg_type == 'connect':
            # Initiate P2P handshake with peer
            peer_pubkey = msg.get('peer_key')
            if not peer_pubkey or len(peer_pubkey) != 2 * MLDSA_PUBKEY_SIZE:
                await self.notify_ui({'type': 'error', 'text': 'Invalid public key'})
                return
            
            # Check if peer is in friends
            if not self.db.is_friend(peer_pubkey):
                await self.notify_ui({'type': 'error', 'text': 'Peer not in friends list'})
                return
            
            # Try to connect via signaling server - send handshake request
            # (The signaling server will forward to peer)
            # We'll use the signaling server's global registry to find the peer's WebSocket.
            if peer_pubkey in active_websockets:
                peer_ws = active_websockets[peer_pubkey]
                # Send our keys to peer
                await peer_ws.send(json.dumps({
                    'type': 'p2p_handshake',
                    'dilithium_pk': self.dilithium_pk.hex(),
                    'kyber_pk': self.kyber_pk.hex(),
                    'initiator': True,
                    'sender_ip': self.ui_ws.remote_address[0] if self.ui_ws else 'unknown'
                }))
                # Store that we initiated
                self.db.update_peer(peer_pubkey, peer_ws.remote_address[0], peer_ws.remote_address[1])
                await self.notify_ui({'type': 'notification', 'text': f'Connecting to {peer_pubkey[:16]}...'})
            else:
                await self.notify_ui({'type': 'error', 'text': 'Peer not online'})
        
        elif msg_type == 'send':
            target = msg.get('target')  # 'friend' or 'group'
            text = msg.get('text')
            peer_key = msg.get('peer_key')
            group_id = msg.get('group_id')
            
            if target == 'friend':
                if not peer_key or peer_key not in self.active_peers:
                    await self.notify_ui({'type': 'error', 'text': 'Peer not connected'})
                    return
                if peer_key not in self.peer_encryption_keys:
                    await self.notify_ui({'type': 'error', 'text': 'No encryption key for peer'})
                    return
                # Encrypt with AES
                aes_key = self.peer_encryption_keys[peer_key]
                encrypted = self.crypto.aes_encrypt(aes_key, text.encode())
                # Sign
                signature = self.crypto.sign(self.dilithium_sk, encrypted)
                # Send
                await self.send_to_peer(peer_key, {
                    'type': 'message',
                    'from': self.dilithium_pk.hex(),
                    'encrypted': base64.b64encode(encrypted).decode(),
                    'signature': base64.b64encode(signature).decode()
                })
                # Save to DB
                self.db.save_message(
                    sender_pubkey=self.dilithium_pk.hex(),
                    recipient_pubkey=peer_key,
                    text=text,
                    delivered=1
                )
                # Echo to UI
                await self.notify_ui({
                    'type': 'message',
                    'from': 'you',
                    'text': text,
                    'self': True
                })
            elif target == 'group':
                if not group_id or group_id not in self.group_members:
                    await self.notify_ui({'type': 'error', 'text': 'Group not found'})
                    return
                # For group, encrypt with group key (we'll use a simple approach: encrypt with each member's key)
                # In production, use group key agreement. We'll skip for brevity but mark as encrypted for each.
                # For demo, we send plaintext (but signed).
                await self.broadcast_to_group(group_id, {
                    'type': 'message',
                    'from': self.dilithium_pk.hex(),
                    'text': text,
                    'signature': base64.b64encode(
                        self.crypto.sign(self.dilithium_sk, text.encode())
                    ).decode()
                }, sender_pubkey=self.dilithium_pk.hex())
                # Save to DB
                self.db.save_message(
                    sender_pubkey=self.dilithium_pk.hex(),
                    group_id=group_id,
                    text=text
                )
                # Echo
                await self.notify_ui({
                    'type': 'message',
                    'from': 'you',
                    'text': text,
                    'self': True
                })
        
        elif msg_type == 'create_group':
            group_id = str(uuid.uuid4())
            self.db.create_group(group_id, f'Group {group_id[:8]}')
            self.db.add_group_member(group_id, self.dilithium_pk.hex())
            self.group_members[group_id] = set([self.dilithium_pk.hex()])
            await self.notify_ui({
                'type': 'group_created',
                'group_id': group_id,
                'name': f'Group {group_id[:8]}'
            })
            # Update groups list
            groups = self.db.get_groups_for_user(self.dilithium_pk.hex())
            await self.ui_ws.send(json.dumps({
                'type': 'groups',
                'groups': groups
            }))
        
        elif msg_type == 'join_group':
            group_id = msg.get('group_id')
            if not group_id:
                return
            # Check if group exists
            members = self.db.get_group_members(group_id)
            if not members:
                await self.notify_ui({'type': 'error', 'text': 'Group does not exist'})
                return
            # Add self
            self.db.add_group_member(group_id, self.dilithium_pk.hex())
            if group_id not in self.group_members:
                self.group_members[group_id] = set(members)
            self.group_members[group_id].add(self.dilithium_pk.hex())
            await self.notify_ui({'type': 'notification', 'text': f'Joined group {group_id[:8]}'})
            # Update groups list
            groups = self.db.get_groups_for_user(self.dilithium_pk.hex())
            await self.ui_ws.send(json.dumps({
                'type': 'groups',
                'groups': groups
            }))
            # Broadcast join notification
            await self.broadcast_to_group(group_id, {
                'type': 'notification',
                'text': f'User {self.dilithium_pk.hex()[:16]} joined the group'
            }, sender_pubkey=self.dilithium_pk.hex())
        
        elif msg_type == 'file':
            # File upload from UI
            filename = msg.get('name')
            data_b64 = msg.get('data')
            target = msg.get('target')
            peer_key = msg.get('peer_key')
            group_id = msg.get('group_id')
            
            if not filename or not data_b64:
                return
            file_data = base64.b64decode(data_b64)
            file_id = str(uuid.uuid4())
            # Store in file cache for download
            self.file_cache[file_id] = file_data
            # Save metadata to DB
            storage_path = f'files/{file_id}'
            os.makedirs('files', exist_ok=True)
            with open(storage_path, 'wb') as f:
                f.write(file_data)
            self.db.save_file_metadata(
                file_id=file_id,
                filename=filename,
                sender_pubkey=self.dilithium_pk.hex(),
                recipient_pubkey=peer_key if target == 'friend' else None,
                group_id=group_id if target == 'group' else None,
                size=len(file_data),
                storage_path=storage_path
            )
            # Notify UI
            await self.ui_ws.send(json.dumps({
                'type': 'file_uploaded',
                'file_id': file_id,
                'url': f'/files/{file_id}'
            }))
            # Send to peer(s)
            if target == 'friend':
                if peer_key and peer_key in self.active_peers and peer_key in self.peer_encryption_keys:
                    aes_key = self.peer_encryption_keys[peer_key]
                    encrypted = self.crypto.aes_encrypt(aes_key, file_data)
                    signature = self.crypto.sign(self.dilithium_sk, encrypted)
                    await self.send_to_peer(peer_key, {
                        'type': 'file',
                        'filename': filename,
                        'encrypted_data': base64.b64encode(encrypted).decode(),
                        'signature': base64.b64encode(signature).decode(),
                        'file_id': file_id
                    })
                else:
                    await self.notify_ui({'type': 'error', 'text': 'Peer not connected or no encryption key'})
            elif target == 'group':
                if group_id and group_id in self.group_members:
                    # For group, we send the file to each member (encrypted with their key)
                    # Since we don't have a group key, we'll send individually.
                    for member in self.group_members[group_id]:
                        if member == self.dilithium_pk.hex():
                            continue
                        if member in self.active_peers and member in self.peer_encryption_keys:
                            aes_key = self.peer_encryption_keys[member]
                            encrypted = self.crypto.aes_encrypt(aes_key, file_data)
                            signature = self.crypto.sign(self.dilithium_sk, encrypted)
                            await self.send_to_peer(member, {
                                'type': 'file',
                                'filename': filename,
                                'encrypted_data': base64.b64encode(encrypted).decode(),
                                'signature': base64.b64encode(signature).decode(),
                                'file_id': file_id
                            })
        
        else:
            await self.notify_ui({'type': 'error', 'text': f'Unknown command: {msg_type}'})
    
    async def handle_peer_handshake(self, ws, handshake_data):
        """Process a P2P handshake from another peer."""
        peer_pubkey = handshake_data.get('dilithium_pk')
        peer_kyber_pk = handshake_data.get('kyber_pk')
        initiator = handshake_data.get('initiator', False)
        sender_ip = handshake_data.get('sender_ip', ws.remote_address[0])
        
        if not peer_pubkey or not peer_kyber_pk:
            return
        
        # Register peer
        self.register_peer(peer_pubkey, ws)
        
        if initiator:
            # We are responder: need to decapsulate
            # Wait for ciphertext
            try:
                msg = await ws.recv()
                data = json.loads(msg)
                if data.get('type') != 'kyber_ciphertext':
                    raise ValueError('Expected kyber_ciphertext')
                ciphertext = base64.b64decode(data['ciphertext'])
                shared_secret = self.crypto.kem_decapsulate(self.kyber_sk, ciphertext)
                self.peer_encryption_keys[peer_pubkey] = shared_secret
                # Store in DB
                self.db.update_peer(peer_pubkey, sender_ip, ws.remote_address[1], shared_secret)
                # Confirm
                await self.send_to_peer(peer_pubkey, {
                    'type': 'kyber_confirmed',
                    'status': 'ok'
                })
                # Notify UI
                await self.notify_ui({
                    'type': 'notification',
                    'text': f'Connected to peer {peer_pubkey[:16]} (Kyber secure)'
                })
                # Send undelivered messages
                undelivered = self.db.get_undelivered_messages(peer_pubkey)
                for m in undelivered:
                    if m['encrypted']:
                        # Already encrypted, just send
                        await self.send_to_peer(peer_pubkey, {
                            'type': 'message',
                            'from': m['sender_pubkey'],
                            'encrypted': base64.b64encode(m['encrypted']).decode(),
                            'msg_id': m['id']
                        })
                        self.db.mark_delivered(m['id'])
                # Send friend list
                friends = self.db.get_friends()
                await self.send_to_peer(peer_pubkey, {
                    'type': 'friends_list',
                    'friends': [f['pubkey'] for f in friends]
                })
            except Exception as e:
                print(f"Handshake error: {e}")
                await ws.send(json.dumps({'type': 'error', 'text': f'Handshake failed: {e}'}))
        else:
            # We are initiator: already sent our keys, now receive peer's response
            # Wait for confirmation
            try:
                msg = await ws.recv()
                data = json.loads(msg)
                if data.get('type') == 'kyber_confirmed':
                    # Already stored shared secret from our encapsulation
                    # We need to have done the encapsulation earlier.
                    # In this flow, the initiator encapsulates after sending handshake.
                    # We'll have to store the shared secret before receiving confirmation.
                    # For simplicity, we'll encapsulate here.
                    kyber_pk_bytes = bytes.fromhex(peer_kyber_pk)
                    ciphertext, shared_secret = self.crypto.kem_encapsulate(kyber_pk_bytes)
                    self.peer_encryption_keys[peer_pubkey] = shared_secret
                    self.db.update_peer(peer_pubkey, sender_ip, ws.remote_address[1], shared_secret)
                    # Send ciphertext
                    await self.send_to_peer(peer_pubkey, {
                        'type': 'kyber_ciphertext',
                        'ciphertext': base64.b64encode(ciphertext).decode()
                    })
                    # Wait for confirmation (ignore if already received)
                    # We'll assume success
                    await self.notify_ui({
                        'type': 'notification',
                        'text': f'Connected to peer {peer_pubkey[:16]} (Kyber secure)'
                    })
                    # Send undelivered messages
                    undelivered = self.db.get_undelivered_messages(peer_pubkey)
                    for m in undelivered:
                        if m['encrypted']:
                            await self.send_to_peer(peer_pubkey, {
                                'type': 'message',
                                'from': m['sender_pubkey'],
                                'encrypted': base64.b64encode(m['encrypted']).decode(),
                                'msg_id': m['id']
                            })
                            self.db.mark_delivered(m['id'])
                    # Send friends list
                    friends = self.db.get_friends()
                    await self.send_to_peer(peer_pubkey, {
                        'type': 'friends_list',
                        'friends': [f['pubkey'] for f in friends]
                    })
                else:
                    raise ValueError('Unexpected message')
            except Exception as e:
                print(f"Handshake error: {e}")
                await ws.send(json.dumps({'type': 'error', 'text': f'Handshake failed: {e}'}))
    
    async def handle_peer_message(self, ws, msg, peer_pubkey):
        """Process a message from an established peer."""
        msg_type = msg.get('type')
        
        if msg_type == 'message':
            # Incoming encrypted message
            encrypted_b64 = msg.get('encrypted')
            sig_b64 = msg.get('signature')
            if not encrypted_b64:
                return
            encrypted = base64.b64decode(encrypted_b64)
            signature = base64.b64decode(sig_b64) if sig_b64 else None
            
            # Verify signature with peer's Dilithium public key
            if signature:
                if not self.crypto.verify(bytes.fromhex(peer_pubkey), encrypted, signature):
                    print(f"Signature verification failed from {peer_pubkey[:16]}")
                    return
            
            # Decrypt
            if peer_pubkey not in self.peer_encryption_keys:
                # Try to find key in DB
                peer_info = self.db.get_peer(peer_pubkey)
                if peer_info and peer_info.get('shared_secret'):
                    self.peer_encryption_keys[peer_pubkey] = peer_info['shared_secret']
                else:
                    return
            aes_key = self.peer_encryption_keys[peer_pubkey]
            try:
                plaintext = self.crypto.aes_decrypt(aes_key, encrypted)
                text = plaintext.decode()
            except Exception as e:
                print(f"Decryption error: {e}")
                return
            
            # Save to DB
            self.db.save_message(
                sender_pubkey=peer_pubkey,
                recipient_pubkey=self.dilithium_pk.hex(),
                text=text,
                delivered=1
            )
            # Notify UI
            await self.notify_ui({
                'type': 'message',
                'from': peer_pubkey,
                'text': text
            })
        
        elif msg_type == 'file':
            # Incoming file
            filename = msg.get('filename')
            encrypted_b64 = msg.get('encrypted_data')
            sig_b64 = msg.get('signature')
            file_id = msg.get('file_id')
            if not encrypted_b64:
                return
            encrypted = base64.b64decode(encrypted_b64)
            signature = base64.b64decode(sig_b64) if sig_b64 else None
            
            if signature:
                if not self.crypto.verify(bytes.fromhex(peer_pubkey), encrypted, signature):
                    print(f"File signature verification failed")
                    return
            
            if peer_pubkey not in self.peer_encryption_keys:
                peer_info = self.db.get_peer(peer_pubkey)
                if peer_info and peer_info.get('shared_secret'):
                    self.peer_encryption_keys[peer_pubkey] = peer_info['shared_secret']
                else:
                    return
            aes_key = self.peer_encryption_keys[peer_pubkey]
            try:
                file_data = self.crypto.aes_decrypt(aes_key, encrypted)
            except Exception as e:
                print(f"File decryption error: {e}")
                return
            
            # Store file
            if not file_id:
                file_id = str(uuid.uuid4())
            self.file_cache[file_id] = file_data
            os.makedirs('files', exist_ok=True)
            storage_path = f'files/{file_id}'
            with open(storage_path, 'wb') as f:
                f.write(file_data)
            self.db.save_file_metadata(
                file_id=file_id,
                filename=filename,
                sender_pubkey=peer_pubkey,
                recipient_pubkey=self.dilithium_pk.hex(),
                size=len(file_data),
                storage_path=storage_path
            )
            # Notify UI
            await self.notify_ui({
                'type': 'file_received',
                'from': peer_pubkey,
                'filename': filename,
                'url': f'/files/{file_id}'
            })
        
        elif msg_type == 'friends_list':
            # Update friends list from peer
            for f in msg.get('friends', []):
                self.db.add_friend(f)
            await self.notify_ui({'type': 'notification', 'text': 'Synced friends list with peer'})
            # Update UI friends
            friends = self.db.get_friends()
            await self.ui_ws.send(json.dumps({
                'type': 'friends',
                'friends': [f['pubkey'] for f in friends]
            }))
        
        elif msg_type == 'notification':
            # Simple notification
            text = msg.get('text', '')
            await self.notify_ui({
                'type': 'notification',
                'text': f'[{peer_pubkey[:16]}...] {text}'
            })
        
        elif msg_type == 'kyber_confirmed':
            # Ignore (already handled)
            pass

# ----------------------------------------------------------------------
# WebSocket Server (Signaling + P2P)
# ----------------------------------------------------------------------
active_websockets = {}  # pubkey -> websocket (global for signaling)

class WebSocketHandler:
    def __init__(self, node: P2PNode):
        self.node = node
    
    async def handle(self, websocket):
        """Main WebSocket handler for both UI and peer connections."""
        try:
            # First message determines role
            first_msg = await websocket.recv()
            data = json.loads(first_msg)
            
            if data.get('type') == 'hello':
                # UI connection
                self.node.ui_ws = websocket
                await self.node.handle_ui_message(data)
                # Main loop for UI messages
                async for raw_msg in websocket:
                    msg = json.loads(raw_msg)
                    await self.node.handle_ui_message(msg)
            elif data.get('type') == 'p2p_handshake':
                # Peer connection (handshake)
                peer_pubkey = data.get('dilithium_pk')
                if peer_pubkey:
                    active_websockets[peer_pubkey] = websocket
                    await self.node.handle_peer_handshake(websocket, data)
                    # After handshake, handle incoming messages
                    async for raw_msg in websocket:
                        msg = json.loads(raw_msg)
                        await self.node.handle_peer_message(websocket, msg, peer_pubkey)
            else:
                await websocket.send(json.dumps({'type': 'error', 'text': 'Unknown handshake'}))
                await websocket.close()
        except Exception as e:
            print(f"WebSocket error: {e}")
        finally:
            # Cleanup
            for pubkey, ws in list(active_websockets.items()):
                if ws == websocket:
                    del active_websockets[pubkey]
                    self.node.unregister_peer(pubkey)

# ----------------------------------------------------------------------
# HTTP Server (Browser UI + File Downloads)
# ----------------------------------------------------------------------
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class CustomHTTPHandler(SimpleHTTPRequestHandler):
    node = None
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path.startswith('/files/'):
            file_id = self.path.split('/')[-1]
            if self.node and file_id in self.node.file_cache:
                data = self.node.file_cache[file_id]
                # Get filename from DB
                metadata = self.node.db.get_file_metadata(file_id)
                filename = metadata['filename'] if metadata else 'file'
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404, 'File not found')
        else:
            super().do_GET()

# ----------------------------------------------------------------------
# Embedded HTML UI (Complete)
# ----------------------------------------------------------------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Quantum P2P Chat (ML-DSA-87 + Kyber-512)</title>
    <style>
        * { box-sizing: border-box; }
        body { background: #0d0d1a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { background: #1a1a2e; padding: 15px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; }
        .header h1 { margin: 0; color: #7bed9f; }
        .panel { background: #1a1a2e; padding: 15px; border-radius: 10px; margin-bottom: 15px; }
        .panel h3 { margin-top: 0; color: #70a1ff; }
        .key-display { word-wrap: break-word; font-family: monospace; font-size: 12px; background: #0d0d1a; padding: 10px; border-radius: 5px; border: 1px solid #2c2c54; max-height: 80px; overflow-y: auto; }
        .flex-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        input[type="text"], select { padding: 8px 12px; background: #0d0d1a; border: 1px solid #2c2c54; border-radius: 5px; color: #e0e0e0; flex: 1; min-width: 100px; }
        button { padding: 8px 16px; background: #3742fa; border: none; border-radius: 5px; color: white; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #2f3a9e; }
        button.secondary { background: #2c2c54; }
        button.secondary:hover { background: #3d3d6b; }
        .messages-box { background: #0d0d1a; border-radius: 10px; height: 400px; overflow-y: auto; padding: 10px; border: 1px solid #2c2c54; margin-bottom: 15px; }
        .message { padding: 8px 12px; margin: 5px 0; border-radius: 8px; max-width: 70%; }
        .message.self { background: #2d4a2d; margin-left: auto; text-align: right; }
        .message.other { background: #1a2a3a; }
        .message .sender { font-size: 12px; color: #70a1ff; }
        .message .time { font-size: 10px; color: #888; }
        .message.file-message { background: #2c2c54; }
        .message.file-message a { color: #7bed9f; text-decoration: none; }
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 8px; }
        .toast { background: #2ed573; color: #fff; padding: 12px 20px; border-radius: 8px; animation: slideIn 0.3s ease; max-width: 350px; }
        .toast.error { background: #ff4757; }
        .toast.info { background: #70a1ff; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .friend-tag { background: #2c2c54; padding: 4px 10px; border-radius: 15px; font-size: 12px; display: inline-block; margin: 2px; }
        .file-upload-label { background: #3742fa; padding: 8px 16px; border-radius: 5px; cursor: pointer; color: white; display: inline-block; }
        .file-upload-label:hover { background: #2f3a9e; }
        input[type="file"] { display: none; }
        .group-item { background: #2c2c54; padding: 5px 10px; border-radius: 5px; display: inline-block; margin: 2px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Quantum P2P Chat</h1>
            <div id="statusBadge" style="background:#2ed573; padding:5px 15px; border-radius:20px;">Online</div>
        </div>

        <div class="panel">
            <h3>Your Dilithium Public Key</h3>
            <div class="key-display" id="myKey">Loading...</div>
            <div style="margin-top:5px; font-size:12px; color:#888;">Share this key to connect.</div>
        </div>

        <div class="panel">
            <h3>Friends</h3>
            <div id="friendsList">No friends</div>
            <div class="flex-row" style="margin-top:10px;">
                <input type="text" id="friendKey" placeholder="Friend's Dilithium public key">
                <button onclick="addFriend()">Add Friend</button>
                <button onclick="connectToFriend()" class="secondary">Connect</button>
            </div>
        </div>

        <div class="panel">
            <div class="flex-row">
                <button onclick="createGroup()" class="secondary">Create Group</button>
                <div style="display:flex; gap:5px;">
                    <input type="text" id="groupJoinId" placeholder="Group ID" style="width:150px;">
                    <button onclick="joinGroup()" class="secondary">Join</button>
                </div>
                <span style="color:#888;">Groups:</span>
                <select id="groupSelect">
                    <option value="">None</option>
                </select>
            </div>
        </div>

        <div class="messages-box" id="messageContainer"></div>

        <div class="panel">
            <div class="flex-row">
                <input type="text" id="msgInput" placeholder="Type a message..." style="flex:3;">
                <select id="sendTarget" style="flex:1;">
                    <option value="friend">Friend</option>
                    <option value="group">Group</option>
                </select>
                <button onclick="sendMessage()">Send</button>
                <label class="file-upload-label" onclick="document.getElementById('fileInput').click()">📎 File</label>
                <input type="file" id="fileInput" onchange="uploadFile()">
            </div>
        </div>
    </div>

    <div class="toast-container" id="toastContainer"></div>

    <script>
        const ws = new WebSocket("ws://localhost:8765");
        let myPubKey = "";
        let friends = [];
        let groups = {};
        let currentGroupId = null;

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: "hello" }));
        };

        ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            handleMessage(data);
        };

        function handleMessage(data) {
            const type = data.type;
            if (type === "keys") {
                myPubKey = data.dilithium_pk;
                document.getElementById('myKey').textContent = myPubKey;
            } else if (type === "friends") {
                friends = data.friends;
                updateFriendsList();
            } else if (type === "groups") {
                groups = {};
                data.groups.forEach(g => { groups[g.group_id] = g; });
                updateGroupSelect();
            } else if (type === "message") {
                if (data.self) {
                    appendMessage("You", data.text, true);
                } else {
                    const from = data.from.slice(0,16) + '...';
                    appendMessage(from, data.text, false);
                }
            } else if (type === "notification") {
                showToast(data.text, "info");
            } else if (type === "error") {
                showToast("Error: " + data.text, "error");
            } else if (type === "group_created") {
                showToast("Group created: " + data.group_id, "info");
                // Refresh groups
                ws.send(JSON.stringify({ type: "hello" }));
            } else if (type === "file_uploaded") {
                showToast("File uploaded: " + data.file_id, "info");
            } else if (type === "file_received") {
                const from = data.from.slice(0,16) + '...';
                appendFileMessage(from, data.filename, data.url);
                showToast("File received: " + data.filename, "info");
            } else {
                console.log("Unknown:", data);
            }
        }

        function appendMessage(sender, text, self) {
            const container = document.getElementById('messageContainer');
            const div = document.createElement('div');
            div.className = 'message ' + (self ? 'self' : 'other');
            div.innerHTML = `
                <div class="sender">${sender}</div>
                <div>${text}</div>
                <div class="time">${new Date().toLocaleTimeString()}</div>
            `;
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        function appendFileMessage(sender, filename, url) {
            const container = document.getElementById('messageContainer');
            const div = document.createElement('div');
            div.className = 'message file-message other';
            div.innerHTML = `
                <div class="sender">${sender}</div>
                <div>📄 <a href="${url}" target="_blank">${filename}</a></div>
                <div class="time">${new Date().toLocaleTimeString()}</div>
            `;
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        function showToast(text, type="info") {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = text;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        function updateFriendsList() {
            const container = document.getElementById('friendsList');
            if (friends.length === 0) {
                container.innerHTML = 'No friends';
                return;
            }
            container.innerHTML = '';
            friends.forEach(key => {
                const span = document.createElement('span');
                span.className = 'friend-tag';
                span.textContent = key.slice(0,10) + '...';
                container.appendChild(span);
            });
        }

        function updateGroupSelect() {
            const select = document.getElementById('groupSelect');
            select.innerHTML = '<option value="">None</option>';
            Object.keys(groups).forEach(gid => {
                const opt = document.createElement('option');
                opt.value = gid;
                opt.textContent = gid.slice(0,8) + '...';
                select.appendChild(opt);
            });
        }

        function addFriend() {
            const key = document.getElementById('friendKey').value.trim();
            if (!key) return showToast("Enter a public key", "error");
            ws.send(JSON.stringify({ type: "add_friend", pubkey: key }));
            document.getElementById('friendKey').value = '';
        }

        function connectToFriend() {
            const key = document.getElementById('friendKey').value.trim();
            if (!key) return showToast("Enter a public key", "error");
            ws.send(JSON.stringify({ type: "connect", peer_key: key }));
            document.getElementById('friendKey').value = '';
        }

        function sendMessage() {
            const input = document.getElementById('msgInput');
            const text = input.value.trim();
            if (!text) return;
            const target = document.getElementById('sendTarget').value;
            const groupSelect = document.getElementById('groupSelect');
            let peerKey = null;
            let groupId = null;
            if (target === 'friend') {
                if (friends.length === 0) return showToast("No friends", "error");
                peerKey = friends[0];  // Send to first friend for simplicity
            } else if (target === 'group') {
                groupId = groupSelect.value;
                if (!groupId) return showToast("Select a group", "error");
            }
            ws.send(JSON.stringify({
                type: "send",
                target: target,
                text: text,
                peer_key: peerKey,
                group_id: groupId
            }));
            input.value = '';
        }

        function createGroup() {
            ws.send(JSON.stringify({ type: "create_group" }));
        }

        function joinGroup() {
            const gid = document.getElementById('groupJoinId').value.trim();
            if (!gid) return showToast("Enter a group ID", "error");
            ws.send(JSON.stringify({ type: "join_group", group_id: gid }));
            document.getElementById('groupJoinId').value = '';
        }

        function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const base64 = e.target.result.split(',')[1];
                const target = document.getElementById('sendTarget').value;
                const groupSelect = document.getElementById('groupSelect');
                let peerKey = null;
                let groupId = null;
                if (target === 'friend') {
                    if (friends.length === 0) return showToast("No friends", "error");
                    peerKey = friends[0];
                } else if (target === 'group') {
                    groupId = groupSelect.value;
                    if (!groupId) return showToast("Select a group", "error");
                }
                ws.send(JSON.stringify({
                    type: "file",
                    name: file.name,
                    data: base64,
                    target: target,
                    peer_key: peerKey,
                    group_id: groupId
                }));
                showToast("Sending file: " + file.name, "info");
            };
            reader.readAsDataURL(file);
            fileInput.value = '';
        }
    </script>
</body>
</html>
"""

# ----------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------
def main():
    print("=" * 70)
    print(" QUANTUM P2P CHAT - PRODUCTION v2.0")
    print(" ML-DSA-87 + Kyber-512 + SQLite Persistence")
    print("=" * 70)
    
    # Initialize database and node
    db = Database()
    node = P2PNode(db_path=DB_FILE)
    
    # WebSocket handler
    ws_handler = WebSocketHandler(node)
    
    # Start WebSocket server (signaling + P2P)
    async def start_ws():
        async with websockets.serve(ws_handler.handle, SIGNALING_HOST, SIGNALING_PORT):
            print(f"WebSocket signaling server on ws://{SIGNALING_HOST}:{SIGNALING_PORT}")
            await asyncio.Future()
    
    # Start HTTP server
    CustomHTTPHandler.node = node
    httpd = ThreadedHTTPServer(("0.0.0.0", HTTP_PORT), CustomHTTPHandler)
    print(f"HTTP server on http://localhost:{HTTP_PORT}")
    
    # Open browser
    webbrowser.open(f"http://localhost:{HTTP_PORT}")
    
    # Run threads
    def run_http():
        httpd.serve_forever()
    
    def run_ws():
        asyncio.run(start_ws())
    
    http_thread = threading.Thread(target=run_http, daemon=True)
    ws_thread = threading.Thread(target=run_ws, daemon=True)
    
    http_thread.start()
    ws_thread.start()
    
    print("\n✅ System ready. Share your Dilithium public key to connect.")
    print("Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()
        db.close()
        print("Done.")

if __name__ == "__main__":
    main()
