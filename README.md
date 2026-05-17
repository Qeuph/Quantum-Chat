# Quantum Chat

Quantum Chat is a single-file, browser-based, post-quantum encrypted peer-to-peer chat application. It includes a local web UI, a local UI WebSocket API, an optional WebSocket signaling/relay server, SQLite persistence, encrypted file transfer, friend management, and small group fan-out.

> **Security note:** this project uses post-quantum primitives through `pqcrypto`, but it has not been independently audited. Treat it as production-oriented application code, not a certified secure messenger.

## Features

- **Persistent identity:** your ML-DSA/Dilithium public/private signing key is created once and stored in SQLite.
- **Trusted friends:** add peers by public key, optionally with a nickname.
- **Post-quantum session setup:** peers authenticate handshakes with ML-DSA/Dilithium signatures and establish shared secrets with Kyber-512.
- **Modern symmetric encryption:** every chat message and file payload is encrypted with AES-256-GCM using HKDF-derived session keys.
- **P2P-style relay:** peers connect to a signaling WebSocket that only routes envelopes; message and file contents remain end-to-end encrypted.
- **Encrypted files:** files are encrypted in transit, checksum verified on receipt, stored locally, and downloadable from the local UI.
- **Groups:** create groups and send messages to members by encrypting a separate copy for each member's current pairwise session.
- **SQLite persistence:** identity, friends, sessions, groups, messages, and file metadata persist across restarts.
- **One-file app:** all Python, HTTP serving, WebSocket handling, and the browser UI live in `chat.py`.

## Requirements

- Python 3.10+
- Packages listed in `requirements.txt`:
  - `cryptography`
  - `websockets`
  - `pqcrypto`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Quick start on one machine

Start a local node and a local signaling server together:

```bash
python chat.py --with-signaling
```

Open the UI at:

```text
http://127.0.0.1:8000
```

To run a second local node for testing, use different ports and a different database:

```bash
python chat.py --db peer2.db --http-port 8001 --ui-ws-port 8767 --signaling-url ws://127.0.0.1:8766 --no-browser
```

Then open `http://127.0.0.1:8001` manually.

## Multi-machine setup

Run the signaling server on a reachable host:

```bash
python chat.py signal --host 0.0.0.0 --port 8766
```

Run each peer and point it at that signaling server:

```bash
python chat.py --signaling-url ws://SIGNALING_HOST_OR_IP:8766
```

Each peer then:

1. Copies their public key from **Your identity**.
2. Shares it with the other peer through a trusted out-of-band channel.
3. Adds the other peer in **Friends**.
4. Clicks **Connect** to complete the Kyber session handshake.
5. Sends messages or files after the secure session notice appears.

## How it works

### Cryptographic flow

1. A peer creates a persistent ML-DSA/Dilithium identity keypair.
2. When connecting to a friend, the initiator creates an ephemeral Kyber keypair and sends a signed `session_offer` through the signaling server.
3. The responder verifies the signature, encapsulates a shared secret to the initiator's Kyber public key, stores an HKDF-derived AES-256-GCM key, and returns a signed `session_accept`.
4. The initiator verifies the acceptance signature, decapsulates the Kyber ciphertext, derives the same AES-256-GCM key, and stores the session.
5. All chat/file payloads are encrypted end-to-end with AES-256-GCM and include authenticated associated data for routing metadata.

### Networking model

Quantum Chat uses a WebSocket signaling/relay server to discover online peers and route encrypted envelopes. The relay can see peer public keys and envelope metadata needed for delivery, but not decrypted message text or file contents.

This model works reliably on LANs and across NAT when peers can reach the signaling server. It does not yet implement direct TCP/WebRTC hole punching.

### Persistence

The default SQLite database is `quantum_chat.db`. File bytes are saved in the `files/` directory and metadata is saved in SQLite.

## Command reference

Run the node UI:

```bash
python chat.py [options]
```

Useful node options:

| Option | Default | Description |
| --- | --- | --- |
| `--db` | `quantum_chat.db` | SQLite database path. |
| `--signaling-url` | `ws://127.0.0.1:8766` | Signaling/relay server URL. |
| `--with-signaling` | disabled | Also start a signaling server in the same process. |
| `--http-host` | `127.0.0.1` | Host for the browser UI. |
| `--http-port` | `8000` | Port for the browser UI. |
| `--ui-ws-host` | `127.0.0.1` | Host for the local UI WebSocket. |
| `--ui-ws-port` | `8765` | Port for the local UI WebSocket. |
| `--no-browser` | disabled | Do not open a browser automatically. |

Run only the signaling server:

```bash
python chat.py signal --host 0.0.0.0 --port 8766
```

## Project structure

```text
chat.py             # Application, crypto, DB, WebSocket relay/client, HTTP UI
requirements.txt   # Runtime dependencies
README.md          # Documentation
quantum_chat.db    # Created at runtime
files/             # Created at runtime for transferred files
```

## Current limits

- Signaling is server-assisted relay, not pure direct WebRTC/TCP hole punching.
- The relay can see routing metadata (public keys, online status, envelope type), but not encrypted payload contents.
- Group messages are pairwise fan-out to current group members rather than TreeKEM or MLS.
- File transfer currently buffers the whole file in memory and is capped at 25 MB by default.
- The app is not externally audited and should be reviewed before high-risk deployments.

## Development checks

Compile the app:

```bash
python -m py_compile chat.py
```

Exercise the database layer without network services:

```bash
python - <<'PY'
from chat import Database
import tempfile, os
fd, path = tempfile.mkstemp(); os.close(fd); os.remove(path)
db = Database(path)
db.save_identity('abc', b'secret')
db.add_friend('friend', 'Alice')
db.create_group('gid', 'Group', 'abc')
db.add_group_member('gid', 'friend')
db.save_message('m1', 'abc', 'hello', 'out', recipient='friend', delivered=True)
print(db.load_identity()[0], db.get_friends()[0]['nickname'], db.groups_for('abc')[0]['name'], db.recent_messages()[0]['body'])
db.close(); os.remove(path)
PY
```

## License

MIT License. See your repository license file if present.
