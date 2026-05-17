# Quantum Chat

Quantum Chat is a single-file, browser-based, post-quantum encrypted peer-to-peer chat application. It includes a local dark-mode web UI, a local UI WebSocket API, an optional WebSocket signaling/relay server, SQLite persistence, encrypted file transfer, friend management, small group fan-out, typing indicators, read receipts, emoji reactions, unread counts, and a health endpoint.

> **Security note:** this project uses post-quantum primitives through `pqcrypto`, but it has not been independently audited. Treat it as hardened experimental application code, not a certified secure messenger. Remote production deployments still need an external security review, TLS, operational monitoring, and a clear key-backup plan.

## Features

- **Persistent identity:** your ML-DSA/Dilithium public/private signing key is created once and stored in SQLite.
- **Trusted friends:** add peers by public key, optionally with a nickname, and see online/session status and unread counts at a glance.
- **Post-quantum session setup:** peers authenticate handshakes with ML-DSA/Dilithium signatures and establish shared secrets with Kyber-512.
- **Session lifecycle:** pairwise sessions track a 24-hour lifetime and the UI warns when session keys are close to expiry.
- **Modern symmetric encryption:** every chat message and file payload is encrypted with AES-256-GCM using HKDF-derived per-message/session keys.
- **P2P-style relay:** peers connect to a signaling WebSocket that only routes envelopes; message and file contents remain end-to-end encrypted.
- **Encrypted files:** files are encrypted in transit, checksum verified on receipt, stored encrypted at rest, shown in a transfer list, previewed where supported by the browser, and downloadable from the local UI.
- **Groups:** create groups from selected or comma-separated members and send messages or files by encrypting a separate copy for each member's current pairwise session.
- **Receipts and reactions:** delivery acknowledgements, read receipts, and emoji reactions are signed, persisted, and reflected in the UI.
- **Typing and unread state:** typing indicators are ephemeral relay messages, while per-friend unread counts persist in SQLite and clear when a conversation is read.
- **SQLite persistence:** identity, friends, sessions, groups, messages, files, outbox state, reactions, read receipts, and session health metadata persist across restarts. Secret keys, session keys, message bodies, and local file bytes are encrypted at rest with a per-database local master key file.
- **Local UI protection:** the browser UI WebSocket requires a random startup token and rejects non-local origins.
- **Replay hardening:** inbound chat/file payloads include counters and duplicate IDs are ignored before UI broadcast.
- **Resilient networking:** the node uses exponential backoff when reconnecting to the signaling server and queues eligible outbound relay payloads for retry.
- **Health and observability:** `/health` exposes local node status as JSON and `--log-level` controls runtime logging verbosity.
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

The process also prints the node identity, public-key fingerprint, UI URL, and health URL. Health status is available at:

```text
http://127.0.0.1:8000/health
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

1. Copies their public key or fingerprint from **Your identity**.
2. Shares it with the other peer through a trusted out-of-band channel.
3. Adds the other peer in **Friends**.
4. Clicks **Connect** to complete the Kyber session handshake.
5. Sends messages, reacts, marks messages read, or transfers files after the secure session notice appears and the friend shows a secure session badge.

## Browser UI

The local browser interface includes:

- A redesigned dark three-column layout with responsive mobile behavior.
- A dashboard for friend, online peer, secure session, and file counts.
- Friend cards with online badges, secure-session badges, unread counters, and last-message previews.
- Target-scoped message history with a quick text filter.
- Typing indicators, delivery/read status ticks, a manual **mark read** action, and hover emoji reaction controls.
- Browser notifications and title unread-count updates when messages arrive while the page is unfocused.
- A session health panel that shows established pairwise sessions and remaining key lifetime.
- A recent encrypted files panel with local download links, image-friendly browser previews, and drag-and-drop upload support.
- Group creation from either the selected friend or comma-separated public keys, plus group file fan-out.

## How it works

### Cryptographic flow

1. A peer creates a persistent ML-DSA/Dilithium identity keypair.
2. When connecting to a friend, the initiator creates an ephemeral Kyber keypair and sends a signed `session_offer` through the signaling server.
3. The responder verifies the signature, encapsulates a shared secret to the initiator's Kyber public key, stores an HKDF-derived AES-256-GCM key, and returns a signed `session_accept`.
4. The initiator verifies the acceptance signature, decapsulates the Kyber ciphertext, derives the same AES-256-GCM key, and stores the session.
5. Session keys are derived with transcript binding and are tracked with a 24-hour lifetime.
6. Chat/file payloads use HKDF-derived per-message keys plus AES-256-GCM authenticated associated data for routing metadata.
7. Delivery acknowledgements, read receipts, reactions, and group invites are signed with the sender's persistent identity key.

### Networking model

Quantum Chat uses a WebSocket signaling/relay server to discover online peers and route encrypted envelopes. The relay can see peer public keys and envelope metadata needed for delivery, but not decrypted message text or file contents.

The relay issues a signed-registration challenge for clients that support it, validates public-key sizes, performs basic payload-shape checks, and applies per-socket rate limiting. Nodes reconnect with exponential backoff after relay failures.

This model works reliably on LANs and across NAT when peers can reach the signaling server. It does not yet implement direct TCP/WebRTC hole punching.

### Persistence

The default SQLite database is `quantum_chat.db`. File metadata is saved in SQLite and encrypted file bytes are saved in the `files/` directory.

A local master key file named like `<database>.key` is created beside the database and protects local secret material, message bodies, session keys, and stored file bytes. Back up both the database and its key file if you need to preserve a node identity and local history.

## Command reference

Run the node UI:

```bash
python chat.py [options]
```

Useful node options:

| Option | Default | Description |
| --- | --- | --- |
| `--db` | `quantum_chat.db` | SQLite database path. A sibling `*.key` file stores the local at-rest encryption key. |
| `--signaling-url` | `ws://127.0.0.1:8766` | Signaling/relay server URL. |
| `--with-signaling` | disabled | Also start a signaling server in the same process. |
| `--signaling-host` | `0.0.0.0` | Host for the bundled signaling server when `--with-signaling` is used. |
| `--signaling-port` | `8766` | Port for the bundled signaling server when `--with-signaling` is used. |
| `--http-host` | `127.0.0.1` | Host for the browser UI. |
| `--http-port` | `8000` | Port for the browser UI and `/health`. |
| `--ui-ws-host` | `127.0.0.1` | Host for the local UI WebSocket. |
| `--ui-ws-port` | `8765` | Port for the local UI WebSocket. |
| `--no-browser` | disabled | Do not open a browser automatically. |
| `--log-level` | `WARNING` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |

Run only the signaling server:

```bash
python chat.py signal --host 0.0.0.0 --port 8766
```

## Project structure

```text
chat.py             # Application, crypto, DB, WebSocket relay/client, HTTP UI
requirements.txt   # Runtime dependencies
pyproject.toml     # Package metadata and console entry point
README.md          # Documentation
quantum_chat.db    # Created at runtime
quantum_chat.db.key # Created at runtime; local at-rest encryption key
files/             # Created at runtime for encrypted transferred files
```

## Threat model and current limits

Quantum Chat aims to protect message and file contents from the signaling relay and passive network observers. It assumes users verify friend public keys or fingerprints through a trusted out-of-band channel and that invited group members are trusted to receive group content.

Important remaining limits:

- Signaling is server-assisted relay, not pure direct WebRTC/TCP hole punching.
- The relay can see routing metadata (public keys, online status, envelope type), but not encrypted payload contents.
- Group messages are pairwise fan-out to current group members rather than TreeKEM or MLS. Group epochs and roles are stored, but membership changes are not yet a full MLS-style group ratchet.
- Delivery acknowledgements, read receipts, reactions, typing indicators, and queued relay retries improve UX but do not provide a full offline multi-device messaging protocol.
- File transfer currently buffers the whole file in memory for each recipient and is capped at 25 MB by default.
- Local at-rest encryption uses a random `*.db.key` file beside the database. Protect and back up this key file; an attacker who steals both the database/files and key file can decrypt local data.
- The browser UI is intended for local use; if exposed beyond localhost, put it behind TLS and additional access controls.
- The app is not externally audited and should be reviewed before high-risk deployments.

## Security and UX hardening in v2.0

- Strict algorithm-sized public-key validation for friends, relay registration, and relay targets.
- Signed signaling registration challenges to reduce public-key hijacking on the relay.
- Basic relay rate limiting and payload shape checks.
- UI WebSocket bearer token and local-origin checks.
- HTTP security headers for the app shell, `/health`, and downloads.
- SQLite schema versioning, busy timeout, indexes, WAL mode, and serialized database access.
- Encrypted-at-rest identity keys, session keys, message bodies, and downloaded/sent file bytes.
- Replay protections using message/file counters plus insert-only duplicate handling.
- Signed delivery acknowledgements, read receipts, emoji reactions, and group invites.
- Persistent unread counts, session TTL warnings, exponential relay reconnection, and a JSON health endpoint.

## Packaging and development

Install as an editable package with development tools:

```bash
python -m pip install -e .[dev]
```

Run the console entry point:

```bash
quantum-chat --with-signaling
```

## Development checks

Compile the app:

```bash
python -m py_compile chat.py
```

Run automated tests:

```bash
pytest
```

Exercise the database layer without network services:

```bash
python - <<'PY'
from chat import Database, LocalKeyStore
import tempfile, os, uuid
fd, path = tempfile.mkstemp(); os.close(fd); os.remove(path)
key_path = path + '.key'
db = Database(path, master_key=LocalKeyStore(path).load_or_create())
file_id = str(uuid.uuid4())
db.save_identity('abc', b'secret')
db.add_friend('friend', 'Alice')
db.create_group('gid', 'Group', 'abc')
db.add_group_member('gid', 'friend')
db.save_message('m1', 'abc', 'hello', 'out', recipient='friend', delivered=True)
db.save_file(file_id, 'note.txt', 'abc', 5, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', path, recipient='friend')
print(db.load_identity()[0], db.get_friends()[0]['nickname'], db.group_details_for('abc')[0]['name'], db.recent_messages()[0]['body'], db.recent_files()[0]['filename'])
db.close(); os.remove(path); os.remove(key_path)
PY
```

## License

MIT License. See [LICENSE](LICENSE).
