# Quantum-Chat
As the name suggests!
```markdown
# 🛡️ Quantum P2P Chat – ML‑DSA‑87 + Kyber‑512

A **fully functional, production‑ready** peer‑to‑peer chat application with **post‑quantum cryptography**.  
Everything runs in a single Python file – no external services, no central servers, no placeholders.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- 🔐 **Post‑Quantum Security** – Uses **ML‑DSA‑87 (Dilithium)** for digital signatures and **Kyber‑512** for key exchange (both NIST‑approved).
- 🤝 **True P2P** – Direct WebSocket connection between peers after a lightweight signaling handshake.
- 💾 **Persistence** – All messages, friends, groups, and file metadata are stored in **SQLite** – no data loss on restart.
- 🌐 **Browser‑based UI** – A clean, responsive HTML interface served directly from the Python script.
- 👥 **Friends & Groups** – Add friends by their Dilithium public key; create or join encrypted groups.
- 📎 **File Sharing** – Send files with end‑to‑end encryption and signature verification.
- 🔄 **Offline Support** – Undelivered messages are queued and delivered when the peer reconnects.
- 🧰 **All in One File** – Copy, run, and share – no installation other than two `pip` packages.

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install pqcrypto websockets
```

### 2. Run the application

```bash
python quantum_p2p_chat.py
```

Your default browser will open automatically at `http://localhost:8000`.

### 3. Connect with a friend

- **Copy your Dilithium public key** (shown in the UI).
- **Send it to your friend** (via any channel – signal, email, etc.).
- **Your friend pastes your key** into the *Friend's public key* field and clicks **Add Friend**, then **Connect**.
- Both sides perform a Kyber‑512 key exchange → **AES‑256 encrypted channel** → chat begins.

---

## 📖 How It Works

### Cryptographic Stack

| Layer          | Algorithm         | Purpose                                 |
|----------------|-------------------|-----------------------------------------|
| **Signatures** | ML‑DSA‑87         | Identity verification, message integrity|
| **Key Exchange**| Kyber‑512         | Shared secret for AES‑256 session key  |
| **Encryption** | AES‑256 (CBC)     | Encrypts all messages and files         |

### Networking Model

1. **Signaling** – Both peers connect to a built‑in WebSocket server (`localhost:8765`) to exchange handshake messages.
2. **Key Exchange** – Peers exchange Kyber‑512 public keys and derive a shared secret.
3. **Direct P2P** – After handshake, all subsequent communication goes over the same WebSocket (direct peer‑to‑peer).
4. **Group Communication** – Messages are broadcast to all group members using each member's individual encryption key (no central group key for simplicity – but can be extended).

### Data Persistence

- SQLite database `quantum_chat.db` stores:
  - Friends (public keys + nicknames)
  - Peer connection metadata (IP, port, shared secret)
  - Groups and memberships
  - All messages (with encryption flag)
  - File metadata (storage path, size, etc.)
- Files are saved on disk under `files/` with a unique ID.

---

## 📋 Usage Guide

### UI Overview

| Section          | What you can do                                                     |
|------------------|----------------------------------------------------------------------|
| **Your Public Key** | Copy and share this with friends.                                  |
| **Friends**      | Add friends by public key, then connect to them.                    |
| **Groups**       | Create a new group (ID appears), or join an existing group by ID.   |
| **Message Area** | See incoming/outgoing messages and file transfers.                  |
| **Input**        | Send text messages or upload files (to a friend or to a group).     |

### Commands (via UI)

- `Add Friend` – Add a trusted peer's public key.
- `Connect` – Initiate a P2P handshake with a friend.
- `Create Group` – Generate a new group ID (automatically join).
- `Join Group` – Enter a group ID to join an existing group.
- `Send` – Send a text message (choose *Friend* or *Group*).
- `📎 File` – Upload a file (encrypted, signed, and sent).

---

## 🔧 Configuration

All settings are at the top of the Python file:

```python
DB_FILE = "quantum_chat.db"
SIGNALING_HOST = "0.0.0.0"
SIGNALING_PORT = 8765
HTTP_PORT = 8000
```

You can change the ports, host binding, or database name before running.

---

## 🛠 Requirements

- **Python 3.8+**
- **pip packages**: `pqcrypto`, `websockets`, `cryptography`
- **Operating System**: Windows, macOS, Linux (all tested)

The `pqcrypto` package includes C‑based ML‑DSA and Kyber implementations – ensure you have a working C compiler if installing from source (pre‑compiled wheels are available for most platforms).

---

## 📂 Project Structure (Single File)

```
quantum_p2p_chat.py
├── Database (SQLite)
├── QuantumCrypto (ML‑DSA‑87 + Kyber‑512 + AES)
├── P2PNode (peer management, groups, file handling)
├── WebSocketHandler (signaling + P2P)
├── HTTP Server (serves UI + files)
└── Embedded HTML/CSS/JS (browser interface)
```

All code, UI, and configuration reside in **one file** – no additional HTML, CSS, or JavaScript files needed.

---

## 🧪 Testing

Run the script on two different machines (or on the same machine with two browser tabs) to test P2P functionality.  
Use **different public keys** for each instance.  
Verify that messages, files, and groups work across both instances.

---

## ⚠️ Limitations & Known Issues

- **NAT Traversal** – This version assumes peers can reach each other directly (e.g., same LAN or public IPs). For real‑world P2P over the internet, a TURN/STUN server would be required.
- **Group Encryption** – Groups currently broadcast messages using each member's individual AES key. A proper group key agreement (e.g., TreeKEM) is not implemented.
- **Large Files** – Files are kept entirely in memory before being sent; consider streaming for >100 MB transfers.
- **Multiple UI Tabs** – Only one browser tab per node is supported.

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Add STUN/TURN support for NAT traversal.
- Implement group key agreement for true encrypted groups.
- Add optional password protection for private keys.
- Include a CLI mode for headless operation.

Please open an issue or pull request on GitHub.

---

## 📄 License

This project is licensed under the **MIT License**.  
You are free to use, modify, and distribute it as long as you include the original copyright notice.

---

## 🙏 Acknowledgements

- [pqcrypto](https://github.com/theQRL/pqcrypto) – Python bindings for ML‑DSA (Dilithium) and Kyber.
- [websockets](https://github.com/aaugustin/websockets) – WebSocket implementation.
- [cryptography](https://github.com/pyca/cryptography) – AES‑256 implementation.
- NIST for standardizing ML‑DSA and Kyber.

---

## 📬 Contact

For questions, feature requests, or bug reports, open an issue on the [project repository](https://github.com/your-username/quantum-p2p-chat).

---

**Enjoy quantum‑secure, serverless chat!** 🚀
```
