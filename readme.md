
# 🔐 Secure Stateless WebSocket Communication

This project demonstrates a **stateless, end-to-end encrypted communication system** using WebSockets with support for:

* Mutual authentication via ECDSA identity keys
* Ephemeral ECDH key exchange
* AES-256-GCM encryption
* Signature verification
* Nonce-based replay protection

## 🧩 Components

* `stateless_server.py`: Acts as a relay server for WebSocket clients.
* `client_bank.py`: One client role (bank) that initiates secure communication.
* `client_customer.py`: Another client role (customer) that connects securely with the bank.

## ⚙️ Features

* TLS-secured WebSocket (`wss://localhost:8765`)
* Stateless relay model (server only forwards messages)
* Public key exchange and storage
* Replay protection using nonces
* Real and dummy encrypted messages
* Signature and encryption-based message integrity and confidentiality

## 🚀 Getting Started

### 1. Install Requirements

```bash
pip install websockets cryptography
```

### 2. Generate TLS Certificate

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
    -out cert.pem -keyout key.pem -days 365 \
    -subj "/CN=localhost"
```

### 3. Run the Server

```bash
python stateless_server.py
```

### 4. Run the Clients

In separate terminals:

```bash
# Terminal 1 (Bank)
python client_bank.py

# Terminal 2 (Customer)
python client_customer.py
```

> Each client will display its session ID. Copy-paste the peer's ID when prompted to begin a secure session.

## 🔐 Protocol Overview

1. Clients generate long-term identity keys (ECDSA).
2. Each session starts with a mutual ECDH handshake using ephemeral keys.
3. Shared session key is derived using HKDF.
4. Messages are encrypted with AES-256-GCM and signed with ECDSA.
5. The server simply relays packets without inspecting them.

## 📁 File Structure

```
.
├── stateless_server.py         # WebSocket relay server
├── client_bank.py              # Bank client implementation
├── client_customer.py          # Customer client implementation
├── cert.pem / key.pem          # Self-signed certificate and key (generate manually)
└── *_identity_keys.json        # Auto-generated identity key files
```

## ✅ Notes

* All messages are base64-encoded before sending.
* Identity keys are stored in JSON PEM format.
* Dummy messages are sent periodically to simulate traffic.

## 🛠 TODO

* Implement handshake message signing
* Add certificate pinning for stronger client auth
* Build a GUI or CLI wrapper

---
