
---

# 🔐 Secure Stateless WebSocket Communication System

This project demonstrates a secure and stateless message relay system using **WebSockets over TLS**. It supports **end-to-end encryption**, **mutual authentication**, and **message integrity** using well-established cryptographic protocols. The system simulates secure communication between two clients — a **bank** and a **customer** — via a stateless relay server.

---

## 📦 Project Structure

```bash
.
├── stateless_server.py           # Stateless WebSocket relay server
├── client_bank.py                # Bank client
├── client_customer.py            # Customer client
├── cert.pem / key.pem            # TLS certificate and private key (generate manually)
├── bank_identity_keys.json       # Bank's ECDSA key pair (auto-generated)
├── customer_identity_keys.json   # Customer's ECDSA key pair (auto-generated)
├── *_public_identity_key.json    # Public identity keys exchanged between clients
```

---

## 🔍 Overview

The system implements the following cryptographic and architectural concepts:

* **Stateless Server:** The server relays messages between clients but never stores or decrypts them.
* **TLS (wss\://):** All communication between clients and the server is encrypted using TLS.
* **End-to-End Encryption:** Clients encrypt, sign, and decrypt messages using a shared session key.
* **Ephemeral ECDH Key Exchange:** Clients perform ECDH key exchange on connection to derive a shared AES session key.
* **ECDSA Identity Keys:** Each client has a persistent ECDSA identity key pair used for message authentication.
* **Replay Protection:** Each message includes a nonce; previously seen nonces are tracked and rejected.
* **Dummy Traffic:** Clients periodically send dummy encrypted messages to simulate noise.

---

## ✅ Features

* TLS-secured WebSocket relay (`wss://localhost:8765`)
* ECDSA identity keys for long-term authentication
* ECDH ephemeral key exchange for perfect forward secrecy
* AES-256-GCM encryption with variable-length payloads
* Signature-based integrity and authenticity checks
* Nonce-based replay attack protection
* Auto-persistence and regeneration of identity keys
* File-based identity key exchange between peers

---

## 🚀 Setup Instructions

### 1. Install Dependencies

Ensure you are using **Python 3.7+** and install required packages:

```bash
pip install websockets cryptography
```

---

### 2. Generate TLS Certificate and Key

Generate a self-signed certificate for local TLS:

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=localhost"
```

Place `cert.pem` and `key.pem` in the same directory as the scripts.

---

### 3. Start the WebSocket Server

The server listens on `wss://localhost:8765` and relays messages between connected clients.

```bash
python stateless_server.py
```

---

### 4. Run the Clients

Start two separate clients — one for each role:

```bash
# Terminal 1 (Bank)
python client_bank.py

# Terminal 2 (Customer)
python client_customer.py
```

* Each client will generate or load its **ECDSA identity key pair**.
* You'll be prompted to enter the peer’s **session ID**, which is printed by their client.
* After exchanging session IDs, an **ECDH key exchange** begins.
* Upon handshake completion, encrypted and signed messages can be exchanged.

---

## 🔐 Security Protocol

### Key Exchange

* Clients generate ephemeral ECDH keys on startup.
* Each client sends its ephemeral public key and long-term identity public key to the peer.
* A shared secret is derived using ECDH and passed through HKDF to generate a 256-bit AES key.

### Message Encryption

* **AES-256-GCM** is used for authenticated encryption with a 16-byte random nonce.
* Message components (nonce + ciphertext + tag) are signed using **ECDSA**.
* The signed payload is then base64-encoded and relayed by the server.

### Replay Protection

* Each client keeps track of previously used nonces.
* Duplicate nonces are rejected to prevent replay attacks.

---

## 📁 Identity Key Management

Each client stores its identity keys in JSON:

```json
{
  "private_key": "PEM string",
  "public_key": "PEM string"
}
```

The peer's public identity key is stored separately in a `*_public_identity_key.json` file and is automatically updated after the first successful handshake.

---

## 📡 Dummy Messages

To simulate real-world noise and enhance obfuscation, clients send encrypted **dummy messages** at random intervals between 30–90 seconds. These are indistinguishable from real messages to the relay server.

---

## 🛠 Developer Notes

* All WebSocket connections are secured via TLS (WSS).
* All message encryption, signing, and validation is done entirely by clients.
* The server does not decrypt, inspect, or modify any payloads.
* Identity key exchange is manual and file-based for proof-of-concept simplicity.
* All crypto operations are performed using Python’s `cryptography` library.

---

## 🧪 Testing Tips

* If peer keys are missing, the first handshake will automatically generate and persist them.
* If the certificate is not trusted by the OS/browser, disable verification or manually trust `cert.pem`.
* Use `DEBUG` level logs to trace nonce, ciphertext, and signature values.

---

## 🔧 Future Enhancements

* Add message queueing/retry on reconnect
* Support signed handshake messages
* Implement GUI or REST API layer
* Use pinned certificates and mutual TLS
* Encrypt identity key files with password

---

## ❓ Troubleshooting

| Problem                         | Solution                                                  |
| ------------------------------- | --------------------------------------------------------- |
| `SSL certificate not found`     | Ensure `cert.pem` and `key.pem` are present               |
| `Connection refused`            | Check if the server is running and listening on port 8765 |
| `Signature verification failed` | Ensure peer's public key is correct and not modified      |
| `Replay attack detected`        | Ensure each message uses a unique nonce                   |

---
