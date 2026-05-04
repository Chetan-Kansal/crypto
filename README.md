# CryptoChat — Forward-Secret Multi-User Chat System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask)
![SocketIO](https://img.shields.io/badge/Flask--SocketIO-Realtime-010101?style=for-the-badge)
![Cryptography](https://img.shields.io/badge/AES--GCM-256bit-FF6B6B?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-00ff41?style=for-the-badge)

**Design and Security Analysis of a Forward-Secret Multi-User Chat System using Ephemeral Diffie–Hellman and AES-GCM**

*Academic cryptography project demonstrating end-to-end encryption, forward secrecy, formal protocol verification, and live attack simulation.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [System Versions](#-system-versions)
- [Features](#-features)
- [Architecture](#-architecture)
- [Cryptographic Protocol](#-cryptographic-protocol)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Tutorial — How to Use Every Feature](#-tutorial--how-to-use-every-feature)
- [Protocol Visualizer](#-protocol-visualizer)
- [Attack Simulation](#-attack-simulation)
- [Formal Verification (Scyther)](#-formal-verification-scyther)
- [Security Properties](#-security-properties)
- [Tech Stack](#-tech-stack)
- [Screenshots](#-screenshots)

---

## 🔐 Overview

CryptoChat is a **research-grade secure messaging system** built to demonstrate and compare three progressively secure chat architectures:

| Version | Name | Security Level |
|---------|------|---------------|
| V1 | Plain Chat | ❌ No encryption — baseline insecure |
| V2 | Encrypted Chat | ✅ AES-GCM + ECDH key exchange |
| V3 | Forward-Secret Chat | 🛡️ V2 + automatic key rotation (HKDF) |

The project includes a **Protocol Visualizer** with a live real-time cryptographic event feed, an **Attacker Dashboard**, a **formal Scyther verification** module, and an **automated attack simulation** framework.

---

## 🏗 System Versions

### Version 1 — Insecure Plain Chat (`app_insecure.py`)
- Messages transmitted as **plaintext**
- No encryption, no integrity, no authentication
- Used as **academic baseline** for attack comparison
- All messages stored in SQLite as readable text

### Version 2 — Encrypted Chat
- **Ephemeral ECDH** (SECP256R1) for key exchange
- **HKDF-SHA256** for AES key derivation
- **AES-256-GCM** for message encryption with authentication tags
- Server relays **ciphertext only** — never sees plaintext

### Version 3 — Forward-Secret Chat (Default, `app.py`)
- Everything in V2 plus **automatic key rotation** every N messages
- Old session keys permanently discarded after rotation
- Compromising the current key **cannot decrypt past messages**
- Live key fingerprint displayed in chat UI

---

## ✨ Features

- 🔐 **End-to-end encryption** using AES-256-GCM
- 🔑 **Ephemeral Diffie–Hellman** (ECDH SECP256R1) key exchange
- 🔄 **Forward Secrecy** via automatic key rotation every 5 messages
- 📡 **Real-time messaging** via WebSocket (Flask-SocketIO)
- 🕵️ **Attacker Dashboard** — live eavesdropper view showing ciphertexts
- 📊 **Protocol Visualizer** — 5 interactive educational modules
- 🔴 **Live Crypto Event Feed** — real-time SocketIO stream of every crypto operation
- 💥 **Attack Simulation** — 5 automated attack scripts with JSON reports
- ✅ **Scyther Formal Verification** — symbolic protocol models (SPDL)
- 🎨 **Cyberpunk UI** — Three.js particle background, glassmorphism, neon aesthetics
- 🛡️ **Identity Verification** — Safety number (key fingerprint) for MitM detection

---

## 🏛 Architecture

```
                    ┌─────────────────────────────────┐
                    │         Flask Server             │
                    │                                 │
  Alice ──[ECDH]──► │  ┌─────────────────────────┐   │ ◄──[ECDH]── Bob
                    │  │    KeyManager (HKDF)     │   │
  Send("Hello") ──► │  │  derive AES session key  │   │
                    │  └──────────┬────────────────┘   │
                    │             │ AES-GCM encrypt     │
                    │  DB: save { ciphertext }          │ ──► Attacker Dashboard
                    │             │ SocketIO emit        │
                    └─────────────┼────────────────────┘
                                  │
                                  ▼
                    Bob receives { ciphertext }
                    Bob decrypts → "Hello"
```

**Key Principle:** The server acts as a **relay only**. It holds ephemeral session keys in RAM (never persisted). Restart = keys destroyed = Forward Secrecy achieved even against server operator.

---

## 🔬 Cryptographic Protocol

```
1. KEY EXCHANGE (once per session)
   Alice: priv_a = random() ∈ SECP256R1
   Bob:   priv_b = random() ∈ SECP256R1
   Alice → Bob: pub_a = priv_a × G
   Bob → Alice: pub_b = priv_b × G
   shared = ECDH(priv_a, pub_b) = ECDH(priv_b, pub_a)

2. KEY DERIVATION
   session_key = HKDF-SHA256(shared_secret, salt=None, info=b'handshake data', length=32)

3. ENCRYPTION (every message)
   iv = os.urandom(12)                          # fresh 96-bit nonce
   ciphertext, tag = AES-256-GCM.encrypt(session_key, iv, plaintext)
   wire_format = base64(iv || ciphertext || tag)

4. KEY ROTATION (every 5 messages)
   new_key = HKDF-SHA256(current_key, salt=b'key_rotation')
   destroy(current_key)                         # Forward Secrecy
```

---

## 📁 Project Structure

```
secure-chat/
├── app.py                      # Main Flask app (V3 — Forward Secret)
├── app_insecure.py             # V1 — Insecure plain chat baseline
├── requirements.txt
│
├── crypto/
│   ├── dh_utils.py             # ECDH SECP256R1 key exchange
│   ├── aes_utils.py            # AES-256-GCM encrypt/decrypt
│   └── key_manager.py          # HKDF key derivation + rotation
│
├── models/
│   └── db.py                   # SQLite ORM (users, messages)
│
├── templates/
│   ├── base.html               # Three.js cyberpunk layout
│   ├── login.html              # Centered glassmorphism login
│   ├── register.html           # Register page
│   ├── chat.html               # Encrypted chat UI
│   ├── attacker.html           # 🕵️ Eavesdropper dashboard
│   └── visualizer.html         # 📊 Protocol visualizer
│
├── static/
│   ├── style.css               # Global cyberpunk CSS
│   ├── chat.js                 # Chat + decrypt logic
│   ├── visualizer.css          # Visualizer styles
│   ├── visualizer.js           # All 5 visualizers + live feed
│   └── socket.io.js            # SocketIO client
│
└── analysis/
    ├── insecure_protocol.spdl  # Scyther model — insecure
    ├── secure_protocol.spdl    # Scyther model — secure
    ├── simulate_attacks.py     # Automated attack scripts
    ├── attack_scripts/         # Individual attack modules
    ├── attack_results/         # JSON experiment results
    ├── scyther_results/        # Formal verification notes
    └── comparison/             # Cross-version analysis reports
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Chetan-Kansal/crypto.git
cd crypto/secure-chat

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
python app.py
```

### Access
Open your browser and navigate to: **`http://localhost:5000`**

> **Note:** For the insecure baseline (Version 1), run `python app_insecure.py` on port 5001 instead.

---

## 📖 Tutorial — How to Use Every Feature

### 1. Register & Login
1. Go to `http://localhost:5000/register`
2. Create two accounts (e.g., `alice` and `bob`) in two separate browser windows/tabs
3. Login to each account

### 2. Secure Chat (`/chat`)
- **Start chatting**: Click any user in the left panel to open a chat with them
- **First message**: Triggers automatic ECDH handshake (watch the Packet Log on the right)
- **Packet Log** (right panel): Shows every crypto event — `[DH] Handshake`, `[HKDF] Key Derivation`, `[AES] Encryption`
- **Security Badge** (top of chat): Shows current AES key fingerprint and messages until next rotation
- **Decrypt button**: Click on any encrypted message to reveal the plaintext
- **Verify Identity button**: Displays your session's safety number (fingerprint) to detect MitM attacks

#### Key Rotation Demo
Send 5 messages — on the 5th, the key fingerprint in the Security Badge will **flash and change** to a new value. This is Forward Secrecy in action!

### 3. Attacker Dashboard (`/attacker`)
Open `http://localhost:5000/attacker` in a third window.
- Simulates what a hacker sees if they tap the network or steal the database
- **Real-time stream** of all ciphertexts flowing between users
- Beautiful ciphertexts — fully unreadable without the session key
- Great for **showcase demonstrations** — show this alongside the chat to prove encryption works

### 4. Protocol Visualizer (`/visualizer`)
The visualizer has 6 tabs — navigate using the tab buttons at the top.

#### 🔴 Tab 0 — LIVE Feed (Real-Time)
- Open the visualizer at `http://localhost:5000/visualizer`
- Open chat in another tab and send messages
- Watch the **pipeline** light up: `ECDH → HKDF → AES-Enc → Network → AES-Dec`
- See real IV, real ciphertext hex, real auth tag from actual crypto operations
- Counter cards track: sessions, messages, key rotations, current fingerprint

#### Tab 1 — DH Key Exchange (Interactive)
- Click **▶ Next Step** 6 times to walk through the entire DH handshake
- Watch Alice's private key (red), public key (blue), and shared secret (green) appear
- The **Attacker panel** at the bottom shows exactly what Eve can intercept (only public keys)
- Press **↺ Reset** to start over

#### Tab 2 — AES Encryption (Interactive)
- Click **🔒 Encrypt & Send** to see plaintext → ciphertext transformation
- Click **🔓 Decrypt at Receiver** to recover plaintext
- Enable **💀 Tamper Attack** checkbox → decrypt again to see AES-GCM authentication failure (red shake animation)

#### Tab 3 — Forward Secrecy Timeline
- Shows 3 key windows: K₁ (msgs 1-5), K₂ (msgs 6-10), K₃ (msgs 11-15)
- Click **💥 Simulate Key Compromise** — K₃ turns red (exposed)
- K₁ and K₂ turn green (🛡️ SAFE) — permanently protected even though the server was "hacked"

#### Tab 4 — Attack Matrix
- Color-coded table: 🔴 Red = vulnerable, 🟡 Yellow = partial, 🟢 Green = secure
- **Hover any cell** for a detailed explanation of what the attacker gains
- Covers: Passive Eavesdropping, DB Leak, Key Compromise, Replay Attack, Tampering

#### Tab 5 — Scyther Formal Verification
- Side-by-side comparison of insecure vs secure protocol symbolic models
- Shows the attacker's exact replay path in the insecure protocol
- Claim results table: Secrecy, Alive, Weakagree, Nisynch (all pass/fail)

### 5. Attack Simulation
Run the attack framework to generate experimental results:

```bash
cd analysis
python simulate_attacks.py --version 1   # Attack insecure chat
python simulate_attacks.py --version 2   # Attack encrypted chat
python simulate_attacks.py --version 3   # Attack forward-secret chat
```

Results saved to `analysis/attack_results/` as JSON files.

Generate a comparison report:
```bash
python comparison/generate_comparison_report.py
# Output: analysis/comparison/attack_comparison_report.md
```

### 6. Forward Secrecy Proof
The most important security property to demonstrate:
1. Chat with someone and send 10+ messages (causes at least 1 key rotation)
2. **Stop the server** (`Ctrl+C`)
3. **Restart the server** (`python app.py`)
4. Go back to chat — old messages show `[Decryption Failed - No Active Session]`
5. **This is the proof**: All session keys were in RAM. They're gone. The ciphertexts in the DB are permanently sealed — even we cannot read them anymore.

---

## 📊 Protocol Visualizer

The visualizer module at `/visualizer` provides 5 interactive educational panels:

| # | Name | What it demonstrates |
|---|------|---------------------|
| 0 | 🔴 Live Feed | Real SocketIO stream of all crypto ops during live chat |
| 1 | DH Exchange | Step-by-step Diffie–Hellman handshake with Eve observer |
| 2 | AES-GCM | Encrypt/decrypt flow + tamper attack demo |
| 3 | Forward Secrecy | Key rotation timeline + compromise simulation |
| 4 | Attack Matrix | Color-coded results across all 3 system versions |
| 5 | Scyther | Formal symbolic verification claims (pass/fail) |

---

## 💥 Attack Simulation

Five attacks are implemented and compared across all three system versions:

| Attack | V1 Plain | V2 Encrypted | V3 Forward-Secret |
|--------|----------|-------------|-------------------|
| Passive Eavesdrop | 💀 Full read | ✅ Ciphertext only | ✅ Ciphertext only |
| Database Leak | 💀 Exposed | ⚠️ Key risk | ✅ Window only |
| Key Compromise | 🚫 N/A | 💀 All history | ⚠️ 5 msgs only |
| Replay Attack | 💀 Accepted | ⚠️ May accept | ✅ Rejected |
| Message Tamper | 💀 Accepted | ✅ Rejected | ✅ Rejected |

---

## ✅ Formal Verification (Scyther)

Two SPDL protocol models in `analysis/`:

### `insecure_protocol.spdl`
- Static key, no nonces, no freshness
- Scyther finds **replay attack** — `Nisynch` claim FAILS
- `Alive` and `Weakagree` also FAIL

### `secure_protocol.spdl`
- Ephemeral nonces, HKDF-derived session key, authenticated exchange
- All claims **PASS**: `Secret`, `Alive`, `Weakagree`, `Nisynch`

Run in Scyther GUI: Load either `.spdl` file → click **Verify Protocol**.

---

## 🛡 Security Properties

| Property | Mechanism | Achieved |
|----------|-----------|---------|
| Confidentiality | AES-256-GCM | ✅ |
| Integrity | GCM Auth Tag | ✅ |
| Authentication | ECDH + fingerprint | ✅ |
| Forward Secrecy | Key rotation (HKDF) | ✅ |
| Replay Resistance | Key rotation invalidates old ciphers | ✅ |
| Freshness | Ephemeral ECDH keys per session | ✅ |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10, Flask 2.x |
| Realtime | Flask-SocketIO (WebSocket) |
| Crypto | `cryptography` (pyca) — ECDH, HKDF, AES-GCM |
| Database | SQLite via custom ORM |
| Frontend | HTML5, Vanilla CSS, Vanilla JS |
| 3D Background | Three.js (r128) |
| Formal Verification | Scyther (SPDL models) |
| Fonts | Fira Code (Google Fonts) |

---

## 📸 Screenshots

> Open `http://localhost:5000` to see the live interface.

| Page | URL |
|------|-----|
| Login | `/login` |
| Chat | `/chat` |
| Attacker Dashboard | `/attacker` |
| Protocol Visualizer | `/visualizer` |

---

## 👥 Authors

- **Gaurang Bhatia** — System design, cryptographic implementation, attack simulation
- **Chetan** — Protocol verification, formal analysis, documentation

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🎓 Academic Context

This project was developed as part of a formal study in applied cryptography. It demonstrates:
- Practical implementation of standard cryptographic primitives
- Comparative security analysis across protocol versions
- Formal symbolic verification using the Scyther tool
- Visual and interactive explanation of cryptographic concepts

> **Important Note on Forward Secrecy:** The "Decryption Failed" message when restarting the server is intentional and proves the system works correctly. Session keys exist only in RAM and are never persisted to disk by design.
