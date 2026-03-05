# 🔐 SFEDST — Secure File Encryption & Digital Signature Tool

A production-grade, open-source command-line PKI toolkit built entirely in Python.  
Demonstrates **confidentiality · integrity · authentication · secure key management**.

---

## Features at a Glance

| Capability | Algorithm |
|---|---|
| Key generation | RSA-2048 / RSA-4096 |
| Private key storage | PKCS#8 + AES-256-CBC + PBKDF2-HMAC-SHA256 |
| Certificates | X.509 v3 self-signed |
| Digital signatures | RSA-PSS + SHA-256 |
| File encryption | AES-256-GCM (hybrid with RSA-OAEP key wrap) |
| Replay prevention | Per-signature nonce + UTC timestamp |
| MITM prevention | X.509 certificate validation before key use |

---

## Project Structure

```
sfedst/
├── main.py                        # Interactive CLI (menu-driven)
├── requirements.txt
├── README.md
│
├── sfedst/                        # Core library
│   ├── __init__.py
│   ├── key_manager.py             # RSA key-pair generation & secure storage
│   ├── certificate_manager.py     # X.509 certificate lifecycle
│   ├── signature_manager.py       # RSA-PSS signatures + replay protection
│   ├── encryption_manager.py      # Hybrid AES-256-GCM + RSA-OAEP encryption
│   └── utils.py                   # CLI helpers (prompts, display)
│
├── tests/
│   ├── __init__.py
│   └── test_sfedst.py             # 30 unit + integration tests
│
├── examples/
│   ├── demo.py                    # Automated Alice-Bob demo + attack sims
│   └── sample.txt                 # Sample file for testing
│
├── keys/                          # Generated key files (auto-created)
└── certs/                         # Generated certificates (auto-created)
```

---

## Installation

### Requirements
- Python 3.8 or higher

```bash
# 1. Clone
git clone https://github.com/yourname/sfedst.git
cd sfedst

# 2. Virtual environment (recommended)
python -m venv venv
source venv/bin/activate       # Linux / macOS
venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the CLI
python main.py
```

---

## Quick Start — CLI Walkthrough

### Step 1 — Generate key pairs for Alice and Bob

```
Menu → 1
Identity name : alice
Key size      : 2048
Password      : (choose a strong passphrase)
```

Repeat for `bob`.

### Step 2 — Create X.509 certificates

```
Menu → 2
Identity name : alice
Common Name   : Alice
Organization  : My Company
```

### Step 3 — Sign a file (as Alice)

```
Menu → 3
Signer identity : alice
File path       : examples/sample.txt
Password        : (alice's passphrase)
```

Output: `examples/sample.txt.sig`

### Step 4 — Verify the signature (as Bob, using Alice's cert)

```
Menu → 4
Signer identity : alice
File path       : examples/sample.txt
Signature file  : examples/sample.txt.sig
```

### Step 5 — Encrypt the file for Bob

```
Menu → 5
Recipient       : bob
File path       : examples/sample.txt
Output path     : examples/sample.txt.enc
```

### Step 6 — Decrypt (as Bob)

```
Menu → 6
Recipient       : bob
Encrypted file  : examples/sample.txt.enc
Password        : (bob's passphrase)
```

### Step 7 — Attack simulation

```
Menu → 7
Signer identity : alice
File path       : examples/sample.txt
Password        : (alice's passphrase)
```

Demonstrates tamper detection and impersonation prevention.

---

## Automated Demo

```bash
python examples/demo.py
```

Runs the complete Alice → Bob workflow and all three attack simulations
without any user interaction.

---

## Running Tests

```bash
# unittest
python -m unittest discover tests -v

# pytest (if installed)
python -m pytest tests/ -v
```

Expected: **30 tests, all passing**.

---

## Cryptographic Architecture

### Hybrid Encryption Flow

```
ENCRYPT
  plaintext
    ├─► AES-256-GCM(random_session_key, random_nonce)  ──► ciphertext + auth_tag
    └─► RSA-OAEP-SHA256(recipient_pub, session_key)    ──► wrapped_key

  FILE LAYOUT: [4-byte key_len][wrapped_key][nonce][ciphertext+tag]

DECRYPT
  ├─► RSA-OAEP-SHA256(recipient_priv)  ──► session_key
  └─► AES-256-GCM.decrypt(session_key, nonce, ciphertext)  ──► plaintext
```

### Signed Envelope (JSON)

```json
{
  "file_hash" : "<SHA-256 hex of file bytes>",
  "timestamp" : "2025-06-01T12:00:00+00:00",
  "nonce"     : "<base64 of 32 random bytes>",
  "signature" : "<base64 RSA-PSS over hash|timestamp|nonce>"
}
```

### Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM — only key holder decrypts |
| Integrity | GCM auth tag + SHA-256 content hash in envelope |
| Authentication | RSA-PSS signature verified via X.509 certificate |
| Non-repudiation | Only private-key holder produces valid signature |
| Replay prevention | Unique nonce + UTC timestamp per signature |
| Forward secrecy | Fresh random AES session key per encryption |
| MITM prevention | Certificate validated before accepting public key |

---

## Security Caveats

> **Self-signed certificates** are used for demonstration.  
> In production: use certificates issued by a trusted CA, validate full chains,
> and check CRL / OCSP revocation status.

> **Private key files** (`keys/*_private.pem`) are encrypted with your passphrase.
> Treat them as secrets — anyone with the file **and** passphrase can impersonate you.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| [cryptography](https://cryptography.io) | ≥ 41.0.0 | All cryptographic primitives |
| pytest | ≥ 7.4.0 | Test runner (optional) |

---

## License

MIT — see [LICENSE](LICENSE).
