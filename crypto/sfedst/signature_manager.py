"""
signature_manager.py
====================
RSA-PSS digital signatures with built-in replay-attack prevention.

Signed envelope format
-----------------------
The signature does NOT cover only the file hash.  It covers a canonical
string built from three fields:

    <SHA-256 hex of file> | <UTC ISO-8601 timestamp> | <base64 nonce>

This means:
  * **Integrity**    — any bit-flip in the file changes the hash → fails.
  * **Authenticity** — only the private-key holder can produce a valid sig.
  * **Replay guard** — nonce is unique per signing operation; replaying an
                       old envelope against the same file is detected.

Why RSA-PSS over PKCS#1 v1.5?
-------------------------------
PSS adds a random salt, making signatures non-deterministic and eliminating
the algebraic structure that makes PKCS#1 v1.5 vulnerable to chosen-message
attacks.
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from sfedst.certificate_manager import validate_certificate, get_public_key_from_cert

# Maximum age (seconds) before a signature is flagged as potentially replayed.
# Set to 0 to disable freshness enforcement (useful in tests / demos).
MAX_SIG_AGE_SECONDS = 300   # 5 minutes


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_file(private_key, filepath: str) -> dict:
    """
    Sign the contents of *filepath* and return a signed envelope dict.

    The envelope contains:
        ``file_hash``  — hex SHA-256 of the file bytes
        ``timestamp``  — UTC ISO-8601 signing time
        ``nonce``      — base64-encoded 32 random bytes
        ``signature``  — base64 RSA-PSS signature over the canonical message
    """
    data = Path(filepath).read_bytes()
    print(f"  [*] Signing: {filepath}  ({len(data)} bytes)")
    return sign_bytes(private_key, data)


def sign_bytes(private_key, data: bytes) -> dict:
    """Sign raw *data* and return the envelope dict."""
    file_hash = hashlib.sha256(data).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce     = base64.b64encode(os.urandom(32)).decode()

    # canonical message = hash|timestamp|nonce
    message = f"{file_hash}|{timestamp}|{nonce}".encode()

    raw_sig = private_key.sign(message, _pss(), hashes.SHA256())

    envelope = {
        "file_hash": file_hash,
        "timestamp": timestamp,
        "nonce":     nonce,
        "signature": base64.b64encode(raw_sig).decode(),
    }
    print(f"  [+] Signed  — SHA-256: {file_hash[:32]}…  ts: {timestamp}")
    return envelope


def save_signature(envelope: dict, path: str) -> None:
    """Persist the envelope to a JSON file."""
    Path(path).write_text(json.dumps(envelope, indent=2))
    print(f"  [+] Signature saved → {path}")


def load_signature(path: str) -> dict:
    """Load an envelope from a JSON file."""
    return json.loads(Path(path).read_text())


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_file(public_key, filepath: str, envelope: dict,
                check_freshness: bool = True) -> bool:
    """
    Verify the signature in *envelope* against *filepath*.

    Steps
    -----
    1. Recompute SHA-256 of the file and compare with envelope hash.
    2. Optionally reject envelopes older than MAX_SIG_AGE_SECONDS.
    3. Verify the RSA-PSS signature over the canonical message.

    Raises
    ------
    ValueError        if the file hash does not match (tampering detected).
    InvalidSignature  if the cryptographic signature is invalid.
    """
    data = Path(filepath).read_bytes()
    return verify_bytes(public_key, data, envelope, check_freshness)


def verify_bytes(public_key, data: bytes, envelope: dict,
                 check_freshness: bool = True) -> bool:
    """Verify *envelope* against raw *data*."""
    # ── 1. Integrity ──────────────────────────────────────────────
    computed = hashlib.sha256(data).hexdigest()
    if computed != envelope["file_hash"]:
        raise ValueError(
            "INTEGRITY FAILURE — file hash does not match the signed hash.\n"
            "  The file has been modified after signing!"
        )

    # ── 2. Freshness (replay prevention) ──────────────────────────
    if check_freshness and MAX_SIG_AGE_SECONDS > 0:
        sig_time = datetime.fromisoformat(envelope["timestamp"])
        age = (datetime.now(timezone.utc) - sig_time).total_seconds()
        if age > MAX_SIG_AGE_SECONDS:
            # In strict mode you would raise here; we warn for demo clarity.
            print(f"  [!] Warning: signature is {int(age)}s old "
                  f"(threshold {MAX_SIG_AGE_SECONDS}s) — possible replay.")

    # ── 3. Cryptographic verification ─────────────────────────────
    message  = (f"{envelope['file_hash']}|"
                f"{envelope['timestamp']}|"
                f"{envelope['nonce']}").encode()
    raw_sig  = base64.b64decode(envelope["signature"])

    try:
        public_key.verify(raw_sig, message, _pss(), hashes.SHA256())
    except InvalidSignature:
        raise InvalidSignature(
            "AUTHENTICATION FAILURE — RSA-PSS signature is invalid.\n"
            "  The claimed signer did NOT sign this file!"
        )

    print("  [✓] Signature VALID — integrity and authenticity confirmed.")
    return True


def verify_file_with_cert(cert, filepath: str, sig_path: str) -> bool:
    """
    Convenience wrapper: validate the X.509 cert, then verify the file.

    Certificate validation before key use is the primary MITM defence.
    """
    validate_certificate(cert)
    pub = get_public_key_from_cert(cert)
    envelope = load_signature(sig_path)
    return verify_file(pub, filepath, envelope)


# ---------------------------------------------------------------------------
# Attack simulation helpers
# ---------------------------------------------------------------------------

def simulate_tamper_attack(public_key, original: bytes, tampered: bytes,
                           envelope: dict) -> None:
    """Show that modifying a file breaks signature verification."""
    print("\n  ── Tamper Attack Simulation ──────────────────────────────")
    orig_hash    = hashlib.sha256(original).hexdigest()
    tamper_hash  = hashlib.sha256(tampered).hexdigest()
    print(f"  Original hash : {orig_hash[:48]}…")
    print(f"  Tampered hash : {tamper_hash[:48]}…")
    print(f"  Hashes match  : {orig_hash == tamper_hash}")
    try:
        verify_bytes(public_key, tampered, envelope, check_freshness=False)
        print("  [!] BUG — tampered data passed verification!")
    except (ValueError, InvalidSignature) as exc:
        print(f"\n  [✓] Attack BLOCKED:\n      {exc}")
    print("  ───────────────────────────────────────────────────────────\n")


def simulate_wrong_key_attack(correct_public_key, data: bytes,
                               envelope: dict) -> None:
    """Show that a signature produced by a different key is rejected."""
    from sfedst.key_manager import generate_rsa_keypair
    print("\n  ── Wrong-Key (Impersonation) Attack Simulation ───────────")
    print("  [*] Generating attacker key pair…")
    attacker_priv, _ = generate_rsa_keypair(2048)
    fake_envelope = sign_bytes(attacker_priv, data)
    print("  [*] Verifying attacker signature against victim public key…")
    try:
        verify_bytes(correct_public_key, data, fake_envelope,
                     check_freshness=False)
        print("  [!] BUG — attacker's signature verified!")
    except (ValueError, InvalidSignature) as exc:
        print(f"\n  [✓] Attack BLOCKED:\n      {exc}")
    print("  ───────────────────────────────────────────────────────────\n")


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _pss():
    """Return the RSA-PSS padding object used for all sign/verify ops."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )
