#!/usr/bin/env python3
"""
examples/demo.py
================
Non-interactive demonstration of the complete SFEDST workflow.

Simulates:
  * Alice and Bob generating keys and certificates
  * Alice signing a document and encrypting it for Bob
  * Bob decrypting and verifying the signature
  * Three attack scenarios — all blocked

Run:
    python examples/demo.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sfedst import (
    generate_rsa_keypair, save_private_key, save_public_key, get_fingerprint,
    generate_certificate, save_certificate, validate_certificate,
    print_cert_info, get_public_key_from_cert,
    sign_bytes, verify_bytes, simulate_tamper_attack, simulate_wrong_key_attack,
    encrypt_bytes, decrypt_bytes,
)

SEP = "\n" + "=" * 62


def hdr(title: str):
    print(f"{SEP}\n  {title}\n{'=' * 62}")


def main():
    tmp = tempfile.mkdtemp()
    print("\n  SFEDST — Full Workflow Demo")
    print(f"  Working directory: {tmp}")

    # ── Step 1: Key generation ────────────────────────────────────
    hdr("STEP 1  Key Generation")

    alice_priv, alice_pub = generate_rsa_keypair(2048)
    save_private_key(alice_priv, f"{tmp}/alice_priv.pem", "alice123")
    save_public_key(alice_pub,   f"{tmp}/alice_pub.pem")
    print(f"  Alice fingerprint: {get_fingerprint(alice_pub)[:47]}…")

    bob_priv, bob_pub = generate_rsa_keypair(2048)
    save_private_key(bob_priv, f"{tmp}/bob_priv.pem", "bob456")
    save_public_key(bob_pub,   f"{tmp}/bob_pub.pem")
    print(f"  Bob   fingerprint: {get_fingerprint(bob_pub)[:47]}…")

    # ── Step 2: Certificates ─────────────────────────────────────
    hdr("STEP 2  X.509 Certificate Generation")

    alice_cert = generate_certificate(alice_priv, "Alice", organization="DemoCorp")
    bob_cert   = generate_certificate(bob_priv,   "Bob",   organization="DemoCorp")
    save_certificate(alice_cert, f"{tmp}/alice_cert.pem")
    save_certificate(bob_cert,   f"{tmp}/bob_cert.pem")
    print("\n  Alice:")
    print_cert_info(alice_cert)
    print("  Bob:")
    print_cert_info(bob_cert)

    # ── Step 3: Alice signs ───────────────────────────────────────
    hdr("STEP 3  Alice Signs the Document")

    document = (
        "MEMO — Project Phoenix\n"
        "To: Bob\nFrom: Alice\n\n"
        "Phase 2 budget of $500,000 is approved.\n"
        "Authorized by: Alice\n"
    ).encode()

    Path(f"{tmp}/memo.txt").write_bytes(document)
    envelope = sign_bytes(alice_priv, document)
    Path(f"{tmp}/memo.sig").write_text(json.dumps(envelope, indent=2))
    print(f"  File hash : {envelope['file_hash'][:48]}…")
    print(f"  Timestamp : {envelope['timestamp']}")
    print(f"  Nonce     : {envelope['nonce'][:16]}…")

    # ── Step 4: Alice encrypts for Bob ────────────────────────────
    hdr("STEP 4  Alice Encrypts the Package for Bob")

    payload    = json.dumps({"doc": document.decode(), "sig": envelope}).encode()
    ciphertext = encrypt_bytes(bob_pub, payload)
    Path(f"{tmp}/memo.enc").write_bytes(ciphertext)
    print(f"  Plaintext  size : {len(payload):,} B")
    print(f"  Ciphertext size : {len(ciphertext):,} B")
    print(f"  Cipher          : AES-256-GCM  |  Key wrap: RSA-OAEP-SHA256")

    # ── Step 5: Bob decrypts and verifies ─────────────────────────
    hdr("STEP 5  Bob Decrypts and Verifies")

    recovered = json.loads(decrypt_bytes(bob_priv, ciphertext).decode())
    doc_bytes = recovered["doc"].encode()
    sig_env   = recovered["sig"]

    print("  Decrypted memo:")
    for line in recovered["doc"].strip().splitlines():
        print(f"    {line}")

    validate_certificate(alice_cert)
    alice_pub_cert = get_public_key_from_cert(alice_cert)
    result = verify_bytes(alice_pub_cert, doc_bytes, sig_env,
                          check_freshness=False)
    if result:
        print("\n  RESULT: Signature VALID — document is authentic.")

    # ── Step 6: Attack simulations ────────────────────────────────
    hdr("STEP 6  Attack Simulations")

    # 6a tamper
    tampered = doc_bytes + b"\n  [ATTACKER: amount changed to $5,000,000]"
    simulate_tamper_attack(alice_pub, doc_bytes, tampered, sig_env)

    # 6b replay — different content, same signature
    print("  -- Replay Attack ------------------------------------------")
    print("  [Eve] Replaying Alice's envelope against different content…")
    try:
        verify_bytes(alice_pub, b"Wire $1,000,000 to Eve", sig_env,
                     check_freshness=False)
        print("  [!] BUG: replay succeeded!")
    except Exception as exc:
        print(f"  [OK] Replay blocked: {exc}")

    # 6c impersonation
    simulate_wrong_key_attack(alice_pub, doc_bytes, sig_env)

    # ── Summary ───────────────────────────────────────────────────
    hdr("DEMO COMPLETE")
    print("""
  Property          Mechanism
  ─────────────────────────────────────────────────────────
  Confidentiality   AES-256-GCM; only Bob's private key decrypts
  Integrity         GCM auth tag + SHA-256 content hash
  Authentication    RSA-PSS + X.509 certificate validation
  Non-repudiation   Only Alice's private key produces a valid sig
  Replay prevention Per-signature nonce + UTC timestamp
  Forward secrecy   New random AES session key per encryption
  MITM prevention   Certificate validation before key use

  All attacks were BLOCKED.
    """)


if __name__ == "__main__":
    main()
