#!/usr/bin/env python3
"""
main.py
=======
Interactive CLI for the Secure File Encryption & Digital Signature Tool.

Run:
    python main.py
"""

import sys
from pathlib import Path

# Ensure project root is importable when run as a script.
sys.path.insert(0, str(Path(__file__).parent))

from sfedst.key_manager          import (generate_rsa_keypair, save_private_key,
                                          save_public_key, load_private_key,
                                          load_public_key, get_fingerprint)
from sfedst.certificate_manager  import (generate_certificate, save_certificate,
                                          load_certificate, validate_certificate,
                                          print_cert_info)
from sfedst.signature_manager    import (sign_file, save_signature, load_signature,
                                          verify_file_with_cert, verify_bytes,
                                          simulate_tamper_attack,
                                          simulate_wrong_key_attack, sign_bytes)
from sfedst.encryption_manager   import encrypt_file, decrypt_file
from sfedst.utils                import (BANNER, MENU, section, pause, ask,
                                          ask_password, ask_password_confirm,
                                          require_file, success, failure)

KEYS_DIR  = Path("keys")
CERTS_DIR = Path("certs")
KEYS_DIR.mkdir(exist_ok=True)
CERTS_DIR.mkdir(exist_ok=True)


# ── Actions ──────────────────────────────────────────────────────────────────

def do_generate_keypair():
    section("Generate RSA Key Pair")
    name     = ask("Identity name (e.g. alice)")
    key_size = int(ask("Key size in bits (2048 / 4096)", "2048"))
    password = ask_password_confirm("Private key password")

    priv, pub = generate_rsa_keypair(key_size)
    save_private_key(priv, str(KEYS_DIR / f"{name}_private.pem"), password)
    save_public_key(pub,   str(KEYS_DIR / f"{name}_public.pem"))

    print(f"\n  Fingerprint (SHA-256):")
    print(f"  {get_fingerprint(pub)}")
    success("Key pair generated.")


def do_generate_certificate():
    section("Generate Self-Signed X.509 Certificate")
    name = ask("Identity name (must match an existing key pair, e.g. alice)")
    priv_path = KEYS_DIR / f"{name}_private.pem"
    if not require_file(str(priv_path), "Private key"):
        print("  Hint: run option 1 first.")
        return

    password = ask_password("Private key password")
    try:
        priv = load_private_key(str(priv_path), password)
    except ValueError as exc:
        failure(str(exc))
        return

    cn   = ask("Common Name (CN)", name)
    org  = ask("Organization (O)", "SFEDST")
    cc   = ask("Country (2-letter code)", "US")
    days = int(ask("Validity in days", "365"))

    cert = generate_certificate(priv, cn, organization=org,
                                 country=cc, valid_days=days)
    save_certificate(cert, str(CERTS_DIR / f"{name}_cert.pem"))
    print_cert_info(cert)
    success("Certificate created.")


def do_sign_file():
    section("Sign File")
    name     = ask("Signer identity (e.g. alice)")
    filepath = ask("Path to file to sign")
    password = ask_password("Private key password")

    priv_path = KEYS_DIR / f"{name}_private.pem"
    if not require_file(str(priv_path), "Private key"):
        return
    if not require_file(filepath, "File"):
        return

    try:
        priv = load_private_key(str(priv_path), password)
    except ValueError as exc:
        failure(str(exc)); return

    envelope = sign_file(priv, filepath)
    sig_path = filepath + ".sig"
    save_signature(envelope, sig_path)
    success(f"File signed.  Signature → {sig_path}")


def do_verify_signature():
    section("Verify File Signature")
    name     = ask("Signer identity (certificate owner, e.g. alice)")
    filepath = ask("Path to the (original) file")
    sig_path = ask("Path to signature file", filepath + ".sig")

    cert_path = CERTS_DIR / f"{name}_cert.pem"
    if not require_file(str(cert_path), "Certificate"):
        return
    if not require_file(filepath, "File"):
        return
    if not require_file(sig_path, "Signature file"):
        return

    cert = load_certificate(str(cert_path))
    try:
        verify_file_with_cert(cert, filepath, sig_path)
        success("Signature is VALID — file is authentic and unmodified.")
    except Exception as exc:
        failure(f"Verification FAILED:\n      {exc}")


def do_encrypt_file():
    section("Encrypt File")
    recipient = ask("Recipient identity (e.g. bob)")
    filepath  = ask("Path to file to encrypt")
    output    = ask("Output path", filepath + ".enc")

    pub_path = KEYS_DIR / f"{recipient}_public.pem"
    if not require_file(str(pub_path), "Recipient public key"):
        return
    if not require_file(filepath, "File"):
        return

    pub = load_public_key(str(pub_path))
    encrypt_file(pub, filepath, output)
    success(f"File encrypted → {output}")


def do_decrypt_file():
    section("Decrypt File")
    name      = ask("Recipient identity (private key owner, e.g. bob)")
    filepath  = ask("Path to encrypted file (.enc)")
    default_out = filepath[:-4] if filepath.endswith(".enc") else filepath + ".dec"
    output    = ask("Output path", default_out)
    password  = ask_password("Private key password")

    priv_path = KEYS_DIR / f"{name}_private.pem"
    if not require_file(str(priv_path), "Private key"):
        return
    if not require_file(filepath, "Encrypted file"):
        return

    try:
        priv = load_private_key(str(priv_path), password)
    except ValueError as exc:
        failure(str(exc)); return

    decrypt_file(priv, filepath, output)
    success(f"File decrypted → {output}")


def do_simulate_attack():
    section("Simulate Unauthorized Signature Attack")
    print("""
  This demo shows two attack scenarios that SFEDST blocks:

    A) Tamper attack  — attacker modifies the file after signing.
                        The hash mismatch is detected immediately.

    B) Impersonation  — attacker generates their own key pair and signs
                        the file, then tries to pass it as the real signer.
                        The RSA-PSS verification rejects the wrong key.
    """)

    name     = ask("Signer identity (e.g. alice)")
    filepath = ask("Path to file to use in the demo")
    password = ask_password("Private key password")

    priv_path = KEYS_DIR / f"{name}_private.pem"
    if not require_file(str(priv_path), "Private key"):
        return
    if not require_file(filepath, "File"):
        return

    try:
        priv = load_private_key(str(priv_path), password)
    except ValueError as exc:
        failure(str(exc)); return

    pub = priv.public_key()
    original_data = Path(filepath).read_bytes()

    # Sign the original
    envelope = sign_bytes(priv, original_data)

    # Scenario A
    tampered_data = original_data + b"\n[ATTACKER INJECTED LINE]\n"
    simulate_tamper_attack(pub, original_data, tampered_data, envelope)

    # Scenario B
    simulate_wrong_key_attack(pub, original_data, envelope)

    success("All attack simulations complete — every attack was BLOCKED.")


def do_list_assets():
    section("Keys & Certificates on Disk")
    keys  = sorted(KEYS_DIR.glob("*.pem"))
    certs = sorted(CERTS_DIR.glob("*.pem"))

    print(f"\n  Keys ({KEYS_DIR}/)")
    if keys:
        for k in keys:
            print(f"    {k.name:<40} {k.stat().st_size:>6} B")
    else:
        print("    (none — use option 1 to generate)")

    print(f"\n  Certificates ({CERTS_DIR}/)")
    if certs:
        for c in certs:
            size = c.stat().st_size
            try:
                cert = load_certificate(str(c))
                validate_certificate(cert)
                status = "valid"
            except Exception as exc:
                status = f"INVALID: {exc}"
            print(f"    {c.name:<40} {size:>6} B  [{status}]")
    else:
        print("    (none — use option 2 to generate)")


# ── Dispatch ─────────────────────────────────────────────────────────────────

_ACTIONS = {
    "1": do_generate_keypair,
    "2": do_generate_certificate,
    "3": do_sign_file,
    "4": do_verify_signature,
    "5": do_encrypt_file,
    "6": do_decrypt_file,
    "7": do_simulate_attack,
    "8": do_list_assets,
}


def main():
    print(BANNER)
    while True:
        print(MENU)
        choice = input("  Enter choice (1-9): ").strip()

        if choice == "9":
            print("\n  Goodbye — stay secure! 🔐\n")
            sys.exit(0)

        action = _ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n  [!] Cancelled.")
            except Exception as exc:
                failure(f"Unexpected error: {exc}")
        else:
            print("  [!] Invalid choice — enter 1 through 9.")

        pause()


if __name__ == "__main__":
    main()
