"""
key_manager.py
==============
RSA key pair generation and secure PEM-based storage.

Design decisions
----------------
* RSA-2048 minimum enforced (configurable up to 4096).
* Private keys are serialised as PKCS#8 and encrypted with
  BestAvailableEncryption, which selects AES-256-CBC + PBKDF2-HMAC-SHA256
  — the closest Python equivalent to a PKCS#12 keystore.
* File permissions are set to 0o600 (owner-read-only) on POSIX systems.
* Public-key fingerprints use SHA-256 over the DER encoding so users can
  visually confirm they are exchanging the correct key.
"""

import os
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate an RSA key pair.

    Parameters
    ----------
    key_size : int
        Modulus size in bits.  Must be >= 2048.

    Returns
    -------
    (private_key, public_key)
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits.")

    # public_exponent=65537 is Fermat F4 — the universally recommended value.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_private_key(private_key, path: str, password: str) -> None:
    """
    Serialize *private_key* to an AES-256-encrypted PKCS#8 PEM file.

    The passphrase is UTF-8 encoded before being handed to the KDF.
    File permissions are tightened to 0o600 on POSIX platforms.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    _write(path, pem, mode=0o600)
    print(f"  [+] Private key saved  → {path}")


def save_public_key(public_key, path: str) -> None:
    """Serialize *public_key* to an unencrypted SubjectPublicKeyInfo PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write(path, pem)
    print(f"  [+] Public key saved   → {path}")


def load_private_key(path: str, password: str):
    """
    Decrypt and load a private key from *path*.

    Raises
    ------
    ValueError
        If the password is wrong or the file is corrupt.
    """
    try:
        data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(
            data, password=password.encode("utf-8"), backend=default_backend()
        )
        print(f"  [+] Private key loaded ← {path}")
        return key
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Cannot load private key — bad password or corrupt file: {exc}") from exc


def load_public_key(path: str):
    """Load a public key from *path*."""
    key = serialization.load_pem_public_key(
        Path(path).read_bytes(), backend=default_backend()
    )
    print(f"  [+] Public key loaded  ← {path}")
    return key


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def get_fingerprint(public_key) -> str:
    """
    Return a colon-separated SHA-256 fingerprint of the DER-encoded public key.

    Similar to SSH key fingerprints — lets users visually confirm
    they hold the right key without comparing full PEM blobs.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(der)
    raw = digest.finalize()
    return ":".join(f"{b:02X}" for b in raw)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Create parent directories, write *data*, apply *mode*."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    try:
        os.chmod(path, mode)
    except AttributeError:
        pass  # Windows — skip chmod
