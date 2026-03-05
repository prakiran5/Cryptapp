"""
encryption_manager.py
=====================
Hybrid file encryption: AES-256-GCM (data) + RSA-OAEP (key wrap).

Why hybrid encryption?
-----------------------
RSA can only encrypt a small payload (≤ key_size − padding overhead).
AES-256-GCM encrypts arbitrary-length data with authenticated encryption
(AEAD), providing both **confidentiality** and **integrity** in one pass.

The hybrid scheme:
  1. Generate a fresh 256-bit AES session key and 96-bit GCM nonce.
  2. Encrypt the plaintext with AES-256-GCM → ciphertext + 16-byte auth tag.
  3. Encrypt the session key with the recipient's RSA public key (OAEP).
  4. Store all components together in a single .enc file.

Forward-secrecy note
--------------------
Each call generates a *new* random session key.  Compromise of the RSA
private key at time T does not retroactively expose session keys used
before T (provided the session keys themselves are not stored).  This
approximates forward secrecy for at-rest file encryption.

Encrypted-file binary layout
------------------------------
  [ 4 bytes big-endian uint32 ] — length of the RSA-wrapped key
  [ N bytes                   ] — RSA-OAEP encrypted AES session key
  [ 12 bytes                  ] — AES-GCM nonce
  [ remaining bytes           ] — AES-GCM ciphertext (includes 16-byte tag)
"""

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

_AES_KEY_LEN  = 32   # 256 bits
_GCM_NONCE_LEN = 12  # 96 bits — NIST SP 800-38D recommended length


# ---------------------------------------------------------------------------
# Core encrypt / decrypt (bytes → bytes)
# ---------------------------------------------------------------------------

def encrypt_bytes(public_key, plaintext: bytes) -> bytes:
    """
    Hybrid-encrypt *plaintext* for the holder of *public_key*.

    Returns the encrypted blob (see module header for layout).
    """
    # 1. Fresh session key + nonce
    session_key = os.urandom(_AES_KEY_LEN)
    nonce       = os.urandom(_GCM_NONCE_LEN)

    # 2. AES-256-GCM: appends 16-byte auth tag automatically
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, None)

    # 3. RSA-OAEP key wrap
    #    OAEP is semantically secure and immune to PKCS#1 v1.5 oracle attacks.
    wrapped_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Pack [key_len][wrapped_key][nonce][ciphertext+tag]
    return struct.pack(">I", len(wrapped_key)) + wrapped_key + nonce + ciphertext


def decrypt_bytes(private_key, blob: bytes) -> bytes:
    """
    Decrypt a blob produced by :func:`encrypt_bytes`.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If the ciphertext has been tampered with (GCM auth tag mismatch).
    """
    # Unpack
    key_len = struct.unpack(">I", blob[:4])[0]
    off = 4
    wrapped_key = blob[off: off + key_len]; off += key_len
    nonce       = blob[off: off + _GCM_NONCE_LEN]; off += _GCM_NONCE_LEN
    ciphertext  = blob[off:]

    # RSA-OAEP key unwrap
    session_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # AES-256-GCM decrypt + verify auth tag
    return AESGCM(session_key).decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# File convenience wrappers
# ---------------------------------------------------------------------------

def encrypt_file(public_key, src: str, dst: str = None) -> str:
    """
    Encrypt *src* and write the result to *dst* (default: *src* + ``.enc``).

    Returns the output path.
    """
    if dst is None:
        dst = src + ".enc"

    plaintext = Path(src).read_bytes()
    blob      = encrypt_bytes(public_key, plaintext)

    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_bytes(blob)

    print(f"  [+] Encrypted: {src} ({len(plaintext):,} B) "
          f"→ {dst} ({len(blob):,} B)")
    print(f"  [+] Cipher: AES-256-GCM  |  Key wrap: RSA-OAEP-SHA256")
    return dst


def decrypt_file(private_key, src: str, dst: str = None) -> str:
    """
    Decrypt *src* (an `.enc` file) and write the plaintext to *dst*.

    Default *dst* strips the `.enc` suffix, or appends `.dec` if no suffix.
    Returns the output path.
    """
    if dst is None:
        dst = src[:-4] if src.endswith(".enc") else src + ".dec"

    blob      = Path(src).read_bytes()
    plaintext = decrypt_bytes(private_key, blob)

    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_bytes(plaintext)

    print(f"  [+] Decrypted: {src} → {dst} ({len(plaintext):,} B)")
    return dst
