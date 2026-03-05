"""
tests/test_sfedst.py
====================
Unit and integration tests for the SFEDST toolkit.

Run:
    python -m unittest discover tests -v
    # or
    python -m pytest tests/ -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.exceptions import InvalidSignature

# ── modules under test ────────────────────────────────────────────────────────
from sfedst.key_manager import (
    generate_rsa_keypair, save_private_key, save_public_key,
    load_private_key, load_public_key, get_fingerprint,
)
from sfedst.certificate_manager import (
    generate_certificate, save_certificate, load_certificate,
    validate_certificate, get_public_key_from_cert,
)
from sfedst.signature_manager import (
    sign_bytes, verify_bytes, save_signature, load_signature,
)
from sfedst.encryption_manager import (
    encrypt_bytes, decrypt_bytes, encrypt_file, decrypt_file,
)


# =============================================================================
#  Key Manager
# =============================================================================

class TestKeyManager(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.tmp = tempfile.mkdtemp()

    # ── Generation ────────────────────────────────────────────────

    def test_generate_returns_keypair(self):
        priv, pub = generate_rsa_keypair(2048)
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_minimum_key_size_enforced(self):
        with self.assertRaises(ValueError):
            generate_rsa_keypair(1024)

    def test_pub_matches_priv(self):
        from cryptography.hazmat.primitives import serialization
        der_from_priv = self.priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        der_pub = self.pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(der_from_priv, der_pub)

    # ── Save / load ───────────────────────────────────────────────

    def test_private_key_roundtrip(self):
        path = os.path.join(self.tmp, "priv.pem")
        save_private_key(self.priv, path, "secret")
        loaded = load_private_key(path, "secret")
        self.assertEqual(self.priv.key_size, loaded.key_size)

    def test_wrong_password_raises(self):
        path = os.path.join(self.tmp, "priv.pem")
        save_private_key(self.priv, path, "correct")
        with self.assertRaises(ValueError):
            load_private_key(path, "wrong")

    def test_public_key_roundtrip(self):
        from cryptography.hazmat.primitives import serialization
        path = os.path.join(self.tmp, "pub.pem")
        save_public_key(self.pub, path)
        loaded = load_public_key(path)
        self.assertEqual(
            self.pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            loaded.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

    # ── Fingerprint ───────────────────────────────────────────────

    def test_fingerprint_deterministic(self):
        self.assertEqual(get_fingerprint(self.pub), get_fingerprint(self.pub))

    def test_different_keys_different_fingerprints(self):
        _, pub2 = generate_rsa_keypair(2048)
        self.assertNotEqual(get_fingerprint(self.pub), get_fingerprint(pub2))


# =============================================================================
#  Certificate Manager
# =============================================================================

class TestCertificateManager(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.tmp = tempfile.mkdtemp()

    def test_generate_cert(self):
        cert = generate_certificate(self.priv, "TestUser")
        self.assertIsNotNone(cert)

    def test_cert_cn(self):
        from cryptography.x509.oid import NameOID
        cert = generate_certificate(self.priv, "Alice")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "Alice")

    def test_cert_validity(self):
        cert = generate_certificate(self.priv, "Bob")
        self.assertTrue(validate_certificate(cert))

    def test_cert_roundtrip(self):
        cert = generate_certificate(self.priv, "Charlie")
        path = os.path.join(self.tmp, "cert.pem")
        save_certificate(cert, path)
        loaded = load_certificate(path)
        self.assertEqual(cert.serial_number, loaded.serial_number)

    def test_public_key_from_cert(self):
        from cryptography.hazmat.primitives import serialization
        cert    = generate_certificate(self.priv, "Dave")
        pub_out = get_public_key_from_cert(cert)
        self.assertEqual(
            self.pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            pub_out.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )


# =============================================================================
#  Signature Manager
# =============================================================================

class TestSignatureManager(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.tmp  = tempfile.mkdtemp()
        self.data = b"The quick brown fox jumps over the lazy dog."

    def test_sign_and_verify(self):
        env = sign_bytes(self.priv, self.data)
        self.assertTrue(verify_bytes(self.pub, self.data, env,
                                     check_freshness=False))

    def test_tampered_data_fails(self):
        """Any modification to the data must break verification."""
        env = sign_bytes(self.priv, self.data)
        with self.assertRaises(ValueError):
            verify_bytes(self.pub, self.data + b"X", env,
                         check_freshness=False)

    def test_wrong_key_fails(self):
        """A signature produced by a different key must be rejected."""
        attacker_priv, _ = generate_rsa_keypair(2048)
        env = sign_bytes(attacker_priv, self.data)
        with self.assertRaises((ValueError, InvalidSignature)):
            verify_bytes(self.pub, self.data, env, check_freshness=False)

    def test_envelope_fields_present(self):
        env = sign_bytes(self.priv, self.data)
        for field in ("file_hash", "timestamp", "nonce", "signature"):
            self.assertIn(field, env)

    def test_nonce_unique_per_signature(self):
        """Two signatures over identical data must carry different nonces."""
        e1 = sign_bytes(self.priv, self.data)
        e2 = sign_bytes(self.priv, self.data)
        self.assertNotEqual(e1["nonce"], e2["nonce"])

    def test_envelope_json_roundtrip(self):
        env  = sign_bytes(self.priv, self.data)
        path = os.path.join(self.tmp, "test.sig")
        save_signature(env, path)
        env2 = load_signature(path)
        self.assertEqual(env["file_hash"], env2["file_hash"])
        self.assertEqual(env["signature"], env2["signature"])

    def test_modified_envelope_fails(self):
        """Swapping the nonce in the envelope should break verification."""
        import base64, os as _os
        env = sign_bytes(self.priv, self.data)
        env["nonce"] = base64.b64encode(_os.urandom(32)).decode()
        with self.assertRaises((ValueError, InvalidSignature)):
            verify_bytes(self.pub, self.data, env, check_freshness=False)


# =============================================================================
#  Encryption Manager
# =============================================================================

class TestEncryptionManager(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.tmp = tempfile.mkdtemp()

    def test_encrypt_decrypt_roundtrip(self):
        pt = b"Top-secret payload \xde\xad\xbe\xef"
        ct = encrypt_bytes(self.pub, pt)
        self.assertEqual(pt, decrypt_bytes(self.priv, ct))

    def test_ciphertext_differs_from_plaintext(self):
        pt = b"Sensitive data"
        self.assertNotEqual(pt, encrypt_bytes(self.pub, pt))

    def test_two_encryptions_differ(self):
        """Random session key + nonce → different ciphertext each time."""
        pt = b"Same plaintext"
        self.assertNotEqual(
            encrypt_bytes(self.pub, pt),
            encrypt_bytes(self.pub, pt),
        )

    def test_wrong_key_cannot_decrypt(self):
        other_priv, _ = generate_rsa_keypair(2048)
        ct = encrypt_bytes(self.pub, b"Secret")
        with self.assertRaises(Exception):
            decrypt_bytes(other_priv, ct)

    def test_tampered_ciphertext_fails(self):
        """AES-GCM auth tag must reject any ciphertext modification."""
        ct = bytearray(encrypt_bytes(self.pub, b"Important"))
        ct[-1] ^= 0xFF      # flip last byte (inside the GCM tag)
        with self.assertRaises(Exception):
            decrypt_bytes(self.priv, bytes(ct))

    def test_file_encrypt_decrypt(self):
        src = os.path.join(self.tmp, "plain.txt")
        enc = os.path.join(self.tmp, "plain.txt.enc")
        dec = os.path.join(self.tmp, "plain_dec.txt")
        content = b"File content goes here.\nSecond line.\n"
        Path(src).write_bytes(content)
        encrypt_file(self.pub, src, enc)
        decrypt_file(self.priv, enc, dec)
        self.assertEqual(content, Path(dec).read_bytes())

    def test_large_file(self):
        src = os.path.join(self.tmp, "big.bin")
        enc = os.path.join(self.tmp, "big.bin.enc")
        dec = os.path.join(self.tmp, "big_dec.bin")
        data = os.urandom(1024 * 1024)   # 1 MiB
        Path(src).write_bytes(data)
        encrypt_file(self.pub, src, enc)
        decrypt_file(self.priv, enc, dec)
        self.assertEqual(data, Path(dec).read_bytes())


# =============================================================================
#  Integration
# =============================================================================

class TestIntegration(unittest.TestCase):
    """End-to-end workflows combining all four modules."""

    def setUp(self):
        self.alice_priv, self.alice_pub = generate_rsa_keypair(2048)
        self.bob_priv,   self.bob_pub   = generate_rsa_keypair(2048)
        self.tmp = tempfile.mkdtemp()

    def test_alice_signs_bob_verifies(self):
        doc = b"Approved - Alice"
        env = sign_bytes(self.alice_priv, doc)
        # Bob uses Alice's certificate to verify
        cert = generate_certificate(self.alice_priv, "Alice")
        validate_certificate(cert)
        pub  = get_public_key_from_cert(cert)
        self.assertTrue(verify_bytes(pub, doc, env, check_freshness=False))

    def test_bob_encrypts_alice_decrypts(self):
        msg = b"Hello Alice - from Bob"
        ct  = encrypt_bytes(self.alice_pub, msg)
        self.assertEqual(msg, decrypt_bytes(self.alice_priv, ct))

    def test_full_sign_encrypt_decrypt_verify(self):
        document = b"Classified document - version 1"
        # Alice signs
        env = sign_bytes(self.alice_priv, document)
        # Pack document + signature into a single JSON payload
        payload = json.dumps({
            "doc": document.decode(),
            "sig": env,
        }).encode()
        # Alice encrypts for Bob
        ct = encrypt_bytes(self.bob_pub, payload)
        # Bob decrypts
        recovered = json.loads(decrypt_bytes(self.bob_priv, ct).decode())
        doc_bytes = recovered["doc"].encode()
        # Bob verifies Alice's signature
        self.assertTrue(
            verify_bytes(self.alice_pub, doc_bytes,
                         recovered["sig"], check_freshness=False)
        )

    def test_attack_tamper_detected(self):
        doc     = b"Original text"
        env     = sign_bytes(self.alice_priv, doc)
        tampered = doc + b" [modified]"
        with self.assertRaises(ValueError):
            verify_bytes(self.alice_pub, tampered, env, check_freshness=False)

    def test_attack_impersonation_detected(self):
        doc  = b"Legit document"
        eve_priv, _ = generate_rsa_keypair(2048)
        fake_env = sign_bytes(eve_priv, doc)      # Eve signs
        with self.assertRaises((ValueError, InvalidSignature)):
            verify_bytes(self.alice_pub, doc, fake_env, check_freshness=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
