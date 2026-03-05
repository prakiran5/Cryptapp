"""
certificate_manager.py
======================
X.509 v3 self-signed certificate generation, storage, and validation.

Why certificates?
-----------------
Even without a commercial CA, X.509 certificates let us bind a public key
to a named identity in a tamper-evident way and use standard tooling for
trust decisions.  Certificate validation before signature verification is
the key defence against Man-in-the-Middle attacks in this tool.

Extensions included
-------------------
* BasicConstraints  ca=False   — mark as end-entity, not a CA
* KeyUsage          digitalSignature + keyEncipherment + contentCommitment
* ExtendedKeyUsage  codeSigning + emailProtection
* SubjectKeyIdentifier          — aids key lookup in chains
"""

import datetime
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_certificate(
    private_key,
    common_name: str,
    organization: str = "SFEDST",
    country: str = "US",
    valid_days: int = 365,
):
    """
    Create a self-signed X.509 v3 certificate for *private_key*.

    Parameters
    ----------
    private_key   : RSA private key (the cert will embed its public key)
    common_name   : CN field, e.g. ``"alice"`` or ``"server.example.com"``
    organization  : O field
    country       : C field (ISO 3166-1 alpha-2)
    valid_days    : How many days the cert remains valid

    Returns
    -------
    cryptography.x509.Certificate
    """
    pub = private_key.public_key()
    now = datetime.datetime.now(timezone.utc)

    # Subject == Issuer for a self-signed certificate.
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                         # self-signed
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        # ── Extensions ────────────────────────────────────────────
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,   # non-repudiation
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub), critical=False
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    print(f"  [+] Certificate generated: CN={common_name}, "
          f"valid {valid_days} days.")
    return cert


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_certificate(cert, path: str) -> None:
    """Write *cert* as a PEM file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [+] Certificate saved  → {path}")


def load_certificate(path: str):
    """Load a certificate from a PEM file."""
    cert = x509.load_pem_x509_certificate(
        Path(path).read_bytes(), default_backend()
    )
    print(f"  [+] Certificate loaded ← {path}")
    return cert


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_certificate(cert) -> bool:
    """
    Check temporal validity of *cert*.

    In a production PKI you would also verify the chain against a trust
    store and check CRL / OCSP status.  For this self-signed demo we
    confirm the certificate is within its validity window.

    Raises
    ------
    ValueError
        If the certificate is expired or not yet valid.
    """
    now = datetime.datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        raise ValueError(
            f"Certificate is not yet valid "
            f"(valid from {cert.not_valid_before_utc.isoformat()})."
        )
    if now > cert.not_valid_after_utc:
        raise ValueError(
            f"Certificate EXPIRED at {cert.not_valid_after_utc.isoformat()}."
        )

    cn = _cn(cert)
    print(f"  [+] Certificate VALID  — CN={cn}, "
          f"expires {cert.not_valid_after_utc.date().isoformat()}")
    return True


def get_public_key_from_cert(cert):
    """Extract and return the public key embedded in *cert*."""
    return cert.public_key()


def print_cert_info(cert) -> None:
    """Pretty-print certificate metadata."""
    print("\n  ╔══ Certificate Details ═══════════════════════════╗")
    print(f"  ║  Subject    : {_cn(cert)}")
    print(f"  ║  Serial     : {cert.serial_number}")
    print(f"  ║  Not Before : {cert.not_valid_before_utc.isoformat()}")
    print(f"  ║  Not After  : {cert.not_valid_after_utc.isoformat()}")
    print(f"  ║  Hash Algo  : {cert.signature_hash_algorithm.name.upper()}")
    print("  ╚══════════════════════════════════════════════════╝\n")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cn(cert) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "N/A"
