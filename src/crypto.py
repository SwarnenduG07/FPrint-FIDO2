"""Cryptographic operations for FIDO2 credentials."""

import os
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, generate_private_key, ECDSA, EllipticCurvePrivateKey
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a P-256 keypair.

    Returns:
        (private_key_der, public_key_der)
    """
    key = generate_private_key(SECP256R1())
    priv = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def sign(private_key_der: bytes, data: bytes) -> bytes:
    """
    Sign data with a P-256 private key using ECDSA/SHA-256.

    Returns:
        DER-encoded signature
    """
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    key = load_der_private_key(private_key_der, password=None)
    return key.sign(data, ECDSA(SHA256()))


def public_key_to_cose(public_key_der: bytes) -> bytes:
    """
    Convert a DER SubjectPublicKeyInfo P-256 key to COSE_Key CBOR format.

    COSE map: {1: 2, 3: -7, -1: 1, -2: x(32), -3: y(32)}
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    key = load_der_public_key(public_key_der)
    pub_numbers = key.public_key().public_numbers() if hasattr(key, 'public_key') else key.public_numbers()
    x = pub_numbers.x.to_bytes(32, "big")
    y = pub_numbers.y.to_bytes(32, "big")

    # CBOR encoding of COSE_Key for ES256
    cbor = bytes([
        0xA5,        # map(5)
        0x01, 0x02,  # kty: EC2
        0x03, 0x26,  # alg: ES256 (-7)
        0x20, 0x01,  # crv: P-256 (key -1 = 0x20)
        0x21, 0x58, 0x20,  # x (key -2 = 0x21), bytes(32)
    ]) + x + bytes([
        0x22, 0x58, 0x20,  # y (key -3 = 0x22), bytes(32)
    ]) + y

    return cbor


def new_credential_id() -> bytes:
    """Generate a random 16-byte credential ID."""
    return os.urandom(16)
