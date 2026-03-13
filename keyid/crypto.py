"""Ed25519 crypto utilities for KeyID agent identity."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair. Returns (public_key_hex, private_key_hex)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pub_hex = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()

    priv_hex = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()

    return pub_hex, priv_hex


def sign(message: str, private_key_hex: str) -> str:
    """Sign a message with an Ed25519 private key. Returns signature hex."""
    priv_bytes = bytes.fromhex(private_key_hex)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = key.sign(message.encode())
    return sig.hex()


def verify(message: str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        key.verify(bytes.fromhex(signature_hex), message.encode())
        return True
    except Exception:
        return False
