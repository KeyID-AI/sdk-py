"""KeyID.ai SDK — agent email infrastructure."""

from .client import KeyID
from .crypto import generate_keypair, sign, verify

__all__ = ["KeyID", "generate_keypair", "sign", "verify"]
__version__ = "0.1.0"
