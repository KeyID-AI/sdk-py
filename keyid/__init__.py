"""KeyID.ai SDK — agent email infrastructure."""

from .client import KeyID, __version__
from .crypto import generate_keypair, sign, verify

__all__ = ["KeyID", "generate_keypair", "sign", "verify", "__version__"]
