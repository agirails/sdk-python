"""
SecureNonce - Cryptographically secure nonce generation.

SECURITY FIX: Provides secure random nonce generation
to prevent weak randomness vulnerabilities in EIP-712 message signing.

PARITY: Matches TypeScript SDK's utils/SecureNonce.ts

Example:
    >>> from agirails.utils.secure_nonce import generate_secure_nonce
    >>> nonce = generate_secure_nonce()
    >>> print(nonce)  # 0x1234...abcd (64 hex chars)
"""

from __future__ import annotations

import os
import re
from typing import List


def generate_secure_nonce() -> str:
    """
    Generate a cryptographically secure random nonce (bytes32).

    Uses os.urandom() which:
    - Uses /dev/urandom on Unix (CSPRNG)
    - Uses CryptGenRandom on Windows (CSPRNG)
    - Guaranteed to be cryptographically secure

    Returns:
        32-byte hex string (0x + 64 hex chars)

    Example:
        >>> nonce = generate_secure_nonce()
        >>> len(nonce)
        66
        >>> nonce.startswith("0x")
        True
    """
    random_bytes = os.urandom(32)
    return "0x" + random_bytes.hex()


def is_valid_nonce(nonce: str) -> bool:
    """
    Validate nonce format (must be bytes32).

    Args:
        nonce: Nonce to validate

    Returns:
        True if valid bytes32 format (0x + 64 hex chars)

    Example:
        >>> is_valid_nonce("0x" + "00" * 32)
        True
        >>> is_valid_nonce("0x1234")
        False
        >>> is_valid_nonce("not-hex")
        False
    """
    return bool(re.match(r"^0x[a-fA-F0-9]{64}$", nonce))


def generate_secure_nonces(count: int) -> List[str]:
    """
    Generate an array of secure nonces.

    Args:
        count: Number of nonces to generate

    Returns:
        List of bytes32 hex strings

    Raises:
        ValueError: If count is not positive or exceeds maximum

    Example:
        >>> nonces = generate_secure_nonces(10)
        >>> len(nonces)
        10
    """
    if count <= 0:
        raise ValueError("Count must be positive")
    if count > 10000:
        raise ValueError("Count exceeds maximum allowed (10000)")

    return [generate_secure_nonce() for _ in range(count)]


__all__ = [
    "generate_secure_nonce",
    "is_valid_nonce",
    "generate_secure_nonces",
]
