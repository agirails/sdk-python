"""
Keystore auto-resolution for ACTP wallets.

Resolution order (AIP-13):
  1. ACTP_PRIVATE_KEY env var (policy-gated: mainnet/unknown = hard fail)
  2. ACTP_KEYSTORE_BASE64 + ACTP_KEY_PASSWORD (deployment-safe, preferred)
  3. .actp/keystore.json decrypted with ACTP_KEY_PASSWORD
  4. None (caller decides what to do)

Security:
  - 30-minute TTL on cached private keys (prevents indefinite retention)
  - Thread-safe with threading.Lock
  - Path traversal and null byte rejection
  - Fail-closed ACTP_PRIVATE_KEY policy (mainnet/unknown = hard fail)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from eth_account import Account

logger = logging.getLogger("agirails.wallet.keystore")

# 30-minute TTL for cached private keys (in seconds)
CACHE_TTL_S = 30 * 60

# Regex for 0x-prefixed 64-char hex private key
_KEY_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


@dataclass
class _CacheEntry:
    """Cached private key with address and expiration."""

    key: str
    address: str
    expires_at: float  # time.time() epoch seconds


class ResolvePrivateKeyOptions:
    """Options for resolve_private_key().

    Attributes:
        network: Network mode -- 'mainnet', 'testnet', or 'mock'.
                 Controls ACTP_PRIVATE_KEY policy.
    """

    def __init__(self, network: Optional[str] = None) -> None:
        self.network = network


# --- Module-level caches (protected by lock) ---
_lock = threading.Lock()
_file_cache: Dict[str, _CacheEntry] = {}  # keyed by resolved keystore path
_env_cache: Optional[_CacheEntry] = None
_base64_cache: Optional[_CacheEntry] = None
# Track whether testnet warning has been emitted
_testnet_warned: bool = False


def _is_expired(entry: _CacheEntry) -> bool:
    return time.time() >= entry.expires_at


def _validate_state_directory(state_directory: str) -> None:
    """Validate that state_directory doesn't escape expected boundaries.

    Guards against path traversal when state_directory comes from user input.

    Raises:
        ValueError: If null bytes or '..' path traversal detected.
    """
    if "\0" in state_directory:
        raise ValueError("Invalid stateDirectory: null byte detected")
    if ".." in state_directory:
        raise ValueError("Invalid stateDirectory: path traversal detected (..)")


def _validate_raw_key(raw: str, source: str) -> str:
    """Validate and normalize a raw private key string.

    Trims whitespace and verifies 0x-prefixed 64-char hex format.

    Args:
        raw: The raw key string (possibly with whitespace).
        source: Human-readable source name for error messages.

    Returns:
        Trimmed, validated key string.

    Raises:
        ValueError: If key format is invalid.
    """
    trimmed = raw.strip()
    if not _KEY_PATTERN.match(trimmed):
        raise ValueError(
            f"Invalid private key from {source}: expected 0x-prefixed 64-char hex string"
        )
    return trimmed


def _get_effective_network(options: Optional[ResolvePrivateKeyOptions] = None) -> Optional[str]:
    """Determine the effective network for ACTP_PRIVATE_KEY policy.

    Falls back to ACTP_NETWORK env var. None means unknown (fail-closed).
    """
    if options and options.network:
        return options.network
    return os.environ.get("ACTP_NETWORK")


def _normalize_network_tier(network: Optional[str]) -> Optional[str]:
    """Map network names to policy tiers: 'mock', 'testnet', 'mainnet', or None.

    Handles both short names ('testnet') and chain names ('base-sepolia').
    """
    if network is None:
        return None
    n = network.lower()
    if n in ("mock",):
        return "mock"
    if n in ("testnet", "base-sepolia"):
        return "testnet"
    if n in ("mainnet", "base-mainnet", "base"):
        return "mainnet"
    return None  # unknown → fail-closed


def _enforce_private_key_policy(network: Optional[str]) -> None:
    """Enforce ACTP_PRIVATE_KEY policy based on network (AIP-13).

    - mainnet/unknown: hard fail
    - testnet: warn once (on first resolution, not cache hits)
    - mock: silent

    Raises:
        PermissionError: If ACTP_PRIVATE_KEY is used on mainnet or unknown network.
    """
    global _testnet_warned

    tier = _normalize_network_tier(network)

    if tier == "mock":
        return

    if tier == "testnet":
        if not _testnet_warned:
            logger.warning(
                "ACTP_PRIVATE_KEY is deprecated. Use ACTP_KEYSTORE_BASE64 instead.\n"
                "Run: actp deploy:env"
            )
            _testnet_warned = True
        return

    # mainnet or unknown (None) -- fail-closed
    network_label = "production" if tier == "mainnet" else "unknown network (fail-closed)"
    raise PermissionError(
        f"ACTP_PRIVATE_KEY is not allowed in {network_label}. "
        "Use ACTP_KEYSTORE_BASE64 instead.\n"
        "Run: actp deploy:env\n"
        "If this is testnet, set ACTP_NETWORK=testnet"
    )


async def resolve_private_key(
    state_directory: Optional[str] = None,
    options: Optional[ResolvePrivateKeyOptions] = None,
) -> Optional[str]:
    """Auto-resolve private key: env var -> base64 keystore -> file keystore -> None.

    Never logs or prints the key itself.

    Args:
        state_directory: Directory containing .actp/ (defaults to cwd).
        options: Options including network for ACTP_PRIVATE_KEY policy.

    Returns:
        Private key string (0x-prefixed hex) or None if no key source found.

    Raises:
        ValueError: If key format or keystore data is invalid.
        PermissionError: If ACTP_PRIVATE_KEY is used on mainnet/unknown network.
        RuntimeError: If password is missing or decryption fails.
    """
    global _env_cache, _base64_cache

    # --- 1. ACTP_PRIVATE_KEY (highest priority, policy-gated) ---
    actp_private_key = os.environ.get("ACTP_PRIVATE_KEY")
    if actp_private_key:
        network = _get_effective_network(options)
        _enforce_private_key_policy(network)

        with _lock:
            if _env_cache is not None and not _is_expired(_env_cache):
                return _env_cache.key

        key = _validate_raw_key(actp_private_key, "ACTP_PRIVATE_KEY env var")
        account = Account.from_key(key)
        entry = _CacheEntry(
            key=key,
            address=account.address,
            expires_at=time.time() + CACHE_TTL_S,
        )
        with _lock:
            _env_cache = entry
        return key

    # --- 2. ACTP_KEYSTORE_BASE64 (deployment-safe, preferred for production) ---
    actp_keystore_b64 = os.environ.get("ACTP_KEYSTORE_BASE64")
    if actp_keystore_b64:
        with _lock:
            if _base64_cache is not None and not _is_expired(_base64_cache):
                return _base64_cache.key

        # Strip whitespace from base64
        raw_b64 = re.sub(r"\s", "", actp_keystore_b64)
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
        except Exception:
            raise ValueError(
                "ACTP_KEYSTORE_BASE64 is not valid base64.\nRun: actp deploy:env"
            )

        try:
            json.loads(decoded)
        except json.JSONDecodeError:
            raise ValueError(
                "ACTP_KEYSTORE_BASE64 is not valid encrypted keystore JSON.\n"
                "Run: actp deploy:env"
            )

        password = os.environ.get("ACTP_KEY_PASSWORD")
        if not password:
            raise RuntimeError(
                "ACTP_KEYSTORE_BASE64 is set but ACTP_KEY_PASSWORD is not set.\n"
                'Set it: export ACTP_KEY_PASSWORD="your-password"'
            )

        try:
            private_key = Account.decrypt(decoded, password)
            account = Account.from_key(private_key)
        except Exception:
            # P-11 fix: sanitize error — some eth_account versions leak key material in exceptions
            raise RuntimeError(
                "Failed to decrypt ACTP_KEYSTORE_BASE64. Check password and keystore format."
            ) from None

        key_hex = account.key.hex() if isinstance(account.key, bytes) else str(account.key)
        if not key_hex.startswith("0x"):
            key_hex = "0x" + key_hex

        entry = _CacheEntry(
            key=key_hex,
            address=account.address,
            expires_at=time.time() + CACHE_TTL_S,
        )
        with _lock:
            _base64_cache = entry
        return entry.key

    # --- 3. Resolve keystore file path ---
    if state_directory is not None:
        _validate_state_directory(state_directory)

    actp_dir_env = os.environ.get("ACTP_DIR")
    if actp_dir_env:
        actp_dir = Path(actp_dir_env)
    elif state_directory is not None:
        actp_dir = Path(state_directory) / ".actp"
    else:
        actp_dir = Path.cwd() / ".actp"

    keystore_path = actp_dir.resolve() / "keystore.json"
    cache_key = str(keystore_path)

    # --- 4. Cache hit (keyed by resolved path, with TTL) ---
    with _lock:
        cached = _file_cache.get(cache_key)
        if cached is not None:
            if not _is_expired(cached):
                return cached.key
            del _file_cache[cache_key]

    # --- 5. Keystore file ---
    if not keystore_path.exists():
        return None

    password = os.environ.get("ACTP_KEY_PASSWORD")
    if not password:
        raise RuntimeError(
            f"Keystore found at {keystore_path} but ACTP_KEY_PASSWORD is not set.\n"
            'Set it: export ACTP_KEY_PASSWORD="your-password"'
        )

    keystore_data = keystore_path.read_text(encoding="utf-8")

    try:
        private_key = Account.decrypt(keystore_data, password)
        account = Account.from_key(private_key)
    except Exception:
        # P-11 fix: sanitize error — some eth_account versions leak key material in exceptions
        raise RuntimeError(
            f"Failed to decrypt keystore at {keystore_path}. Check password and keystore format."
        ) from None

    key_hex = account.key.hex() if isinstance(account.key, bytes) else str(account.key)
    if not key_hex.startswith("0x"):
        key_hex = "0x" + key_hex

    entry = _CacheEntry(
        key=key_hex,
        address=account.address,
        expires_at=time.time() + CACHE_TTL_S,
    )
    with _lock:
        _file_cache[cache_key] = entry
    return entry.key


def get_cached_address(state_directory: Optional[str] = None) -> Optional[str]:
    """Get cached address from last resolve_private_key() call.

    Works for env-var, base64, and keystore resolution paths.

    Args:
        state_directory: Directory containing .actp/ (defaults to cwd).

    Returns:
        Ethereum address string or None if no valid cache entry.
    """
    with _lock:
        # Env var path
        if _env_cache is not None and not _is_expired(_env_cache):
            return _env_cache.address

        # Base64 path
        if _base64_cache is not None and not _is_expired(_base64_cache):
            return _base64_cache.address

        # Keystore path -- look up by resolved path
        if state_directory is not None:
            actp_dir = Path(state_directory) / ".actp"
        else:
            actp_dir = Path.cwd() / ".actp"
        keystore_path = str((actp_dir / "keystore.json").resolve())
        cached = _file_cache.get(keystore_path)
        if cached is not None and not _is_expired(cached):
            return cached.address
        return None


def _clear_cache() -> None:
    """Clear all cached keys and addresses (for testing).

    .. warning::
        Internal API. Do not use in production code.
    """
    global _env_cache, _base64_cache, _testnet_warned
    with _lock:
        _file_cache.clear()
        _env_cache = None
        _base64_cache = None
        _testnet_warned = False
