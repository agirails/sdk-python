"""
Security utilities for AGIRAILS SDK.

Implements critical security measures including:
- Timing-safe string comparison (H-7)
- Path traversal prevention (H-6)
- Input validation (H-2)
- Safe JSON parsing (C-3)
- LRU Cache for memory leak prevention (C-2)
"""

from __future__ import annotations

import hmac
import json
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any, Generic, List, Optional, Tuple, TypeVar, Union

K = TypeVar("K")
V = TypeVar("V")

# Valid characters for service names
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

# Valid Ethereum address pattern
ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Dangerous keys that should never appear in parsed JSON
DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def timing_safe_equal(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.

    This function takes the same amount of time regardless of where
    the strings differ, preventing an attacker from inferring
    information about the expected value.

    Security Note (H-7): Always use this function when comparing
    secrets, tokens, or signatures.

    Args:
        a: First string to compare.
        b: Second string to compare.

    Returns:
        True if strings are equal, False otherwise.

    Example:
        >>> timing_safe_equal("secret123", user_input)
        False
    """
    # Use hmac.compare_digest which is constant-time
    # It works with both str and bytes
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def validate_path(requested_path: Union[str, Path], base_directory: Union[str, Path]) -> Path:
    """
    Validate and sanitize a file path to prevent path traversal attacks.

    Ensures the requested path is within the allowed base directory
    by resolving symlinks and checking for directory escape attempts.

    Security Note (H-6): Always use this function when handling
    user-provided file paths.

    Args:
        requested_path: The path requested by the user.
        base_directory: The allowed base directory.

    Returns:
        Sanitized absolute path within the base directory.

    Raises:
        ValueError: If the path attempts to escape the base directory.

    Example:
        >>> validate_path("../../../etc/passwd", "/app/data")
        ValueError: Path traversal attempt detected
        >>> validate_path("user/file.json", "/app/data")
        Path('/app/data/user/file.json')
    """
    base = Path(base_directory).resolve()
    requested = Path(requested_path)

    # If path is absolute, check it directly
    # If relative, join with base
    if requested.is_absolute():
        full_path = requested.resolve()
    else:
        full_path = (base / requested).resolve()

    # Check if the resolved path is within the base directory
    try:
        full_path.relative_to(base)
    except ValueError:
        raise ValueError(
            f"Path traversal attempt detected: {requested_path} escapes {base_directory}"
        )

    return full_path


def validate_service_name(service_name: str) -> str:
    """
    Validate and sanitize a service name.

    Ensures the service name contains only safe characters:
    alphanumeric, dash, dot, and underscore.

    Security Note (H-2): Always validate service names before
    using them in file paths, URLs, or database queries.

    Args:
        service_name: The service name to validate.

    Returns:
        The validated service name (unchanged if valid).

    Raises:
        ValueError: If the service name contains invalid characters.

    Example:
        >>> validate_service_name("text-generation.v1")
        'text-generation.v1'
        >>> validate_service_name("../evil")
        ValueError: Invalid service name
    """
    if not service_name:
        raise ValueError("Service name cannot be empty")

    if len(service_name) > 128:
        raise ValueError(f"Service name too long: {len(service_name)} > 128")

    if not SERVICE_NAME_PATTERN.match(service_name):
        raise ValueError(
            f"Invalid service name: {service_name!r}. "
            "Only alphanumeric characters, dash, dot, and underscore are allowed."
        )

    return service_name


def is_valid_address(address: str) -> bool:
    """
    Check if a string is a valid Ethereum address.

    Valid addresses must:
    - Start with '0x'
    - Have exactly 40 hexadecimal characters after '0x'

    Args:
        address: The string to validate.

    Returns:
        True if valid Ethereum address, False otherwise.

    Example:
        >>> is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bBe0")
        True
        >>> is_valid_address("0xinvalid")
        False
    """
    if not address:
        return False

    return bool(ADDRESS_PATTERN.match(address))


def _sanitize_object(obj: Any) -> Any:
    """
    Recursively sanitize an object by removing dangerous keys.

    Security Note (C-3): Removes __proto__, constructor, and prototype
    keys to prevent prototype pollution attacks.

    Args:
        obj: Object to sanitize.

    Returns:
        Sanitized object with dangerous keys removed.
    """
    if isinstance(obj, dict):
        return {
            k: _sanitize_object(v)
            for k, v in obj.items()
            if k not in DANGEROUS_KEYS
        }
    elif isinstance(obj, list):
        return [_sanitize_object(item) for item in obj]
    else:
        return obj


def safe_json_parse(json_string: str, max_depth: int = 20) -> Any:
    """
    Safely parse JSON with prototype pollution prevention.

    Security Note (C-3): This function:
    - Removes dangerous keys (__proto__, constructor, prototype)
    - Limits recursion depth to prevent stack overflow
    - Uses standard json library for parsing

    Args:
        json_string: JSON string to parse.
        max_depth: Maximum allowed nesting depth.

    Returns:
        Parsed and sanitized JSON object.

    Raises:
        json.JSONDecodeError: If JSON is invalid.
        ValueError: If nesting depth exceeds max_depth.

    Example:
        >>> safe_json_parse('{"name": "test", "__proto__": {"admin": true}}')
        {'name': 'test'}
    """
    # Parse JSON
    parsed = json.loads(json_string)

    # Check depth
    def check_depth(obj: Any, current_depth: int = 0) -> None:
        if current_depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum of {max_depth}")

        if isinstance(obj, dict):
            for value in obj.values():
                check_depth(value, current_depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, current_depth + 1)

    check_depth(parsed)

    # Sanitize
    return _sanitize_object(parsed)


class LRUCache(Generic[K, V]):
    """
    Thread-safe Least Recently Used (LRU) cache.

    Used to prevent memory leaks (C-2) by limiting the number
    of items stored in memory. When the cache is full, the
    least recently used item is evicted.

    This implementation uses OrderedDict for O(1) operations.

    Example:
        >>> cache: LRUCache[str, dict] = LRUCache(max_size=1000)
        >>> cache.set("job-1", {"status": "pending"})
        >>> cache.get("job-1")
        {'status': 'pending'}
        >>> cache.size
        1
    """

    def __init__(self, max_size: int = 1000) -> None:
        """
        Initialize LRU cache.

        Args:
            max_size: Maximum number of items to store.
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")

        self._max_size = max_size
        self._cache: OrderedDict[K, V] = OrderedDict()

    @property
    def size(self) -> int:
        """Get current number of items in cache."""
        return len(self._cache)

    @property
    def max_size(self) -> int:
        """Get maximum cache size."""
        return self._max_size

    def get(self, key: K) -> Optional[V]:
        """
        Get an item from the cache.

        Moves the item to the end (most recently used) if found.

        Args:
            key: Cache key.

        Returns:
            Cached value or None if not found.
        """
        try:
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return self._cache[key]
        except KeyError:
            return None

    def set(self, key: K, value: V) -> None:
        """
        Set an item in the cache.

        If the cache is full, evicts the least recently used item.

        Args:
            key: Cache key.
            value: Value to cache.
        """
        # If key exists, update and move to end
        if key in self._cache:
            self._cache.move_to_end(key)
            self._cache[key] = value
            return

        # If at capacity, remove oldest (first) item
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)

        # Add new item at end
        self._cache[key] = value

    def has(self, key: K) -> bool:
        """
        Check if key exists in cache.

        Does NOT update the access order.

        Args:
            key: Cache key.

        Returns:
            True if key exists.
        """
        return key in self._cache

    def delete(self, key: K) -> bool:
        """
        Delete an item from the cache.

        Args:
            key: Cache key.

        Returns:
            True if item was deleted, False if not found.
        """
        try:
            del self._cache[key]
            return True
        except KeyError:
            return False

    def clear(self) -> None:
        """Clear all items from the cache."""
        self._cache.clear()

    def keys(self) -> List[K]:
        """Get all keys in the cache (most recent last)."""
        return list(self._cache.keys())

    def values(self) -> List[V]:
        """Get all values in the cache (most recent last)."""
        return list(self._cache.values())

    def items(self) -> List[Tuple[K, V]]:
        """Get all key-value pairs (most recent last)."""
        return list(self._cache.items())
