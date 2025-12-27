"""
Security utilities for AGIRAILS SDK.

Implements critical security measures including:
- Timing-safe string comparison (H-7)
- Path traversal prevention (H-6)
- Input validation (H-2)
- Safe JSON parsing (C-3)
- LRU Cache for memory leak prevention (C-2)
- Secure private key handling (C-1)
- RPC rate limiting (C-3)
"""

from __future__ import annotations

import asyncio
import ctypes
import hmac
import json
import logging
import re
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Generic, List, Optional, Tuple, TypeVar, Union


# ============================================================================
# L-2: Security Event Logging
# ============================================================================


class SecurityEventType(Enum):
    """Types of security events to log."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    KEY_CREATED = "key_created"
    KEY_DISPOSED = "key_disposed"

    # Rate limiting events
    RATE_LIMIT_HIT = "rate_limit_hit"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    # Validation events
    INVALID_ADDRESS = "invalid_address"
    INVALID_INPUT = "invalid_input"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    PROTOTYPE_POLLUTION_ATTEMPT = "prototype_pollution_attempt"

    # Transaction events
    TX_SUBMITTED = "tx_submitted"
    TX_CONFIRMED = "tx_confirmed"
    TX_FAILED = "tx_failed"
    TX_TIMEOUT = "tx_timeout"

    # Access control events
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"

    # Suspicious activity
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


@dataclass
class SecurityEvent:
    """
    Security event record.

    Security Note (L-2): Contains all information needed for
    security auditing and incident investigation.
    """

    event_type: SecurityEventType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message: str = ""
    source: str = ""  # Module/function that generated the event
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "source": self.source,
            "severity": self.severity,
            "details": self.details,
        }


class SecurityLogger:
    """
    Security event logger for AGIRAILS SDK.

    Security Note (L-2): Provides centralized logging of security-relevant
    events for auditing, monitoring, and incident response.

    Features:
    - Structured security event logging
    - Configurable severity filtering
    - Thread-safe operation
    - Integration with Python logging

    Example:
        >>> logger = SecurityLogger.get_instance()
        >>> logger.log_event(
        ...     SecurityEventType.AUTH_FAILURE,
        ...     message="Invalid signature",
        ...     source="kernel.verify_signature",
        ...     severity="WARNING",
        ...     details={"address": "0x..."}
        ... )
    """

    _instance: Optional["SecurityLogger"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        """Initialize security logger."""
        self._logger = logging.getLogger("agirails.security")
        self._handlers: List[Callable[[SecurityEvent], None]] = []
        self._event_lock = threading.Lock()
        self._min_severity = "INFO"
        self._severity_levels = {
            "DEBUG": 0,
            "INFO": 1,
            "WARNING": 2,
            "ERROR": 3,
            "CRITICAL": 4,
        }

    @classmethod
    def get_instance(cls) -> "SecurityLogger":
        """
        Get singleton instance of SecurityLogger.

        Returns:
            The global SecurityLogger instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def set_min_severity(self, severity: str) -> None:
        """
        Set minimum severity level for logging.

        Args:
            severity: Minimum severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        if severity.upper() not in self._severity_levels:
            raise ValueError(f"Invalid severity: {severity}")
        self._min_severity = severity.upper()

    def add_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """
        Add custom event handler.

        Args:
            handler: Callable that receives SecurityEvent objects
        """
        with self._event_lock:
            self._handlers.append(handler)

    def remove_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """
        Remove custom event handler.

        Args:
            handler: Handler to remove
        """
        with self._event_lock:
            if handler in self._handlers:
                self._handlers.remove(handler)

    def log_event(
        self,
        event_type: SecurityEventType,
        *,
        message: str = "",
        source: str = "",
        severity: str = "INFO",
        details: Optional[dict] = None,
    ) -> None:
        """
        Log a security event.

        Args:
            event_type: Type of security event
            message: Human-readable description
            source: Source module/function
            severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
            details: Additional event details (will be sanitized)
        """
        # Check severity threshold
        if self._severity_levels.get(severity.upper(), 1) < self._severity_levels.get(
            self._min_severity, 1
        ):
            return

        # Create event
        event = SecurityEvent(
            event_type=event_type,
            message=message,
            source=source,
            severity=severity.upper(),
            details=details or {},
        )

        # Log to Python logging
        log_level = getattr(logging, severity.upper(), logging.INFO)
        self._logger.log(
            log_level,
            "[%s] %s - %s",
            event_type.value,
            source or "unknown",
            message,
            extra={"security_event": event.to_dict()},
        )

        # Call custom handlers
        with self._event_lock:
            for handler in self._handlers:
                try:
                    handler(event)
                except Exception:
                    # Don't let handler errors affect logging
                    pass

    # Convenience methods for common events

    def log_auth_failure(
        self,
        source: str,
        reason: str,
        address: Optional[str] = None,
    ) -> None:
        """Log authentication failure."""
        details = {"reason": reason}
        if address:
            # Only log partial address for privacy
            details["address"] = f"{address[:10]}...{address[-4:]}" if len(address) > 14 else "[redacted]"

        self.log_event(
            SecurityEventType.AUTH_FAILURE,
            message=f"Authentication failed: {reason}",
            source=source,
            severity="WARNING",
            details=details,
        )

    def log_rate_limit(self, source: str, limit: float, window: float) -> None:
        """Log rate limit hit."""
        self.log_event(
            SecurityEventType.RATE_LIMIT_HIT,
            message=f"Rate limit hit: {limit} per {window}s",
            source=source,
            severity="INFO",
            details={"limit": limit, "window": window},
        )

    def log_invalid_input(
        self,
        source: str,
        input_type: str,
        reason: str,
    ) -> None:
        """Log invalid input attempt."""
        self.log_event(
            SecurityEventType.INVALID_INPUT,
            message=f"Invalid {input_type}: {reason}",
            source=source,
            severity="WARNING",
            details={"input_type": input_type, "reason": reason},
        )

    def log_path_traversal(self, source: str, path: str, base_dir: str) -> None:
        """Log path traversal attempt."""
        self.log_event(
            SecurityEventType.PATH_TRAVERSAL_ATTEMPT,
            message="Path traversal attempt detected",
            source=source,
            severity="ERROR",
            details={"attempted_path": "[redacted]", "base_directory": base_dir},
        )

    def log_tx_submitted(
        self,
        source: str,
        tx_hash: str,
        tx_type: str = "unknown",
    ) -> None:
        """Log transaction submission."""
        self.log_event(
            SecurityEventType.TX_SUBMITTED,
            message=f"Transaction submitted: {tx_type}",
            source=source,
            severity="INFO",
            details={"tx_hash": tx_hash, "tx_type": tx_type},
        )

    def log_tx_failed(
        self,
        source: str,
        tx_hash: str,
        reason: str,
    ) -> None:
        """Log transaction failure."""
        self.log_event(
            SecurityEventType.TX_FAILED,
            message=f"Transaction failed: {reason}",
            source=source,
            severity="ERROR",
            details={"tx_hash": tx_hash, "reason": reason},
        )


# Global security logger instance
_security_logger: Optional[SecurityLogger] = None


def get_security_logger() -> SecurityLogger:
    """
    Get the global security logger instance.

    Returns:
        SecurityLogger singleton instance
    """
    return SecurityLogger.get_instance()

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


def safe_json_parse(
    json_string: str,
    schema: Optional[Dict[str, str]] = None,
    max_depth: int = 20,
    max_size: int = 1_000_000,  # 1MB default (C-3 DoS protection)
) -> Optional[Any]:
    """
    Safely parse JSON with prototype pollution prevention and optional schema validation.

    PARITY: Matches TypeScript SDK's safeJSONParse() behavior exactly:
    - Size limit to prevent DoS attacks (C-3)
    - Schema validation with type checking and field whitelisting
    - Returns None instead of raising on parse errors
    - Removes dangerous keys (__proto__, constructor, prototype)
    - Limits recursion depth to prevent stack overflow

    Args:
        json_string: JSON string to parse.
        schema: Optional schema for field validation. Dict mapping field names
                to expected types ('string', 'number', 'object', 'array', 'any').
                If provided, only whitelisted fields matching types are returned.
        max_depth: Maximum allowed nesting depth (default: 20).
        max_size: Maximum JSON string size in bytes (default: 1MB).

    Returns:
        Parsed and sanitized JSON object, or None if parsing fails.

    Example:
        >>> safe_json_parse('{"name": "test", "__proto__": {"admin": true}}')
        {'name': 'test'}

        >>> # With schema validation
        >>> schema = {"name": "string", "count": "number"}
        >>> safe_json_parse('{"name": "test", "count": 5, "extra": true}', schema)
        {'name': 'test', 'count': 5}  # 'extra' filtered out
    """
    # SECURITY FIX (C-3): Check size to prevent DoS attacks
    if not json_string or not isinstance(json_string, str):
        return None

    if len(json_string) > max_size:
        return None

    # Parse JSON
    try:
        parsed = json.loads(json_string)
    except (json.JSONDecodeError, ValueError):
        return None

    # Ensure we got an object (not a primitive or array at top level)
    if not isinstance(parsed, dict):
        return None

    # Check depth
    def check_depth(obj: Any, current_depth: int = 0) -> bool:
        if current_depth > max_depth:
            return False

        if isinstance(obj, dict):
            for value in obj.values():
                if not check_depth(value, current_depth + 1):
                    return False
        elif isinstance(obj, list):
            for item in obj:
                if not check_depth(item, current_depth + 1):
                    return False
        return True

    if not check_depth(parsed):
        return None

    # Remove dangerous properties
    for key in DANGEROUS_KEYS:
        parsed.pop(key, None)

    # If schema is provided, validate and whitelist
    if schema:
        validated: Dict[str, Any] = {}

        for field_name, expected_type in schema.items():
            value = parsed.get(field_name)

            # Skip if field doesn't exist
            if value is None:
                continue

            # Type check
            actual_type = "array" if isinstance(value, list) else type(value).__name__
            # Map Python types to schema types
            type_map = {
                "str": "string",
                "int": "number",
                "float": "number",
                "bool": "boolean",
                "dict": "object",
                "list": "array",
            }
            mapped_type = type_map.get(actual_type, actual_type)

            if mapped_type != expected_type and expected_type != "any":
                # Type mismatch - skip this field
                continue

            # Recursively sanitize nested objects
            if isinstance(value, dict):
                validated[field_name] = _sanitize_object(value)
            elif isinstance(value, list):
                validated[field_name] = [
                    _sanitize_object(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                validated[field_name] = value

        return validated

    # No schema - return sanitized object
    return _sanitize_object(parsed)


class LRUCache(Generic[K, V]):
    """
    Thread-safe Least Recently Used (LRU) cache.

    Security Note (M-4): Uses reentrant lock (RLock) for thread safety.
    All operations are protected to prevent race conditions during
    concurrent access.

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
        # Security Note (M-4): RLock allows same thread to acquire multiple times
        self._lock = threading.RLock()

    @property
    def size(self) -> int:
        """Get current number of items in cache."""
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            return key in self._cache

    def delete(self, key: K) -> bool:
        """
        Delete an item from the cache.

        Args:
            key: Cache key.

        Returns:
            True if item was deleted, False if not found.
        """
        with self._lock:
            try:
                del self._cache[key]
                return True
            except KeyError:
                return False

    def clear(self) -> None:
        """Clear all items from the cache."""
        with self._lock:
            self._cache.clear()

    def keys(self) -> List[K]:
        """Get all keys in the cache (most recent last)."""
        with self._lock:
            return list(self._cache.keys())

    def values(self) -> List[V]:
        """Get all values in the cache (most recent last)."""
        with self._lock:
            return list(self._cache.values())

    def items(self) -> List[Tuple[K, V]]:
        """Get all key-value pairs (most recent last)."""
        with self._lock:
            return list(self._cache.items())


# ============================================================================
# C-1: Secure Private Key Handling
# ============================================================================


def _secure_zero_memory(data: bytes) -> None:
    """
    Attempt to securely zero memory containing sensitive data.

    This is a best-effort attempt since Python doesn't guarantee
    control over memory. Uses ctypes to overwrite the buffer.

    Security Note (C-1): Call this when disposing of sensitive data
    like private keys to reduce the window of exposure.

    Args:
        data: Bytes object to zero (must be mutable or we copy)
    """
    try:
        # Get the address of the bytes object's buffer
        # This is a best-effort approach - Python may still have copies
        buffer_address = id(data) + bytes.__basicsize__
        buffer_size = len(data)

        # Create a ctypes pointer to the buffer
        buffer_ptr = (ctypes.c_char * buffer_size).from_address(buffer_address)

        # Zero the memory
        ctypes.memset(buffer_ptr, 0, buffer_size)
    except Exception:
        # Silently fail - this is best-effort
        pass


class SecureAccountWrapper:
    """
    Secure wrapper for eth_account LocalAccount.

    Provides security measures for handling private keys:
    - Attempts to zero memory on deletion
    - Prevents accidental leaking via __repr__/__str__
    - Thread-safe access to account

    Security Note (C-1): Use this wrapper instead of directly storing
    LocalAccount objects to reduce the risk of key exposure.

    Example:
        >>> from eth_account import Account
        >>> account = Account.from_key(private_key)
        >>> secure = SecureAccountWrapper(account, private_key_bytes)
        >>> signature = secure.sign_message(message)
        >>> del secure  # Attempts to zero key memory
    """

    # Track all instances for cleanup
    _instances: weakref.WeakSet["SecureAccountWrapper"] = weakref.WeakSet()

    def __init__(
        self,
        account: Any,  # LocalAccount
        private_key_bytes: Optional[bytes] = None,
    ) -> None:
        """
        Initialize secure account wrapper.

        Args:
            account: The LocalAccount instance to wrap
            private_key_bytes: Optional raw private key bytes for zeroing
        """
        self._account = account
        self._private_key_bytes = private_key_bytes
        self._lock = threading.RLock()
        self._disposed = False

        # Track instance for cleanup
        SecureAccountWrapper._instances.add(self)

    @property
    def address(self) -> str:
        """Get account address (safe to expose)."""
        with self._lock:
            if self._disposed:
                raise RuntimeError("Account has been disposed")
            return self._account.address

    @property
    def account(self) -> Any:
        """Get underlying account (use with caution)."""
        with self._lock:
            if self._disposed:
                raise RuntimeError("Account has been disposed")
            return self._account

    def sign_message(self, message: Any) -> Any:
        """
        Sign a message using the account.

        Args:
            message: Message to sign (SignableMessage)

        Returns:
            Signed message
        """
        with self._lock:
            if self._disposed:
                raise RuntimeError("Account has been disposed")
            return self._account.sign_message(message)

    def sign_transaction(self, transaction: dict) -> Any:
        """
        Sign a transaction using the account.

        Args:
            transaction: Transaction dict to sign

        Returns:
            Signed transaction
        """
        with self._lock:
            if self._disposed:
                raise RuntimeError("Account has been disposed")
            return self._account.sign_transaction(transaction)

    def dispose(self) -> None:
        """
        Explicitly dispose the account and zero key memory.

        Call this when the account is no longer needed.
        """
        with self._lock:
            if self._disposed:
                return

            self._disposed = True

            # Attempt to zero private key bytes if we have them
            if self._private_key_bytes:
                _secure_zero_memory(self._private_key_bytes)
                self._private_key_bytes = None

            # Clear reference to account
            self._account = None

    def __del__(self) -> None:
        """Destructor - attempt to zero key memory."""
        try:
            self.dispose()
        except Exception:
            pass  # Ignore errors during destruction

    def __repr__(self) -> str:
        """Safe repr that doesn't leak key information."""
        if self._disposed:
            return "SecureAccountWrapper(disposed)"
        return f"SecureAccountWrapper(address={self.address})"

    def __str__(self) -> str:
        """Safe str that doesn't leak key information."""
        return self.__repr__()

    # Prevent pickling which could leak keys
    def __getstate__(self) -> None:
        raise RuntimeError("SecureAccountWrapper cannot be pickled")

    def __reduce__(self) -> None:
        raise RuntimeError("SecureAccountWrapper cannot be pickled")


# ============================================================================
# C-3: RPC Rate Limiting
# ============================================================================


class TokenBucketRateLimiter:
    """
    Async-compatible token bucket rate limiter.

    Limits the rate of operations using the token bucket algorithm.
    Thread-safe and async-compatible. Supports waiting for tokens
    unlike the sliding window RateLimiter in semaphore.py.

    Security Note (C-3): Use this to prevent RPC rate limit exhaustion
    and protect against DoS attacks.

    Example:
        >>> limiter = TokenBucketRateLimiter(max_rate=10, time_period=1.0)  # 10 req/sec
        >>> async with limiter:
        ...     await make_rpc_call()

    Attributes:
        max_rate: Maximum number of operations per time period
        time_period: Time period in seconds
    """

    def __init__(
        self,
        max_rate: float = 10.0,
        time_period: float = 1.0,
        burst_size: Optional[int] = None,
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            max_rate: Maximum operations per time_period
            time_period: Time period in seconds (default: 1 second)
            burst_size: Maximum burst size (default: max_rate)
        """
        if max_rate <= 0:
            raise ValueError("max_rate must be positive")
        if time_period <= 0:
            raise ValueError("time_period must be positive")

        self._max_rate = max_rate
        self._time_period = time_period
        self._burst_size = burst_size if burst_size is not None else int(max_rate)

        # Token bucket state
        self._tokens = float(self._burst_size)
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def max_rate(self) -> float:
        """Get maximum rate."""
        return self._max_rate

    @property
    def time_period(self) -> float:
        """Get time period."""
        return self._time_period

    async def acquire(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Acquire tokens from the bucket.

        Waits until tokens are available or timeout expires.

        Args:
            tokens: Number of tokens to acquire (default: 1)
            timeout: Maximum time to wait in seconds (None = wait forever)

        Returns:
            True if tokens acquired, False if timeout expired
        """
        start_time = time.monotonic()

        async with self._lock:
            while True:
                # Refill tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self._last_update
                self._tokens = min(
                    self._burst_size,
                    self._tokens + (elapsed * self._max_rate / self._time_period),
                )
                self._last_update = now

                # Check if we have enough tokens
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True

                # Calculate wait time
                tokens_needed = tokens - self._tokens
                wait_time = tokens_needed * self._time_period / self._max_rate

                # Check timeout
                if timeout is not None:
                    elapsed_total = now - start_time
                    remaining = timeout - elapsed_total
                    if remaining <= 0:
                        return False
                    wait_time = min(wait_time, remaining)

                # Wait for tokens to accumulate
                await asyncio.sleep(wait_time)

    async def __aenter__(self) -> "TokenBucketRateLimiter":
        """Async context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        pass


class RetryConfig:
    """
    Configuration for retry with exponential backoff.

    Attributes:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
        jitter: Whether to add random jitter
    """

    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 0.5,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ) -> None:
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter


async def retry_with_backoff(
    operation: Callable[[], Any],
    config: Optional[RetryConfig] = None,
    retryable_exceptions: Tuple[type, ...] = (Exception,),
) -> Any:
    """
    Execute an operation with exponential backoff retry.

    Security Note (C-3): Use this for RPC calls to handle transient
    failures and rate limiting gracefully.

    Args:
        operation: Async callable to execute
        config: Retry configuration (default: RetryConfig())
        retryable_exceptions: Exception types to retry on

    Returns:
        Result of the operation

    Raises:
        Last exception if all retries exhausted

    Example:
        >>> async def fetch_data():
        ...     return await rpc_call()
        >>> result = await retry_with_backoff(fetch_data)
    """
    import random

    if config is None:
        config = RetryConfig()

    last_exception: Optional[Exception] = None

    for attempt in range(config.max_retries + 1):
        try:
            return await operation()
        except retryable_exceptions as e:
            last_exception = e

            if attempt >= config.max_retries:
                raise

            # Calculate delay with exponential backoff
            delay = config.initial_delay * (config.exponential_base ** attempt)
            delay = min(delay, config.max_delay)

            # Add jitter
            if config.jitter:
                delay = delay * (0.5 + random.random())

            await asyncio.sleep(delay)

    # Should never reach here, but satisfy type checker
    if last_exception:
        raise last_exception
    raise RuntimeError("Retry loop completed unexpectedly")
