"""
AGIRAILS SDK Utilities.

This module provides utility functions and classes for the SDK.
"""

from agirails.utils.logger import Logger
from agirails.utils.logging import (
    LogContext,
    configure_logging,
    disable_logging,
    enable_debug,
    get_logger,
    set_level,
)
from agirails.utils.received_nonce_tracker import (
    InMemoryReceivedNonceTracker,
    IReceivedNonceTracker,
    NonceValidationResult,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
)

# PARITY: New utilities matching TS SDK
from agirails.utils.secure_nonce import (
    generate_secure_nonce,
    generate_secure_nonces,
    is_valid_nonce,
)
from agirails.utils.security import (
    LRUCache,
    is_valid_address,
    safe_json_parse,
    timing_safe_equal,
    validate_path,
    validate_service_name,
)
from agirails.utils.semaphore import RateLimiter, Semaphore
from agirails.utils.used_attestation_tracker import (
    FileBasedUsedAttestationTracker,
    InMemoryUsedAttestationTracker,
    IUsedAttestationTracker,
    create_used_attestation_tracker,
)

__all__ = [
    # Security
    "timing_safe_equal",
    "validate_path",
    "validate_service_name",
    "is_valid_address",
    "safe_json_parse",
    "LRUCache",
    # Logger (legacy)
    "Logger",
    # Structured logging
    "get_logger",
    "configure_logging",
    "set_level",
    "disable_logging",
    "enable_debug",
    "LogContext",
    # Concurrency
    "Semaphore",
    "RateLimiter",
    # PARITY: SecureNonce (matches TS SDK)
    "generate_secure_nonce",
    "is_valid_nonce",
    "generate_secure_nonces",
    # PARITY: UsedAttestationTracker (matches TS SDK)
    "IUsedAttestationTracker",
    "InMemoryUsedAttestationTracker",
    "FileBasedUsedAttestationTracker",
    "create_used_attestation_tracker",
    # PARITY: ReceivedNonceTracker (matches TS SDK)
    "NonceValidationResult",
    "IReceivedNonceTracker",
    "InMemoryReceivedNonceTracker",
    "SetBasedReceivedNonceTracker",
    "create_received_nonce_tracker",
]
