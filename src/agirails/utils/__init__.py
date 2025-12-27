"""
AGIRAILS SDK Utilities.

This module provides utility functions and classes for the SDK.
"""

from agirails.utils.security import (
    timing_safe_equal,
    validate_path,
    validate_service_name,
    is_valid_address,
    safe_json_parse,
    LRUCache,
)
from agirails.utils.logger import Logger
from agirails.utils.semaphore import Semaphore, RateLimiter
from agirails.utils.nonce_tracker import NonceTracker, NonceManager, NonceStatus
from agirails.utils.logging import (
    get_logger,
    configure_logging,
    set_level,
    disable_logging,
    enable_debug,
    LogContext,
)

# PARITY: New utilities matching TS SDK
from agirails.utils.secure_nonce import (
    generate_secure_nonce,
    is_valid_nonce,
    generate_secure_nonces,
)
from agirails.utils.used_attestation_tracker import (
    IUsedAttestationTracker,
    InMemoryUsedAttestationTracker,
    FileBasedUsedAttestationTracker,
    create_used_attestation_tracker,
)
from agirails.utils.received_nonce_tracker import (
    NonceValidationResult,
    IReceivedNonceTracker,
    InMemoryReceivedNonceTracker,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
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
    # Nonce tracking
    "NonceTracker",
    "NonceManager",
    "NonceStatus",
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
