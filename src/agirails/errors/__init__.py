"""
AGIRAILS SDK Error Hierarchy.

This module provides a comprehensive exception hierarchy for the ACTP protocol.
All exceptions inherit from ACTPError as the base class.

Example:
    >>> from agirails.errors import ACTPError, TransactionNotFoundError
    >>> try:
    ...     raise TransactionNotFoundError("0x123...")
    ... except ACTPError as e:
    ...     print(f"ACTP error: {e.code}")
"""

from agirails.errors.base import (
    ACTPError,
    DEBUG_MODE,
    set_debug_mode,
    is_debug_mode,
)
from agirails.errors.transaction import (
    TransactionNotFoundError,
    InvalidStateTransitionError,
    EscrowNotFoundError,
    DeadlinePassedError,
    DeadlineExpiredError,
    DisputeWindowActiveError,
    ContractPausedError,
    InsufficientBalanceError,
)
from agirails.errors.validation import (
    ValidationError,
    InvalidAddressError,
    InvalidAmountError,
)
from agirails.errors.network import (
    NetworkError,
    TransactionRevertedError,
    SignatureVerificationError,
)
from agirails.errors.storage import (
    StorageError,
    InvalidCIDError,
    UploadTimeoutError,
    DownloadTimeoutError,
    FileSizeLimitExceededError,
    StorageAuthenticationError,
    StorageRateLimitError,
    ContentNotFoundError,
)
from agirails.errors.agent import (
    NoProviderFoundError,
    TimeoutError as ACTPTimeoutError,
    ProviderRejectedError,
    DeliveryFailedError,
    DisputeRaisedError,
    ServiceConfigError,
    AgentLifecycleError,
    QueryCapExceededError,
)
from agirails.errors.mock import (
    MockStateCorruptedError,
    MockStateVersionError,
    MockStateLockError,
)

__all__ = [
    # Base
    "ACTPError",
    "DEBUG_MODE",
    "set_debug_mode",
    "is_debug_mode",
    # Transaction
    "TransactionNotFoundError",
    "InvalidStateTransitionError",
    "EscrowNotFoundError",
    "DeadlinePassedError",
    "DeadlineExpiredError",
    "DisputeWindowActiveError",
    "ContractPausedError",
    "InsufficientBalanceError",
    # Validation
    "ValidationError",
    "InvalidAddressError",
    "InvalidAmountError",
    # Network
    "NetworkError",
    "TransactionRevertedError",
    "SignatureVerificationError",
    # Storage
    "StorageError",
    "InvalidCIDError",
    "UploadTimeoutError",
    "DownloadTimeoutError",
    "FileSizeLimitExceededError",
    "StorageAuthenticationError",
    "StorageRateLimitError",
    "ContentNotFoundError",
    # Agent
    "NoProviderFoundError",
    "ACTPTimeoutError",
    "ProviderRejectedError",
    "DeliveryFailedError",
    "DisputeRaisedError",
    "ServiceConfigError",
    "AgentLifecycleError",
    "QueryCapExceededError",
    # Mock
    "MockStateCorruptedError",
    "MockStateVersionError",
    "MockStateLockError",
]
