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

from agirails.errors.agent import (
    AgentLifecycleError,
    DeliveryFailedError,
    DisputeRaisedError,
    NoProviderFoundError,
    ProviderRejectedError,
    QueryCapExceededError,
    ServiceConfigError,
)
from agirails.errors.agent import (
    TimeoutError as ACTPTimeoutError,
)
from agirails.errors.base import (
    DEBUG_MODE,
    ACTPError,
    is_debug_mode,
    set_debug_mode,
)
from agirails.errors.mock import (
    MockStateCorruptedError,
    MockStateLockError,
    MockStateVersionError,
)
from agirails.errors.network import (
    NetworkError,
    SignatureVerificationError,
    TransactionRevertedError,
    TransientRPCError,
)
from agirails.errors.storage import (
    ContentNotFoundError,
    DownloadTimeoutError,
    FileSizeLimitExceededError,
    InvalidCIDError,
    StorageAuthenticationError,
    StorageError,
    StorageRateLimitError,
    UploadTimeoutError,
)
from agirails.errors.transaction import (
    ContractPausedError,
    DeadlineExpiredError,
    DeadlinePassedError,
    DisputeWindowActiveError,
    EscrowError,
    EscrowNotFoundError,
    InsufficientBalanceError,
    InvalidStateTransitionError,
    TransactionError,
    TransactionNotFoundError,
)
from agirails.errors.validation import (
    InvalidAddressError,
    InvalidAmountError,
    ValidationError,
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
    "TransactionError",
    "EscrowError",
    # Validation
    "ValidationError",
    "InvalidAddressError",
    "InvalidAmountError",
    # Network
    "NetworkError",
    "TransientRPCError",
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
