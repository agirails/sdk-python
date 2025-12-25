"""
AGIRAILS Python SDK - Agent Commerce Transaction Protocol.

This SDK provides a complete implementation of the ACTP protocol for AI agents.

Quick Start:
    >>> from agirails import ACTPClient
    >>> import asyncio
    >>>
    >>> async def main():
    ...     client = await ACTPClient.create(
    ...         mode="mock",
    ...         requester_address="0x1234567890123456789012345678901234567890"
    ...     )
    ...     result = await client.beginner.pay({
    ...         "to": "0xabcdefABCDEFabcdefABCDEFabcdefABCDEFabcd",
    ...         "amount": 100
    ...     })
    ...     print(f"Transaction: {result.tx_id}")
    ...
    >>> asyncio.run(main())

The SDK provides three levels of API:
- **Beginner**: Simple `pay()` method for quick payments
- **Intermediate**: Explicit lifecycle control with `create_transaction()`, `link_escrow()`, etc.
- **Advanced**: Direct runtime access for custom workflows

Modules:
- `client`: ACTPClient factory and configuration
- `adapters`: BeginnerAdapter, IntermediateAdapter
- `runtime`: MockRuntime and BlockchainRuntime implementations
- `errors`: Exception hierarchy for ACTP errors
- `utils`: Helpers, security, logging, and concurrency utilities
"""

from agirails.version import __version__, __version_info__

# Client
from agirails.client import (
    ACTPClient,
    ACTPClientConfig,
    ACTPClientInfo,
    ACTPClientMode,
)

# Adapters
from agirails.adapters import (
    BaseAdapter,
    BeginnerAdapter,
    BeginnerPayParams,
    BeginnerPayResult,
    IntermediateAdapter,
    IntermediateTransactionParams,
    TransactionDetails,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
    MIN_AMOUNT_WEI,
    MAX_DEADLINE_HOURS,
    MAX_DEADLINE_DAYS,
)

# Runtime Layer
from agirails.runtime import (
    # Types
    State,
    TransactionStateValue,
    MockTransaction,
    MockEscrow,
    MockAccount,
    MockBlockchain,
    MockEvent,
    MockState,
    STATE_TRANSITIONS,
    is_valid_transition,
    is_terminal_state,
    MOCK_STATE_DEFAULTS,
    # Interfaces
    CreateTransactionParams,
    TimeInterface,
    IACTPRuntime,
    IMockRuntime,
    is_mock_runtime,
    # Implementations
    MockStateManager,
    MockRuntime,
)

# Errors
from agirails.errors import (
    ACTPError,
    TransactionNotFoundError,
    InvalidStateTransitionError,
    EscrowNotFoundError,
    DeadlinePassedError,
    DeadlineExpiredError,
    DisputeWindowActiveError,
    ContractPausedError,
    InsufficientBalanceError,
    ValidationError,
    InvalidAddressError,
    InvalidAmountError,
    NetworkError,
    TransactionRevertedError,
    SignatureVerificationError,
    StorageError,
    InvalidCIDError,
    UploadTimeoutError,
    DownloadTimeoutError,
    FileSizeLimitExceededError,
    StorageAuthenticationError,
    StorageRateLimitError,
    ContentNotFoundError,
    NoProviderFoundError,
    ACTPTimeoutError,
    ProviderRejectedError,
    DeliveryFailedError,
    DisputeRaisedError,
    ServiceConfigError,
    AgentLifecycleError,
    QueryCapExceededError,
    MockStateCorruptedError,
    MockStateVersionError,
    MockStateLockError,
)

# Utilities - Security
from agirails.utils import (
    timing_safe_equal,
    validate_path,
    validate_service_name,
    is_valid_address,
    safe_json_parse,
    LRUCache,
    Logger,
    Semaphore,
    RateLimiter,
)

# Utilities - Helpers
from agirails.utils.helpers import (
    USDC,
    Deadline,
    Address,
    Bytes32,
    StateHelper,
    DisputeWindow,
    ServiceHash,
    ServiceMetadata,
    parse_usdc,
    format_usdc,
    shorten_address,
    hash_service_metadata,
)

# Utilities - Validation
from agirails.utils.validation import (
    validate_address,
    validate_amount,
    validate_deadline,
    validate_tx_id,
    validate_endpoint_url,
    validate_dispute_window,
    validate_bytes32,
)

# Utilities - Canonical JSON
from agirails.utils.canonical_json import (
    canonical_json_dumps,
    compute_type_hash,
    hash_struct,
    compute_domain_separator,
)

# Level 0 API - Low-level primitives
from agirails.level0 import (
    ServiceDirectory,
    ServiceEntry,
    ServiceQuery,
    Provider,
    ProviderConfig,
    ProviderStatus,
    provide,
    ProvideOptions,
    request,
    RequestOptions,
    RequestResult,
)

# Level 1 API - Agent abstraction
from agirails.level1 import (
    Agent,
    AgentConfig,
    AgentBehavior,
    AgentStatus,
    AgentStats,
    AgentBalance,
    Job,
    JobContext,
    JobHandler,
    JobResult,
    ServiceConfig,
    ServiceFilter,
    RetryConfig,
    PricingStrategy,
    CostModel,
    PriceCalculation,
    calculate_price,
)

# Types
from agirails.types import (
    AgentDID,
    DIDDocument,
    Transaction,
    TransactionState,
    TransactionReceipt,
    TransactionFilter,
    EIP712Domain,
    ServiceRequest,
    ServiceResponse,
    DeliveryProof,
    SignedMessage,
    TypedData,
)

__all__ = [
    # Version
    "__version__",
    "__version_info__",
    # Client
    "ACTPClient",
    "ACTPClientConfig",
    "ACTPClientInfo",
    "ACTPClientMode",
    # Adapters
    "BaseAdapter",
    "BeginnerAdapter",
    "BeginnerPayParams",
    "BeginnerPayResult",
    "IntermediateAdapter",
    "IntermediateTransactionParams",
    "TransactionDetails",
    "DEFAULT_DEADLINE_SECONDS",
    "DEFAULT_DISPUTE_WINDOW_SECONDS",
    "MIN_AMOUNT_WEI",
    "MAX_DEADLINE_HOURS",
    "MAX_DEADLINE_DAYS",
    # Runtime Types
    "State",
    "TransactionStateValue",
    "MockTransaction",
    "MockEscrow",
    "MockAccount",
    "MockBlockchain",
    "MockEvent",
    "MockState",
    "STATE_TRANSITIONS",
    "is_valid_transition",
    "is_terminal_state",
    "MOCK_STATE_DEFAULTS",
    # Runtime Interfaces
    "CreateTransactionParams",
    "TimeInterface",
    "IACTPRuntime",
    "IMockRuntime",
    "is_mock_runtime",
    # Runtime Implementations
    "MockStateManager",
    "MockRuntime",
    # Errors - Base
    "ACTPError",
    # Errors - Transaction
    "TransactionNotFoundError",
    "InvalidStateTransitionError",
    "EscrowNotFoundError",
    "DeadlinePassedError",
    "DeadlineExpiredError",
    "DisputeWindowActiveError",
    "ContractPausedError",
    "InsufficientBalanceError",
    # Errors - Validation
    "ValidationError",
    "InvalidAddressError",
    "InvalidAmountError",
    # Errors - Network
    "NetworkError",
    "TransactionRevertedError",
    "SignatureVerificationError",
    # Errors - Storage
    "StorageError",
    "InvalidCIDError",
    "UploadTimeoutError",
    "DownloadTimeoutError",
    "FileSizeLimitExceededError",
    "StorageAuthenticationError",
    "StorageRateLimitError",
    "ContentNotFoundError",
    # Errors - Agent
    "NoProviderFoundError",
    "ACTPTimeoutError",
    "ProviderRejectedError",
    "DeliveryFailedError",
    "DisputeRaisedError",
    "ServiceConfigError",
    "AgentLifecycleError",
    "QueryCapExceededError",
    # Errors - Mock
    "MockStateCorruptedError",
    "MockStateVersionError",
    "MockStateLockError",
    # Utilities - Security
    "timing_safe_equal",
    "validate_path",
    "validate_service_name",
    "is_valid_address",
    "safe_json_parse",
    "LRUCache",
    "Logger",
    "Semaphore",
    "RateLimiter",
    # Utilities - Helpers
    "USDC",
    "Deadline",
    "Address",
    "Bytes32",
    "StateHelper",
    "DisputeWindow",
    "ServiceHash",
    "ServiceMetadata",
    "parse_usdc",
    "format_usdc",
    "shorten_address",
    "hash_service_metadata",
    # Utilities - Validation
    "validate_address",
    "validate_amount",
    "validate_deadline",
    "validate_tx_id",
    "validate_endpoint_url",
    "validate_dispute_window",
    "validate_bytes32",
    # Utilities - Canonical JSON
    "canonical_json_dumps",
    "compute_type_hash",
    "hash_struct",
    "compute_domain_separator",
    # Level 0 API
    "ServiceDirectory",
    "ServiceEntry",
    "ServiceQuery",
    "Provider",
    "ProviderConfig",
    "ProviderStatus",
    "provide",
    "ProvideOptions",
    "request",
    "RequestOptions",
    "RequestResult",
    # Level 1 API
    "Agent",
    "AgentConfig",
    "AgentBehavior",
    "AgentStatus",
    "AgentStats",
    "AgentBalance",
    "Job",
    "JobContext",
    "JobHandler",
    "JobResult",
    "ServiceConfig",
    "ServiceFilter",
    "RetryConfig",
    "PricingStrategy",
    "CostModel",
    "PriceCalculation",
    "calculate_price",
    # Types
    "AgentDID",
    "DIDDocument",
    "Transaction",
    "TransactionState",
    "TransactionReceipt",
    "TransactionFilter",
    "EIP712Domain",
    "ServiceRequest",
    "ServiceResponse",
    "DeliveryProof",
    "SignedMessage",
    "TypedData",
]
