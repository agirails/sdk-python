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
    ...     result = await client.basic.pay({
    ...         "to": "0xabcdefABCDEFabcdefABCDEFabcdefABCDEFabcd",
    ...         "amount": 100
    ...     })
    ...     print(f"Transaction: {result.tx_id}")
    ...
    >>> asyncio.run(main())

The SDK provides three levels of API:
- **Basic**: Simple `pay()` method for quick payments
- **Standard**: Explicit lifecycle control with `create_transaction()`, `link_escrow()`, etc.
- **Advanced**: Direct runtime access for custom workflows

Modules:
- `client`: ACTPClient factory and configuration
- `adapters`: BasicAdapter, StandardAdapter
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
    BasicAdapter,
    BasicPayParams,
    BasicPayResult,
    CheckStatusResult,
    StandardAdapter,
    StandardTransactionParams,
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
    # PARITY: SecureNonce
    generate_secure_nonce,
    is_valid_nonce,
    generate_secure_nonces,
    # PARITY: UsedAttestationTracker
    IUsedAttestationTracker,
    InMemoryUsedAttestationTracker,
    FileBasedUsedAttestationTracker,
    create_used_attestation_tracker,
    # PARITY: ReceivedNonceTracker
    NonceValidationResult,
    IReceivedNonceTracker,
    InMemoryReceivedNonceTracker,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
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
    DeliveryProofMessage,
    DeliveryProofMetadata,
    SignedMessage,
    TypedData,
    compute_result_hash,
)

# Protocol Layer (PARITY: Match TS SDK exports)
from agirails.protocol import (
    # Messages
    MessageSigner,
    SignatureComponents,
    hash_typed_data,
    create_typed_data,
    HAS_MESSAGES,
    # Proofs
    ProofGenerator,
    ContentProof,
    MerkleProof,
    verify_merkle_proof,
    hash_service_input,
    hash_service_output,
    # DID
    DIDManager,
    DIDResolver,
    VerificationMethod,
    ServiceEndpoint,
    create_did_from_address,
    did_to_address,
)

# Protocol modules (conditional, require web3)
try:
    from agirails.protocol import (
        # Kernel
        ACTPKernel,
        TransactionView,
        # Escrow
        EscrowVault,
        CreateEscrowParams,
        EscrowInfo,
        generate_escrow_id,
        # Events
        EventMonitor,
        EventFilter,
        EventType,
        ACTPEvent,
        TransactionCreatedEvent,
        StateTransitionedEvent,
        EscrowCreatedEvent,
        EscrowPayoutEvent,
        # Nonce
        NonceManager,
        NonceManagerPool,
        # EAS
        EASHelper,
        Attestation,
        DeliveryAttestationData,
        Schema,
        DELIVERY_SCHEMA,
        ZERO_BYTES32,
        # Agent Registry
        AgentRegistry,
        AgentProfile,
        ServiceDescriptor,
        compute_service_type_hash,
    )
    HAS_WEB3_PROTOCOL = True
except ImportError:
    HAS_WEB3_PROTOCOL = False

# Builders
from agirails.builders import (
    DeliveryProofBuilder,
    QuoteBuilder,
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
    "BasicAdapter",
    "BasicPayParams",
    "BasicPayResult",
    "CheckStatusResult",
    "StandardAdapter",
    "StandardTransactionParams",
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
    # PARITY: SecureNonce
    "generate_secure_nonce",
    "is_valid_nonce",
    "generate_secure_nonces",
    # PARITY: UsedAttestationTracker
    "IUsedAttestationTracker",
    "InMemoryUsedAttestationTracker",
    "FileBasedUsedAttestationTracker",
    "create_used_attestation_tracker",
    # PARITY: ReceivedNonceTracker
    "NonceValidationResult",
    "IReceivedNonceTracker",
    "InMemoryReceivedNonceTracker",
    "SetBasedReceivedNonceTracker",
    "create_received_nonce_tracker",
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
    "DeliveryProofMessage",
    "DeliveryProofMetadata",
    "SignedMessage",
    "TypedData",
    "compute_result_hash",
    # Protocol Layer (PARITY with TS SDK)
    "MessageSigner",
    "SignatureComponents",
    "hash_typed_data",
    "create_typed_data",
    "HAS_MESSAGES",
    "ProofGenerator",
    "ContentProof",
    "MerkleProof",
    "verify_merkle_proof",
    "hash_service_input",
    "hash_service_output",
    "DIDManager",
    "DIDResolver",
    "VerificationMethod",
    "ServiceEndpoint",
    "create_did_from_address",
    "did_to_address",
    # Protocol (web3 required)
    "HAS_WEB3_PROTOCOL",
    "ACTPKernel",
    "TransactionView",
    "EscrowVault",
    "CreateEscrowParams",
    "EscrowInfo",
    "generate_escrow_id",
    "EventMonitor",
    "EventFilter",
    "EventType",
    "ACTPEvent",
    "TransactionCreatedEvent",
    "StateTransitionedEvent",
    "EscrowCreatedEvent",
    "EscrowPayoutEvent",
    "NonceManager",
    "NonceManagerPool",
    "EASHelper",
    "Attestation",
    "DeliveryAttestationData",
    "Schema",
    "DELIVERY_SCHEMA",
    "ZERO_BYTES32",
    "AgentRegistry",
    "AgentProfile",
    "ServiceDescriptor",
    "compute_service_type_hash",
    # Builders
    "DeliveryProofBuilder",
    "QuoteBuilder",
]
