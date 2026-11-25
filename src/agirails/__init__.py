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
- `storage`: Hybrid storage layer (AIP-7 §4) - IPFS (Filebase) + Arweave (Irys)
"""

# Adapters
from agirails.adapters import (
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
    MAX_DEADLINE_DAYS,
    MAX_DEADLINE_HOURS,
    MIN_AMOUNT_WEI,
    BaseAdapter,
    BasicAdapter,
    BasicPayParams,
    BasicPayResult,
    CheckStatusResult,
    StandardAdapter,
    StandardTransactionParams,
    TransactionDetails,
    TransactionStatus,
    X402Adapter,
)

# Service discovery (agirails.app API)
from agirails.api import discover_agents

# Client
from agirails.client import (
    ACTPClient,
    ACTPClientConfig,
    ACTPClientInfo,
    ACTPClientMode,
)

# ERC-8004 identity + reputation
from agirails.erc8004 import (
    ERC8004Bridge,
    ReputationReporter,
)

# Errors
from agirails.errors import (
    ACTPError,
    ACTPTimeoutError,
    AgentLifecycleError,
    ContentNotFoundError,
    ContractPausedError,
    DeadlineExpiredError,
    DeadlinePassedError,
    DeliveryFailedError,
    DisputeRaisedError,
    DisputeWindowActiveError,
    DownloadTimeoutError,
    EscrowNotFoundError,
    FileSizeLimitExceededError,
    InsufficientBalanceError,
    InvalidAddressError,
    InvalidAmountError,
    InvalidCIDError,
    InvalidStateTransitionError,
    MockStateCorruptedError,
    MockStateLockError,
    MockStateVersionError,
    NetworkError,
    NoProviderFoundError,
    ProviderRejectedError,
    QueryCapExceededError,
    ServiceConfigError,
    SignatureVerificationError,
    StorageAuthenticationError,
    StorageError,
    StorageRateLimitError,
    TransactionNotFoundError,
    TransactionRevertedError,
    UploadTimeoutError,
    ValidationError,
)

# Level 0 API - Low-level primitives
from agirails.level0 import (
    ProvideOptions,
    Provider,
    ProviderConfig,
    ProviderStatus,
    RequestOptions,
    RequestResult,
    ServiceDirectory,
    ServiceEntry,
    ServiceQuery,
    provide,
    request,
)

# Level 1 API - Agent abstraction
from agirails.level1 import (
    Agent,
    AgentBalance,
    AgentBehavior,
    AgentConfig,
    AgentStats,
    AgentStatus,
    CostModel,
    Job,
    JobContext,
    JobHandler,
    JobResult,
    PriceCalculation,
    PricingStrategy,
    RetryConfig,
    ServiceConfig,
    ServiceFilter,
    calculate_price,
)

# Protocol Layer (PARITY: Match TS SDK exports)
from agirails.protocol import (
    HAS_MESSAGES,
    ContentProof,
    # DID
    DIDManager,
    DIDResolver,
    MerkleProof,
    # Messages
    MessageSigner,
    # Proofs
    ProofGenerator,
    ServiceEndpoint,
    SignatureComponents,
    VerificationMethod,
    create_did_from_address,
    create_typed_data,
    did_to_address,
    hash_service_input,
    hash_service_output,
    hash_typed_data,
    verify_merkle_proof,
)

# Runtime Layer
from agirails.runtime import (
    MOCK_STATE_DEFAULTS,
    STATE_TRANSITIONS,
    # Interfaces
    CreateTransactionParams,
    IACTPRuntime,
    IMockRuntime,
    MockAccount,
    MockBlockchain,
    MockEscrow,
    MockEvent,
    MockRuntime,
    MockState,
    # Implementations
    MockStateManager,
    MockTransaction,
    # Types
    State,
    TimeInterface,
    TransactionStateValue,
    is_mock_runtime,
    is_terminal_state,
    is_valid_transition,
)

# Types
from agirails.types import (
    AgentDID,
    DeliveryProof,
    DeliveryProofMessage,
    DeliveryProofMetadata,
    DIDDocument,
    EIP712Domain,
    ServiceRequest,
    ServiceResponse,
    SignedMessage,
    Transaction,
    TransactionFilter,
    TransactionReceipt,
    TransactionState,
    TypedData,
    compute_result_hash,
)

# Utilities - Security
from agirails.utils import (
    FileBasedUsedAttestationTracker,
    InMemoryReceivedNonceTracker,
    InMemoryUsedAttestationTracker,
    IReceivedNonceTracker,
    # PARITY: UsedAttestationTracker
    IUsedAttestationTracker,
    Logger,
    LRUCache,
    # PARITY: ReceivedNonceTracker
    NonceValidationResult,
    RateLimiter,
    Semaphore,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
    create_used_attestation_tracker,
    # PARITY: SecureNonce
    generate_secure_nonce,
    generate_secure_nonces,
    is_valid_address,
    is_valid_nonce,
    safe_json_parse,
    timing_safe_equal,
    validate_path,
    validate_service_name,
)

# Utilities - Canonical JSON
from agirails.utils.canonical_json import (
    canonical_json_dumps,
    compute_domain_separator,
    compute_type_hash,
    hash_struct,
)

# Utilities - Helpers
from agirails.utils.helpers import (
    USDC,
    Address,
    Bytes32,
    Deadline,
    DisputeWindow,
    ServiceHash,
    ServiceMetadata,
    StateHelper,
    format_usdc,
    hash_service_metadata,
    parse_usdc,
    shorten_address,
)

# Utilities - Validation
from agirails.utils.validation import (
    validate_address,
    validate_amount,
    validate_bytes32,
    validate_deadline,
    validate_dispute_window,
    validate_endpoint_url,
    validate_tx_id,
)
from agirails.version import __version__, __version_info__

# Wallet providers (Tier 1 = AA gasless, Tier 2 = EOA)
from agirails.wallet import (
    AutoWalletProvider,
    EOAWalletProvider,
    IWalletProvider,
    WalletInfo,
    WalletTier,
)

# Transaction ID computation (canonical hash used by Smart Wallet
# routing + AIP-2 quote anchoring)
from agirails.wallet.aa.transaction_batcher import compute_transaction_id

# Protocol modules (conditional, require web3)
try:
    from agirails.protocol import (
        DELIVERY_SCHEMA,
        ZERO_BYTES32,
        ACTPEvent,
        # Kernel
        ACTPKernel,
        AgentProfile,
        # Agent Registry
        AgentRegistry,
        Attestation,
        CreateEscrowParams,
        DeliveryAttestationData,
        # EAS
        EASHelper,
        EscrowCreatedEvent,
        EscrowInfo,
        EscrowPayoutEvent,
        # Escrow
        EscrowVault,
        EventFilter,
        # Events
        EventMonitor,
        EventType,
        # Nonce
        NonceManager,
        NonceManagerPool,
        Schema,
        ServiceDescriptor,
        StateTransitionedEvent,
        TransactionCreatedEvent,
        TransactionView,
        compute_service_type_hash,
        generate_escrow_id,
    )
    HAS_WEB3_PROTOCOL = True
except ImportError:
    HAS_WEB3_PROTOCOL = False

# Builders
from agirails.builders import (
    AIP2QuoteTypes,
    CounterAcceptBuilder,
    CounterAcceptMessage,
    CounterAcceptParams,
    CounterOfferBuilder,
    CounterOfferJustification,
    CounterOfferMessage,
    CounterOfferParams,
    DeliveryProofBuilder,
    LegacyQuoteBuilder,
    MessageNonceManager,
    QuoteBuilder,
    QuoteMessage,
    QuoteParams,
)

# AIP-16 secure delivery channel (encrypted envelopes, EIP-712, Mock/Relay).
from agirails.delivery import (
    BuildEncryptedEnvelopeParams,
    BuildPublicEnvelopeParams,
    BuildSetupParams,
    DeliveryChannel,
    DeliveryEnvelopeBuilder,
    DeliverySetupBuilder,
    DeliverySubscription,
    MockDeliveryChannel,
    MockDeliveryChannelOptions,
    RelayDeliveryChannel,
    RelayDeliveryChannelOptions,
    build_envelope_aad,
)

# Dispute Module — Evidence Bundle canonical serializer (AIP-14b / PRD P2-3)
from agirails.dispute import (
    EVIDENCE_BUNDLE_SCHEMA_VERSION,
    MAX_BUNDLE_TOKENS,
    SUPPORTED_BUNDLE_MAJOR,
    BundleTooLargeError,
    EvidenceBundle,
    EvidenceBundleDelivery,
    EvidenceBundleDispute,
    EvidenceBundleReasoning,
    EvidenceBundleSpec,
    EvidenceBundleTimelineEvent,
    InvalidBundleError,
    PinEvidenceBundleResult,
    UnsupportedBundleVersionError,
    assert_supported_version,
    bundle_hash,
    compute_bundle_hash,
    count_bundle_tokens,
    enforce_token_cap,
    pin_evidence_bundle,
    serialize_bundle,
    serialize_bundle_to_string,
    set_bundle_tokenizer,
    validate_bundle,
)

# Negotiation Module (autonomous buyer-side negotiation)
from agirails.negotiation import (
    DEFAULT_WEIGHTS,
    BuyerOrchestrator,
    BuyerPolicy,
    CandidateStats,
    Constraints,
    DecisionEngine,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    NegotiationResult,
    OrchestratorConfig,
    PolicyEngine,
    PolicyResult,
    PolicyViolation,
    ProviderPolicyEngine,
    QuoteOffer,
    RequoteGuardViolation,
    RoundResult,
    ScoreBreakdown,
    ScoredCandidate,
    ScoringWeights,
    Selection,
    SessionMapping,
    SessionStore,
    VerifyOnChainResult,
    verify_quote_hash_on_chain,
)

# Web Receipts (AIP-7 §6 — agirails.app public receipt artifact)
from agirails.receipts import (
    PushReceiptArgs,
    PushReceiptResult,
    ReceiptUploadFailure,
    ReceiptUploadOptions,
    ReceiptUploadPayload,
    ReceiptUploadResult,
    ReceiptUploadSuccess,
    format_settled_line,
    push_receipt_on_settled,
    upload_receipt,
)

# Storage Layer (AIP-7 §4 - Hybrid Storage)
from agirails.storage import (
    ARCHIVE_BUNDLE_TYPE,
    ARCHIVE_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    ArchiveAttestation,
    # Types - Archive Bundle
    ArchiveBundle,
    # Builders
    ArchiveBundleBuilder,
    ArchiveChainId,
    ArchiveFinalState,
    ArchiveHashes,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveSettlement,
    ArchiveSignatures,
    ArchiveTags,
    ArweaveClient,
    # Types - Arweave
    ArweaveConfig,
    ArweaveUploadResult,
    # Types - Circuit Breaker
    CircuitBreakerConfig,
    DownloadResult,
    EscrowRelease,
    # Clients
    FilebaseClient,
    # Types - Filebase
    FilebaseConfig,
    # Types - Results
    IPFSUploadResult,
    IrysCurrency,
    IrysNetwork,
    compute_content_hash,
    compute_json_hash,
    validate_archive_bundle,
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
    "TransactionStatus",
    "X402Adapter",
    "DEFAULT_DEADLINE_SECONDS",
    "DEFAULT_DISPUTE_WINDOW_SECONDS",
    "MIN_AMOUNT_WEI",
    "MAX_DEADLINE_HOURS",
    "MAX_DEADLINE_DAYS",
    # Wallet providers
    "AutoWalletProvider",
    "EOAWalletProvider",
    "IWalletProvider",
    "WalletTier",
    "WalletInfo",
    # ERC-8004
    "ERC8004Bridge",
    "ReputationReporter",
    # Service discovery
    "discover_agents",
    # Transaction ID helper
    "compute_transaction_id",
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
    "QuoteMessage",
    "QuoteParams",
    "AIP2QuoteTypes",
    "LegacyQuoteBuilder",
    "CounterOfferBuilder",
    "CounterOfferMessage",
    "CounterOfferParams",
    "CounterOfferJustification",
    "CounterAcceptBuilder",
    "CounterAcceptMessage",
    "CounterAcceptParams",
    "MessageNonceManager",
    # Web Receipts (AIP-7 §6 — agirails.app)
    "ReceiptUploadFailure",
    "ReceiptUploadOptions",
    "ReceiptUploadPayload",
    "ReceiptUploadResult",
    "ReceiptUploadSuccess",
    "upload_receipt",
    "push_receipt_on_settled",
    "format_settled_line",
    "PushReceiptArgs",
    "PushReceiptResult",
    # Storage Layer (AIP-7 §4 - Hybrid Storage)
    # Clients
    "FilebaseClient",
    "ArweaveClient",
    # Builders
    "ArchiveBundleBuilder",
    "compute_content_hash",
    "compute_json_hash",
    "validate_archive_bundle",
    "PROTOCOL_VERSION",
    "ARCHIVE_SCHEMA_VERSION",
    # Types - Filebase
    "FilebaseConfig",
    # Types - Arweave
    "ArweaveConfig",
    "IrysCurrency",
    "IrysNetwork",
    # Types - Archive Bundle
    "ArchiveBundle",
    "ArchiveChainId",
    "ArchiveFinalState",
    "ArchiveParticipants",
    "ArchiveReferences",
    "ArchiveHashes",
    "ArchiveSignatures",
    "ArchiveAttestation",
    "ArchiveSettlement",
    "EscrowRelease",
    "ArchiveTags",
    "ARCHIVE_BUNDLE_TYPE",
    # Types - Results
    "IPFSUploadResult",
    "ArweaveUploadResult",
    "DownloadResult",
    # Types - Circuit Breaker
    "CircuitBreakerConfig",
    # Dispute — Evidence Bundle serializer (AIP-14b / PRD P2-3)
    "serialize_bundle",
    "serialize_bundle_to_string",
    "bundle_hash",
    "compute_bundle_hash",
    "validate_bundle",
    "assert_supported_version",
    "count_bundle_tokens",
    "enforce_token_cap",
    "set_bundle_tokenizer",
    "pin_evidence_bundle",
    "EVIDENCE_BUNDLE_SCHEMA_VERSION",
    "SUPPORTED_BUNDLE_MAJOR",
    "MAX_BUNDLE_TOKENS",
    "EvidenceBundle",
    "EvidenceBundleSpec",
    "EvidenceBundleDelivery",
    "EvidenceBundleDispute",
    "EvidenceBundleTimelineEvent",
    "EvidenceBundleReasoning",
    "PinEvidenceBundleResult",
    "BundleTooLargeError",
    "UnsupportedBundleVersionError",
    "InvalidBundleError",
    # Negotiation Module
    "DEFAULT_WEIGHTS",
    "PolicyEngine",
    "BuyerPolicy",
    "Constraints",
    "MaxUnitPrice",
    "MaxDailySpend",
    "Negotiation",
    "Selection",
    "QuoteOffer",
    "PolicyViolation",
    "PolicyResult",
    "DecisionEngine",
    "ScoringWeights",
    "CandidateStats",
    "ScoredCandidate",
    "ScoreBreakdown",
    "SessionStore",
    "SessionMapping",
    "BuyerOrchestrator",
    "ProviderPolicyEngine",
    "verify_quote_hash_on_chain",
    "VerifyOnChainResult",
    "RequoteGuardViolation",
    # AIP-16 delivery channel
    "DeliverySetupBuilder",
    "BuildSetupParams",
    "DeliveryEnvelopeBuilder",
    "BuildPublicEnvelopeParams",
    "BuildEncryptedEnvelopeParams",
    "MockDeliveryChannel",
    "MockDeliveryChannelOptions",
    "RelayDeliveryChannel",
    "RelayDeliveryChannelOptions",
    "DeliveryChannel",
    "DeliverySubscription",
    "build_envelope_aad",
    "NegotiationResult",
    "RoundResult",
    "OrchestratorConfig",
]
