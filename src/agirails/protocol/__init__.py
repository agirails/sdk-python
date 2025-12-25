"""
Protocol modules for blockchain interaction.

This module provides contract wrappers for the ACTP protocol:
- ACTPKernel: Main transaction state machine
- EscrowVault: Fund management
- EventMonitor: Blockchain event monitoring
- NonceManager: Transaction nonce management
- MessageSigner: EIP-712 message signing
- ProofGenerator: Content hashing and proofs
- EASHelper: Ethereum Attestation Service
- AgentRegistry: Agent discovery and management
- DIDManager: Decentralized identity

Note: Many modules require web3 and eth_account packages.
If they are not installed, the imports will fail gracefully.
"""

# Modules that don't require web3
from agirails.protocol.messages import (
    MessageSigner,
    SignatureComponents,
    hash_typed_data,
    create_typed_data,
    HAS_ETH_ACCOUNT as HAS_MESSAGES,
)
from agirails.protocol.proofs import (
    ProofGenerator,
    ContentProof,
    MerkleProof,
    verify_merkle_proof,
    hash_service_input,
    hash_service_output,
)
from agirails.protocol.did import (
    DIDManager,
    DIDResolver,
    VerificationMethod,
    ServiceEndpoint,
    create_did_from_address,
    did_to_address,
)

# Base exports (always available)
__all__ = [
    # Messages (partial functionality without eth_account)
    "MessageSigner",
    "SignatureComponents",
    "hash_typed_data",
    "create_typed_data",
    "HAS_MESSAGES",
    # Proofs
    "ProofGenerator",
    "ContentProof",
    "MerkleProof",
    "verify_merkle_proof",
    "hash_service_input",
    "hash_service_output",
    # DID
    "DIDManager",
    "DIDResolver",
    "VerificationMethod",
    "ServiceEndpoint",
    "create_did_from_address",
    "did_to_address",
]

# Protocol modules that require web3 - make imports conditional
try:
    from agirails.protocol.escrow import (
        CreateEscrowParams,
        EscrowInfo,
        EscrowVault,
        generate_escrow_id,
    )
    from agirails.protocol.events import (
        ACTPEvent,
        EscrowCreatedEvent,
        EscrowPayoutEvent,
        EventFilter,
        EventMonitor,
        EventType,
        StateTransitionedEvent,
        TransactionCreatedEvent,
    )
    from agirails.protocol.kernel import (
        ACTPKernel,
        CreateTransactionParams,
        TransactionView,
    )
    from agirails.protocol.nonce import (
        NonceManager,
        NonceManagerPool,
    )
    from agirails.protocol.eas import (
        EASHelper,
        Attestation,
        DeliveryAttestationData,
        Schema,
        DELIVERY_SCHEMA,
        ZERO_BYTES32,
    )
    from agirails.protocol.agent_registry import (
        AgentRegistry,
        AgentProfile,
        ServiceDescriptor,
        compute_service_type_hash,
    )

    __all__.extend([
        # Kernel
        "ACTPKernel",
        "CreateTransactionParams",
        "TransactionView",
        # Escrow
        "EscrowVault",
        "CreateEscrowParams",
        "EscrowInfo",
        "generate_escrow_id",
        # Events
        "EventMonitor",
        "EventFilter",
        "EventType",
        "ACTPEvent",
        "TransactionCreatedEvent",
        "StateTransitionedEvent",
        "EscrowCreatedEvent",
        "EscrowPayoutEvent",
        # Nonce
        "NonceManager",
        "NonceManagerPool",
        # EAS
        "EASHelper",
        "Attestation",
        "DeliveryAttestationData",
        "Schema",
        "DELIVERY_SCHEMA",
        "ZERO_BYTES32",
        # Agent Registry
        "AgentRegistry",
        "AgentProfile",
        "ServiceDescriptor",
        "compute_service_type_hash",
    ])

except ImportError:
    # web3/eth_account not installed - blockchain protocol modules not available
    pass
