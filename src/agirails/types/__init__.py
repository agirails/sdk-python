"""
AGIRAILS SDK Type Definitions.

Provides core types used throughout the SDK:
- DID types for agent identity
- Message types for EIP-712 signing
- Transaction types for ACTP protocol
"""

from agirails.types.did import (
    AgentDID,
    DIDDocument,
    DIDMethod,
    DIDNetwork,
    is_valid_did,
    parse_did,
)
from agirails.types.message import (
    EIP712Domain,
    ServiceRequest,
    ServiceResponse,
    DeliveryProof,
    DeliveryProofMessage,
    DeliveryProofMetadata,
    SignedMessage,
    TypedData,
    hash_message,
    create_input_hash,
    create_output_hash,
    compute_result_hash,
)
from agirails.types.transaction import (
    Transaction,
    TransactionState,
    TransactionReceipt,
    TransactionFilter,
    is_valid_transition,
    VALID_TRANSITIONS,
)
from agirails.types.dispute import (
    Ruling,
    Tier,
    AIRuling,
    DisputeState,
    DisputeEIP712Domain,
    DOMAIN_TYPEHASH,
    RULING_TYPEHASH,
    AIRULING_TYPES,
    DISPUTE_EVALUATOR_DOMAIN_NAME,
    DISPUTE_EVALUATOR_DOMAIN_VERSION,
    dispute_evaluator_domain,
    compute_ruling_struct_hash,
    compute_ruling_domain_separator,
    compute_ruling_digest,
    sign_ruling,
    recover_ruling_signer,
)

__all__ = [
    # DID types
    "AgentDID",
    "DIDDocument",
    "DIDMethod",
    "DIDNetwork",
    "is_valid_did",
    "parse_did",
    # Message types
    "EIP712Domain",
    "ServiceRequest",
    "ServiceResponse",
    "DeliveryProof",
    "DeliveryProofMessage",
    "DeliveryProofMetadata",
    "SignedMessage",
    "TypedData",
    "hash_message",
    "create_input_hash",
    "create_output_hash",
    "compute_result_hash",
    # Transaction types
    "Transaction",
    "TransactionState",
    "TransactionReceipt",
    "TransactionFilter",
    "is_valid_transition",
    "VALID_TRANSITIONS",
    # Dispute types (AIP-14b AIRuling EIP-712)
    "Ruling",
    "Tier",
    "AIRuling",
    "DisputeState",
    "DisputeEIP712Domain",
    "DOMAIN_TYPEHASH",
    "RULING_TYPEHASH",
    "AIRULING_TYPES",
    "DISPUTE_EVALUATOR_DOMAIN_NAME",
    "DISPUTE_EVALUATOR_DOMAIN_VERSION",
    "dispute_evaluator_domain",
    "compute_ruling_struct_hash",
    "compute_ruling_domain_separator",
    "compute_ruling_digest",
    "sign_ruling",
    "recover_ruling_signer",
]
