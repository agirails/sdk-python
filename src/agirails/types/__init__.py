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
    SignedMessage,
    TypedData,
    hash_message,
    create_input_hash,
    create_output_hash,
)
from agirails.types.transaction import (
    Transaction,
    TransactionState,
    TransactionReceipt,
    TransactionFilter,
    is_valid_transition,
    VALID_TRANSITIONS,
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
    "SignedMessage",
    "TypedData",
    "hash_message",
    "create_input_hash",
    "create_output_hash",
    # Transaction types
    "Transaction",
    "TransactionState",
    "TransactionReceipt",
    "TransactionFilter",
    "is_valid_transition",
    "VALID_TRANSITIONS",
]
