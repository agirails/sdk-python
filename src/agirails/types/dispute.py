# PARITY: sdk-js/src/types/dispute.ts
# This file and its TypeScript twin MUST stay 1:1 — same public function/type/enum
# names + arity, same EIP-712 digest, same enum VALUES (Tier/Ruling). Any change
# here (rename, reorder, new export) must be mirrored in the twin and vice versa.
"""
AIP-14b dispute types + AIRuling EIP-712 signing for the AGIRAILS SDK.

This module is the Python half of the cross-language AIRuling signer. It is
1:1 with the TypeScript SDK (`sdk-js/src/types/dispute.ts`): same public API
names + arity, same canonical EIP-712 digest, anchored to the GOLDEN VECTOR.

Source of truth for the encoding:
    Protocol/actp-kernel/src/interfaces/DisputeTypes.sol  (AIRuling struct)
    Protocol/actp-kernel/test/EncodingCanonical.t.sol     (golden vector)

The AIRuling field ORDER is load-bearing — it is hashed into RULING_TYPEHASH,
so any reorder breaks signature verification across the off-chain evaluator,
the SDK, and the on-chain `_verifyEvaluatorSignatures`. Field order matches
AIP-14b §4.4 exactly:

    disputeId, ruling, confidence, splitBps, timestamp, reasoningHash, bundleHash

Golden vector (cross-language anchor, MUST reproduce GOLDEN_DIGEST exactly):
    domain: name="ACTPDisputeEvaluator", version="1", chainId=8453,
            verifyingContract=0x3c68CC8dFe901c7e89eC9f738F9a81709E6e7737
    AIRuling: disputeId=keccak256("ACTP_GOLDEN_VECTOR_DISPUTE"), ruling=1,
              confidence=9500, splitBps=0, timestamp=1700000000,
              reasoningHash=keccak256("golden-reasoning"),
              bundleHash=keccak256("golden-bundle")
    => GOLDEN_DIGEST = 0x9b477852dd1ddad0105ca5e2a320c6ca72105215985b53878ae12b49eb34e365

Example:
    >>> ruling = AIRuling(
    ...     dispute_id="0x...",
    ...     ruling=Ruling.REQUESTER_WINS,
    ...     confidence=9500,
    ...     split_bps=0,
    ...     timestamp=1700000000,
    ...     reasoning_hash="0x...",
    ...     bundle_hash="0x...",
    ... )
    >>> digest = compute_ruling_digest(ruling, chain_id=8453,
    ...                                verifying_contract="0x3c68...")
    >>> sig = sign_ruling(ruling, private_key, chain_id=8453,
    ...                    verifying_contract="0x3c68...")
    >>> signer = recover_ruling_signer(ruling, sig, chain_id=8453,
    ...                                verifying_contract="0x3c68...")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional, Union

from eth_abi import encode as _abi_encode
from eth_account import Account
from eth_utils import keccak as _keccak, to_checksum_address


# ---------------------------------------------------------------------------
# Enums (1:1 with TS SDK Ruling / DisputeTier)
# ---------------------------------------------------------------------------


class Ruling(IntEnum):
    """
    AIRuling.ruling values (INV-1 canonical mapping — load-bearing).

    Matches DisputeTypes.sol:
        0 = provider wins
        1 = requester wins
        2 = split (provider share given by splitBps)
    """

    PROVIDER_WINS = 0
    REQUESTER_WINS = 1
    SPLIT = 2


class Tier(IntEnum):
    """
    AIP-14b dispute escalation tier — 1:1 with the TS ``Tier`` twin AND the
    on-chain ``BondEscalation.sol`` ``d.tier`` field (which is 0-based):

        tier: 0 (opened)  ->  d.tier = 1 (proposal/challenge live)  ->  d.tier = 2 (UMA)

    A ``disputes()`` / ``d.tier`` reader in either SDK MUST classify identically;
    a 1-based enum would alias every on-chain tier value by one and misclassify
    the moment a reader is wired (see the negative-control test pinning
    ``Tier.TIER1 == 1``).

    - ``TIER0`` (0): dispute opened, no proposal yet (bond game not started).
    - ``TIER1`` (1): a direct/AI proposal is live in the challengeable bond game.
    - ``TIER2`` (2): escalated to UMA Optimistic Oracle V3.
    """

    TIER0 = 0
    TIER1 = 1
    TIER2 = 2


# ---------------------------------------------------------------------------
# EIP-712 constants (frozen — match EncodingCanonical.t.sol)
# ---------------------------------------------------------------------------

# keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
#
# REPRESENTATION NOTE: this is `bytes` in Python; the TS twin (`DOMAIN_TYPEHASH`)
# exposes the same constant as a 0x-hex `string`. The underlying 32 bytes are
# identical — compare raw bytes across langs, not the surface type.
DOMAIN_TYPEHASH: bytes = _keccak(
    text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)

# keccak256("AIRuling(bytes32 disputeId,uint8 ruling,uint16 confidence,uint16 splitBps,uint64 timestamp,bytes32 reasoningHash,bytes32 bundleHash)")
#
# REPRESENTATION NOTE: this is `bytes` in Python; the TS twin (`RULING_TYPEHASH`)
# exposes the same constant as a 0x-hex `string`. Cross-language VALUE is
# byte-identical (golden test proves it) — a consumer comparing across langs
# must compare the 32 raw bytes (Py: `RULING_TYPEHASH`,
# TS: `ethers.getBytes(RULING_TYPEHASH)`), NOT the surface type.
RULING_TYPEHASH: bytes = _keccak(
    text="AIRuling(bytes32 disputeId,uint8 ruling,uint16 confidence,uint16 splitBps,uint64 timestamp,bytes32 reasoningHash,bytes32 bundleHash)"
)

# EIP-712 domain identity for the dispute evaluator (AIP-14b §4.5).
# Names mirror the TS twin's `DISPUTE_EVALUATOR_DOMAIN_NAME` / `_VERSION` exactly.
DISPUTE_EVALUATOR_DOMAIN_NAME: str = "ACTPDisputeEvaluator"
DISPUTE_EVALUATOR_DOMAIN_VERSION: str = "1"

# EIP-712 typed-data definition for AIRuling (mirrors the TS `AIRulingTypes`
# const). Field ORDER is load-bearing — it is hashed into RULING_TYPEHASH and is
# the single source the struct hash is derived from.
AIRULING_TYPES: Dict[str, List[Dict[str, str]]] = {
    "AIRuling": [
        {"name": "disputeId", "type": "bytes32"},
        {"name": "ruling", "type": "uint8"},
        {"name": "confidence", "type": "uint16"},
        {"name": "splitBps", "type": "uint16"},
        {"name": "timestamp", "type": "uint64"},
        {"name": "reasoningHash", "type": "bytes32"},
        {"name": "bundleHash", "type": "bytes32"},
    ]
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_bytes32(value: Union[str, bytes]) -> bytes:
    """
    Normalize a bytes32 input (0x-hex string or raw bytes) to exactly 32 bytes.

    Raises:
        ValueError: if the decoded value is not 32 bytes.
    """
    if isinstance(value, bytes):
        raw = value
    else:
        s = value[2:] if value.startswith(("0x", "0X")) else value
        raw = bytes.fromhex(s)
    if len(raw) != 32:
        raise ValueError(f"expected bytes32 (32 bytes), got {len(raw)} bytes")
    return raw


def _normalize_signature(signature: Union[str, bytes]) -> bytes:
    """Normalize a 65-byte signature (0x-hex string or raw bytes) to bytes."""
    if isinstance(signature, bytes):
        return signature
    s = signature[2:] if signature.startswith(("0x", "0X")) else signature
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# EIP712Domain for disputes
# ---------------------------------------------------------------------------


@dataclass
class DisputeEIP712Domain:
    """
    EIP-712 domain for the ACTP dispute evaluator.

    Mirrors the TS SDK domain builder. Defaults to the AIP-14b dispute identity
    (name="ACTPDisputeEvaluator", version="1").
    """

    chain_id: int
    verifying_contract: str
    name: str = DISPUTE_EVALUATOR_DOMAIN_NAME
    version: str = DISPUTE_EVALUATOR_DOMAIN_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (camelCase, for EIP-712 tooling)."""
        return {
            "name": self.name,
            "version": self.version,
            "chainId": self.chain_id,
            "verifyingContract": to_checksum_address(self.verifying_contract),
        }

    def separator(self) -> bytes:
        """Compute the EIP-712 domain separator (32 bytes)."""
        return _keccak(
            _abi_encode(
                ["bytes32", "bytes32", "bytes32", "uint256", "address"],
                [
                    DOMAIN_TYPEHASH,
                    _keccak(text=self.name),
                    _keccak(text=self.version),
                    self.chain_id,
                    to_checksum_address(self.verifying_contract),
                ],
            )
        )


# ---------------------------------------------------------------------------
# AIRuling
# ---------------------------------------------------------------------------


@dataclass
class AIRuling:
    """
    AIP-14b §4.4 AI ruling for EIP-712 signing.

    PARITY CRITICAL: field order is load-bearing and matches DisputeTypes.sol
    AIRuling struct exactly. The TYPE_DEFINITION mirrors the TS SDK.

    Attributes:
        dispute_id:     bytes32 dispute id
        ruling:         uint8 — 0 provider wins, 1 requester wins, 2 split (INV-1)
        confidence:     uint16 — confidence in basis points (0..10000)
        split_bps:      uint16 — provider share when ruling == 2 (basis points)
        timestamp:      uint64 — unix epoch seconds
        reasoning_hash: bytes32 — hash of the evaluator's reasoning
        bundle_hash:    bytes32 — hash of the canonical evidence bundle
    """

    dispute_id: Union[str, bytes]
    ruling: int
    confidence: int
    split_bps: int
    timestamp: int
    reasoning_hash: Union[str, bytes]
    bundle_hash: Union[str, bytes]

    # EIP-712 type constants — MUST match DisputeTypes.sol field order exactly.
    TYPE_NAME = "AIRuling"
    TYPE_DEFINITION = [
        {"name": "disputeId", "type": "bytes32"},
        {"name": "ruling", "type": "uint8"},
        {"name": "confidence", "type": "uint16"},
        {"name": "splitBps", "type": "uint16"},
        {"name": "timestamp", "type": "uint64"},
        {"name": "reasoningHash", "type": "bytes32"},
        {"name": "bundleHash", "type": "bytes32"},
    ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (camelCase) for EIP-712 signing tooling."""
        return {
            "disputeId": self.dispute_id
            if isinstance(self.dispute_id, str)
            else "0x" + self.dispute_id.hex(),
            "ruling": int(self.ruling),
            "confidence": int(self.confidence),
            "splitBps": int(self.split_bps),
            "timestamp": int(self.timestamp),
            "reasoningHash": self.reasoning_hash
            if isinstance(self.reasoning_hash, str)
            else "0x" + self.reasoning_hash.hex(),
            "bundleHash": self.bundle_hash
            if isinstance(self.bundle_hash, str)
            else "0x" + self.bundle_hash.hex(),
        }

    def struct_hash(self) -> bytes:
        """
        Compute the EIP-712 struct hash (32 bytes):

            keccak256(abi.encode(RULING_TYPEHASH, disputeId, ruling, confidence,
                                 splitBps, timestamp, reasoningHash, bundleHash))

        Each field is ABI-encoded (padded to 32 bytes). Field order is load-bearing.
        """
        return _keccak(
            _abi_encode(
                [
                    "bytes32",  # RULING_TYPEHASH
                    "bytes32",  # disputeId
                    "uint8",  # ruling
                    "uint16",  # confidence
                    "uint16",  # splitBps
                    "uint64",  # timestamp
                    "bytes32",  # reasoningHash
                    "bytes32",  # bundleHash
                ],
                [
                    RULING_TYPEHASH,
                    _to_bytes32(self.dispute_id),
                    int(self.ruling),
                    int(self.confidence),
                    int(self.split_bps),
                    int(self.timestamp),
                    _to_bytes32(self.reasoning_hash),
                    _to_bytes32(self.bundle_hash),
                ],
            )
        )


# ---------------------------------------------------------------------------
# DisputeState (1:1 with the TS `DisputeState` interface)
# ---------------------------------------------------------------------------


@dataclass
class DisputeState:
    """
    On-chain dispute state view (AIP-14b) — mirrors the TS ``DisputeState``
    interface. The fields a ``disputes(...)`` reader surfaces from BondEscalation.

    Attributes:
        tx_id:      the transaction this dispute is bound to (bytes32 txId).
        dispute_id: keccak256 dispute identifier (bytes32).
        tier:       current escalation tier (0-based; see :class:`Tier`).
        ruling:     finalized ruling once resolved (``None`` while unresolved).
        split_bps:  provider share in basis points (relevant for ``ruling == 2``).
        resolved:   whether the dispute has been finalized / resolved on-chain.
    """

    tx_id: str
    dispute_id: str
    tier: int
    resolved: bool
    ruling: Optional[int] = None
    split_bps: Optional[int] = None


# ---------------------------------------------------------------------------
# Top-level signing API (1:1 with TS SDK names + arity)
# ---------------------------------------------------------------------------


def dispute_evaluator_domain(
    chain_id: int,
    verifying_contract: str,
) -> DisputeEIP712Domain:
    """
    Build the EIP-712 domain for the dispute evaluator (AIP-14b §4.5).

    Module-level builder mirroring the TS twin's ``disputeEvaluatorDomain``
    (same name + arity). Returns a :class:`DisputeEIP712Domain` pinned to the
    frozen ``ACTPDisputeEvaluator`` / version ``1`` identity.

    Args:
        chain_id: chain the verifying contract is deployed on (e.g. 8453 = Base).
        verifying_contract: the BondEscalation (dispute evaluator) contract address.
    """
    return DisputeEIP712Domain(
        chain_id=chain_id, verifying_contract=verifying_contract
    )


def compute_ruling_struct_hash(ruling: AIRuling) -> bytes:
    """
    Compute the EIP-712 struct hash for an AIRuling
    (``keccak256(abi.encode(RULING_TYPEHASH, ...fields))``).

    Module-level free function mirroring the TS twin's ``computeRulingStructHash``
    (same name + arity); delegates to :meth:`AIRuling.struct_hash`.

    Returns:
        32-byte struct hash.
    """
    return ruling.struct_hash()


def compute_ruling_domain_separator(
    chain_id: int,
    verifying_contract: str,
) -> bytes:
    """
    Compute the EIP-712 domain separator for the dispute-evaluator domain
    (``keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(name), keccak256(version),
    chainId, verifyingContract))``).

    Module-level free function mirroring the TS twin's
    ``computeRulingDomainSeparator`` (same name + arity); delegates to
    :meth:`DisputeEIP712Domain.separator`.

    Returns:
        32-byte domain separator.
    """
    return dispute_evaluator_domain(chain_id, verifying_contract).separator()


def compute_ruling_digest(
    ruling: AIRuling,
    chain_id: int,
    verifying_contract: str,
) -> bytes:
    """
    Compute the EIP-712 digest for an AIRuling.

        digest = keccak256(0x1901 || DOMAIN_SEPARATOR || structHash)

    Mirrors the TS SDK `computeRulingDigest`. The digest is exactly what the
    on-chain `submitAIRuling` path verifies — sign THIS to produce an
    on-chain-verifiable ruling.

    Args:
        ruling: the AIRuling to hash.
        chain_id: EIP-712 domain chain id (e.g. 8453 for Base mainnet).
        verifying_contract: the dispute contract address (BondEscalation).

    Returns:
        32-byte EIP-712 digest.
    """
    domain = DisputeEIP712Domain(
        chain_id=chain_id, verifying_contract=verifying_contract
    )
    return _keccak(b"\x19\x01" + domain.separator() + ruling.struct_hash())


def sign_ruling(
    ruling: AIRuling,
    private_key: Union[str, bytes],
    chain_id: int,
    verifying_contract: str,
) -> str:
    """
    Sign an AIRuling, producing a 65-byte (r||s||v) signature over the EIP-712
    digest. Mirrors the TS SDK `signRuling`.

    Args:
        ruling: the AIRuling to sign.
        private_key: evaluator private key (0x-hex string or raw bytes).
        chain_id: EIP-712 domain chain id.
        verifying_contract: the dispute contract address.

    Returns:
        0x-prefixed hex signature (65 bytes, canonical r||s||v).
    """
    digest = compute_ruling_digest(ruling, chain_id, verifying_contract)
    account = Account.from_key(private_key)
    signed = account.unsafe_sign_hash(digest)
    return signed.signature.hex() if signed.signature.hex().startswith("0x") else "0x" + signed.signature.hex()


def recover_ruling_signer(
    ruling: AIRuling,
    signature: Union[str, bytes],
    chain_id: int,
    verifying_contract: str,
) -> str:
    """
    Recover the signer address from an AIRuling signature. Mirrors the TS SDK
    `recoverRulingSigner`.

    Args:
        ruling: the AIRuling that was signed.
        signature: 65-byte signature (0x-hex string or raw bytes).
        chain_id: EIP-712 domain chain id.
        verifying_contract: the dispute contract address.

    Returns:
        Checksummed signer address.
    """
    digest = compute_ruling_digest(ruling, chain_id, verifying_contract)
    sig = _normalize_signature(signature)
    return Account._recover_hash(digest, signature=sig)


__all__ = [
    # Enums
    "Ruling",
    "Tier",
    # Types
    "AIRuling",
    "DisputeState",
    "DisputeEIP712Domain",
    # Constants
    "DOMAIN_TYPEHASH",
    "RULING_TYPEHASH",
    "AIRULING_TYPES",
    "DISPUTE_EVALUATOR_DOMAIN_NAME",
    "DISPUTE_EVALUATOR_DOMAIN_VERSION",
    # Domain / digest helpers (1:1 with TS standalone functions)
    "dispute_evaluator_domain",
    "compute_ruling_struct_hash",
    "compute_ruling_domain_separator",
    # Signing API
    "compute_ruling_digest",
    "sign_ruling",
    "recover_ruling_signer",
]
