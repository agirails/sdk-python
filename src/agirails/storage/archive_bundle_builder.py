"""
Archive Bundle Builder (AIP-7 §4.4)

Fluent builder for creating archive bundles with validation.
"""

from __future__ import annotations

import json
import re
import time
from typing import List, Literal, Optional

from eth_utils import keccak

from agirails.errors.storage import ArchiveBundleValidationError
from agirails.storage.types import (
    ARCHIVE_BUNDLE_TYPE,
    ArchiveAttestation,
    ArchiveBundle,
    ArchiveChainId,
    ArchiveFinalState,
    ArchiveHashes,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveSettlement,
    ArchiveSignatures,
    EscrowRelease,
)


# Current versions
PROTOCOL_VERSION = "1.0.0"
ARCHIVE_SCHEMA_VERSION = "1.0.0"


def compute_content_hash(content: bytes) -> str:
    """
    Compute keccak256 hash of content (Ethereum-compatible).

    Args:
        content: Raw bytes to hash

    Returns:
        Hex-encoded hash with 0x prefix
    """
    return "0x" + keccak(content).hex()


def compute_json_hash(data: dict) -> str:
    """
    Compute keccak256 hash of canonical JSON.

    Args:
        data: Dictionary to hash

    Returns:
        Hex-encoded hash with 0x prefix
    """
    canonical = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return compute_content_hash(canonical.encode("utf-8"))


def _is_valid_address(addr: str) -> bool:
    """Check if address is valid Ethereum address."""
    if not addr or not addr.startswith("0x"):
        return False
    if len(addr) != 42:
        return False
    try:
        int(addr, 16)
        return True
    except ValueError:
        return False


def _is_valid_cid(cid: str) -> bool:
    """Check if CID has valid format."""
    if not cid:
        return False
    # CIDv0 starts with Qm (46 chars)
    if cid.startswith("Qm") and len(cid) == 46:
        return True
    # CIDv1 starts with b (base32, variable length 59+)
    if cid.startswith("b") and len(cid) >= 50:
        return True
    return False


def _is_valid_hash(h: str) -> bool:
    """Check if hash is valid keccak256."""
    if not h or not h.startswith("0x"):
        return False
    if len(h) != 66:
        return False
    try:
        int(h, 16)
        return True
    except ValueError:
        return False


def validate_archive_bundle(bundle: ArchiveBundle) -> bool:
    """
    Validate archive bundle structure and required fields.

    Args:
        bundle: Bundle to validate

    Returns:
        True if valid

    Raises:
        ArchiveBundleValidationError: If validation fails
    """
    errors: List[str] = []

    # Transaction ID validation
    if not bundle.tx_id or not _is_valid_hash(bundle.tx_id):
        errors.append("Invalid tx_id format (must be 0x-prefixed bytes32)")

    # Chain ID validation
    if bundle.chain_id not in (8453, 84532):
        errors.append(f"Invalid chain_id: {bundle.chain_id}")

    # Type validation
    if bundle.type != ARCHIVE_BUNDLE_TYPE:
        errors.append(f"Invalid type: {bundle.type}")

    # Participant validation
    if not _is_valid_address(bundle.participants.requester):
        errors.append("Invalid requester address")
    if not _is_valid_address(bundle.participants.provider):
        errors.append("Invalid provider address")

    # Reference validation (CID format)
    if not _is_valid_cid(bundle.references.request_cid):
        errors.append("Invalid request_cid format")
    if not _is_valid_cid(bundle.references.delivery_cid):
        errors.append("Invalid delivery_cid format")

    # Hash validation (0x-prefixed, 66 chars)
    if not _is_valid_hash(bundle.hashes.request_hash):
        errors.append("Invalid request_hash format")
    if not _is_valid_hash(bundle.hashes.delivery_hash):
        errors.append("Invalid delivery_hash format")
    if not _is_valid_hash(bundle.hashes.service_hash):
        errors.append("Invalid service_hash format")

    # Settlement validation
    if bundle.settlement.final_state not in ("SETTLED", "CANCELLED"):
        errors.append(f"Invalid final_state: {bundle.settlement.final_state}")

    if errors:
        raise ArchiveBundleValidationError(
            f"Archive bundle validation failed: {'; '.join(errors)}"
        )

    return True


class ArchiveBundleBuilder:
    """
    Fluent builder for creating archive bundles.

    Example:
        ```python
        from agirails.storage import ArchiveBundleBuilder

        bundle = (
            ArchiveBundleBuilder()
            .set_transaction_id(tx_id)
            .set_chain_id(8453)
            .set_participants(requester, provider)
            .set_references(request_cid, delivery_cid)
            .set_hashes(request_hash, delivery_hash, service_hash)
            .set_signatures(provider_sig)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=provider,
                escrow_amount=amount,
                platform_fee=fee,
                was_disputed=False,
            )
            .build()
        )
        ```
    """

    def __init__(self) -> None:
        """Initialize builder with empty fields."""
        self._tx_id: Optional[str] = None
        self._chain_id: Optional[ArchiveChainId] = None
        self._archived_at: int = int(time.time())
        self._participants: Optional[ArchiveParticipants] = None
        self._references: Optional[ArchiveReferences] = None
        self._hashes: Optional[ArchiveHashes] = None
        self._signatures: Optional[ArchiveSignatures] = None
        self._attestation: Optional[ArchiveAttestation] = None
        self._settlement: Optional[ArchiveSettlement] = None

    def set_transaction_id(self, tx_id: str) -> ArchiveBundleBuilder:
        """
        Set ACTP transaction ID (bytes32).

        Args:
            tx_id: Transaction ID (0x-prefixed, 66 chars)

        Returns:
            Self for chaining

        Raises:
            ValueError: If tx_id format is invalid
        """
        if not tx_id.startswith("0x") or len(tx_id) != 66:
            raise ValueError("tx_id must be 0x-prefixed bytes32 (66 chars)")
        self._tx_id = tx_id.lower()
        return self

    def set_chain_id(self, chain_id: ArchiveChainId) -> ArchiveBundleBuilder:
        """
        Set blockchain chain ID.

        Args:
            chain_id: Chain ID (8453 for mainnet, 84532 for sepolia)

        Returns:
            Self for chaining

        Raises:
            ValueError: If chain_id is not supported
        """
        if chain_id not in (8453, 84532):
            raise ValueError("chain_id must be 8453 (mainnet) or 84532 (sepolia)")
        self._chain_id = chain_id
        return self

    def set_archived_at(self, timestamp: int) -> ArchiveBundleBuilder:
        """
        Set archive timestamp (Unix seconds).

        Args:
            timestamp: Unix timestamp in seconds

        Returns:
            Self for chaining
        """
        self._archived_at = timestamp
        return self

    def set_participants(
        self,
        requester: str,
        provider: str,
    ) -> ArchiveBundleBuilder:
        """
        Set transaction participants.

        Args:
            requester: Requester Ethereum address
            provider: Provider Ethereum address

        Returns:
            Self for chaining
        """
        self._participants = ArchiveParticipants(
            requester=requester.lower(),
            provider=provider.lower(),
        )
        return self

    def set_references(
        self,
        request_cid: str,
        delivery_cid: str,
        result_cid: Optional[str] = None,
    ) -> ArchiveBundleBuilder:
        """
        Set IPFS CID references.

        Args:
            request_cid: IPFS CID of request metadata
            delivery_cid: IPFS CID of delivery proof
            result_cid: Optional IPFS CID of result

        Returns:
            Self for chaining
        """
        self._references = ArchiveReferences(
            requestCID=request_cid,
            deliveryCID=delivery_cid,
            resultCID=result_cid,
        )
        return self

    def set_hashes(
        self,
        request_hash: str,
        delivery_hash: str,
        service_hash: str,
    ) -> ArchiveBundleBuilder:
        """
        Set cryptographic hashes.

        Args:
            request_hash: keccak256 of request metadata
            delivery_hash: keccak256 of delivery proof
            service_hash: serviceHash from ACTPKernel

        Returns:
            Self for chaining
        """
        self._hashes = ArchiveHashes(
            requestHash=request_hash.lower(),
            deliveryHash=delivery_hash.lower(),
            serviceHash=service_hash.lower(),
        )
        return self

    def set_signatures(
        self,
        provider_delivery_signature: str,
        requester_settlement_signature: Optional[str] = None,
    ) -> ArchiveBundleBuilder:
        """
        Set cryptographic signatures.

        Args:
            provider_delivery_signature: Provider's EIP-712 signature
            requester_settlement_signature: Optional requester signature

        Returns:
            Self for chaining
        """
        self._signatures = ArchiveSignatures(
            providerDeliverySignature=provider_delivery_signature,
            requesterSettlementSignature=requester_settlement_signature,
        )
        return self

    def set_attestation(
        self,
        eas_uid: str,
        schema_uid: Optional[str] = None,
    ) -> ArchiveBundleBuilder:
        """
        Set EAS attestation reference.

        Args:
            eas_uid: Ethereum Attestation Service UID
            schema_uid: Optional schema UID

        Returns:
            Self for chaining
        """
        self._attestation = ArchiveAttestation(
            easUID=eas_uid.lower(),
            schemaUID=schema_uid.lower() if schema_uid else None,
        )
        return self

    def set_settlement(
        self,
        settled_at: int,
        final_state: ArchiveFinalState,
        escrow_to: str,
        escrow_amount: str,
        platform_fee: str,
        was_disputed: bool = False,
    ) -> ArchiveBundleBuilder:
        """
        Set settlement information.

        Args:
            settled_at: Settlement timestamp (Unix seconds)
            final_state: Final state ("SETTLED" or "CANCELLED")
            escrow_to: Recipient address
            escrow_amount: Released amount (string for BigInt safety)
            platform_fee: Platform fee (string for BigInt safety)
            was_disputed: Whether transaction went through dispute

        Returns:
            Self for chaining
        """
        self._settlement = ArchiveSettlement(
            settledAt=settled_at,
            finalState=final_state,
            escrowReleased=EscrowRelease(
                to=escrow_to.lower(),
                amount=escrow_amount,
            ),
            platformFee=platform_fee,
            wasDisputed=was_disputed,
        )
        return self

    def build(self) -> ArchiveBundle:
        """
        Build and validate the archive bundle.

        Returns:
            Validated ArchiveBundle

        Raises:
            ArchiveBundleValidationError: If required fields missing
        """
        # Check required fields
        missing: List[str] = []

        if not self._tx_id:
            missing.append("tx_id")
        if self._chain_id is None:
            missing.append("chain_id")
        if not self._participants:
            missing.append("participants")
        if not self._references:
            missing.append("references")
        if not self._hashes:
            missing.append("hashes")
        if not self._signatures:
            missing.append("signatures")
        if not self._settlement:
            missing.append("settlement")

        if missing:
            raise ArchiveBundleValidationError(
                f"Missing required fields: {', '.join(missing)}"
            )

        # Build bundle
        bundle = ArchiveBundle(
            protocolVersion=PROTOCOL_VERSION,
            archiveSchemaVersion=ARCHIVE_SCHEMA_VERSION,
            type=ARCHIVE_BUNDLE_TYPE,
            txId=self._tx_id,
            chainId=self._chain_id,
            archivedAt=self._archived_at,
            participants=self._participants,
            references=self._references,
            hashes=self._hashes,
            signatures=self._signatures,
            attestation=self._attestation,
            settlement=self._settlement,
        )

        # Validate
        validate_archive_bundle(bundle)

        return bundle
