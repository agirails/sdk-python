"""
Network and blockchain-related exceptions for ACTP protocol.

These exceptions are raised during blockchain interactions,
including transaction submission, signature verification,
and network connectivity issues.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agirails.errors.base import ACTPError


class NetworkError(ACTPError):
    """
    Raised when a network or RPC error occurs.

    This can include:
    - RPC endpoint unavailable
    - Connection timeouts
    - Rate limiting
    - Invalid responses

    Example:
        >>> raise NetworkError("RPC endpoint timeout", endpoint="https://rpc.base.org")
    """

    def __init__(
        self,
        message: str,
        *,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if endpoint:
            details["endpoint"] = endpoint
        if status_code is not None:
            details["status_code"] = status_code

        super().__init__(
            message,
            code="NETWORK_ERROR",
            details=details,
        )
        self.endpoint = endpoint
        self.status_code = status_code


class TransactionRevertedError(ACTPError):
    """
    Raised when a blockchain transaction reverts.

    Includes the revert reason if available from the contract.

    Example:
        >>> raise TransactionRevertedError(
        ...     "0x123...",
        ...     revert_reason="Insufficient balance"
        ... )
    """

    def __init__(
        self,
        tx_hash: str,
        *,
        revert_reason: Optional[str] = None,
        gas_used: Optional[int] = None,
        block_number: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if revert_reason:
            details["revert_reason"] = revert_reason
        if gas_used is not None:
            details["gas_used"] = gas_used
        if block_number is not None:
            details["block_number"] = block_number

        message = f"Transaction reverted: {tx_hash[:18]}..."
        if revert_reason:
            message += f" - {revert_reason}"

        super().__init__(
            message,
            code="TRANSACTION_REVERTED",
            tx_hash=tx_hash,
            details=details,
        )
        self.revert_reason = revert_reason
        self.gas_used = gas_used
        self.block_number = block_number


class SignatureVerificationError(ACTPError):
    """
    Raised when a cryptographic signature verification fails.

    This can occur during:
    - EIP-712 message verification
    - Delivery proof verification
    - Quote signature verification

    Example:
        >>> raise SignatureVerificationError(
        ...     "Invalid quote signature",
        ...     expected_signer="0xProvider...",
        ...     actual_signer="0xAttacker..."
        ... )
    """

    def __init__(
        self,
        message: str,
        *,
        expected_signer: Optional[str] = None,
        actual_signer: Optional[str] = None,
        signature: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if expected_signer:
            details["expected_signer"] = expected_signer
        if actual_signer:
            details["actual_signer"] = actual_signer
        if signature:
            # Only include first/last 8 chars of signature for security
            details["signature_preview"] = f"{signature[:10]}...{signature[-8:]}"

        super().__init__(
            message,
            code="SIGNATURE_VERIFICATION_FAILED",
            details=details,
        )
        self.expected_signer = expected_signer
        self.actual_signer = actual_signer
