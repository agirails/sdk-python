"""
X402 Protocol Types and Constants.

Defines types for the HTTP 402 Payment Required protocol implementation.
X402 enables atomic, instant API payments - NO escrow, NO state machine.

Key difference from ACTP:
- ACTP: escrow -> state machine -> disputes -> explicit release
- x402: atomic payment -> instant settlement -> done

Flow:
1. Client requests protected HTTPS endpoint -> gets 402 response
2. Parse X-Payment-* headers (address, amount, network, deadline)
3. Execute atomic USDC transfer to provider (no escrow!)
4. Retry request with tx hash as proof
5. Return response - payment complete, no release needed

Use x402 for: Simple API calls, instant delivery, low-value transactions
Use ACTP for: Complex services, dispute protection, high-value transactions

@module types/x402
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


# ============================================================================
# X402 Header Constants
# ============================================================================

X402_HEADERS = {
    "REQUIRED": "x-payment-required",
    "ADDRESS": "x-payment-address",
    "AMOUNT": "x-payment-amount",
    "NETWORK": "x-payment-network",
    "TOKEN": "x-payment-token",
    "DEADLINE": "x-payment-deadline",
    "SERVICE_ID": "x-service-id",
}
"""Standard X402 payment headers sent in 402 responses."""

X402_PROOF_HEADERS = {
    "TX_ID": "x-payment-tx-id",
    "ESCROW_ID": "x-payment-escrow-id",
}
"""Proof headers sent when retrying with payment."""

# ============================================================================
# X402 Literal Types
# ============================================================================

X402Network = Literal["base-mainnet", "base-sepolia"]
"""Supported networks for x402 payments."""

X402HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH"]
"""Supported HTTP methods for x402 requests."""

VALID_X402_NETWORKS = {"base-mainnet", "base-sepolia"}
"""Set of valid X402 network strings for validation."""


def is_valid_x402_network(network: str) -> bool:
    """Check if a network string is a valid X402Network."""
    return network in VALID_X402_NETWORKS


# ============================================================================
# X402 Data Classes
# ============================================================================


@dataclass
class X402PaymentHeaders:
    """
    Parsed payment headers from HTTP 402 response.

    Contains all information needed to execute an atomic payment
    for the requested resource.

    Attributes:
        required: Whether payment is required (always True for valid 402).
        payment_address: Provider's wallet address (0x-prefixed, lowercased).
        amount: Amount in USDC wei (6 decimals, as string).
        network: Target network.
        token: Token type (always 'USDC').
        deadline: Unix timestamp deadline for accepting payment.
        service_id: Optional service identifier for tracking.
    """

    required: bool
    payment_address: str
    amount: str
    network: str
    token: str
    deadline: int
    service_id: Optional[str] = None


@dataclass
class X402FeeBreakdown:
    """
    Fee breakdown for x402 payments routed through X402Relay.

    Shows how the gross amount was split between provider and platform.
    Fee = max(grossAmount * feeBps / 10000, MIN_FEE).

    NOTE: This is a client-side estimate computed from the configured
    platformFeeBps. The on-chain X402Relay contract is the source of truth.

    Attributes:
        gross_amount: Total amount from the 402 header (USDC wei).
        provider_net: Estimated amount provider received.
        platform_fee: Estimated amount treasury received.
        fee_bps: Fee rate used for estimate (basis points, e.g. 100 = 1%).
        estimated: True -- this is a client-side estimate, not read from chain.
    """

    gross_amount: str
    provider_net: str
    platform_fee: str
    fee_bps: int
    estimated: bool = True


# ============================================================================
# X402 Error Handling
# ============================================================================


class X402ErrorCode(Enum):
    """Error codes for X402 protocol failures."""

    NOT_402_RESPONSE = "NOT_402_RESPONSE"
    MISSING_HEADERS = "MISSING_HEADERS"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    INVALID_AMOUNT = "INVALID_AMOUNT"
    INVALID_NETWORK = "INVALID_NETWORK"
    NETWORK_MISMATCH = "NETWORK_MISMATCH"
    DEADLINE_PASSED = "DEADLINE_PASSED"
    PAYMENT_FAILED = "PAYMENT_FAILED"
    RETRY_FAILED = "RETRY_FAILED"
    INSECURE_PROTOCOL = "INSECURE_PROTOCOL"


class X402Error(Exception):
    """
    Custom error for X402 protocol failures.

    Provides structured error information for debugging and error handling.

    Attributes:
        code: Error code for programmatic handling.
        response: Optional HTTP response that triggered the error.

    Example::

        try:
            await x402_adapter.pay(params)
        except X402Error as e:
            if e.code == X402ErrorCode.NETWORK_MISMATCH:
                print(f"Wrong network: {e}")
    """

    def __init__(
        self,
        message: str,
        code: X402ErrorCode,
        response: object = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.response = response

    def __str__(self) -> str:
        return f"X402Error [{self.code.value}]: {super().__str__()}"


# ============================================================================
# Type Guards
# ============================================================================


def is_x402_error(error: BaseException) -> bool:
    """Check if an error is an X402Error."""
    return isinstance(error, X402Error)
