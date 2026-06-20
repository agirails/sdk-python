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

import re
import sys
from dataclasses import dataclass
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


# ============================================================================
# x402 v2 (native EIP-3009 / Permit2) — constants + errors
#
# Mirrors sdk-js/src/adapters/X402Adapter.ts + sdk-js/src/errors/X402Errors.ts.
# The legacy custom `x-payment-*` types above are preserved for backward compat
# (see LegacyX402Adapter); the v2 surface below is the canonical path.
# ============================================================================

# DEFAULT_EVM_NETWORKS — X402Adapter.ts:156-163. CAIP-2 keys.
DEFAULT_EVM_NETWORKS = (
    "eip155:1",       # Ethereum mainnet
    "eip155:8453",    # Base mainnet
    "eip155:84532",   # Base Sepolia
    "eip155:10",      # Optimism
    "eip155:42161",   # Arbitrum One
    "eip155:137",     # Polygon
)
"""Default x402 v2 allowed networks (CAIP-2) — maximal interop default."""

# DEFAULT_USDC_BY_NETWORK — X402Adapter.ts:175-182. Lowercase addresses.
DEFAULT_USDC_BY_NETWORK = {
    "eip155:1":     "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # Ethereum USDC
    "eip155:8453":  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # Base USDC
    "eip155:84532": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",  # Base Sepolia USDC
    "eip155:10":    "0x0b2c639c533813f4aa9d7837caf62653d097ff85",  # Optimism USDC
    "eip155:42161": "0xaf88d065e77c8cc2239327c5edb3a432268e5831",  # Arbitrum USDC
    "eip155:137":   "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",  # Polygon USDC
}
"""Canonical USDC contract address per supported EVM network (CAIP-2 keys)."""


# --- x402 v2 errors (1:1 with errors/X402Errors.ts) ----------------------
#
# In TS these extend ACTPError. Python's existing X402Error (above) is a bare
# Exception kept for legacy callers; the v2 errors extend ACTPError to match the
# TS hierarchy and carry machine-readable codes verbatim.

try:
    from agirails.errors.base import ACTPError as _ACTPError
except Exception:  # pragma: no cover - defensive
    _ACTPError = Exception  # type: ignore[assignment,misc]


class X402V2Error(_ACTPError):  # type: ignore[valid-type,misc]
    """Base class for all x402 v2 errors (mirrors TS X402Error : ACTPError)."""

    def __init__(self, message: str, code: str, details: Optional[dict] = None) -> None:
        super().__init__(message, code=code, details=details)
        self.name = "X402Error"


class X402ConfigError(X402V2Error):
    """X402Adapter constructor received invalid config (code X402_CONFIG_ERROR)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_CONFIG_ERROR", details)
        self.name = "X402ConfigError"


class X402PublishRequiredError(X402V2Error):
    """Paymaster rejected sponsorship because the agent isn't published."""

    def __init__(self) -> None:
        super().__init__(
            "Paymaster rejected gas sponsorship because this agent is not published.\n"
            "Run `actp publish` to activate sponsorship, then retry your payment.\n"
            "(One-time setup — subsequent x402 payments will work automatically.)",
            "X402_PUBLISH_REQUIRED",
        )
        self.name = "X402PublishRequiredError"


class X402UnsupportedWalletError(X402V2Error):
    """Smart Wallet tried to pay an EIP-3009-only server (code X402_UNSUPPORTED_WALLET)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_UNSUPPORTED_WALLET", details)
        self.name = "X402UnsupportedWalletError"


class X402NetworkNotAllowedError(X402V2Error):
    """Server offered no network/asset the client allows (code X402_NETWORK_NOT_ALLOWED)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_NETWORK_NOT_ALLOWED", details)
        self.name = "X402NetworkNotAllowedError"


class X402AmountExceededError(X402V2Error):
    """Required amount exceeds maxAmountPerTx cap (code X402_AMOUNT_EXCEEDED)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_AMOUNT_EXCEEDED", details)
        self.name = "X402AmountExceededError"


class X402ApprovalFailedError(X402V2Error):
    """One-time Permit2 approve failed (code X402_APPROVAL_FAILED)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_APPROVAL_FAILED", details)
        self.name = "X402ApprovalFailedError"


class X402SignatureFailedError(X402V2Error):
    """walletProvider.sign_typed_data failed (code X402_SIGNATURE_FAILED)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_SIGNATURE_FAILED", details)
        self.name = "X402SignatureFailedError"


class X402SettlementProofMissingError(X402V2Error):
    """200 OK but no `payment-response` settlement proof (code X402_SETTLEMENT_PROOF_MISSING)."""

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(
            message
            or (
                "Server returned 200 but no `payment-response` header. Settlement is "
                "unconfirmed. This may indicate reorg, facilitator failure, or protocol "
                "mismatch. Do not consider the payment final without on-chain verification."
            ),
            "X402_SETTLEMENT_PROOF_MISSING",
        )
        self.name = "X402SettlementProofMissingError"


class X402PaymentFailedError(X402V2Error):
    """Non-2xx after signing/submitting the payment payload (code X402_PAYMENT_FAILED)."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, "X402_PAYMENT_FAILED", details)
        self.name = "X402PaymentFailedError"


def is_paymaster_gate_error(e: object) -> bool:
    """Detect a paymaster policy-gate error (1:1 with TS isPaymasterGateError).

    Used to convert generic paymaster errors into X402PublishRequiredError.
    """
    if not isinstance(e, BaseException):
        return False
    msg = str(e)
    return bool(
        re.search(
            r"gas sponsorship|paymaster|policy|sponsorship|unauthorized",
            msg,
            re.IGNORECASE,
        )
    )
