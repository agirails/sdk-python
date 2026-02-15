"""
X402Adapter - HTTP 402 Payment Required Protocol (Atomic Payments).

Implements the x402 protocol for atomic, instant API payments.
NO escrow, NO state machine, NO disputes - just pay and receive.

This is fundamentally different from ACTP:
- ACTP: escrow -> state machine -> disputes -> explicit release
- x402: atomic payment -> instant settlement -> done

Use x402 for:
- Simple API calls (pay-per-request)
- Instant delivery (response IS the delivery)
- Low-value, high-frequency transactions

Use ACTP for:
- Complex services requiring verification
- High-value transactions needing dispute protection
- Multi-step deliveries

@module adapters/x402_adapter
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Optional,
    Union,
)
from urllib.parse import urlparse

import httpx

from agirails.adapters.types import AdapterMetadata, UnifiedPayParams
from agirails.types.x402 import (
    X402_HEADERS,
    X402_PROOF_HEADERS,
    X402ErrorCode,
    X402Error,
    X402FeeBreakdown,
    X402HttpMethod,
    X402PaymentHeaders,
    is_valid_x402_network,
)


# ============================================================================
# Type Aliases
# ============================================================================

TransferFunction = Callable[[str, str], Awaitable[str]]
"""(to, amount) -> tx_hash. Direct atomic USDC transfer."""

ApproveFunction = Callable[[str, str], Awaitable[str]]
"""(spender, amount) -> tx_hash. USDC approval for relay contract."""

RelayPayFunction = Callable[[str, str, str], Awaitable[str]]
"""(provider, grossAmount, serviceId) -> tx_hash. Relay payWithFee call."""

FetchFunction = Callable[..., Awaitable[httpx.Response]]
"""Custom fetch function signature for testing."""


# ============================================================================
# Configuration
# ============================================================================


@dataclass
class X402AdapterConfig:
    """
    Configuration options for X402Adapter.

    For fee-enabled payments via X402Relay, provide relay_address + approve_fn
    + relay_pay_fn. Without relay config, falls back to direct transfer (no fee).

    Attributes:
        expected_network: Expected network for validation.
        transfer_fn: Transfer function for direct atomic payments (legacy).
        request_timeout: Request timeout in seconds (default: 30).
        fetch_fn: Custom fetch function for testing (default: httpx).
        default_headers: Default headers for all requests.
        relay_address: X402Relay contract address for fee splitting.
        approve_fn: USDC approve function (required when relay_address is set).
        relay_pay_fn: Relay payWithFee function (required when relay_address is set).
        platform_fee_bps: Platform fee in basis points (default: 100 = 1%).
    """

    expected_network: str  # X402Network
    transfer_fn: TransferFunction
    request_timeout: float = 30.0
    fetch_fn: Optional[FetchFunction] = None
    default_headers: Optional[Dict[str, str]] = None
    relay_address: Optional[str] = None
    approve_fn: Optional[ApproveFunction] = None
    relay_pay_fn: Optional[RelayPayFunction] = None
    platform_fee_bps: int = 100


# ============================================================================
# Pay Parameters (x402-specific extensions)
# ============================================================================


@dataclass
class X402PayParams(UnifiedPayParams):
    """
    Extended payment parameters for x402 with full HTTP support.

    Attributes:
        method: HTTP method (default: GET).
        headers: Custom request headers.
        body: Request body (string or dict, will be JSON-serialized if dict).
        content_type: Content-Type header.
    """

    method: X402HttpMethod = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Union[str, Dict[str, Any]]] = None
    content_type: Optional[str] = None


# ============================================================================
# Pay Result
# ============================================================================


@dataclass
class X402PayResult:
    """
    Result from x402 atomic payment.

    Attributes:
        tx_id: Transaction hash (proof of payment).
        escrow_id: Always None (no escrow for x402).
        adapter: Adapter ID ('x402').
        state: Always 'COMMITTED' (atomic = immediately settled).
        success: Whether payment succeeded.
        amount: Human-readable amount string.
        response: The HTTP response from the retry request.
        release_required: Always False (no escrow).
        provider: Provider address (lowercased).
        requester: Requester address (lowercased).
        deadline: ISO 8601 deadline string.
        fee_breakdown: Optional fee breakdown (when using relay).
    """

    tx_id: str
    escrow_id: Optional[str]
    adapter: str
    state: str
    success: bool
    amount: str
    response: Optional[httpx.Response]
    release_required: bool
    provider: str
    requester: str
    deadline: str
    fee_breakdown: Optional[X402FeeBreakdown] = None


# ============================================================================
# Atomic Payment Record (local cache)
# ============================================================================


@dataclass
class _AtomicPaymentRecord:
    """Internal record for status lookups."""

    tx_hash: str
    provider: str
    requester: str
    amount: str
    timestamp: int
    endpoint: str
    fee_breakdown: Optional[X402FeeBreakdown] = None


# ============================================================================
# Address Validation (standalone, no BaseAdapter dependency)
# ============================================================================

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + "0" * 40


def _validate_address(address: str, field_name: str = "address") -> str:
    """Validate and normalize an Ethereum address."""
    if not address or not _ADDRESS_RE.match(address):
        raise ValueError(f"Invalid {field_name}: must be 0x followed by 40 hex characters")
    normalized = address.lower()
    if normalized == _ZERO_ADDRESS:
        raise ValueError(f"{field_name} cannot be zero address")
    return normalized


def _format_amount(wei: Union[int, str]) -> str:
    """Format USDC wei to human-readable string (6 decimals)."""
    wei_int = int(wei)
    whole = wei_int // 1_000_000
    frac = wei_int % 1_000_000
    if frac == 0:
        return f"{whole}.00 USDC"
    frac_str = f"{frac:06d}".rstrip("0")
    return f"{whole}.{frac_str} USDC"


# ============================================================================
# X402Adapter Implementation
# ============================================================================


class X402Adapter:
    """
    X402Adapter - Atomic HTTP payment protocol.

    Key characteristics:
    - usesEscrow: False (direct payment)
    - supportsDisputes: False (atomic = final)
    - releaseRequired: False (no escrow to release)
    - priority: 70

    Example::

        adapter = X402Adapter("0x1111...", X402AdapterConfig(
            expected_network="base-sepolia",
            transfer_fn=my_transfer_fn,
        ))

        result = await adapter.pay(UnifiedPayParams(
            to="https://api.provider.com/service",
            amount="10",
        ))
        # Done! No release() needed.
        print(result.response.status_code)  # 200
        print(result.release_required)       # False
    """

    metadata: AdapterMetadata = AdapterMetadata(
        id="x402",
        priority=70,
        uses_escrow=False,
        supports_disputes=False,
        release_required=False,
    )

    def __init__(
        self,
        requester_address: str,
        config: X402AdapterConfig,
    ) -> None:
        """
        Create a new X402Adapter instance.

        Args:
            requester_address: The requester's Ethereum address.
            config: X402-specific configuration.
        """
        self._requester_address = requester_address.lower()
        self._config = config
        self._timeout = config.request_timeout
        self._default_headers = config.default_headers or {}
        self._transfer_fn = config.transfer_fn
        self._payments: Dict[str, _AtomicPaymentRecord] = {}

    # ========================================================================
    # IAdapter Implementation
    # ========================================================================

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """
        Check if this adapter can handle the given parameters.

        X402Adapter handles HTTPS URLs only (security requirement).
        """
        to = params.to
        if not isinstance(to, str):
            return False
        try:
            parsed = urlparse(to)
            return parsed.scheme == "https"
        except Exception:
            return False

    def validate(self, params: UnifiedPayParams) -> None:
        """
        Validate parameters before execution.

        Raises:
            X402Error: If URL is not HTTPS or contains embedded credentials.
        """
        if not self.can_handle(params):
            raise X402Error(
                f'X402 requires HTTPS URL, got: "{params.to}". '
                f"HTTP endpoints are not supported for security reasons.",
                X402ErrorCode.INSECURE_PROTOCOL,
            )

        parsed = urlparse(params.to)
        if parsed.username or parsed.password:
            raise X402Error(
                "URL cannot contain embedded credentials (username:password).",
                X402ErrorCode.MISSING_HEADERS,
            )

    async def pay(
        self, params: Union[UnifiedPayParams, X402PayParams]
    ) -> X402PayResult:
        """
        Execute atomic x402 payment flow with full HTTP support.

        1. Request endpoint -> get 402
        2. Parse payment headers
        3. Execute atomic USDC transfer
        4. Retry with tx hash as proof (same method/headers/body)
        5. Return response (settlement complete!)

        Args:
            params: Payment parameters with optional HTTP method, headers, body.

        Returns:
            X402PayResult with transaction details and response.

        Raises:
            X402Error: On protocol errors (network mismatch, deadline, etc.).
        """
        self.validate(params)

        endpoint = params.to

        # Extract HTTP options if X402PayParams
        method: X402HttpMethod = "GET"
        request_headers: Dict[str, str] = {}
        request_body: Optional[str] = None
        content_type: Optional[str] = None

        if isinstance(params, X402PayParams):
            method = params.method or "GET"
            request_headers = params.headers or {}
            request_body = self._serialize_body(params.body, params.content_type)
            content_type = params.content_type
            if content_type is None and params.body and method != "GET":
                content_type = "application/json"

        # Step 1: Initial request
        initial_response = await self._make_request(
            endpoint, method, request_headers, request_body, content_type
        )

        # Step 2: Check response status
        if initial_response.status_code != 402:
            if 200 <= initial_response.status_code < 300:
                return self._create_free_service_result(params, initial_response)
            raise X402Error(
                f"Expected 402 Payment Required, got {initial_response.status_code}",
                X402ErrorCode.NOT_402_RESPONSE,
                initial_response,
            )

        # Step 3: Parse payment headers
        payment_headers = self._parse_payment_headers(initial_response)

        # Step 4: Validate network
        if payment_headers.network != self._config.expected_network:
            raise X402Error(
                f"Network mismatch: expected {self._config.expected_network}, "
                f"got {payment_headers.network}",
                X402ErrorCode.NETWORK_MISMATCH,
                initial_response,
            )

        # Step 5: Validate deadline
        now = int(time.time())
        if payment_headers.deadline <= now:
            from datetime import datetime, timezone

            deadline_str = datetime.fromtimestamp(
                payment_headers.deadline, tz=timezone.utc
            ).isoformat()
            raise X402Error(
                f"Payment deadline has passed: {deadline_str}",
                X402ErrorCode.DEADLINE_PASSED,
                initial_response,
            )

        # Step 6: ATOMIC PAYMENT
        tx_hash, fee_breakdown = await self._execute_atomic_payment(payment_headers)

        # Step 7: Retry with proof
        service_response = await self._retry_with_proof(
            endpoint, tx_hash, method, request_headers, request_body, content_type
        )

        # Step 8: Cache payment record
        self._payments[tx_hash] = _AtomicPaymentRecord(
            tx_hash=tx_hash,
            provider=payment_headers.payment_address.lower(),
            requester=self._requester_address,
            amount=payment_headers.amount,
            timestamp=now,
            endpoint=endpoint,
            fee_breakdown=fee_breakdown,
        )

        # Step 9: Return result
        from datetime import datetime, timezone

        deadline_iso = datetime.fromtimestamp(
            payment_headers.deadline, tz=timezone.utc
        ).isoformat()

        return X402PayResult(
            tx_id=tx_hash,
            escrow_id=None,
            adapter=self.metadata.id,
            state="COMMITTED",
            success=True,
            amount=_format_amount(payment_headers.amount),
            response=service_response,
            release_required=False,
            provider=payment_headers.payment_address.lower(),
            requester=self._requester_address,
            deadline=deadline_iso,
            fee_breakdown=fee_breakdown,
        )

    async def get_status(self, tx_id: str) -> Dict[str, Any]:
        """
        Get payment status by transaction hash.

        For atomic payments, status is simple:
        - If tx exists -> SETTLED (atomic = instant settlement)

        Args:
            tx_id: Transaction hash.

        Returns:
            Status dict with state and action flags.

        Raises:
            ValueError: If payment not found.
        """
        record = self._payments.get(tx_id)
        if record is None:
            raise ValueError(
                f"Payment {tx_id} not found. X402 payments are atomic and stateless."
            )
        return {
            "state": "SETTLED",
            "can_start_work": False,
            "can_deliver": False,
            "can_release": False,
            "can_dispute": False,
            "amount": _format_amount(record.amount),
            "provider": record.provider,
            "requester": record.requester,
        }

    async def start_work(self, tx_id: str) -> None:
        """Not applicable for atomic payments.

        Raises:
            RuntimeError: Always - x402 has no lifecycle.
        """
        raise RuntimeError(
            "X402 is atomic - no lifecycle methods. "
            "Payment and delivery happen atomically. Use ACTP for stateful transactions."
        )

    async def deliver(self, tx_id: str, proof: Optional[str] = None) -> None:
        """Not applicable for atomic payments.

        Raises:
            RuntimeError: Always - x402 has no lifecycle.
        """
        raise RuntimeError(
            "X402 is atomic - no lifecycle methods. "
            "The HTTP response IS the delivery. Use ACTP for stateful transactions."
        )

    async def release(self, escrow_id: str, attestation_uid: Optional[str] = None) -> None:
        """Not applicable for atomic payments.

        Raises:
            RuntimeError: Always - x402 has no escrow.
        """
        raise RuntimeError(
            "X402 is atomic - no escrow to release. "
            "Payment settled instantly. Use ACTP for escrow-based transactions."
        )

    # ========================================================================
    # Private Helpers
    # ========================================================================

    async def _make_request(
        self,
        url: str,
        method: X402HttpMethod = "GET",
        custom_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
        proof_headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make an HTTP request with full options support."""
        headers: Dict[str, str] = dict(self._default_headers)

        if custom_headers:
            headers.update(custom_headers)
        if content_type:
            headers["content-type"] = content_type
        if proof_headers:
            headers.update(proof_headers)

        # Use custom fetch function if provided (for testing)
        if self._config.fetch_fn is not None:
            return await self._config.fetch_fn(
                url,
                method=method,
                headers=headers,
                content=body.encode() if body and method != "GET" else None,
            )

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            kwargs: Dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers,
            }
            if body and method != "GET":
                kwargs["content"] = body.encode()

            return await client.request(**kwargs)

    def _parse_payment_headers(self, response: httpx.Response) -> X402PaymentHeaders:
        """Parse X-Payment-* headers from 402 response."""
        h = response.headers

        # Check required header
        required_val = h.get(X402_HEADERS["REQUIRED"])
        if not required_val or required_val.lower() != "true":
            raise X402Error(
                f"Missing or invalid {X402_HEADERS['REQUIRED']} header",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )

        address = h.get(X402_HEADERS["ADDRESS"])
        amount = h.get(X402_HEADERS["AMOUNT"])
        network = h.get(X402_HEADERS["NETWORK"])
        token = h.get(X402_HEADERS["TOKEN"])
        deadline = h.get(X402_HEADERS["DEADLINE"])

        if not address:
            raise X402Error(
                f"Missing {X402_HEADERS['ADDRESS']}",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        if not amount:
            raise X402Error(
                f"Missing {X402_HEADERS['AMOUNT']}",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        if not network:
            raise X402Error(
                f"Missing {X402_HEADERS['NETWORK']}",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        if not token:
            raise X402Error(
                f"Missing {X402_HEADERS['TOKEN']}",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        if not deadline:
            raise X402Error(
                f"Missing {X402_HEADERS['DEADLINE']}",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )

        # Validate address
        validated_address = self._validate_payment_address(address, response)

        # Validate amount
        if not re.match(r"^\d+$", amount):
            raise X402Error(
                f'Invalid {X402_HEADERS["AMOUNT"]}: "{amount}"',
                X402ErrorCode.INVALID_AMOUNT,
                response,
            )

        # Validate network
        if not is_valid_x402_network(network):
            raise X402Error(
                f'Invalid {X402_HEADERS["NETWORK"]}: "{network}"',
                X402ErrorCode.INVALID_NETWORK,
                response,
            )

        # Validate token
        if token.upper() != "USDC":
            raise X402Error(
                f'Unsupported token: "{token}". Only USDC supported.',
                X402ErrorCode.MISSING_HEADERS,
                response,
            )

        # Validate deadline
        try:
            deadline_num = int(deadline)
        except ValueError:
            deadline_num = 0
        if deadline_num <= 0:
            raise X402Error(
                f'Invalid {X402_HEADERS["DEADLINE"]}: "{deadline}"',
                X402ErrorCode.MISSING_HEADERS,
                response,
            )

        return X402PaymentHeaders(
            required=True,
            payment_address=validated_address,
            amount=amount,
            network=network,
            token="USDC",
            deadline=deadline_num,
            service_id=h.get(X402_HEADERS["SERVICE_ID"]) or None,
        )

    def _validate_payment_address(
        self, address: str, response: httpx.Response
    ) -> str:
        """Validate payment address from header."""
        try:
            return _validate_address(address, X402_HEADERS["ADDRESS"])
        except ValueError:
            raise X402Error(
                f'Invalid {X402_HEADERS["ADDRESS"]}: "{address}"',
                X402ErrorCode.INVALID_ADDRESS,
                response,
            )

    async def _execute_atomic_payment(
        self, headers: X402PaymentHeaders
    ) -> tuple[str, Optional[X402FeeBreakdown]]:
        """
        Execute atomic payment with fee splitting via X402Relay (if configured),
        or direct transfer as legacy fallback.

        Returns:
            Tuple of (tx_hash, optional fee_breakdown).
        """
        try:
            # Relay path: on-chain fee splitting
            if (
                self._config.relay_address
                and self._config.approve_fn
                and self._config.relay_pay_fn
            ):
                gross_amount = headers.amount
                fee_bps = self._config.platform_fee_bps
                MIN_FEE = 50_000  # $0.05 USDC

                # Calculate fee: max(gross * bps / 10000, MIN_FEE)
                gross_big = int(gross_amount)
                bps_fee = (gross_big * fee_bps) // 10_000
                fee = bps_fee if bps_fee > MIN_FEE else MIN_FEE
                provider_net = gross_big - fee

                # 1. Approve relay for gross amount
                await self._config.approve_fn(
                    self._config.relay_address, gross_amount
                )

                # 2. Call relay.payWithFee
                service_id = headers.service_id or ("0x" + "0" * 64)
                tx_hash = await self._config.relay_pay_fn(
                    headers.payment_address,
                    gross_amount,
                    service_id,
                )

                breakdown = X402FeeBreakdown(
                    gross_amount=gross_amount,
                    provider_net=str(provider_net),
                    platform_fee=str(fee),
                    fee_bps=fee_bps,
                    estimated=True,
                )
                return tx_hash, breakdown

            # Legacy path: direct transfer, no fee
            tx_hash = await self._transfer_fn(
                headers.payment_address,
                headers.amount,
            )
            return tx_hash, None

        except X402Error:
            raise
        except Exception as exc:
            raise X402Error(
                f"Atomic payment failed: {exc}",
                X402ErrorCode.PAYMENT_FAILED,
            )

    async def _retry_with_proof(
        self,
        endpoint: str,
        tx_hash: str,
        method: X402HttpMethod = "GET",
        custom_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> httpx.Response:
        """Retry request with payment proof (tx hash)."""
        proof_headers = {
            X402_PROOF_HEADERS["TX_ID"]: tx_hash,
        }

        response = await self._make_request(
            endpoint,
            method,
            custom_headers,
            body,
            content_type,
            proof_headers,
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise X402Error(
                f"Retry failed: {response.status_code} {response.reason_phrase}",
                X402ErrorCode.RETRY_FAILED,
                response,
            )

        return response

    @staticmethod
    def _serialize_body(
        body: Optional[Union[str, Dict[str, Any]]],
        content_type: Optional[str] = None,
    ) -> Optional[str]:
        """Serialize request body to string."""
        if body is None:
            return None
        if isinstance(body, str):
            return body
        return json.dumps(body)

    def _create_free_service_result(
        self,
        params: UnifiedPayParams,
        response: httpx.Response,
    ) -> X402PayResult:
        """Create result for free services (200 on initial request)."""
        from datetime import datetime, timezone

        deadline_iso = datetime.fromtimestamp(
            time.time() + 86400, tz=timezone.utc
        ).isoformat()

        return X402PayResult(
            tx_id="0x" + "0" * 64,
            escrow_id=None,
            adapter=self.metadata.id,
            state="COMMITTED",
            success=True,
            amount="0.00 USDC",
            response=response,
            release_required=False,
            provider="0x" + "0" * 40,
            requester=self._requester_address,
            deadline=deadline_iso,
        )
