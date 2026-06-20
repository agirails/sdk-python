"""
Base adapter for AGIRAILS SDK.

Provides shared utilities for Basic and Standard adapters:
- Amount parsing and formatting
- Deadline parsing
- Address validation
- Dispute window validation

All adapters inherit from BaseAdapter.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Optional, Union

from agirails.errors import ValidationError, InvalidAmountError
from agirails.utils.helpers import USDC, Deadline, Address, DisputeWindow

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime


# Default configuration
DEFAULT_DEADLINE_SECONDS = 86400  # 24 hours
DEFAULT_DISPUTE_WINDOW_SECONDS = 172800  # 2 days
MIN_AMOUNT_WEI = 50_000  # $0.05 USDC

# Maximum deadline bounds (10 years) — mirrors TS BaseAdapter.ts:62,68.
# Prevents integer overflow in deadline calculations.
MAX_DEADLINE_HOURS = 87600  # 10 years
MAX_DEADLINE_DAYS = 3650  # 10 years

# Relative deadline pattern: "+Nh" or "+Nd" only.
# Mirrors TS BaseAdapter.ts:284  deadline.match(/^\+(\d+)(h|d)$/)
# re.ASCII keeps \d ASCII-only, matching JS's ASCII \d (no Unicode digits).
_RELATIVE_DEADLINE_RE = re.compile(r"^\+(\d+)(h|d)$", re.ASCII)


class BaseAdapter:
    """
    Base adapter providing shared utilities for all adapters.

    Handles common operations like amount parsing, deadline calculation,
    and validation. Should not be used directly - use BasicAdapter
    or StandardAdapter instead.
    """

    def __init__(
        self,
        runtime: IACTPRuntime,
        requester_address: str,
        eas_helper: Optional[object] = None,
        wallet_provider: Optional[object] = None,
        contract_addresses: Optional[object] = None,
    ) -> None:
        """
        Initialize base adapter.

        Args:
            runtime: ACTP runtime (mock or blockchain)
            requester_address: Address of the requester
            eas_helper: Optional EAS helper for attestations
            wallet_provider: Optional wallet provider (AutoWalletProvider or
                EOAWalletProvider). When set with ``pay_actp_batched`` and
                ``contract_addresses`` populated, BasicAdapter routes ACTP
                payments through a single batched UserOp (approve +
                createTransaction + linkEscrow). Without it, payments fall
                back to sequential ``runtime.create_transaction`` calls.
            contract_addresses: Optional :class:`ContractAddresses` instance
                (from ``agirails.wallet.aa.transaction_batcher``) holding
                ``usdc``, ``actp_kernel``, ``escrow_vault``. Required
                alongside ``wallet_provider`` for the batched UserOp path.
        """
        self._runtime = runtime
        self._requester_address = requester_address.lower()
        self._eas_helper = eas_helper
        self._wallet_provider = wallet_provider
        self._contract_addresses = contract_addresses

        # Build SmartWalletRouter when wallet provider is AA-capable.
        # Lazy import keeps the wallet/web3 dependency cost off mock-only callers.
        self._smart_wallet_router: Optional[object] = None
        if wallet_provider is not None and contract_addresses is not None:
            from agirails.wallet.smart_wallet_router import (
                SmartWalletContractAddresses,
                create_smart_wallet_router,
            )
            router_contracts = SmartWalletContractAddresses(
                usdc=contract_addresses.usdc,
                actp_kernel=contract_addresses.actp_kernel,
                escrow_vault=contract_addresses.escrow_vault,
            )
            self._smart_wallet_router = create_smart_wallet_router(
                wallet_provider, router_contracts, runtime, eas_helper
            )

    @property
    def runtime(self) -> IACTPRuntime:
        """Get the underlying runtime."""
        return self._runtime

    @property
    def requester_address(self) -> str:
        """Get the requester address."""
        return self._requester_address

    def parse_amount(self, amount: Union[str, int, float]) -> str:
        """
        Parse amount to USDC wei string.

        Accepts:
        - String: "100", "100.50", "$100.50"
        - Integer: 100 (interpreted as USDC, not wei)
        - Float: 100.50

        Args:
            amount: Amount in various formats

        Returns:
            Amount as wei string

        Raises:
            InvalidAmountError: If amount is invalid or below minimum
        """
        try:
            wei = USDC.to_wei(amount)
        except (ValueError, TypeError) as e:
            raise InvalidAmountError(
                str(amount),
                reason=f"Invalid amount format: {e}",
            )

        if wei < MIN_AMOUNT_WEI:
            raise InvalidAmountError(
                str(amount),
                reason=f"Amount must be at least ${USDC.from_wei(MIN_AMOUNT_WEI)} USDC",
                min_amount=MIN_AMOUNT_WEI,
            )

        return str(wei)

    def parse_deadline(
        self,
        deadline: Optional[Union[str, int]] = None,
        current_time: Optional[int] = None,
    ) -> int:
        """
        Parse deadline from relative time expression or Unix timestamp.

        Mirrors TS ``BaseAdapter.parseDeadline`` (sdk-js/src/adapters/BaseAdapter.ts:271)
        byte-for-byte:

        Accepts:
        - None         -> now + 24 hours (default)
        - 1734076400   -> int passed through verbatim as a Unix timestamp
        - "+1h"        -> now + 1 hour
        - "+24h"       -> now + 24 hours
        - "+7d"        -> now + 7 days

        Rejects (raises ValidationError):
        - "24h" / "7d" (bare, no ``+`` prefix)
        - "-24h"       (negative / wrong format)
        - "invalid"    (unparseable)
        - "+99999h"    (beyond 10-year bound, ``MAX_DEADLINE_HOURS``)

        Args:
            deadline: Deadline as relative time string, Unix timestamp, or None.
            current_time: Current time in seconds. Defaults to runtime/system time.

        Returns:
            Unix timestamp in seconds.

        Raises:
            ValidationError: If deadline format is invalid.
        """
        # TS: const now = currentTime ?? Math.floor(Date.now() / 1000)
        now = current_time if current_time is not None else self._get_current_time()

        # TS: if (deadline === undefined) return now + DEFAULT_DEADLINE_SECONDS
        if deadline is None:
            return now + DEFAULT_DEADLINE_SECONDS

        # TS: if (typeof deadline === 'number') return deadline
        # bool is a subclass of int in Python; exclude it so True/False are not
        # silently treated as 1/0 timestamps.
        if isinstance(deadline, int) and not isinstance(deadline, bool):
            return deadline

        if not isinstance(deadline, str):
            raise ValidationError(
                message=(
                    f'Invalid deadline format: "{deadline}". '
                    'Expected Unix timestamp or relative time (e.g., "+24h", "+7d")'
                ),
                details={"deadline": str(deadline)},
            )

        # TS: const match = deadline.match(/^\+(\d+)(h|d)$/)
        match = _RELATIVE_DEADLINE_RE.match(deadline)
        if not match:
            raise ValidationError(
                message=(
                    f'Invalid deadline format: "{deadline}". '
                    'Expected Unix timestamp or relative time (e.g., "+24h", "+7d")'
                ),
                details={"deadline": deadline},
            )

        amount = int(match.group(1))
        unit = match.group(2)

        # TS H1 Fix: bounds check to prevent integer overflow.
        if unit == "h" and amount > MAX_DEADLINE_HOURS:
            raise ValidationError(
                message=(
                    f'Deadline too far in future: "{deadline}". '
                    f"Maximum is 10 years ({MAX_DEADLINE_HOURS}h)"
                ),
                details={"deadline": deadline, "maximum_hours": MAX_DEADLINE_HOURS},
            )
        if unit == "d" and amount > MAX_DEADLINE_DAYS:
            raise ValidationError(
                message=(
                    f'Deadline too far in future: "{deadline}". '
                    f"Maximum is 10 years ({MAX_DEADLINE_DAYS}d)"
                ),
                details={"deadline": deadline, "maximum_days": MAX_DEADLINE_DAYS},
            )

        multiplier = 3600 if unit == "h" else 86400
        return now + amount * multiplier

    def format_amount(self, wei: Union[int, str]) -> str:
        """
        Format USDC wei to human-readable string.

        Args:
            wei: Amount in wei

        Returns:
            Formatted string like "100.50"
        """
        return USDC.from_wei(wei)

    def validate_address(self, address: str, field: str = "address") -> str:
        """
        Validate Ethereum address.

        Args:
            address: Address to validate
            field: Field name for error messages

        Returns:
            Normalized lowercase address

        Raises:
            ValidationError: If address is invalid
        """
        if not address:
            raise ValidationError(
                message=f"{field} is required",
                details={"field": field},
            )

        if not Address.is_valid(address):
            raise ValidationError(
                message=f"Invalid {field}: must be 0x followed by 40 hex characters",
                details={"field": field, "value": address},
            )

        if Address.is_zero(address):
            raise ValidationError(
                message=f"{field} cannot be zero address",
                details={"field": field},
            )

        return Address.normalize(address)

    def validate_dispute_window(self, seconds: Optional[int] = None) -> int:
        """
        Validate dispute window duration.

        Args:
            seconds: Dispute window in seconds (None for default)

        Returns:
            Validated dispute window in seconds

        Raises:
            ValidationError: If dispute window is out of bounds
        """
        if seconds is None:
            return DEFAULT_DISPUTE_WINDOW_SECONDS

        if seconds < DisputeWindow.MIN:
            raise ValidationError(
                message=f"Dispute window must be at least {DisputeWindow.MIN} seconds (1 hour)",
                details={"value": seconds, "minimum": DisputeWindow.MIN},
            )

        if seconds > DisputeWindow.MAX:
            raise ValidationError(
                message=f"Dispute window cannot exceed {DisputeWindow.MAX} seconds (30 days)",
                details={"value": seconds, "maximum": DisputeWindow.MAX},
            )

        return seconds

    def _get_current_time(self) -> int:
        """
        Get current time from runtime or system.

        Uses runtime time for mock mode, system time otherwise.
        """
        if hasattr(self._runtime, "time") and hasattr(self._runtime.time, "now"):
            return self._runtime.time.now()
        return int(time.time())

    def encode_dispute_window_proof(self, dispute_window_seconds: int) -> str:
        """
        Encode dispute window as ABI-encoded proof for the DELIVERED transition.

        Centralizes proof encoding so adapters never drift from the on-chain
        expectation: a single ``uint256``. Mirrors TS
        ``BaseAdapter.encodeDisputeWindowProof`` (BaseAdapter.ts:497-504).

        Args:
            dispute_window_seconds: Dispute window in seconds.

        Returns:
            ABI-encoded ``0x``-prefixed proof (uint256).
        """
        from eth_abi import encode as abi_encode

        return "0x" + abi_encode(["uint256"], [int(dispute_window_seconds)]).hex()
