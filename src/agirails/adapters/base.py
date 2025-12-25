"""
Base adapter for AGIRAILS SDK.

Provides shared utilities for Beginner and Intermediate adapters:
- Amount parsing and formatting
- Deadline parsing
- Address validation
- Dispute window validation

All adapters inherit from BaseAdapter.
"""

from __future__ import annotations

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
MAX_DEADLINE_HOURS = 168  # 7 days
MAX_DEADLINE_DAYS = 30


class BaseAdapter:
    """
    Base adapter providing shared utilities for all adapters.

    Handles common operations like amount parsing, deadline calculation,
    and validation. Should not be used directly - use BeginnerAdapter
    or IntermediateAdapter instead.
    """

    def __init__(
        self,
        runtime: IACTPRuntime,
        requester_address: str,
        eas_helper: Optional[object] = None,
    ) -> None:
        """
        Initialize base adapter.

        Args:
            runtime: ACTP runtime (mock or blockchain)
            requester_address: Address of the requester
            eas_helper: Optional EAS helper for attestations
        """
        self._runtime = runtime
        self._requester_address = requester_address.lower()
        self._eas_helper = eas_helper

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

    def parse_deadline(self, deadline: Optional[Union[str, int]] = None) -> int:
        """
        Parse deadline to Unix timestamp.

        Accepts:
        - None: Default (24 hours from now)
        - Integer: Unix timestamp or seconds from now (auto-detected)
        - String: ISO date, or relative like "1h", "24h", "7d"

        Args:
            deadline: Deadline in various formats

        Returns:
            Unix timestamp in seconds

        Raises:
            ValidationError: If deadline is invalid or in the past
        """
        now = self._get_current_time()

        # Default: 24 hours from now
        if deadline is None:
            return now + DEFAULT_DEADLINE_SECONDS

        # Integer handling
        if isinstance(deadline, int):
            # If small number, interpret as hours from now
            if deadline <= MAX_DEADLINE_HOURS:
                return now + (deadline * 3600)
            # If slightly larger, interpret as days from now
            if deadline <= MAX_DEADLINE_DAYS:
                return now + (deadline * 86400)
            # Otherwise it's a timestamp
            if deadline <= now:
                raise ValidationError(
                    message="Deadline must be in the future",
                    details={"deadline": deadline, "current_time": now},
                )
            return deadline

        # String handling
        if isinstance(deadline, str):
            # Check for relative format like "1h", "24h", "7d"
            deadline_lower = deadline.lower().strip()

            # Hours format: "1h", "24h"
            if deadline_lower.endswith("h"):
                try:
                    hours = int(deadline_lower[:-1])
                    if hours <= 0:
                        raise ValidationError(message="Hours must be positive")
                    return now + (hours * 3600)
                except ValueError:
                    pass

            # Days format: "1d", "7d"
            if deadline_lower.endswith("d"):
                try:
                    days = int(deadline_lower[:-1])
                    if days <= 0:
                        raise ValidationError(message="Days must be positive")
                    return now + (days * 86400)
                except ValueError:
                    pass

            # ISO date format
            try:
                return Deadline.at(deadline)
            except Exception:
                pass

            # Try parsing as integer timestamp
            try:
                ts = int(deadline)
                if ts <= now:
                    raise ValidationError(
                        message="Deadline must be in the future",
                        details={"deadline": ts, "current_time": now},
                    )
                return ts
            except ValueError:
                pass

            raise ValidationError(
                message=f"Invalid deadline format: {deadline}",
                details={
                    "deadline": deadline,
                    "hint": "Use: integer timestamp, '24h', '7d', or ISO date string",
                },
            )

        raise ValidationError(
            message=f"Invalid deadline type: {type(deadline).__name__}",
            details={"deadline": str(deadline)},
        )

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
