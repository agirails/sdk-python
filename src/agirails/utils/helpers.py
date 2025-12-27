"""
Helper utilities for AGIRAILS SDK.

Provides convenience functions for common operations:
- USDC: Amount conversion (6 decimal places)
- Deadline: Time utilities
- Address: Ethereum address utilities
- Bytes32: Transaction ID utilities
- StateHelper: State machine utilities
- DisputeWindow: Dispute window utilities
- ServiceHash: Service metadata hashing

SECURITY FIX (L-7): Convenience methods reduce boilerplate and prevent mistakes.
SECURITY FIX (MEDIUM-6): Uses integer arithmetic for USDC to prevent precision loss.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from agirails.runtime.types import State, STATE_TRANSITIONS, TERMINAL_STATES


class USDC:
    """
    USDC amount utilities (6 decimal places).

    SECURITY FIX (MEDIUM-6): Uses integer arithmetic to prevent precision loss.
    SECURITY FIX (L-4): Includes bounds checking to prevent overflow.

    Example:
        >>> USDC.to_wei("100.50")
        100500000
        >>> USDC.from_wei(100500000)
        '100.50'
        >>> USDC.format(100500000)
        '100.50 USDC'
    """

    DECIMALS: int = 6
    MIN_AMOUNT_WEI: int = 50_000  # $0.05
    # Security Note (L-4): Maximum amount bounds
    # Total USDC supply is ~50 billion, so 100 billion is a safe upper bound
    MAX_AMOUNT_WEI: int = 100_000_000_000_000_000  # $100 billion
    MAX_AMOUNT_HUMAN: int = 100_000_000_000  # $100 billion

    @staticmethod
    def to_wei(amount: Union[str, int, float], validate_bounds: bool = True) -> int:
        """
        Convert human-readable USDC amount to wei (6 decimals).

        Security Note (L-4): Validates bounds by default to prevent overflow.

        Args:
            amount: Amount as string, int, or float (e.g., "100.50", 100, 100.50)
            validate_bounds: If True, raises ValueError for out-of-bounds amounts

        Returns:
            Amount in USDC wei (integer)

        Raises:
            ValueError: If amount is out of bounds (when validate_bounds=True)

        Example:
            >>> USDC.to_wei("100")
            100000000
            >>> USDC.to_wei("100.50")
            100500000
            >>> USDC.to_wei(100)
            100000000
        """
        # Convert to string and remove formatting
        amount_str = str(amount).replace(",", "").replace("$", "").replace(" ", "")

        # Handle negative amounts
        is_negative = amount_str.startswith("-")
        if is_negative:
            amount_str = amount_str[1:]

        # Split into whole and decimal parts
        parts = amount_str.split(".")
        whole_part = parts[0] or "0"
        decimal_part = (parts[1] if len(parts) > 1 else "").ljust(6, "0")[:6]

        # Security Note (L-4): Validate whole part doesn't exceed bounds
        try:
            whole_int = int(whole_part)
        except ValueError:
            raise ValueError(f"Invalid USDC amount: {amount}")

        if validate_bounds and whole_int > USDC.MAX_AMOUNT_HUMAN:
            raise ValueError(
                f"USDC amount exceeds maximum: ${whole_int:,} > ${USDC.MAX_AMOUNT_HUMAN:,}"
            )

        # Calculate wei using integer arithmetic
        result = whole_int * 1_000_000 + int(decimal_part)

        # Security Note (L-4): Final bounds check on wei value
        if validate_bounds and result > USDC.MAX_AMOUNT_WEI:
            raise ValueError(
                f"USDC wei amount exceeds maximum: {result:,} > {USDC.MAX_AMOUNT_WEI:,}"
            )

        return -result if is_negative else result

    @staticmethod
    def from_wei(
        wei_amount: Union[int, str],
        decimals: int = 2,
        validate_bounds: bool = True,
    ) -> str:
        """
        Convert USDC wei to human-readable string.

        SECURITY FIX (MEDIUM-6): Uses pure integer arithmetic for precision.
        SECURITY FIX (L-4): Validates bounds by default.

        Args:
            wei_amount: Amount in USDC wei
            decimals: Number of decimal places to show (default: 2)
            validate_bounds: If True, raises ValueError for out-of-bounds amounts

        Returns:
            Formatted string (e.g., "100.50")

        Raises:
            ValueError: If wei_amount exceeds bounds (when validate_bounds=True)

        Example:
            >>> USDC.from_wei(100500000)
            '100.50'
            >>> USDC.from_wei(100000000)
            '100.00'
            >>> USDC.from_wei(100126000, 4)
            '100.1260'
        """
        amount = int(wei_amount) if isinstance(wei_amount, str) else wei_amount

        # Security Note (L-4): Validate bounds
        if validate_bounds and abs(amount) > USDC.MAX_AMOUNT_WEI:
            raise ValueError(
                f"USDC wei amount exceeds maximum: {abs(amount):,} > {USDC.MAX_AMOUNT_WEI:,}"
            )

        # Handle negative amounts
        is_negative = amount < 0
        amount = abs(amount)

        # Calculate divisor and max decimal using integer arithmetic
        divisor_exponent = 6 - decimals
        if divisor_exponent >= 0:
            divisor = 10 ** divisor_exponent
            # Round using integer arithmetic (add half divisor before division)
            rounded_amount = (amount + divisor // 2) // divisor
        else:
            rounded_amount = amount * (10 ** (-divisor_exponent))

        max_decimal = 10 ** decimals
        whole_part = rounded_amount // max_decimal
        decimal_part = rounded_amount % max_decimal

        # Handle decimals=0 case (no decimal point)
        if decimals == 0:
            result = str(whole_part)
        else:
            result = f"{whole_part}.{str(decimal_part).zfill(decimals)}"
        return f"-{result}" if is_negative else result

    @staticmethod
    def format(wei_amount: Union[int, str]) -> str:
        """
        Format USDC amount with currency symbol.

        Args:
            wei_amount: Amount in USDC wei

        Returns:
            Formatted string with USDC suffix (e.g., "100.50 USDC")
        """
        return f"{USDC.from_wei(wei_amount)} USDC"

    @staticmethod
    def meets_minimum(wei_amount: Union[int, str]) -> bool:
        """
        Check if amount meets minimum transaction requirement ($0.05).

        Args:
            wei_amount: Amount in USDC wei

        Returns:
            True if amount >= $0.05
        """
        amount = int(wei_amount) if isinstance(wei_amount, str) else wei_amount
        return amount >= USDC.MIN_AMOUNT_WEI


class Deadline:
    """
    Deadline utilities for transaction timing.

    Example:
        >>> Deadline.hours_from_now(24)  # 24 hours from now
        >>> Deadline.days_from_now(7)    # 7 days from now
        >>> Deadline.is_past(timestamp)  # Check if expired
    """

    # Security Note (M-2): Maximum deadline constraints
    MAX_DEADLINE_DAYS = 365  # 1 year maximum
    MIN_DEADLINE_HOURS = 0.0167  # ~1 minute minimum (0.0167 hours)

    @staticmethod
    def hours_from_now(hours: Union[int, float]) -> int:
        """
        Create deadline N hours from now.

        Security Note (M-2): Validates input is positive and within bounds.

        Args:
            hours: Number of hours from now (must be positive, max 8760 = 1 year)

        Returns:
            Unix timestamp in seconds

        Raises:
            ValueError: If hours is non-positive or exceeds maximum
        """
        if hours <= 0:
            raise ValueError(f"hours must be positive, got {hours}")
        max_hours = 24 * Deadline.MAX_DEADLINE_DAYS
        if hours > max_hours:
            raise ValueError(f"hours exceeds maximum ({max_hours}h = {Deadline.MAX_DEADLINE_DAYS} days)")
        return int(time.time()) + int(hours * 3600)

    @staticmethod
    def days_from_now(days: Union[int, float]) -> int:
        """
        Create deadline N days from now.

        Security Note (M-2): Validates input is positive and within bounds.

        Args:
            days: Number of days from now (must be positive, max 365)

        Returns:
            Unix timestamp in seconds

        Raises:
            ValueError: If days is non-positive or exceeds maximum
        """
        if days <= 0:
            raise ValueError(f"days must be positive, got {days}")
        if days > Deadline.MAX_DEADLINE_DAYS:
            raise ValueError(f"days exceeds maximum ({Deadline.MAX_DEADLINE_DAYS})")
        return int(time.time()) + int(days * 86400)

    @staticmethod
    def at(date: Union[datetime, str]) -> int:
        """
        Create deadline at specific date.

        Args:
            date: datetime object or ISO format string

        Returns:
            Unix timestamp in seconds

        Example:
            >>> Deadline.at(datetime(2025, 1, 1))
            >>> Deadline.at("2025-01-01T00:00:00Z")
        """
        if isinstance(date, str):
            # Parse ISO format string
            from dateutil import parser
            date = parser.isoparse(date)
        return int(date.timestamp())

    @staticmethod
    def is_past(deadline: int) -> bool:
        """
        Check if deadline has passed.

        Args:
            deadline: Unix timestamp in seconds

        Returns:
            True if deadline is in the past
        """
        return deadline <= int(time.time())

    @staticmethod
    def time_remaining(deadline: int) -> int:
        """
        Get time remaining until deadline.

        Args:
            deadline: Unix timestamp in seconds

        Returns:
            Time remaining in seconds (negative if past)
        """
        return deadline - int(time.time())

    @staticmethod
    def format(deadline: int) -> str:
        """
        Format deadline as human-readable string.

        Args:
            deadline: Unix timestamp in seconds

        Returns:
            Human-readable string (e.g., "in 2 hours", "expired 1 day ago")
        """
        remaining = Deadline.time_remaining(deadline)

        if remaining <= 0:
            ago = abs(remaining)
            if ago < 60:
                return f"expired {ago} seconds ago"
            if ago < 3600:
                return f"expired {ago // 60} minutes ago"
            if ago < 86400:
                return f"expired {ago // 3600} hours ago"
            return f"expired {ago // 86400} days ago"

        if remaining < 60:
            return f"in {remaining} seconds"
        if remaining < 3600:
            return f"in {remaining // 60} minutes"
        if remaining < 86400:
            return f"in {remaining // 3600} hours"
        return f"in {remaining // 86400} days"


class Address:
    """
    Ethereum address utilities.

    Example:
        >>> Address.normalize("0xABC...DEF")
        '0xabc...def'
        >>> Address.equals("0xABC", "0xabc")
        True
        >>> Address.truncate("0x1234567890123456789012345678901234567890")
        '0x1234...7890'
    """

    @staticmethod
    def normalize(address: str) -> str:
        """
        Normalize address to lowercase with 0x prefix.

        Args:
            address: Ethereum address

        Returns:
            Normalized lowercase address
        """
        return address.lower()

    @staticmethod
    def equals(a: str, b: str) -> bool:
        """
        Check if two addresses are the same (case-insensitive).

        Args:
            a: First address
            b: Second address

        Returns:
            True if addresses match
        """
        return a.lower() == b.lower()

    @staticmethod
    def truncate(address: str, chars: int = 4) -> str:
        """
        Truncate address for display.

        Args:
            address: Ethereum address
            chars: Characters to show on each side (default: 4)

        Returns:
            Truncated address (e.g., "0x1234...5678")
        """
        if len(address) <= 2 + chars * 2:
            return address
        return f"{address[:2 + chars]}...{address[-chars:]}"

    @staticmethod
    def is_valid(address: str) -> bool:
        """
        Check if string is valid Ethereum address format.

        Args:
            address: String to check

        Returns:
            True if valid address format (0x + 40 hex chars)
        """
        if not address:
            return False
        return bool(re.match(r"^0x[0-9a-fA-F]{40}$", address))

    @staticmethod
    def is_zero(address: str) -> bool:
        """
        Check if address is zero address.

        Args:
            address: Ethereum address

        Returns:
            True if zero address
        """
        return address.lower() == "0x" + "0" * 40


class Bytes32:
    """
    Bytes32 utilities for transaction IDs and hashes.

    Example:
        >>> Bytes32.is_valid("0x" + "a" * 64)
        True
        >>> Bytes32.zero()
        '0x0000...0000'
        >>> Bytes32.truncate("0x123456...abcdef")
        '0x123456...abcdef'
    """

    @staticmethod
    def is_valid(value: str) -> bool:
        """
        Check if string is valid bytes32 format.

        Args:
            value: String to check

        Returns:
            True if valid bytes32 format (0x + 64 hex chars)
        """
        if not value:
            return False
        return bool(re.match(r"^0x[0-9a-fA-F]{64}$", value))

    @staticmethod
    def normalize(value: str) -> str:
        """
        Normalize bytes32 to lowercase.

        Args:
            value: Bytes32 string

        Returns:
            Normalized lowercase string
        """
        return value.lower()

    @staticmethod
    def equals(a: str, b: str) -> bool:
        """
        Check if two bytes32 values are equal.

        Args:
            a: First value
            b: Second value

        Returns:
            True if equal
        """
        return a.lower() == b.lower()

    @staticmethod
    def is_zero(value: str) -> bool:
        """
        Check if bytes32 is zero.

        Args:
            value: Bytes32 string

        Returns:
            True if zero
        """
        return value.lower() == "0x" + "0" * 64

    @staticmethod
    def zero() -> str:
        """
        Create zero bytes32.

        Returns:
            Zero bytes32 string
        """
        return "0x" + "0" * 64

    @staticmethod
    def truncate(value: str, chars: int = 6) -> str:
        """
        Truncate bytes32 for display.

        Args:
            value: Bytes32 string
            chars: Characters to show on each side (default: 6)

        Returns:
            Truncated string (e.g., "0x123456...abcdef")
        """
        if len(value) <= 2 + chars * 2:
            return value
        return f"{value[:2 + chars]}...{value[-chars:]}"


class StateHelper:
    """
    State machine utilities.

    Note: Named StateHelper to avoid conflict with State enum from runtime.types.

    Example:
        >>> StateHelper.is_terminal("SETTLED")
        True
        >>> StateHelper.can_transition("COMMITTED", "DELIVERED")
        True
        >>> StateHelper.valid_transitions("COMMITTED")
        ['IN_PROGRESS', 'DELIVERED', 'CANCELLED']
    """

    STATES: Tuple[str, ...] = (
        "INITIATED",
        "QUOTED",
        "COMMITTED",
        "IN_PROGRESS",
        "DELIVERED",
        "SETTLED",
        "DISPUTED",
        "CANCELLED",
    )

    TERMINAL: Tuple[str, ...] = ("SETTLED", "CANCELLED")

    @staticmethod
    def is_terminal(state: Union[str, State]) -> bool:
        """
        Check if state is terminal.

        Args:
            state: State to check

        Returns:
            True if terminal state (SETTLED or CANCELLED)
        """
        if isinstance(state, State):
            return state in TERMINAL_STATES
        return state in StateHelper.TERMINAL

    @staticmethod
    def is_valid(state: str) -> bool:
        """
        Check if state is valid.

        Args:
            state: State to check

        Returns:
            True if valid state
        """
        return state in StateHelper.STATES

    @staticmethod
    def valid_transitions(current_state: Union[str, State]) -> List[str]:
        """
        Get valid next states from current state.

        SECURITY FIX (CRITICAL-1): Must match ACTPKernel contract state machine.

        Args:
            current_state: Current state

        Returns:
            List of valid next states
        """
        if isinstance(current_state, str):
            try:
                current_state = State(current_state)
            except ValueError:
                return []

        transitions = STATE_TRANSITIONS.get(current_state, [])
        return [t.value for t in transitions]

    @staticmethod
    def can_transition(from_state: Union[str, State], to_state: Union[str, State]) -> bool:
        """
        Check if transition is valid.

        Args:
            from_state: Current state
            to_state: Target state

        Returns:
            True if transition is valid
        """
        if isinstance(from_state, str):
            try:
                from_state = State(from_state)
            except ValueError:
                return False
        if isinstance(to_state, str):
            try:
                to_state = State(to_state)
            except ValueError:
                return False

        return to_state in STATE_TRANSITIONS.get(from_state, [])


class DisputeWindow:
    """
    Dispute window utilities.

    Example:
        >>> DisputeWindow.hours(2)  # 7200 seconds
        >>> DisputeWindow.days(2)   # 172800 seconds
        >>> DisputeWindow.is_active(completed_at, 172800)
        True
    """

    DEFAULT: int = 172800  # 2 days
    MIN: int = 3600  # 1 hour
    MAX: int = 30 * 24 * 3600  # 30 days

    @staticmethod
    def hours(h: Union[int, float]) -> int:
        """
        Convert hours to seconds.

        Args:
            h: Number of hours

        Returns:
            Seconds
        """
        return int(h * 3600)

    @staticmethod
    def days(d: Union[int, float]) -> int:
        """
        Convert days to seconds.

        Args:
            d: Number of days

        Returns:
            Seconds
        """
        return int(d * 86400)

    @staticmethod
    def is_active(completed_at: int, window_seconds: int) -> bool:
        """
        Check if dispute window is still active.

        Args:
            completed_at: Completion timestamp
            window_seconds: Dispute window in seconds

        Returns:
            True if window is still active
        """
        expires_at = completed_at + window_seconds
        return int(time.time()) < expires_at

    @staticmethod
    def remaining(completed_at: int, window_seconds: int) -> int:
        """
        Get time remaining in dispute window.

        Args:
            completed_at: Completion timestamp
            window_seconds: Dispute window in seconds

        Returns:
            Seconds remaining (0 if expired)
        """
        expires_at = completed_at + window_seconds
        now = int(time.time())
        return max(0, expires_at - now)


@dataclass
class ServiceMetadata:
    """Service metadata structure."""

    service: str
    input: Any = None
    version: Optional[str] = None
    timestamp: Optional[int] = None


class ServiceHash:
    """
    Service metadata utilities for ACTP transactions.

    SECURITY FIX (CRITICAL): The ACTPKernel contract expects a bytes32 serviceHash,
    not a raw JSON string. This utility properly hashes metadata.

    PARITY NOTE: Matches TypeScript SDK's ServiceHash exactly:
    - Uses insertion order (NOT sorted keys)
    - Field order: service, input, version, timestamp
    - Minimal separators (no whitespace)

    Example:
        >>> ServiceHash.hash(ServiceMetadata(service="echo", input="hello"))
        '0x1234...abcd'
        >>> ServiceHash.to_canonical(ServiceMetadata(service="echo"))
        '{"service":"echo"}'
    """

    ZERO: str = "0x" + "0" * 64

    @staticmethod
    def to_canonical(metadata: ServiceMetadata) -> str:
        """
        Create canonical JSON from service metadata.

        PARITY: Matches TypeScript SDK's ServiceHash.toCanonical() exactly:
        - Uses insertion order (NOT sorted keys) to match JSON.stringify()
        - Fields added in specific order: service, input, version, timestamp
        - Uses minimal separators (no whitespace)
        - Uses ensure_ascii=False to preserve unicode (matches JSON.stringify())

        Args:
            metadata: Service metadata object

        Returns:
            Canonical JSON string (insertion order, no whitespace)
        """
        # Build canonical object in specific order to match TS SDK
        # TypeScript uses: { service, ...(input && { input }), ...(version && { version }), ...(timestamp && { timestamp }) }
        # This creates insertion order: service first, then optional fields
        canonical: Dict[str, Any] = {"service": metadata.service}
        if metadata.input is not None:
            canonical["input"] = metadata.input
        if metadata.version is not None:
            canonical["version"] = metadata.version
        if metadata.timestamp is not None:
            canonical["timestamp"] = metadata.timestamp

        # PARITY FIX: Do NOT use sort_keys - match TS SDK's JSON.stringify() behavior
        # Python dict maintains insertion order (Python 3.7+), so this matches TS
        # PARITY FIX: Use ensure_ascii=False to preserve unicode characters
        return json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def hash(metadata: Union[ServiceMetadata, str]) -> str:
        """
        Hash service metadata to bytes32 using keccak256.

        SECURITY FIX (CRITICAL): This is what should be passed to
        ACTPKernel.createTransaction().

        Args:
            metadata: Service metadata (string or object)

        Returns:
            bytes32 hash string (0x-prefixed, 64 hex chars)

        Example:
            >>> ServiceHash.hash(ServiceMetadata(service="echo", input="hello"))
            '0x1234...abcd'
        """
        from eth_hash.auto import keccak

        if isinstance(metadata, str):
            canonical = metadata
        else:
            canonical = ServiceHash.to_canonical(metadata)

        hash_bytes = keccak(canonical.encode("utf-8"))
        return "0x" + hash_bytes.hex()

    @staticmethod
    def from_legacy(legacy_format: str) -> Optional[ServiceMetadata]:
        """
        Parse legacy service description format.

        Parses "service:NAME;input:JSON" format.

        Args:
            legacy_format: Legacy service description string

        Returns:
            Parsed ServiceMetadata or None if invalid
        """
        service_match = re.match(r"^service:([^;]+)", legacy_format)
        if not service_match:
            return None

        service = service_match.group(1)

        input_match = re.search(r";input:(.+)$", legacy_format)
        input_data: Any = None

        if input_match:
            try:
                input_data = json.loads(input_match.group(1))
            except json.JSONDecodeError:
                input_data = input_match.group(1)

        return ServiceMetadata(service=service, input=input_data)

    @staticmethod
    def get_service_name(metadata: Union[ServiceMetadata, str]) -> str:
        """
        Extract service name from metadata.

        Args:
            metadata: Service metadata or legacy string

        Returns:
            Service name
        """
        if isinstance(metadata, str):
            parsed = ServiceHash.from_legacy(metadata)
            return parsed.service if parsed else "unknown"
        return metadata.service

    @staticmethod
    def is_valid_hash(value: str) -> bool:
        """
        Validate bytes32 format.

        Args:
            value: Value to check

        Returns:
            True if valid bytes32 format
        """
        return Bytes32.is_valid(value)


# ============================================================================
# Convenience Wrappers
# ============================================================================


def parse_usdc(amount: Union[str, int, float]) -> int:
    """
    Parse USDC amount string to wei (6 decimals).

    Convenience wrapper for USDC.to_wei().

    Args:
        amount: Amount in USDC (e.g., "100" or "0.50")

    Returns:
        Integer in wei (e.g., 100000000 for $100)

    Example:
        >>> parse_usdc("100")
        100000000
        >>> parse_usdc("0.50")
        500000
    """
    return USDC.to_wei(amount)


def format_usdc(wei: Union[int, str]) -> str:
    """
    Format USDC wei to human-readable string.

    Convenience wrapper for USDC.from_wei().

    Args:
        wei: Amount in wei (int or string)

    Returns:
        Formatted string (e.g., "100.00")

    Example:
        >>> format_usdc(100000000)
        '100.00'
        >>> format_usdc("100000000")
        '100.00'
    """
    return USDC.from_wei(wei)


def shorten_address(address: str, chars: int = 4) -> str:
    """
    Shorten Ethereum address for display.

    Convenience wrapper for Address.truncate().

    Args:
        address: Full Ethereum address
        chars: Characters to show on each side (default: 4)

    Returns:
        Shortened address (e.g., "0x1234...abcd")
    """
    return Address.truncate(address, chars)


def hash_service_metadata(service: str, input_data: Any = None) -> str:
    """
    Hash service description for on-chain storage.

    Convenience function for ServiceHash.hash().

    Args:
        service: Service name
        input_data: Input data (optional)

    Returns:
        bytes32 hash
    """
    return ServiceHash.hash(ServiceMetadata(service=service, input=input_data))
