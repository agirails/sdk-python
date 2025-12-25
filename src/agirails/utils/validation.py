"""
Validation utilities for AGIRAILS SDK.

Provides input validation functions for:
- Ethereum addresses
- USDC amounts
- Transaction deadlines
- Transaction IDs (bytes32)
- Endpoint URLs (SSRF protection)
- Dispute windows

All validation functions raise ValidationError (or subclasses) on failure.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Union
from urllib.parse import urlparse

from agirails.errors import ValidationError, InvalidAddressError, InvalidAmountError
from agirails.utils.helpers import DisputeWindow


# Constants
MAX_UINT256 = 2**256 - 1
MAX_USDC_WEI = 10**18  # 1 trillion USDC in wei (reasonable max)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_address(address: str, field_name: str = "address") -> str:
    """
    Validate Ethereum address format.

    Args:
        address: Address to validate
        field_name: Field name for error messages

    Returns:
        Normalized (lowercase) address

    Raises:
        InvalidAddressError: If address is invalid
    """
    if not address:
        raise InvalidAddressError(
            address="" if not address else str(address),
            field=field_name,
            reason=f"{field_name} is required",
        )

    if not isinstance(address, str):
        raise InvalidAddressError(
            str(address),
            field=field_name,
            reason=f"{field_name} must be a string",
        )

    # Check format: 0x + 40 hex chars
    if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
        raise InvalidAddressError(
            address,
            field=field_name,
            reason="must be 0x followed by 40 hex characters",
        )

    return address.lower()


def validate_amount(
    amount: Union[int, str],
    field_name: str = "amount",
    min_amount: int = 0,
    max_amount: int = MAX_USDC_WEI,
) -> int:
    """
    Validate USDC amount (in wei, 6 decimals).

    Args:
        amount: Amount in wei (integer or string)
        field_name: Field name for error messages
        min_amount: Minimum allowed amount (default: 0)
        max_amount: Maximum allowed amount (default: 1 trillion USDC)

    Returns:
        Validated amount as integer

    Raises:
        InvalidAmountError: If amount is invalid
    """
    try:
        amount_int = int(amount) if isinstance(amount, str) else amount
    except (ValueError, TypeError):
        raise InvalidAmountError(
            str(amount),
            field=field_name,
            reason="must be a valid number",
        )

    if amount_int < 0:
        raise InvalidAmountError(
            str(amount_int),
            field=field_name,
            reason="cannot be negative",
        )

    if amount_int < min_amount:
        raise InvalidAmountError(
            str(amount_int),
            field=field_name,
            reason=f"must be at least {min_amount}",
            min_amount=min_amount,
        )

    if amount_int > max_amount:
        raise InvalidAmountError(
            str(amount_int),
            field=field_name,
            reason=f"exceeds maximum allowed ({max_amount})",
        )

    return amount_int


def validate_deadline(deadline: int, current_time: int, field_name: str = "deadline") -> int:
    """
    Validate transaction deadline.

    Args:
        deadline: Deadline timestamp in seconds
        current_time: Current timestamp in seconds
        field_name: Field name for error messages

    Returns:
        Validated deadline

    Raises:
        ValidationError: If deadline is in the past
    """
    if not isinstance(deadline, int):
        try:
            deadline = int(deadline)
        except (ValueError, TypeError):
            raise ValidationError(
                message=f"{field_name} must be a valid timestamp",
                details={"field": field_name, "value": str(deadline)},
            )

    if deadline <= current_time:
        raise ValidationError(
            message=f"{field_name} must be in the future",
            details={
                "field": field_name,
                "deadline": deadline,
                "current_time": current_time,
                "difference": current_time - deadline,
            },
        )

    return deadline


def validate_tx_id(tx_id: str, field_name: str = "tx_id") -> str:
    """
    Validate transaction ID (bytes32 hex format).

    Args:
        tx_id: Transaction ID to validate
        field_name: Field name for error messages

    Returns:
        Normalized (lowercase) transaction ID

    Raises:
        ValidationError: If tx_id is invalid
    """
    if not tx_id:
        raise ValidationError(
            message=f"{field_name} is required",
            details={"field": field_name, "value": None},
        )

    if not isinstance(tx_id, str):
        raise ValidationError(
            message=f"{field_name} must be a string",
            details={"field": field_name, "value": str(tx_id)},
        )

    # Check format: 0x + 64 hex chars
    if not re.match(r"^0x[0-9a-fA-F]{64}$", tx_id):
        raise ValidationError(
            message=f"Invalid {field_name}: must be 0x followed by 64 hex characters",
            details={"field": field_name, "value": tx_id},
        )

    return tx_id.lower()


def validate_endpoint_url(url: str, field_name: str = "url") -> str:
    """
    Validate endpoint URL with SSRF protection.

    Blocks requests to:
    - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - Localhost (127.x.x.x)
    - Link-local addresses
    - IPv6 private ranges

    Args:
        url: URL to validate
        field_name: Field name for error messages

    Returns:
        Validated URL

    Raises:
        ValidationError: If URL is invalid or points to private network
    """
    if not url:
        raise ValidationError(
            message=f"{field_name} is required",
            details={"field": field_name, "value": None},
        )

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError(
            message=f"Invalid {field_name}: malformed URL",
            details={"field": field_name, "value": url},
        )

    # Check scheme
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            message=f"Invalid {field_name}: scheme must be http or https",
            details={"field": field_name, "value": url, "scheme": parsed.scheme},
        )

    # Check hostname exists
    if not parsed.hostname:
        raise ValidationError(
            message=f"Invalid {field_name}: missing hostname",
            details={"field": field_name, "value": url},
        )

    hostname = parsed.hostname.lower()

    # Block localhost aliases
    localhost_aliases = ["localhost", "0.0.0.0", "[::]", "[::1]"]
    if hostname in localhost_aliases:
        raise ValidationError(
            message=f"Invalid {field_name}: localhost not allowed",
            details={"field": field_name, "value": url, "reason": "localhost blocked"},
        )

    # Try to parse as IP address
    try:
        ip = ipaddress.ip_address(hostname)
        for private_range in PRIVATE_IP_RANGES:
            if ip in private_range:
                raise ValidationError(
                    message=f"Invalid {field_name}: private IP addresses not allowed",
                    details={
                        "field": field_name,
                        "value": url,
                        "reason": "private IP blocked",
                        "ip": str(ip),
                    },
                )
    except ValueError:
        # Not an IP address, it's a hostname - that's OK
        pass

    # Block metadata endpoints (common cloud vulnerability)
    metadata_hosts = [
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "metadata.google.internal",
        "metadata",
    ]
    if hostname in metadata_hosts:
        raise ValidationError(
            message=f"Invalid {field_name}: cloud metadata endpoint not allowed",
            details={"field": field_name, "value": url, "reason": "metadata endpoint blocked"},
        )

    return url


def validate_dispute_window(
    seconds: int,
    field_name: str = "dispute_window",
    min_seconds: Optional[int] = None,
    max_seconds: Optional[int] = None,
) -> int:
    """
    Validate dispute window duration.

    Args:
        seconds: Dispute window in seconds
        field_name: Field name for error messages
        min_seconds: Minimum allowed (default: DisputeWindow.MIN)
        max_seconds: Maximum allowed (default: DisputeWindow.MAX)

    Returns:
        Validated dispute window in seconds

    Raises:
        ValidationError: If dispute window is out of bounds
    """
    min_val = min_seconds if min_seconds is not None else DisputeWindow.MIN
    max_val = max_seconds if max_seconds is not None else DisputeWindow.MAX

    if not isinstance(seconds, int):
        try:
            seconds = int(seconds)
        except (ValueError, TypeError):
            raise ValidationError(
                message=f"{field_name} must be a valid integer",
                details={"field": field_name, "value": str(seconds)},
            )

    if seconds < min_val:
        hours = min_val / 3600
        raise ValidationError(
            message=f"{field_name} must be at least {min_val} seconds ({hours:.1f} hours)",
            details={
                "field": field_name,
                "value": seconds,
                "minimum": min_val,
            },
        )

    if seconds > max_val:
        days = max_val / 86400
        raise ValidationError(
            message=f"{field_name} cannot exceed {max_val} seconds ({days:.0f} days)",
            details={
                "field": field_name,
                "value": seconds,
                "maximum": max_val,
            },
        )

    return seconds


def validate_bytes32(value: str, field_name: str = "value") -> str:
    """
    Validate bytes32 hex format.

    Alias for validate_tx_id for clarity in different contexts.

    Args:
        value: Value to validate
        field_name: Field name for error messages

    Returns:
        Normalized (lowercase) bytes32 value

    Raises:
        ValidationError: If value is invalid
    """
    return validate_tx_id(value, field_name)


def validate_service_name(name: str, field_name: str = "service_name") -> str:
    """
    Validate service name format.

    Allows: alphanumeric, dash, dot, underscore
    Max length: 128 characters

    Args:
        name: Service name to validate
        field_name: Field name for error messages

    Returns:
        Validated service name

    Raises:
        ValidationError: If name is invalid
    """
    if not name:
        raise ValidationError(
            message=f"{field_name} is required",
            details={"field": field_name, "value": None},
        )

    if len(name) > 128:
        raise ValidationError(
            message=f"{field_name} too long (max 128 characters)",
            details={"field": field_name, "value": name, "length": len(name)},
        )

    # Allow alphanumeric, dash, dot, underscore
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        raise ValidationError(
            message=f"Invalid {field_name}: only alphanumeric, dash, dot, underscore allowed",
            details={"field": field_name, "value": name},
        )

    return name
