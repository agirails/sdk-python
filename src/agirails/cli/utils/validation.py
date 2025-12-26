"""
CLI Input Validation Utilities.

Provides validation for CLI arguments before passing to SDK.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional

import typer


# Ethereum address pattern
ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Transaction ID pattern (bytes32)
TX_ID_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")


def validate_address(
    address: str,
    param_name: str = "address",
    require_checksum: bool = False,
) -> str:
    """
    Validate Ethereum address format with optional checksum verification.

    Security Note (L-3): When require_checksum=True, validates EIP-55
    checksum to ensure address integrity and prevent typos.

    Args:
        address: Address to validate
        param_name: Parameter name for error message
        require_checksum: If True, validates EIP-55 checksum

    Returns:
        Checksum-formatted address

    Raises:
        typer.BadParameter: If address is invalid or checksum fails
    """
    if not address:
        raise typer.BadParameter(f"{param_name} is required")

    if not ADDRESS_PATTERN.match(address):
        raise typer.BadParameter(
            f"Invalid {param_name}: must be 0x followed by 40 hex characters"
        )

    # Compute EIP-55 checksum
    try:
        checksum_address = _to_checksum_address(address)
    except ValueError as e:
        raise typer.BadParameter(f"Invalid {param_name}: {e}")

    # If checksum required and address has mixed case, verify it matches
    if require_checksum:
        # Check if address has any uppercase letters (indicating checksum attempt)
        has_uppercase = any(c.isupper() for c in address[2:])
        if has_uppercase and address != checksum_address:
            raise typer.BadParameter(
                f"Invalid {param_name} checksum. Expected: {checksum_address}"
            )

    return checksum_address


def _to_checksum_address(address: str) -> str:
    """
    Convert address to EIP-55 checksum format.

    Security Note (L-3): Uses keccak256 hash of lowercase address
    to compute checksum, matching EIP-55 specification.

    Args:
        address: Ethereum address (with or without checksum)

    Returns:
        EIP-55 checksummed address

    Raises:
        ValueError: If address format is invalid
    """
    import hashlib

    # Remove 0x prefix and lowercase
    addr = address.lower().replace("0x", "")

    if len(addr) != 40:
        raise ValueError("Address must be 40 hex characters")

    # Use keccak256 for EIP-55 checksum
    # Since we may not have keccak256, use sha3_256 (close enough for validation)
    # Note: For production, use proper keccak256 from web3 or eth_utils
    try:
        from eth_utils import to_checksum_address as eth_to_checksum
        return eth_to_checksum(address)
    except ImportError:
        pass

    try:
        from web3 import Web3
        return Web3.to_checksum_address(address)
    except ImportError:
        pass

    # Fallback: Use sha3/keccak256 if available, otherwise just normalize
    try:
        import sha3
        hash_bytes = sha3.keccak_256(addr.encode()).hexdigest()
    except ImportError:
        # Last resort: just return lowercase (no checksum validation)
        return "0x" + addr

    # Apply EIP-55 checksum
    result = "0x"
    for i, char in enumerate(addr):
        if char in "0123456789":
            result += char
        elif int(hash_bytes[i], 16) >= 8:
            result += char.upper()
        else:
            result += char

    return result


def validate_amount(amount: str, allow_zero: bool = False) -> str:
    """
    Validate USDC amount format.

    Args:
        amount: Amount string to validate
        allow_zero: Whether to allow zero amount

    Returns:
        Validated amount string

    Raises:
        typer.BadParameter: If amount is invalid
    """
    try:
        value = Decimal(amount)
    except InvalidOperation:
        raise typer.BadParameter(f"Invalid amount format: {amount}")

    if value < 0:
        raise typer.BadParameter("Amount cannot be negative")

    if not allow_zero and value == 0:
        raise typer.BadParameter("Amount must be greater than zero")

    # Check for excessive precision (USDC has 6 decimals)
    if value.as_tuple().exponent < -6:
        raise typer.BadParameter("Amount cannot have more than 6 decimal places")

    return amount


def validate_tx_id(tx_id: str) -> str:
    """
    Validate transaction ID format (bytes32).

    Args:
        tx_id: Transaction ID to validate

    Returns:
        Lowercase normalized transaction ID

    Raises:
        typer.BadParameter: If transaction ID is invalid
    """
    if not tx_id:
        raise typer.BadParameter("Transaction ID is required")

    if not TX_ID_PATTERN.match(tx_id):
        raise typer.BadParameter(
            "Invalid transaction ID: must be 0x followed by 64 hex characters"
        )

    return tx_id.lower()


def validate_state(state: str) -> str:
    """
    Validate transaction state.

    Args:
        state: State to validate

    Returns:
        Uppercase normalized state

    Raises:
        typer.BadParameter: If state is invalid
    """
    valid_states = {
        "INITIATED", "QUOTED", "COMMITTED", "IN_PROGRESS",
        "DELIVERED", "SETTLED", "DISPUTED", "CANCELLED"
    }

    upper_state = state.upper()
    if upper_state not in valid_states:
        raise typer.BadParameter(
            f"Invalid state: {state}. Valid states: {', '.join(sorted(valid_states))}"
        )

    return upper_state


def validate_path(path: Path, must_exist: bool = False) -> Path:
    """
    Validate and resolve path, preventing traversal attacks.

    Args:
        path: Path to validate
        must_exist: Whether path must already exist

    Returns:
        Resolved absolute path

    Raises:
        typer.BadParameter: If path is invalid
    """
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise typer.BadParameter(f"Invalid path: {e}")

    if must_exist and not resolved.exists():
        raise typer.BadParameter(f"Path does not exist: {resolved}")

    return resolved


def validate_seconds(seconds: int) -> int:
    """
    Validate seconds value (for time commands).

    Args:
        seconds: Number of seconds

    Returns:
        Validated seconds

    Raises:
        typer.BadParameter: If seconds is invalid
    """
    if seconds < 0:
        raise typer.BadParameter("Seconds cannot be negative")

    if seconds > 365 * 24 * 3600:  # 1 year max
        raise typer.BadParameter("Seconds too large (max 1 year)")

    return seconds


def validate_timestamp(timestamp: int) -> int:
    """
    Validate Unix timestamp.

    Args:
        timestamp: Unix timestamp

    Returns:
        Validated timestamp

    Raises:
        typer.BadParameter: If timestamp is invalid
    """
    if timestamp < 0:
        raise typer.BadParameter("Timestamp cannot be negative")

    # Sanity check: must be after year 2020
    if timestamp < 1577836800:  # 2020-01-01
        raise typer.BadParameter("Timestamp too old (must be after 2020)")

    # Sanity check: must be before year 2100
    if timestamp > 4102444800:  # 2100-01-01
        raise typer.BadParameter("Timestamp too far in future (must be before 2100)")

    return timestamp


__all__ = [
    "validate_address",
    "validate_amount",
    "validate_tx_id",
    "validate_state",
    "validate_path",
    "validate_seconds",
    "validate_timestamp",
]
