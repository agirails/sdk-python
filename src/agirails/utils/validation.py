"""
Validation utilities for AGIRAILS SDK.

Provides input validation functions for:
- Ethereum addresses
- USDC amounts
- Transaction deadlines
- Transaction IDs (bytes32)
- Endpoint URLs (SSRF protection with DNS rebinding defense)
- Dispute windows
- Service metadata size limits

All validation functions raise ValidationError (or subclasses) on failure.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import List, Optional, Union
from urllib.parse import urlparse

from agirails.errors import ValidationError, InvalidAddressError, InvalidAmountError
from agirails.utils.helpers import DisputeWindow


# Constants
MAX_UINT256 = 2**256 - 1
MAX_USDC_WEI = 10**18  # 1 trillion USDC in wei (reasonable max)

# Maximum service metadata size (10 KB)
MAX_SERVICE_METADATA_SIZE = 10_000

# Private IP ranges for SSRF protection
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),     # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),    # IPv6 link-local
    ipaddress.ip_network("fd00::/8"),     # IPv6 private
]

# Cloud metadata endpoints to block (H-1 SSRF protection)
METADATA_HOSTS = frozenset([
    # AWS IPv4 metadata
    "169.254.169.254",
    # AWS IPv6 metadata
    "fd00:ec2::254",
    "[fd00:ec2::254]",
    # GCP metadata
    "metadata.google.internal",
    "metadata",
    # Azure metadata
    "169.254.169.254",
    # Generic
    "metadata.internal",
])

# Regex patterns for cloud metadata hosts
METADATA_HOST_PATTERNS = [
    re.compile(r"^metadata\..*\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"^.*\.metadata\.google\.internal$", re.IGNORECASE),
    re.compile(r"^metadata\.azure\.com$", re.IGNORECASE),
    re.compile(r"^management\.azure\.com$", re.IGNORECASE),
]

# Localhost aliases to block
LOCALHOST_ALIASES = frozenset([
    "localhost",
    "0.0.0.0",
    "[::]",
    "[::1]",
    "127.0.0.1",
    "0",
    "0.0.0.0.0",
])


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


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is in a private range."""
    for private_range in PRIVATE_IP_RANGES:
        if ip in private_range:
            return True
    return False


def _is_metadata_host(hostname: str) -> bool:
    """
    Check if hostname matches a cloud metadata endpoint.

    Security Note (H-1): Blocks known cloud metadata endpoints
    including regional AWS endpoints.
    """
    hostname_lower = hostname.lower()

    # Check exact matches
    if hostname_lower in METADATA_HOSTS:
        return True

    # Check regex patterns (regional endpoints, subdomains)
    for pattern in METADATA_HOST_PATTERNS:
        if pattern.match(hostname_lower):
            return True

    return False


def _resolve_and_check_ip(hostname: str, field_name: str, url: str) -> None:
    """
    Resolve hostname to IP and check for private IPs.

    Security Note (H-1): Prevents DNS rebinding attacks by resolving
    the hostname and checking if it points to a private IP.

    Args:
        hostname: Hostname to resolve
        field_name: Field name for error messages
        url: Original URL for error messages

    Raises:
        ValidationError: If hostname resolves to a private IP
    """
    try:
        # Get all IP addresses for the hostname
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if _is_private_ip(ip):
                    raise ValidationError(
                        message=f"Invalid {field_name}: hostname resolves to private IP",
                        details={
                            "field": field_name,
                            "value": url,
                            "reason": "DNS rebinding protection - hostname resolves to private IP",
                            "hostname": hostname,
                            "resolved_ip": str(ip),
                        },
                    )
            except ValueError:
                # Invalid IP format - skip
                continue

    except socket.gaierror:
        # DNS resolution failed - allow it to fail naturally on actual request
        pass
    except socket.timeout:
        # DNS timeout - allow it to fail naturally
        pass


def validate_endpoint_url(
    url: str,
    field_name: str = "url",
    resolve_dns: bool = True,
) -> str:
    """
    Validate endpoint URL with comprehensive SSRF protection.

    Security Note (H-1): Provides defense-in-depth SSRF protection:
    - Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)
    - Blocks localhost aliases (localhost, 0.0.0.0, ::1)
    - Blocks IPv6 private ranges (fc00::/7, fe80::/10, fd00::/8)
    - Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
    - Blocks regional AWS metadata endpoints (metadata.*.amazonaws.com)
    - DNS rebinding protection: resolves hostname and checks resolved IP

    Args:
        url: URL to validate
        field_name: Field name for error messages
        resolve_dns: Whether to resolve DNS and check for private IPs (default: True)

    Returns:
        Validated URL

    Raises:
        ValidationError: If URL is invalid or points to private/blocked network
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
    if hostname in LOCALHOST_ALIASES:
        raise ValidationError(
            message=f"Invalid {field_name}: localhost not allowed",
            details={"field": field_name, "value": url, "reason": "localhost blocked"},
        )

    # Block cloud metadata endpoints (including patterns)
    if _is_metadata_host(hostname):
        raise ValidationError(
            message=f"Invalid {field_name}: cloud metadata endpoint not allowed",
            details={"field": field_name, "value": url, "reason": "metadata endpoint blocked"},
        )

    # Try to parse as IP address and check for private ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_private_ip(ip):
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
        # Not an IP address, it's a hostname
        # Perform DNS rebinding check if enabled
        if resolve_dns:
            _resolve_and_check_ip(hostname, field_name, url)

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


def validate_service_metadata(
    metadata: Union[str, bytes, dict],
    field_name: str = "service_metadata",
    max_size: int = MAX_SERVICE_METADATA_SIZE,
) -> Union[str, bytes, dict]:
    """
    Validate service metadata size and content.

    Security Note (H-4): Prevents DoS attacks via oversized metadata
    that could exhaust memory or storage.

    Args:
        metadata: Service metadata (string, bytes, or dict)
        field_name: Field name for error messages
        max_size: Maximum size in bytes (default: 10 KB)

    Returns:
        Validated metadata (unchanged if valid)

    Raises:
        ValidationError: If metadata exceeds size limit or is invalid
    """
    import json

    if metadata is None:
        return metadata  # type: ignore[return-value]

    # Calculate size based on type
    if isinstance(metadata, str):
        size = len(metadata.encode("utf-8"))
    elif isinstance(metadata, bytes):
        size = len(metadata)
    elif isinstance(metadata, dict):
        try:
            # Serialize to JSON to calculate size
            serialized = json.dumps(metadata, separators=(",", ":"))
            size = len(serialized.encode("utf-8"))
        except (TypeError, ValueError) as e:
            raise ValidationError(
                message=f"Invalid {field_name}: not JSON-serializable",
                details={"field": field_name, "reason": str(e)},
            )
    else:
        raise ValidationError(
            message=f"Invalid {field_name}: must be string, bytes, or dict",
            details={"field": field_name, "type": type(metadata).__name__},
        )

    if size > max_size:
        raise ValidationError(
            message=f"{field_name} exceeds maximum size ({max_size} bytes)",
            details={
                "field": field_name,
                "size": size,
                "max_size": max_size,
                "exceeded_by": size - max_size,
            },
        )

    return metadata


def validate_content_hash(
    content_hash: str,
    field_name: str = "content_hash",
    expected_prefix: str = "0x",
) -> str:
    """
    Validate content hash format.

    Args:
        content_hash: Hash to validate (hex string)
        field_name: Field name for error messages
        expected_prefix: Expected prefix (default: "0x")

    Returns:
        Normalized (lowercase) content hash

    Raises:
        ValidationError: If hash is invalid
    """
    if not content_hash:
        raise ValidationError(
            message=f"{field_name} is required",
            details={"field": field_name, "value": None},
        )

    if not isinstance(content_hash, str):
        raise ValidationError(
            message=f"{field_name} must be a string",
            details={"field": field_name, "type": type(content_hash).__name__},
        )

    # Check prefix
    if expected_prefix and not content_hash.startswith(expected_prefix):
        raise ValidationError(
            message=f"Invalid {field_name}: must start with {expected_prefix}",
            details={"field": field_name, "value": content_hash},
        )

    # Check hex format (after 0x prefix)
    hex_part = content_hash[len(expected_prefix):] if expected_prefix else content_hash
    if not re.match(r"^[0-9a-fA-F]+$", hex_part):
        raise ValidationError(
            message=f"Invalid {field_name}: must contain only hex characters",
            details={"field": field_name, "value": content_hash},
        )

    # Common hash lengths: 32 bytes (SHA256/Keccak256), 20 bytes (RIPEMD160)
    if len(hex_part) not in (40, 64, 128):  # 20, 32, or 64 bytes
        raise ValidationError(
            message=f"Invalid {field_name}: unexpected hash length",
            details={
                "field": field_name,
                "value": content_hash,
                "length": len(hex_part) // 2,
                "expected_lengths": [20, 32, 64],
            },
        )

    return content_hash.lower()


# ============================================================================
# Storage Validation (AIP-7)
# ============================================================================

# IPFS Gateway Whitelist (SSRF Protection)
ALLOWED_IPFS_GATEWAYS = frozenset([
    "https://ipfs.filebase.io",
    "https://gateway.pinata.cloud",
    "https://ipfs.io",
    "https://cloudflare-ipfs.com",
    "https://w3s.link",
    "https://dweb.link",
])

# Arweave Gateway Whitelist
ALLOWED_ARWEAVE_GATEWAYS = frozenset([
    "https://arweave.net",
    "https://gateway.irys.xyz",
])

# CID Patterns
CID_V0_PATTERN = re.compile(r"^Qm[1-9A-HJ-NP-Za-km-z]{44}$")
CID_V1_PATTERN = re.compile(r"^b[a-z2-7]{58,}$")


def validate_cid(cid: str) -> bool:
    """
    Validate IPFS CID format (v0 or v1).

    Args:
        cid: IPFS CID to validate

    Returns:
        True if valid CID format, False otherwise

    Example:
        >>> validate_cid("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
        True
        >>> validate_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        True
        >>> validate_cid("invalid-cid")
        False
    """
    if not cid:
        return False

    # CIDv0 starts with Qm (46 chars total)
    if CID_V0_PATTERN.match(cid):
        return True

    # CIDv1 starts with b (base32, variable length but typically 59+ chars)
    if CID_V1_PATTERN.match(cid):
        return True

    return False


def is_gateway_allowed(gateway_url: str) -> bool:
    """
    Check if gateway URL is in whitelist (SSRF protection).

    Args:
        gateway_url: Gateway URL to check

    Returns:
        True if gateway is whitelisted, False otherwise

    Example:
        >>> is_gateway_allowed("https://ipfs.filebase.io/ipfs/Qm...")
        True
        >>> is_gateway_allowed("https://evil.com/ipfs/Qm...")
        False
    """
    if not gateway_url:
        return False

    try:
        parsed = urlparse(gateway_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check against both IPFS and Arweave gateways
        return base in ALLOWED_IPFS_GATEWAYS or base in ALLOWED_ARWEAVE_GATEWAYS
    except Exception:
        return False


def sanitize_for_logging(value: str) -> str:
    """
    Sanitize sensitive values for safe logging.

    Masks sensitive data while keeping enough info for debugging.

    Args:
        value: Value to sanitize

    Returns:
        Sanitized string safe for logs

    Example:
        >>> sanitize_for_logging("sk_live_abc123xyz789secret")
        "sk_l...cret"
        >>> sanitize_for_logging("short")
        "[redacted]"
    """
    if not value:
        return "[empty]"

    if len(value) <= 8:
        return "[redacted]"

    # Show first 4 and last 4 characters
    return f"{value[:4]}...{value[-4:]}"
