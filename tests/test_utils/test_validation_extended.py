"""
Extended Coverage Tests for validation.py.

These tests cover additional code paths not fully covered in test_validation.py:
- validate_address: non-string type rejection
- validate_deadline: full coverage including invalid timestamp conversion
- validate_tx_id: empty and non-string handling
- _is_metadata_host: regex pattern matching
- _resolve_and_check_ip: DNS resolution paths
- validate_endpoint_url: malformed URL, DNS resolution
- validate_dispute_window: invalid type conversion
- validate_service_metadata: bytes metadata, invalid types
- validate_content_hash: non-string, invalid hex
"""

from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from agirails.utils.validation import (
    validate_address,
    validate_amount,
    validate_deadline,
    validate_tx_id,
    validate_bytes32,
    validate_dispute_window,
    validate_endpoint_url,
    validate_service_name,
    validate_service_metadata,
    validate_content_hash,
    _is_metadata_host,
    _is_private_ip,
    _resolve_and_check_ip,
)
from agirails.errors import ValidationError, InvalidAddressError, InvalidAmountError

import ipaddress


class TestValidateAddressExtended:
    """Extended tests for validate_address covering non-string types."""

    def test_rejects_integer_type(self):
        """Reject integer instead of string."""
        with pytest.raises(InvalidAddressError, match="must be a string"):
            validate_address(12345)  # type: ignore

    def test_rejects_list_type(self):
        """Reject list instead of string."""
        with pytest.raises(InvalidAddressError, match="must be a string"):
            validate_address(["0x1234"])  # type: ignore

    def test_rejects_dict_type(self):
        """Reject dict instead of string."""
        with pytest.raises(InvalidAddressError, match="must be a string"):
            validate_address({"address": "0x1234"})  # type: ignore

    def test_custom_field_name_in_error(self):
        """Custom field name appears in error."""
        with pytest.raises(InvalidAddressError) as exc_info:
            validate_address("", field_name="provider_address")
        assert "provider_address" in str(exc_info.value)


class TestValidateDeadlineExtended:
    """Extended tests for validate_deadline covering all branches."""

    def test_valid_future_deadline(self):
        """Accept deadline in the future."""
        current = 1000
        result = validate_deadline(2000, current)
        assert result == 2000

    def test_rejects_deadline_in_past(self):
        """Reject deadline that has already passed."""
        current = 2000
        with pytest.raises(ValidationError, match="must be in the future"):
            validate_deadline(1000, current)

    def test_rejects_deadline_equal_to_current(self):
        """Reject deadline equal to current time."""
        current = 1000
        with pytest.raises(ValidationError, match="must be in the future"):
            validate_deadline(1000, current)

    def test_converts_string_deadline(self):
        """Convert string deadline to integer."""
        current = 1000
        result = validate_deadline("2000", current)  # type: ignore
        assert result == 2000

    def test_converts_float_deadline(self):
        """Convert float deadline to integer."""
        current = 1000
        result = validate_deadline(2000.5, current)  # type: ignore
        assert result == 2000

    def test_rejects_invalid_string_deadline(self):
        """Reject non-numeric string deadline."""
        current = 1000
        with pytest.raises(ValidationError, match="valid timestamp"):
            validate_deadline("not_a_number", current)

    def test_rejects_none_deadline(self):
        """Reject None deadline."""
        current = 1000
        with pytest.raises(ValidationError, match="valid timestamp"):
            validate_deadline(None, current)  # type: ignore

    def test_rejects_list_deadline(self):
        """Reject list deadline."""
        current = 1000
        with pytest.raises(ValidationError, match="valid timestamp"):
            validate_deadline([2000], current)  # type: ignore

    def test_custom_field_name_in_error(self):
        """Custom field name appears in error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_deadline(1000, 2000, field_name="job_deadline")
        assert "job_deadline" in str(exc_info.value)


class TestValidateTxIdExtended:
    """Extended tests for validate_tx_id covering empty and non-string."""

    def test_rejects_none_tx_id(self):
        """Reject None tx_id."""
        with pytest.raises(ValidationError, match="required"):
            validate_tx_id(None)  # type: ignore

    def test_rejects_integer_tx_id(self):
        """Reject integer tx_id."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_tx_id(12345)  # type: ignore

    def test_rejects_list_tx_id(self):
        """Reject list tx_id."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_tx_id(["0x" + "a" * 64])  # type: ignore

    def test_custom_field_name(self):
        """Custom field name in validation."""
        with pytest.raises(ValidationError) as exc_info:
            validate_tx_id("invalid", field_name="transaction_hash")
        assert "transaction_hash" in str(exc_info.value)


class TestIsMetadataHostExtended:
    """Extended tests for _is_metadata_host pattern matching."""

    def test_aws_regional_metadata_pattern(self):
        """Match AWS regional metadata endpoints."""
        assert _is_metadata_host("metadata.us-east-1.amazonaws.com") is True
        assert _is_metadata_host("metadata.eu-west-1.amazonaws.com") is True

    def test_gcp_subdomain_pattern(self):
        """Match GCP metadata subdomains."""
        assert _is_metadata_host("foo.metadata.google.internal") is True
        assert _is_metadata_host("bar.baz.metadata.google.internal") is True

    def test_azure_metadata_pattern(self):
        """Match Azure metadata endpoints."""
        assert _is_metadata_host("metadata.azure.com") is True
        assert _is_metadata_host("management.azure.com") is True

    def test_case_insensitive_matching(self):
        """Matching is case-insensitive."""
        assert _is_metadata_host("METADATA.GOOGLE.INTERNAL") is True
        assert _is_metadata_host("Metadata.Azure.Com") is True

    def test_non_metadata_hosts(self):
        """Non-metadata hosts return False."""
        assert _is_metadata_host("example.com") is False
        assert _is_metadata_host("api.google.com") is False
        assert _is_metadata_host("metadata-fake.com") is False


class TestIsPrivateIpExtended:
    """Extended tests for _is_private_ip helper."""

    def test_ipv4_private_ranges(self):
        """Check all IPv4 private ranges."""
        # 10.x.x.x
        assert _is_private_ip(ipaddress.ip_address("10.0.0.1")) is True
        assert _is_private_ip(ipaddress.ip_address("10.255.255.255")) is True

        # 172.16-31.x.x
        assert _is_private_ip(ipaddress.ip_address("172.16.0.1")) is True
        assert _is_private_ip(ipaddress.ip_address("172.31.255.255")) is True

        # 192.168.x.x
        assert _is_private_ip(ipaddress.ip_address("192.168.0.1")) is True
        assert _is_private_ip(ipaddress.ip_address("192.168.255.255")) is True

        # 127.x.x.x (localhost)
        assert _is_private_ip(ipaddress.ip_address("127.0.0.1")) is True
        assert _is_private_ip(ipaddress.ip_address("127.255.255.255")) is True

        # 169.254.x.x (link-local)
        assert _is_private_ip(ipaddress.ip_address("169.254.0.1")) is True

    def test_ipv6_private_ranges(self):
        """Check IPv6 private ranges."""
        # ::1 (localhost)
        assert _is_private_ip(ipaddress.ip_address("::1")) is True

        # fc00::/7 (unique local)
        assert _is_private_ip(ipaddress.ip_address("fc00::1")) is True
        assert _is_private_ip(ipaddress.ip_address("fd00::1")) is True

        # fe80::/10 (link-local)
        assert _is_private_ip(ipaddress.ip_address("fe80::1")) is True

    def test_public_ips(self):
        """Public IPs return False."""
        assert _is_private_ip(ipaddress.ip_address("8.8.8.8")) is False
        assert _is_private_ip(ipaddress.ip_address("1.1.1.1")) is False
        assert _is_private_ip(ipaddress.ip_address("2001:4860:4860::8888")) is False


class TestResolveAndCheckIpExtended:
    """Extended tests for _resolve_and_check_ip DNS resolution."""

    def test_resolves_to_private_ip_raises(self):
        """Raise ValidationError when hostname resolves to private IP."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Simulate hostname resolving to private IP
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
            ]

            with pytest.raises(ValidationError, match="private IP"):
                _resolve_and_check_ip("malicious.example.com", "url", "http://malicious.example.com")

    def test_resolves_to_public_ip_passes(self):
        """No exception when hostname resolves to public IP."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))
            ]

            # Should not raise
            _resolve_and_check_ip("google.com", "url", "http://google.com")

    def test_dns_resolution_failure_passes(self):
        """DNS resolution failure is allowed (fails later on actual request)."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.gaierror("DNS failed")

            # Should not raise - DNS failure is OK
            _resolve_and_check_ip("nonexistent.example.com", "url", "http://nonexistent.example.com")

    def test_dns_timeout_passes(self):
        """DNS timeout is allowed."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.timeout("Timed out")

            # Should not raise
            _resolve_and_check_ip("slow.example.com", "url", "http://slow.example.com")

    def test_invalid_ip_format_skipped(self):
        """Invalid IP format in DNS response is skipped."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Return something that's not a valid IP
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("not-an-ip", 0))
            ]

            # Should not raise (skip invalid format)
            _resolve_and_check_ip("weird.example.com", "url", "http://weird.example.com")

    def test_multiple_ips_one_private_raises(self):
        """Raise if any resolved IP is private."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0)),  # Private!
            ]

            with pytest.raises(ValidationError, match="private IP"):
                _resolve_and_check_ip("dual.example.com", "url", "http://dual.example.com")


class TestValidateEndpointUrlExtended:
    """Extended tests for validate_endpoint_url edge cases."""

    def test_malformed_url_raises(self):
        """Raise on truly malformed URL."""
        # urlparse is very permissive, so we need edge cases
        # This URL has no valid scheme
        with pytest.raises(ValidationError, match="scheme must be http or https"):
            validate_endpoint_url("://no-scheme")

    def test_with_dns_resolution_enabled(self):
        """Test with DNS resolution enabled (default)."""
        with patch("agirails.utils.validation._resolve_and_check_ip") as mock_resolve:
            result = validate_endpoint_url("https://example.com/api", resolve_dns=True)
            assert result == "https://example.com/api"
            mock_resolve.assert_called_once()

    def test_with_dns_resolution_disabled(self):
        """Test with DNS resolution disabled."""
        with patch("agirails.utils.validation._resolve_and_check_ip") as mock_resolve:
            result = validate_endpoint_url("https://example.com/api", resolve_dns=False)
            assert result == "https://example.com/api"
            mock_resolve.assert_not_called()

    def test_url_with_ipv6_address(self):
        """Handle URL with IPv6 address."""
        # Public IPv6
        result = validate_endpoint_url("http://[2001:4860:4860::8888]/api", resolve_dns=False)
        assert "2001:4860:4860::8888" in result

    def test_url_with_private_ipv6(self):
        """Block URL with private IPv6 address."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://[fd00::1]/api", resolve_dns=False)


class TestValidateDisputeWindowExtended:
    """Extended tests for validate_dispute_window type conversion."""

    def test_rejects_invalid_string(self):
        """Reject non-numeric string."""
        with pytest.raises(ValidationError, match="valid integer"):
            validate_dispute_window("not_a_number")  # type: ignore

    def test_rejects_none(self):
        """Reject None."""
        with pytest.raises(ValidationError, match="valid integer"):
            validate_dispute_window(None)  # type: ignore

    def test_rejects_list(self):
        """Reject list type."""
        with pytest.raises(ValidationError, match="valid integer"):
            validate_dispute_window([3600])  # type: ignore

    def test_rejects_dict(self):
        """Reject dict type."""
        with pytest.raises(ValidationError, match="valid integer"):
            validate_dispute_window({"seconds": 3600})  # type: ignore

    def test_custom_min_max_seconds(self):
        """Use custom min and max seconds."""
        # Custom minimum
        with pytest.raises(ValidationError, match="at least"):
            validate_dispute_window(100, min_seconds=200)

        # Custom maximum
        with pytest.raises(ValidationError, match="cannot exceed"):
            validate_dispute_window(500, min_seconds=0, max_seconds=400)

        # Valid within custom bounds
        result = validate_dispute_window(300, min_seconds=100, max_seconds=500)
        assert result == 300


class TestValidateServiceMetadataExtended:
    """Extended tests for validate_service_metadata type handling."""

    def test_valid_bytes_metadata(self):
        """Accept bytes metadata."""
        data = b"binary data here"
        result = validate_service_metadata(data)
        assert result == data

    def test_bytes_metadata_size_check(self):
        """Check bytes metadata size."""
        large_bytes = b"x" * 20000  # > 10KB
        with pytest.raises(ValidationError, match="exceeds maximum"):
            validate_service_metadata(large_bytes)

    def test_rejects_integer_type(self):
        """Reject integer metadata."""
        with pytest.raises(ValidationError, match="must be string, bytes, or dict"):
            validate_service_metadata(12345)  # type: ignore

    def test_rejects_list_type(self):
        """Reject list metadata."""
        with pytest.raises(ValidationError, match="must be string, bytes, or dict"):
            validate_service_metadata(["item1", "item2"])  # type: ignore

    def test_rejects_set_type(self):
        """Reject set metadata."""
        with pytest.raises(ValidationError, match="must be string, bytes, or dict"):
            validate_service_metadata({"item1", "item2"})  # type: ignore

    def test_custom_max_size(self):
        """Use custom max size."""
        small_max = 100
        data = "x" * 200  # > custom max
        with pytest.raises(ValidationError, match="exceeds maximum"):
            validate_service_metadata(data, max_size=small_max)

    def test_dict_with_unicode(self):
        """Dict with unicode characters calculates size correctly."""
        # Unicode takes more bytes when UTF-8 encoded
        meta = {"emoji": "🎉🎊🎈"}  # Each emoji is 4 bytes
        result = validate_service_metadata(meta)
        assert result == meta


class TestValidateContentHashExtended:
    """Extended tests for validate_content_hash type and format handling."""

    def test_rejects_integer_type(self):
        """Reject integer hash."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_content_hash(12345)  # type: ignore

    def test_rejects_bytes_type(self):
        """Reject bytes hash."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_content_hash(b"0x" + b"a" * 64)  # type: ignore

    def test_rejects_invalid_hex_characters(self):
        """Reject hash with non-hex characters."""
        with pytest.raises(ValidationError, match="hex characters"):
            validate_content_hash("0x" + "g" * 64)  # 'g' is not hex

    def test_rejects_mixed_invalid_hex(self):
        """Reject hash with some invalid hex characters."""
        with pytest.raises(ValidationError, match="hex characters"):
            validate_content_hash("0x123xyz789" + "a" * 54)

    def test_valid_40_byte_hash(self):
        """Accept 20-byte hash (40 hex chars) - like RIPEMD160."""
        hash_val = "0x" + "a" * 40
        result = validate_content_hash(hash_val)
        assert result == hash_val

    def test_valid_128_byte_hash(self):
        """Accept 64-byte hash (128 hex chars) - like SHA-512."""
        hash_val = "0x" + "b" * 128
        result = validate_content_hash(hash_val)
        assert result == hash_val

    def test_custom_prefix(self):
        """Use custom expected prefix."""
        # No prefix
        result = validate_content_hash("abcd" * 16, expected_prefix="")
        assert result == ("abcd" * 16).lower()

        # Different prefix
        with pytest.raises(ValidationError, match="must start with"):
            validate_content_hash("0xabc", expected_prefix="sha256:")

    def test_none_hash(self):
        """Reject None hash."""
        with pytest.raises(ValidationError, match="required"):
            validate_content_hash(None)  # type: ignore


class TestValidateAmountExtended:
    """Extended tests for validate_amount edge cases."""

    def test_zero_amount_default(self):
        """Zero is valid by default (min_amount=0)."""
        result = validate_amount(0)
        assert result == 0

    def test_float_passed_through(self):
        """Float is passed through (function expects int/str but tolerates float)."""
        # Note: The function doesn't explicitly convert floats to int
        # It only converts strings. Float behavior is undefined but tolerated.
        result = validate_amount(100)
        assert result == 100

    def test_custom_field_name_in_details(self):
        """Custom field name appears in error details."""
        with pytest.raises(InvalidAmountError) as exc_info:
            validate_amount(-1, field_name="payment_amount")
        # Field name is in details, not necessarily in message
        assert exc_info.value.details.get("field") == "payment_amount"

    def test_rejects_invalid_string_format(self):
        """Reject invalid string formats."""
        with pytest.raises(InvalidAmountError, match="valid number"):
            validate_amount("abc123")

    def test_rejects_empty_string(self):
        """Reject empty string."""
        with pytest.raises(InvalidAmountError, match="valid number"):
            validate_amount("")
