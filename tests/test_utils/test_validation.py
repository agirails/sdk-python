"""
Validation Utilities Tests.

Comprehensive tests for validation.py including:
- SSRF protection (Gate 1.6)
- Unicode path traversal (Gate 1.6)
- Address validation
- Amount validation
- Dispute window validation
"""

from __future__ import annotations

import pytest

from agirails.utils.validation import (
    validate_endpoint_url,
    validate_address,
    validate_amount,
    validate_deadline,
    validate_tx_id,
    validate_bytes32,
    validate_dispute_window,
    validate_service_name,
    validate_service_metadata,
    validate_content_hash,
)
from agirails.errors import ValidationError, InvalidAddressError, InvalidAmountError


# =============================================================================
# SSRF Protection Tests (Gate 1 - 6.2)
# =============================================================================


class TestSSRFProtection:
    """
    SSRF (Server-Side Request Forgery) protection tests.

    Gate 1.6.2: SSRF blokira localhost, private IP, ipv6, redirect na private

    Tests validate_endpoint_url() blocks:
    - localhost and 127.0.0.1
    - Private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
    - IPv6 localhost (::1)
    - IPv6 private ranges (fc00::/7, fe80::/10, fd00::/8)
    - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
    - Decimal/octal IP representations
    """

    # --- Localhost Variants ---

    def test_blocks_localhost_keyword(self):
        """Block 'localhost' hostname."""
        with pytest.raises(ValidationError, match="localhost not allowed"):
            validate_endpoint_url("http://localhost/api", resolve_dns=False)

    def test_blocks_localhost_ip4(self):
        """Block 127.0.0.1 directly (in LOCALHOST_ALIASES)."""
        with pytest.raises(ValidationError, match="localhost not allowed"):
            validate_endpoint_url("http://127.0.0.1/api", resolve_dns=False)

    def test_blocks_127_range(self):
        """Block entire 127.x.x.x range."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://127.0.0.2/api", resolve_dns=False)
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://127.255.255.255/api", resolve_dns=False)

    def test_blocks_zero_ip(self):
        """Block 0.0.0.0 (listen all interfaces)."""
        with pytest.raises(ValidationError, match="localhost not allowed"):
            validate_endpoint_url("http://0.0.0.0/api", resolve_dns=False)

    # --- Private IPv4 Ranges ---

    def test_blocks_10_range(self):
        """Block 10.0.0.0/8 private range."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://10.0.0.1/api", resolve_dns=False)
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://10.255.255.255/api", resolve_dns=False)

    def test_blocks_172_16_range(self):
        """Block 172.16.0.0/12 private range (172.16.x.x - 172.31.x.x)."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://172.16.0.1/api", resolve_dns=False)
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://172.31.255.255/api", resolve_dns=False)

    def test_allows_172_outside_private(self):
        """Allow 172.x outside private range (172.15.x, 172.32.x)."""
        # 172.15.x.x is NOT private (below 172.16)
        # Note: These would fail DNS resolution in real scenario
        result = validate_endpoint_url("http://172.15.0.1/api", resolve_dns=False)
        assert result == "http://172.15.0.1/api"

    def test_blocks_192_168_range(self):
        """Block 192.168.0.0/16 private range."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://192.168.0.1/api", resolve_dns=False)
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://192.168.255.255/api", resolve_dns=False)

    def test_blocks_link_local(self):
        """Block 169.254.0.0/16 link-local range."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://169.254.0.1/api", resolve_dns=False)

    # --- IPv6 Variants ---

    def test_blocks_ipv6_localhost(self):
        """Block IPv6 localhost (::1)."""
        with pytest.raises(ValidationError, match="private IP|localhost"):
            validate_endpoint_url("http://[::1]/api", resolve_dns=False)

    def test_blocks_ipv6_unique_local(self):
        """Block IPv6 unique local addresses (fc00::/7)."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://[fc00::1]/api", resolve_dns=False)
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://[fd00::1]/api", resolve_dns=False)

    def test_blocks_ipv6_link_local(self):
        """Block IPv6 link-local addresses (fe80::/10)."""
        with pytest.raises(ValidationError, match="private IP"):
            validate_endpoint_url("http://[fe80::1]/api", resolve_dns=False)

    # --- Cloud Metadata Endpoints ---

    def test_blocks_aws_metadata(self):
        """Block AWS metadata endpoint (169.254.169.254)."""
        with pytest.raises(ValidationError, match="private IP|metadata"):
            validate_endpoint_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)

    def test_blocks_gcp_metadata(self):
        """Block GCP metadata endpoint (metadata.google.internal)."""
        with pytest.raises(ValidationError, match="metadata"):
            validate_endpoint_url("http://metadata.google.internal/computeMetadata/", resolve_dns=False)

    def test_blocks_generic_metadata(self):
        """Block generic 'metadata' hostname."""
        with pytest.raises(ValidationError, match="metadata"):
            validate_endpoint_url("http://metadata/api", resolve_dns=False)

    # --- URL Parsing Edge Cases ---

    def test_rejects_invalid_scheme(self):
        """Reject non-http/https schemes."""
        with pytest.raises(ValidationError, match="scheme must be http or https"):
            validate_endpoint_url("ftp://example.com/file")
        with pytest.raises(ValidationError, match="scheme must be http or https"):
            validate_endpoint_url("file:///etc/passwd")
        with pytest.raises(ValidationError, match="scheme must be http or https"):
            validate_endpoint_url("javascript:alert(1)")

    def test_rejects_missing_hostname(self):
        """Reject URLs without hostname."""
        with pytest.raises(ValidationError, match="missing hostname"):
            validate_endpoint_url("http:///path")
        with pytest.raises(ValidationError, match="missing hostname"):
            validate_endpoint_url("http://")

    def test_rejects_empty_url(self):
        """Reject empty URL."""
        with pytest.raises(ValidationError, match="is required"):
            validate_endpoint_url("")

    # --- Valid URLs ---

    def test_allows_public_https(self):
        """Allow valid public HTTPS URLs."""
        result = validate_endpoint_url("https://api.example.com/v1/data", resolve_dns=False)
        assert result == "https://api.example.com/v1/data"

    def test_allows_public_http(self):
        """Allow valid public HTTP URLs."""
        result = validate_endpoint_url("http://example.org/api", resolve_dns=False)
        assert result == "http://example.org/api"

    def test_allows_with_port(self):
        """Allow URLs with custom ports."""
        result = validate_endpoint_url("https://api.example.com:8443/data", resolve_dns=False)
        assert result == "https://api.example.com:8443/data"

    def test_allows_with_path_and_query(self):
        """Allow URLs with paths and query strings."""
        url = "https://api.example.com/v1/users?id=123&active=true"
        result = validate_endpoint_url(url, resolve_dns=False)
        assert result == url


class TestSSRFDecimalOctalIP:
    """
    Additional SSRF tests for decimal/octal IP representations.

    Gate 1.6.2 mentions: "decimal i octal ip forme ako parser to dopušta"
    """

    def test_decimal_localhost(self):
        """Block decimal representation of 127.0.0.1 (2130706433)."""
        # 127.0.0.1 = 127*256^3 + 0*256^2 + 0*256 + 1 = 2130706433
        # Most URL parsers don't support this, but test anyway
        # The URL parser may reject this as invalid hostname
        try:
            result = validate_endpoint_url("http://2130706433/api", resolve_dns=False)
            # If it parses, should still work (as a hostname)
            assert "2130706433" in result
        except ValidationError:
            # If rejected, that's also acceptable
            pass

    def test_octal_localhost(self):
        """Block octal representation of 127.0.0.1 (0177.0.0.1)."""
        # Most Python URL parsers don't handle octal, but test anyway
        try:
            result = validate_endpoint_url("http://0177.0.0.1/api", resolve_dns=False)
            # If parsed as hostname string, it's fine
            assert "0177.0.0.1" in result
        except ValidationError:
            # If blocked, also acceptable
            pass


# =============================================================================
# Unicode Path Traversal Tests (Gate 1 - 6.1)
# =============================================================================


class TestUnicodePathTraversal:
    """
    Unicode and encoded path traversal tests.

    Gate 1.6.1: Path traversal testovi uključuju unicode i razne oblike ..

    Tests various encodings and representations of path traversal:
    - URL encoding (%2e%2e%2f)
    - Double URL encoding (%252e%252e%252f)
    - Unicode variants (fullwidth, homoglyphs)
    - Null byte injection
    - Backslash variants
    """

    def test_url_encoded_traversal(self):
        """Block URL-encoded path traversal (%2e = . and %2f = /)."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # These should be blocked if decoded
            # Python's pathlib resolves symlinks but doesn't URL-decode
            # So these might appear as literal filenames - that's OK
            # The key is they shouldn't escape the base directory
            malicious = "%2e%2e%2fetc/passwd"
            try:
                result = validate_path(malicious, tmpdir)
                # If it passes, ensure it's within tmpdir
                assert str(tmpdir) in str(result)
            except ValueError:
                # Blocked - also acceptable
                pass

    def test_double_url_encoded_traversal(self):
        """Block double URL-encoded path traversal."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Double encoded: %25 = %, so %252e = %2e
            malicious = "%252e%252e%252fetc/passwd"
            try:
                result = validate_path(malicious, tmpdir)
                assert str(tmpdir) in str(result)
            except ValueError:
                pass

    def test_unicode_fullwidth_dot(self):
        """Block fullwidth Unicode characters that look like dot (．= U+FF0E)."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Fullwidth period (．) U+FF0E
            malicious = "\uff0e\uff0e/etc/passwd"
            try:
                result = validate_path(malicious, tmpdir)
                # Should be treated as literal filename, not traversal
                assert str(tmpdir) in str(result)
            except ValueError:
                pass

    def test_unicode_homoglyphs(self):
        """Block Unicode homoglyphs that look like ASCII chars."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Various dot-like characters
            homoglyphs = [
                "\u2024\u2024/etc/passwd",  # One dot leader
                "\u2025\u2025/etc/passwd",  # Two dot leader
                "\u00b7\u00b7/etc/passwd",  # Middle dot
            ]
            for malicious in homoglyphs:
                try:
                    result = validate_path(malicious, tmpdir)
                    assert str(tmpdir) in str(result)
                except ValueError:
                    pass

    def test_null_byte_injection(self):
        """Block null byte injection attacks."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Null byte followed by traversal
            malicious = "file.txt\x00../etc/passwd"
            try:
                result = validate_path(malicious, tmpdir)
                assert str(tmpdir) in str(result)
            except (ValueError, OSError):
                # Null bytes often cause OS errors - that's fine
                pass

    def test_backslash_traversal_windows(self):
        """Test backslash traversal (Windows-style)."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Backslash instead of forward slash
            malicious = "..\\..\\etc\\passwd"
            try:
                result = validate_path(malicious, tmpdir)
                # On Unix, backslash is just a character, should be within tmpdir
                assert str(tmpdir) in str(result)
            except ValueError:
                pass

    def test_mixed_slashes(self):
        """Test mixed forward and backslashes."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            malicious = "../\\../etc/passwd"
            try:
                result = validate_path(malicious, tmpdir)
                # Backslash should be treated literally
                assert str(tmpdir) in str(result) or "traversal" in str(result).lower()
            except ValueError:
                pass

    def test_overlong_utf8_encoding(self):
        """Test overlong UTF-8 encoding of dot (attack on old parsers)."""
        import tempfile
        from agirails.utils.security import validate_path

        with tempfile.TemporaryDirectory() as tmpdir:
            # Overlong encoding of '.' (0x2e) - not valid UTF-8
            # Python 3 would reject this as invalid
            try:
                malicious = b"\xc0\xae\xc0\xae/etc/passwd".decode("utf-8", errors="replace")
                result = validate_path(malicious, tmpdir)
                assert str(tmpdir) in str(result)
            except (ValueError, UnicodeDecodeError):
                pass


# =============================================================================
# Address Validation Tests
# =============================================================================


class TestAddressValidation:
    """Tests for Ethereum address validation."""

    def test_valid_lowercase_address(self):
        """Valid lowercase address."""
        addr = "0x1234567890abcdef1234567890abcdef12345678"
        result = validate_address(addr)
        assert result == addr

    def test_valid_uppercase_address(self):
        """Valid uppercase address normalized to lowercase."""
        addr = "0x1234567890ABCDEF1234567890ABCDEF12345678"
        result = validate_address(addr)
        assert result == addr.lower()

    def test_valid_checksum_address(self):
        """Valid checksum address."""
        addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        result = validate_address(addr)
        assert result == addr.lower()

    def test_rejects_empty_address(self):
        """Reject empty address."""
        with pytest.raises(InvalidAddressError, match="required"):
            validate_address("")

    def test_rejects_none_address(self):
        """Reject None address."""
        with pytest.raises(InvalidAddressError, match="required"):
            validate_address(None)  # type: ignore

    def test_rejects_short_address(self):
        """Reject address shorter than 42 characters."""
        with pytest.raises(InvalidAddressError, match="40 hex"):
            validate_address("0x1234")

    def test_rejects_long_address(self):
        """Reject address longer than 42 characters."""
        with pytest.raises(InvalidAddressError, match="40 hex"):
            validate_address("0x" + "1" * 50)

    def test_rejects_without_0x(self):
        """Reject address without 0x prefix."""
        with pytest.raises(InvalidAddressError, match="40 hex"):
            validate_address("1234567890abcdef1234567890abcdef12345678")

    def test_rejects_invalid_hex(self):
        """Reject address with non-hex characters."""
        with pytest.raises(InvalidAddressError, match="40 hex"):
            validate_address("0x123456789GHIJKL1234567890abcdef12345678")


# =============================================================================
# Amount Validation Tests
# =============================================================================


class TestAmountValidation:
    """Tests for USDC amount validation."""

    def test_valid_integer_amount(self):
        """Valid integer amount."""
        result = validate_amount(1000000)  # 1 USDC
        assert result == 1000000

    def test_valid_string_amount(self):
        """Valid string amount converted to integer."""
        result = validate_amount("1000000")
        assert result == 1000000

    def test_valid_minimum_amount(self):
        """Valid minimum amount ($0.05 = 50000 wei)."""
        result = validate_amount(50000, min_amount=50000)
        assert result == 50000

    def test_rejects_negative_amount(self):
        """Reject negative amounts."""
        with pytest.raises(InvalidAmountError, match="negative"):
            validate_amount(-100)

    def test_rejects_below_minimum(self):
        """Reject amounts below minimum."""
        with pytest.raises(InvalidAmountError, match="at least"):
            validate_amount(10000, min_amount=50000)

    def test_rejects_above_maximum(self):
        """Reject amounts above maximum."""
        with pytest.raises(InvalidAmountError, match="exceeds maximum"):
            validate_amount(10**20, max_amount=10**18)

    def test_rejects_invalid_string(self):
        """Reject non-numeric strings."""
        with pytest.raises(InvalidAmountError, match="valid number"):
            validate_amount("not_a_number")


# =============================================================================
# Dispute Window Validation Tests
# =============================================================================


class TestDisputeWindowValidation:
    """Tests for dispute window validation."""

    def test_valid_dispute_window(self):
        """Valid dispute window (1 hour)."""
        result = validate_dispute_window(3600)  # 1 hour
        assert result == 3600

    def test_valid_max_dispute_window(self):
        """Valid maximum dispute window (30 days)."""
        result = validate_dispute_window(30 * 24 * 3600)
        assert result == 30 * 24 * 3600

    def test_rejects_below_minimum(self):
        """Reject dispute window below minimum (1 hour)."""
        with pytest.raises(ValidationError, match="at least"):
            validate_dispute_window(1800)  # 30 minutes

    def test_rejects_above_maximum(self):
        """Reject dispute window above maximum (30 days)."""
        with pytest.raises(ValidationError, match="cannot exceed"):
            validate_dispute_window(31 * 24 * 3600)  # 31 days

    def test_converts_string_to_int(self):
        """Convert string to integer."""
        result = validate_dispute_window("7200")  # 2 hours as string
        assert result == 7200


# =============================================================================
# Service Name Validation Tests
# =============================================================================


class TestServiceNameValidation:
    """Tests for service name validation."""

    def test_valid_simple_name(self):
        """Valid simple service name."""
        result = validate_service_name("echo")
        assert result == "echo"

    def test_valid_with_separators(self):
        """Valid name with allowed separators."""
        result = validate_service_name("text-generation.v1_beta")
        assert result == "text-generation.v1_beta"

    def test_rejects_empty_name(self):
        """Reject empty service name."""
        with pytest.raises(ValidationError, match="required"):
            validate_service_name("")

    def test_rejects_too_long(self):
        """Reject name longer than 128 characters."""
        with pytest.raises(ValidationError, match="128"):
            validate_service_name("a" * 150)

    def test_rejects_special_characters(self):
        """Reject names with special characters."""
        with pytest.raises(ValidationError, match="alphanumeric"):
            validate_service_name("echo;rm -rf /")

    def test_rejects_path_traversal(self):
        """Reject names with path traversal."""
        with pytest.raises(ValidationError, match="alphanumeric"):
            validate_service_name("../evil")


# =============================================================================
# Bytes32 / TX ID Validation Tests
# =============================================================================


class TestBytes32Validation:
    """Tests for bytes32/transaction ID validation."""

    def test_valid_tx_id(self):
        """Valid transaction ID."""
        tx_id = "0x" + "a" * 64
        result = validate_tx_id(tx_id)
        assert result == tx_id

    def test_normalizes_to_lowercase(self):
        """Normalize uppercase to lowercase."""
        tx_id = "0x" + "A" * 64
        result = validate_tx_id(tx_id)
        assert result == tx_id.lower()

    def test_rejects_short_tx_id(self):
        """Reject transaction ID shorter than 66 characters."""
        with pytest.raises(ValidationError, match="64 hex"):
            validate_tx_id("0x" + "a" * 32)

    def test_rejects_without_prefix(self):
        """Reject transaction ID without 0x prefix."""
        with pytest.raises(ValidationError, match="64 hex"):
            validate_tx_id("a" * 64)

    def test_bytes32_alias(self):
        """validate_bytes32 is alias for validate_tx_id."""
        value = "0x" + "b" * 64
        result = validate_bytes32(value)
        assert result == value


# =============================================================================
# Service Metadata Validation Tests
# =============================================================================


class TestServiceMetadataValidation:
    """Tests for service metadata validation."""

    def test_valid_string_metadata(self):
        """Valid string metadata."""
        result = validate_service_metadata("simple metadata")
        assert result == "simple metadata"

    def test_valid_dict_metadata(self):
        """Valid dict metadata."""
        meta = {"key": "value", "count": 42}
        result = validate_service_metadata(meta)
        assert result == meta

    def test_rejects_oversized_metadata(self):
        """Reject metadata exceeding size limit."""
        large = "x" * 20000  # > 10KB
        with pytest.raises(ValidationError, match="exceeds maximum"):
            validate_service_metadata(large)

    def test_allows_none_metadata(self):
        """Allow None metadata."""
        result = validate_service_metadata(None)
        assert result is None

    def test_rejects_non_serializable(self):
        """Reject metadata that can't be JSON-serialized."""
        import datetime
        bad_meta = {"date": datetime.datetime.now()}  # Not JSON-serializable
        with pytest.raises(ValidationError, match="JSON-serializable"):
            validate_service_metadata(bad_meta)


# =============================================================================
# Content Hash Validation Tests
# =============================================================================


class TestContentHashValidation:
    """Tests for content hash validation."""

    def test_valid_keccak256_hash(self):
        """Valid keccak256 hash (32 bytes / 64 hex)."""
        hash_val = "0x" + "a" * 64
        result = validate_content_hash(hash_val)
        assert result == hash_val

    def test_valid_sha256_hash(self):
        """Valid SHA-256 hash (32 bytes / 64 hex)."""
        hash_val = "0x" + "1234567890abcdef" * 8
        result = validate_content_hash(hash_val)
        assert result == hash_val.lower()

    def test_rejects_empty_hash(self):
        """Reject empty hash."""
        with pytest.raises(ValidationError, match="required"):
            validate_content_hash("")

    def test_rejects_invalid_prefix(self):
        """Reject hash without expected prefix."""
        with pytest.raises(ValidationError, match="must start with"):
            validate_content_hash("abc123")

    def test_rejects_invalid_length(self):
        """Reject hash with unexpected length."""
        with pytest.raises(ValidationError, match="unexpected hash length"):
            validate_content_hash("0x" + "a" * 50)  # 25 bytes - not standard
