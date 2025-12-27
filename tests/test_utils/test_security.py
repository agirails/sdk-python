"""
Tests for security utilities.

These tests verify critical security measures including:
- Timing-safe string comparison (H-7)
- Path traversal prevention (H-6)
- Input validation (H-2)
- Safe JSON parsing (C-3)
- LRU Cache for memory leak prevention (C-2)
"""

import json
import tempfile
from pathlib import Path

import pytest

from agirails.utils.security import (
    timing_safe_equal,
    validate_path,
    validate_service_name,
    is_valid_address,
    safe_json_parse,
    LRUCache,
)


class TestTimingSafeEqual:
    """Tests for timing_safe_equal function (H-7)."""

    def test_equal_strings(self):
        """Equal strings should return True."""
        assert timing_safe_equal("secret123", "secret123") is True
        assert timing_safe_equal("", "") is True
        assert timing_safe_equal("a", "a") is True

    def test_unequal_strings(self):
        """Unequal strings should return False."""
        assert timing_safe_equal("secret123", "secret124") is False
        assert timing_safe_equal("secret123", "secret12") is False
        assert timing_safe_equal("secret123", "") is False
        assert timing_safe_equal("", "secret123") is False

    def test_different_lengths(self):
        """Strings of different lengths should return False."""
        assert timing_safe_equal("short", "longer_string") is False
        assert timing_safe_equal("longer_string", "short") is False

    def test_unicode_strings(self):
        """Unicode strings should be handled correctly."""
        assert timing_safe_equal("šđčćž", "šđčćž") is True
        assert timing_safe_equal("emoji🎉", "emoji🎉") is True
        assert timing_safe_equal("šđčćž", "sđčćž") is False

    def test_case_sensitivity(self):
        """Comparison should be case-sensitive."""
        assert timing_safe_equal("Secret", "secret") is False
        assert timing_safe_equal("SECRET", "secret") is False


class TestValidatePath:
    """Tests for validate_path function (H-6)."""

    def test_valid_relative_path(self):
        """Valid relative paths should be resolved within base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_path("subdir/file.json", tmpdir)
            # Use resolve() on both sides to handle macOS /var -> /private/var symlink
            expected = (Path(tmpdir) / "subdir" / "file.json").resolve()
            assert result == expected

    def test_valid_absolute_path_within_base(self):
        """Absolute paths within base directory should be accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            abs_path = Path(tmpdir) / "file.json"
            result = validate_path(str(abs_path), tmpdir)
            # Use resolve() to handle symlinks
            assert result == abs_path.resolve()

    def test_path_traversal_simple(self):
        """Simple path traversal should be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Path traversal attempt"):
                validate_path("../etc/passwd", tmpdir)

    def test_path_traversal_nested(self):
        """Nested path traversal should be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Path traversal attempt"):
                validate_path("subdir/../../etc/passwd", tmpdir)

    def test_path_traversal_absolute(self):
        """Absolute path outside base should be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Path traversal attempt"):
                validate_path("/etc/passwd", tmpdir)

    def test_path_with_dots(self):
        """Paths with legitimate dots should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_path("file.v1.json", tmpdir)
            expected = (Path(tmpdir) / "file.v1.json").resolve()
            assert result == expected

    def test_path_with_current_dir(self):
        """Paths with ./ should work correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_path("./subdir/file.json", tmpdir)
            expected = (Path(tmpdir) / "subdir" / "file.json").resolve()
            assert result == expected


class TestValidateServiceName:
    """Tests for validate_service_name function (H-2)."""

    def test_valid_simple_name(self):
        """Simple alphanumeric names should be valid."""
        assert validate_service_name("textgen") == "textgen"
        assert validate_service_name("TextGen") == "TextGen"
        assert validate_service_name("text123") == "text123"

    def test_valid_with_separators(self):
        """Names with allowed separators should be valid."""
        assert validate_service_name("text-generation") == "text-generation"
        assert validate_service_name("text_generation") == "text_generation"
        assert validate_service_name("text.generation.v1") == "text.generation.v1"
        assert validate_service_name("text-gen_v1.0") == "text-gen_v1.0"

    def test_empty_name(self):
        """Empty names should be rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_service_name("")

    def test_too_long_name(self):
        """Names exceeding 128 characters should be rejected."""
        long_name = "a" * 129
        with pytest.raises(ValueError, match="too long"):
            validate_service_name(long_name)

    def test_max_length_name(self):
        """Names exactly 128 characters should be valid."""
        max_name = "a" * 128
        assert validate_service_name(max_name) == max_name

    def test_invalid_characters(self):
        """Names with invalid characters should be rejected."""
        invalid_names = [
            "../evil",
            "name/subdir",
            "name\\subdir",
            "name with space",
            "name@symbol",
            "name#hash",
            "name$dollar",
            "name%percent",
            "name&amp",
            "name*star",
            "name?question",
        ]
        for name in invalid_names:
            with pytest.raises(ValueError, match="Invalid service name"):
                validate_service_name(name)


class TestIsValidAddress:
    """Tests for is_valid_address function."""

    def test_valid_addresses(self):
        """Valid Ethereum addresses should return True."""
        valid_addresses = [
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bBe0",
            "0x" + "a" * 40,
            "0x" + "A" * 40,
            "0x" + "0" * 40,
            "0x" + "f" * 40,
            "0x" + "F" * 40,
            "0xaAbBcCdDeEfF0011223344556677889900112233",
        ]
        for addr in valid_addresses:
            assert is_valid_address(addr) is True, f"Expected {addr} to be valid"

    def test_invalid_addresses(self):
        """Invalid addresses should return False."""
        invalid_addresses = [
            "",
            "0x",
            "0xinvalid",
            "0x" + "g" * 40,  # 'g' is not hex
            "0x" + "a" * 39,  # too short
            "0x" + "a" * 41,  # too long
            "742d35Cc6634C0532925a3b844Bc9e7595f0bBe0",  # missing 0x
            "0X" + "a" * 40,  # capital X
            None,
        ]
        for addr in invalid_addresses:
            if addr is None:
                assert is_valid_address("") is False  # Handle None case
            else:
                assert is_valid_address(addr) is False, f"Expected {addr} to be invalid"


class TestSafeJsonParse:
    """Tests for safe_json_parse function (C-3)."""

    def test_valid_json(self):
        """Valid JSON should be parsed correctly."""
        result = safe_json_parse('{"name": "test", "value": 123}')
        assert result == {"name": "test", "value": 123}

    def test_array_json_returns_none(self):
        """JSON arrays at top level should return None (TS parity: only objects allowed)."""
        result = safe_json_parse('[1, 2, 3]')
        assert result is None  # TS SDK only accepts objects at top level

    def test_nested_json(self):
        """Nested JSON should be parsed correctly."""
        result = safe_json_parse('{"outer": {"inner": "value"}}')
        assert result == {"outer": {"inner": "value"}}

    def test_removes_proto(self):
        """__proto__ keys should be removed."""
        result = safe_json_parse('{"name": "test", "__proto__": {"admin": true}}')
        assert result == {"name": "test"}
        assert "__proto__" not in result

    def test_removes_constructor(self):
        """constructor keys should be removed."""
        result = safe_json_parse('{"name": "test", "constructor": {"evil": true}}')
        assert result == {"name": "test"}
        assert "constructor" not in result

    def test_removes_prototype(self):
        """prototype keys should be removed."""
        result = safe_json_parse('{"name": "test", "prototype": {"hack": true}}')
        assert result == {"name": "test"}
        assert "prototype" not in result

    def test_removes_nested_dangerous_keys(self):
        """Dangerous keys in nested objects should be removed."""
        result = safe_json_parse(
            '{"outer": {"__proto__": {"admin": true}, "safe": "value"}}'
        )
        assert result == {"outer": {"safe": "value"}}

    def test_removes_dangerous_keys_in_nested_arrays(self):
        """Dangerous keys in objects within nested arrays should be removed."""
        result = safe_json_parse(
            '{"items": [{"name": "safe"}, {"__proto__": {"admin": true}, "value": 1}]}'
        )
        assert result == {"items": [{"name": "safe"}, {"value": 1}]}

    def test_invalid_json_returns_none(self):
        """Invalid JSON should return None (TS parity: no exceptions)."""
        result = safe_json_parse("{invalid json}")
        assert result is None

    def test_max_depth_exceeded_returns_none(self):
        """JSON exceeding max depth should return None (TS parity: no exceptions)."""
        # Create deeply nested JSON
        deep_json = '{"a": ' * 25 + '1' + '}' * 25
        result = safe_json_parse(deep_json, max_depth=20)
        assert result is None

    def test_max_size_exceeded_returns_none(self):
        """JSON exceeding max size should return None (C-3 DoS protection)."""
        # Create large JSON (over 1MB)
        large_json = '{"data": "' + "x" * 1_000_001 + '"}'
        result = safe_json_parse(large_json)
        assert result is None

    def test_schema_validation_filters_fields(self):
        """Schema validation should whitelist fields and check types."""
        schema = {"name": "string", "count": "number"}
        result = safe_json_parse(
            '{"name": "test", "count": 5, "extra": true}',
            schema=schema
        )
        assert result == {"name": "test", "count": 5}
        assert "extra" not in result

    def test_schema_validation_type_mismatch(self):
        """Schema validation should skip fields with wrong types."""
        schema = {"name": "string", "count": "number"}
        result = safe_json_parse(
            '{"name": 123, "count": "not a number"}',
            schema=schema
        )
        assert result == {}  # Both fields filtered due to type mismatch

    def test_max_depth_at_limit(self):
        """JSON at exactly max depth should be accepted."""
        # Create JSON at exactly 5 levels deep
        nested_json = '{"a": {"b": {"c": {"d": {"e": 1}}}}}'
        result = safe_json_parse(nested_json, max_depth=5)
        assert result == {"a": {"b": {"c": {"d": {"e": 1}}}}}


class TestLRUCache:
    """Tests for LRUCache class (C-2)."""

    def test_basic_operations(self):
        """Basic get/set operations should work."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        assert cache.get("a") == 1
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        assert cache.get("d") is None

    def test_eviction_oldest(self):
        """Oldest items should be evicted when cache is full."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.set("d", 4)  # This should evict "a"

        assert cache.get("a") is None  # Evicted
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        assert cache.get("d") == 4
        assert cache.size == 3

    def test_access_updates_order(self):
        """Accessing an item should update its position."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        # Access "a" to make it most recently used
        cache.get("a")

        # Add new item - should evict "b" (now oldest)
        cache.set("d", 4)

        assert cache.get("a") == 1  # Still there
        assert cache.get("b") is None  # Evicted
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_update_existing_key(self):
        """Updating existing key should not increase size."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("a", 10)  # Update existing

        assert cache.get("a") == 10
        assert cache.size == 2

    def test_has_method(self):
        """has() should check existence without updating order."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        assert cache.has("a") is True
        assert cache.has("d") is False

        # Add new item - "a" should be evicted if has() updated order
        cache.set("d", 4)
        cache.set("e", 5)

        # has() does NOT update order, so "a" was evicted
        assert cache.has("a") is False

    def test_delete_method(self):
        """delete() should remove items."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)

        assert cache.delete("a") is True
        assert cache.get("a") is None
        assert cache.size == 1

        assert cache.delete("nonexistent") is False

    def test_clear_method(self):
        """clear() should remove all items."""
        cache: LRUCache[str, int] = LRUCache(max_size=3)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        cache.clear()

        assert cache.size == 0
        assert cache.get("a") is None
        assert cache.get("b") is None
        assert cache.get("c") is None

    def test_keys_values_items(self):
        """keys(), values(), items() should return correct data."""
        cache: LRUCache[str, int] = LRUCache(max_size=5)

        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        # Access "a" to change order
        cache.get("a")

        # Order should be: b, c, a (most recent last)
        assert cache.keys() == ["b", "c", "a"]
        assert cache.values() == [2, 3, 1]
        assert cache.items() == [("b", 2), ("c", 3), ("a", 1)]

    def test_size_and_max_size(self):
        """size and max_size properties should work correctly."""
        cache: LRUCache[str, int] = LRUCache(max_size=5)

        assert cache.size == 0
        assert cache.max_size == 5

        cache.set("a", 1)
        assert cache.size == 1

        cache.set("b", 2)
        cache.set("c", 3)
        assert cache.size == 3

    def test_invalid_max_size(self):
        """max_size <= 0 should raise ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            LRUCache(max_size=0)

        with pytest.raises(ValueError, match="must be positive"):
            LRUCache(max_size=-1)

    def test_large_eviction(self):
        """Cache should handle large-scale evictions correctly."""
        cache: LRUCache[int, int] = LRUCache(max_size=100)

        # Add 200 items
        for i in range(200):
            cache.set(i, i * 10)

        # Only last 100 should remain
        assert cache.size == 100
        for i in range(100):
            assert cache.get(i) is None  # Evicted
        for i in range(100, 200):
            assert cache.get(i) == i * 10  # Still there

    def test_typed_cache(self):
        """Cache should work with various types."""
        # String keys, dict values
        cache1: LRUCache[str, dict] = LRUCache(max_size=10)
        cache1.set("job-1", {"status": "pending"})
        assert cache1.get("job-1") == {"status": "pending"}

        # Int keys, string values
        cache2: LRUCache[int, str] = LRUCache(max_size=10)
        cache2.set(123, "value")
        assert cache2.get(123) == "value"

        # Tuple keys
        cache3: LRUCache[tuple, int] = LRUCache(max_size=10)
        cache3.set(("a", 1), 100)
        assert cache3.get(("a", 1)) == 100
