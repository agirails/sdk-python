"""Tests for AGIRAILS.md Parser + Canonical Hash.

Tests: parsing, canonicalization, hashing determinism,
publish metadata stripping, datetime handling, serialization round-trips,
and cross-SDK parity with the TypeScript implementation.
"""

from __future__ import annotations

import datetime

import pytest

from agirails.config.agirailsmd import (
    PUBLISH_METADATA_KEYS,
    AgirailsMdConfig,
    AgirailsMdHashResult,
    canonicalize,
    compute_config_hash,
    compute_config_hash_from_parts,
    normalize_body,
    parse_agirails_md,
    serialize_agirails_md,
    strip_publish_metadata,
)


# ============================================================================
# Test fixtures
# ============================================================================

MINIMAL_MD = """---
name: test-agent
version: "1.0.0"
---
# Hello
"""

FULL_MD = """---
name: test-agent
version: "1.0.0"
network: base-sepolia
capabilities:
  - text-generation
  - code-review
pricing:
  min: 1.0
  max: 100.0
sla:
  uptime: 99.9
  response_time: 5000
---
# Test Agent

This agent does cool things.

## Features

- Feature A
- Feature B
"""

WITH_PUBLISH_METADATA = """---
name: test-agent
version: "1.0.0"
config_hash: "0xabc123"
published_at: "2026-02-08T00:00:00.000Z"
config_cid: "bafybeig"
arweave_tx: "abc123def456"
template_source: "openclaw/skill-template"
---
# Hello
"""

# Cross-SDK parity test content (matches TypeScript SDK test exactly)
PARITY_MD = """---
name: parity-test-agent
version: "2.0.0"
network: base-sepolia
capabilities:
  - text-generation
  - code-review
  - analysis
pricing:
  min: 1.0
  max: 100.0
  currency: USDC
metadata:
  author: test
  created: "2026-02-15T00:00:00.000Z"
tags:
  - ai
  - payments
  - web3
---
# Parity Test Agent

This is a cross-SDK parity test.

## Features

- Feature A
- Feature B
"""

# Expected hashes from TypeScript SDK (verified 2026-02-15)
PARITY_STRUCTURED_HASH = (
    "0x1b55e75a13efd4664aa95072cbea0078d325962d9882f563ffa94b574aad7ff9"
)
PARITY_BODY_HASH = (
    "0xd4755ac1c730aabe6c486eb18dbc3b4270b685f16a99252bc2158d045cca5695"
)
PARITY_CONFIG_HASH = (
    "0xdf1c9dafe3bb717b4c280f03ca74ded46ea8cdd2ba7dbe1e28af94b51d95febf"
)


# ============================================================================
# 1. Test basic parsing (frontmatter + body)
# ============================================================================


class TestParseAgirailsMd:
    """Tests for parse_agirails_md."""

    def test_parses_minimal_md(self) -> None:
        result = parse_agirails_md(MINIMAL_MD)
        assert result.frontmatter == {"name": "test-agent", "version": "1.0.0"}
        assert "# Hello" in result.body

    def test_parses_full_md_with_nested_frontmatter(self) -> None:
        result = parse_agirails_md(FULL_MD)
        assert result.frontmatter["name"] == "test-agent"
        assert result.frontmatter["capabilities"] == ["text-generation", "code-review"]
        assert result.frontmatter["pricing"]["min"] == 1.0
        assert result.frontmatter["sla"]["uptime"] == 99.9
        assert "# Test Agent" in result.body
        assert "- Feature A" in result.body

    def test_strips_leading_whitespace_before_frontmatter(self) -> None:
        content = "  \n\n---\nname: test\n---\n# Body"
        result = parse_agirails_md(content)
        assert result.frontmatter["name"] == "test"

    def test_handles_empty_body(self) -> None:
        result = parse_agirails_md("---\nname: test\n---\n")
        assert result.frontmatter["name"] == "test"
        assert result.body == ""

    def test_preserves_publish_metadata_in_parsed_output(self) -> None:
        result = parse_agirails_md(WITH_PUBLISH_METADATA)
        assert result.frontmatter["config_hash"] == "0xabc123"
        assert result.frontmatter["published_at"] == "2026-02-08T00:00:00.000Z"
        assert result.frontmatter["config_cid"] == "bafybeig"
        assert result.frontmatter["arweave_tx"] == "abc123def456"
        assert result.frontmatter["template_source"] == "openclaw/skill-template"

    def test_returns_dataclass(self) -> None:
        result = parse_agirails_md(MINIMAL_MD)
        assert isinstance(result, AgirailsMdConfig)


# ============================================================================
# 2. Test missing frontmatter error
# ============================================================================


class TestMissingFrontmatter:
    def test_throws_on_missing_frontmatter(self) -> None:
        with pytest.raises(ValueError, match="must start with YAML frontmatter"):
            parse_agirails_md("# Just markdown")


# ============================================================================
# 3. Test unclosed frontmatter error
# ============================================================================


class TestUnclosedFrontmatter:
    def test_throws_on_unclosed_frontmatter(self) -> None:
        with pytest.raises(ValueError, match="not closed"):
            parse_agirails_md("---\nname: test\n# No closing")

    def test_throws_on_invalid_yaml(self) -> None:
        with pytest.raises(ValueError, match="Failed to parse YAML"):
            parse_agirails_md("---\n: invalid: yaml: [unclosed\n---\n")

    def test_throws_on_non_object_frontmatter(self) -> None:
        with pytest.raises(ValueError, match="must be an object"):
            parse_agirails_md("---\njust a string\n---\n")


# ============================================================================
# 4. Test publish metadata stripping
# ============================================================================


class TestStripPublishMetadata:
    def test_strips_all_publish_metadata_keys(self) -> None:
        fm = {
            "name": "test-agent",
            "version": "1.0.0",
            "config_hash": "0xabc",
            "published_at": "2026-01-01",
            "config_cid": "bafytest",
            "arweave_tx": "artx123",
            "template_source": "openclaw/test",
        }
        stripped = strip_publish_metadata(fm)
        assert stripped == {"name": "test-agent", "version": "1.0.0"}

    def test_does_not_mutate_original_object(self) -> None:
        fm = {"name": "test", "config_hash": "0xabc"}
        strip_publish_metadata(fm)
        assert fm["config_hash"] == "0xabc"

    def test_handles_object_with_no_publish_metadata(self) -> None:
        fm = {"name": "test", "version": "1.0.0"}
        stripped = strip_publish_metadata(fm)
        assert stripped == fm

    def test_publish_metadata_keys_contains_all_expected(self) -> None:
        assert "config_hash" in PUBLISH_METADATA_KEYS
        assert "published_at" in PUBLISH_METADATA_KEYS
        assert "config_cid" in PUBLISH_METADATA_KEYS
        assert "arweave_tx" in PUBLISH_METADATA_KEYS
        assert "template_source" in PUBLISH_METADATA_KEYS
        assert "wallet" in PUBLISH_METADATA_KEYS
        assert "agent_id" in PUBLISH_METADATA_KEYS
        assert "did" in PUBLISH_METADATA_KEYS
        assert len(PUBLISH_METADATA_KEYS) == 8


# ============================================================================
# 5. Test canonicalize with sorted keys
# ============================================================================


class TestCanonicalizeSortedKeys:
    def test_sorts_object_keys_lexicographically(self) -> None:
        result = canonicalize({"z": 1, "a": 2, "m": 3})
        keys = list(result.keys())
        assert keys == ["a", "m", "z"]

    def test_sorts_nested_object_keys_recursively(self) -> None:
        result = canonicalize({
            "outer": {"z": 1, "a": 2},
            "inner": {"b": 3, "a": 4},
        })
        assert list(result.keys()) == ["inner", "outer"]
        assert list(result["outer"].keys()) == ["a", "z"]
        assert list(result["inner"].keys()) == ["a", "b"]


# ============================================================================
# 6. Test canonicalize with primitive array sorting
# ============================================================================


class TestCanonicalizePrimitiveArrays:
    def test_sorts_string_arrays_lexicographically(self) -> None:
        result = canonicalize(["code-review", "text-generation", "analysis"])
        assert result == ["analysis", "code-review", "text-generation"]

    def test_sorts_numeric_arrays(self) -> None:
        result = canonicalize([3, 1, 2])
        assert result == [1, 2, 3]

    def test_sorts_boolean_arrays(self) -> None:
        result = canonicalize([True, False, True])
        assert result == [False, True, True]

    def test_handles_empty_array(self) -> None:
        assert canonicalize([]) == []


# ============================================================================
# 7. Test canonicalize with object array order preservation
# ============================================================================


class TestCanonicalizeObjectArrays:
    def test_preserves_order_of_object_arrays(self) -> None:
        input_arr = [
            {"name": "second", "order": 2},
            {"name": "first", "order": 1},
        ]
        result = canonicalize(input_arr)
        assert result[0]["name"] == "second"
        assert result[1]["name"] == "first"

    def test_handles_mixed_primitive_object_arrays(self) -> None:
        # Array with objects -- should preserve order (not all primitives)
        input_arr = [{"a": 1}, "string"]
        result = canonicalize(input_arr)
        assert result[0] == {"a": 1}
        assert result[1] == "string"


# ============================================================================
# 8. Test canonicalize with datetime conversion
# ============================================================================


class TestCanonicalizeDatetime:
    def test_converts_date_to_iso_string(self) -> None:
        d = datetime.date(2026, 2, 8)
        assert canonicalize(d) == "2026-02-08T00:00:00.000Z"

    def test_converts_datetime_to_iso_string(self) -> None:
        dt = datetime.datetime(2026, 2, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
        assert canonicalize(dt) == "2026-02-08T12:00:00.000Z"

    def test_handles_nested_dates_in_objects(self) -> None:
        result = canonicalize({
            "created": datetime.date(2026, 1, 1),
            "name": "test",
        })
        assert result["created"] == "2026-01-01T00:00:00.000Z"

    def test_handles_naive_datetime(self) -> None:
        dt = datetime.datetime(2026, 2, 15, 0, 0, 0)
        assert canonicalize(dt) == "2026-02-15T00:00:00.000Z"


# ============================================================================
# 9. Test body normalization (CRLF, trailing whitespace)
# ============================================================================


class TestNormalizeBody:
    def test_crlf_to_lf(self) -> None:
        assert normalize_body("line1\r\nline2") == "line1\nline2"

    def test_cr_to_lf(self) -> None:
        assert normalize_body("line1\rline2") == "line1\nline2"

    def test_strips_trailing_whitespace_per_line(self) -> None:
        assert normalize_body("line1   \nline2  ") == "line1\nline2"

    def test_trims_leading_trailing(self) -> None:
        assert normalize_body("\n\n  content  \n\n") == "content"

    def test_combined_normalization(self) -> None:
        result = normalize_body("  line1  \r\n  line2  \r\n")
        assert result == "line1\n  line2"


# ============================================================================
# 10. Test hash computation produces hex strings
# ============================================================================


class TestHashFormat:
    def test_hash_is_bytes32_format(self) -> None:
        result = compute_config_hash(MINIMAL_MD)
        assert isinstance(result, AgirailsMdHashResult)
        # 0x + 64 hex chars
        hex_pattern = r"^0x[a-f0-9]{64}$"
        import re

        assert re.match(hex_pattern, result.config_hash)
        assert re.match(hex_pattern, result.structured_hash)
        assert re.match(hex_pattern, result.body_hash)

    def test_different_frontmatter_different_hash(self) -> None:
        md1 = "---\nname: agent-a\n---\n# Body"
        md2 = "---\nname: agent-b\n---\n# Body"
        assert compute_config_hash(md1).config_hash != compute_config_hash(md2).config_hash

    def test_different_body_different_hash(self) -> None:
        md1 = "---\nname: test\n---\n# Body A"
        md2 = "---\nname: test\n---\n# Body B"
        assert compute_config_hash(md1).config_hash != compute_config_hash(md2).config_hash


# ============================================================================
# 11. Test serialize round-trip
# ============================================================================


class TestSerializeRoundTrip:
    def test_produces_valid_agirails_md_format(self) -> None:
        result = serialize_agirails_md(
            {"name": "test", "version": "1.0.0"}, "# Hello\n"
        )
        assert result.startswith("---\n")
        assert "name: test" in result
        assert "\n---\n" in result
        assert "# Hello" in result

    def test_round_trip_preserves_data(self) -> None:
        original = parse_agirails_md(FULL_MD)
        serialized = serialize_agirails_md(original.frontmatter, original.body)
        reparsed = parse_agirails_md(serialized)

        assert reparsed.frontmatter["name"] == original.frontmatter["name"]
        assert reparsed.frontmatter["capabilities"] == original.frontmatter["capabilities"]
        assert "# Test Agent" in reparsed.body

    def test_round_trip_preserves_hash(self) -> None:
        original = parse_agirails_md(FULL_MD)
        serialized = serialize_agirails_md(original.frontmatter, original.body)

        hash_original = compute_config_hash(FULL_MD)
        hash_serialized = compute_config_hash(serialized)

        assert hash_serialized.config_hash == hash_original.config_hash


# ============================================================================
# 12. Test hash stability
# ============================================================================


class TestHashStability:
    def test_same_input_always_same_hash(self) -> None:
        hash1 = compute_config_hash(MINIMAL_MD)
        hash2 = compute_config_hash(MINIMAL_MD)
        assert hash1 == hash2

    def test_key_order_does_not_affect_hash(self) -> None:
        md1 = '---\nname: test\nversion: "1.0.0"\n---\n# Body'
        md2 = '---\nversion: "1.0.0"\nname: test\n---\n# Body'
        assert compute_config_hash(md1).config_hash == compute_config_hash(md2).config_hash

    def test_publish_metadata_does_not_affect_hash(self) -> None:
        without_meta = '---\nname: test\nversion: "1.0.0"\n---\n# Body'
        with_meta = (
            '---\nname: test\nversion: "1.0.0"\nconfig_hash: "0xold"\n'
            'published_at: "2026-01-01"\nconfig_cid: "bafyold"\n'
            'arweave_tx: "artxold"\ntemplate_source: "github"\n---\n# Body'
        )
        assert (
            compute_config_hash(without_meta).config_hash
            == compute_config_hash(with_meta).config_hash
        )

    def test_crlf_vs_lf_does_not_affect_body_hash(self) -> None:
        lf = "---\nname: test\n---\n# Line1\n# Line2"
        crlf = "---\nname: test\n---\n# Line1\r\n# Line2"
        assert compute_config_hash(lf).config_hash == compute_config_hash(crlf).config_hash

    def test_trailing_whitespace_does_not_affect_body_hash(self) -> None:
        clean = "---\nname: test\n---\n# Line1\n# Line2"
        trailing = "---\nname: test\n---\n# Line1   \n# Line2  "
        assert compute_config_hash(clean).config_hash == compute_config_hash(trailing).config_hash

    def test_primitive_array_order_does_not_affect_hash(self) -> None:
        md1 = "---\ncapabilities:\n  - b\n  - a\n---\n# Body"
        md2 = "---\ncapabilities:\n  - a\n  - b\n---\n# Body"
        assert compute_config_hash(md1).config_hash == compute_config_hash(md2).config_hash

    def test_compute_config_hash_from_parts_matches(self) -> None:
        config = parse_agirails_md(FULL_MD)
        from_content = compute_config_hash(FULL_MD)
        from_parts = compute_config_hash_from_parts(config.frontmatter, config.body)
        assert from_parts == from_content

    def test_from_parts_strips_publish_metadata(self) -> None:
        fm = {"name": "test", "config_hash": "0xold", "published_at": "2026-01-01"}
        fm_clean = {"name": "test"}
        body = "# Body"
        assert (
            compute_config_hash_from_parts(fm, body).config_hash
            == compute_config_hash_from_parts(fm_clean, body).config_hash
        )


# ============================================================================
# 13. CROSS-SDK PARITY TEST
# ============================================================================


class TestCrossSDKParity:
    """Verify that Python SDK produces IDENTICAL hashes as the TypeScript SDK.

    These expected values were computed by the TypeScript SDK (sdk-js)
    on 2026-02-15 using the exact same PARITY_MD content.
    """

    def test_structured_hash_matches_typescript(self) -> None:
        result = compute_config_hash(PARITY_MD)
        assert result.structured_hash == PARITY_STRUCTURED_HASH, (
            f"Structured hash mismatch!\n"
            f"  Python:     {result.structured_hash}\n"
            f"  TypeScript: {PARITY_STRUCTURED_HASH}"
        )

    def test_body_hash_matches_typescript(self) -> None:
        result = compute_config_hash(PARITY_MD)
        assert result.body_hash == PARITY_BODY_HASH, (
            f"Body hash mismatch!\n"
            f"  Python:     {result.body_hash}\n"
            f"  TypeScript: {PARITY_BODY_HASH}"
        )

    def test_config_hash_matches_typescript(self) -> None:
        result = compute_config_hash(PARITY_MD)
        assert result.config_hash == PARITY_CONFIG_HASH, (
            f"Config hash mismatch!\n"
            f"  Python:     {result.config_hash}\n"
            f"  TypeScript: {PARITY_CONFIG_HASH}"
        )

    def test_all_three_hashes_match_typescript(self) -> None:
        """Single test that verifies all three hashes for easy CI reporting."""
        result = compute_config_hash(PARITY_MD)
        assert result.structured_hash == PARITY_STRUCTURED_HASH
        assert result.body_hash == PARITY_BODY_HASH
        assert result.config_hash == PARITY_CONFIG_HASH


# ============================================================================
# Edge cases
# ============================================================================


class TestEdgeCases:
    def test_frontmatter_with_special_characters(self) -> None:
        md = '---\nname: "test: agent"\n---\n# Body'
        result = parse_agirails_md(md)
        assert result.frontmatter["name"] == "test: agent"

    def test_frontmatter_with_unicode(self) -> None:
        md = '---\nname: "Agent \U0001f916"\nlang: "\u65e5\u672c\u8a9e"\n---\n# Body'
        result = parse_agirails_md(md)
        assert result.frontmatter["name"] == "Agent \U0001f916"
        assert result.frontmatter["lang"] == "\u65e5\u672c\u8a9e"

        # Hash is deterministic
        h1 = compute_config_hash(md)
        h2 = compute_config_hash(md)
        assert h1.config_hash == h2.config_hash

    def test_deeply_nested_objects(self) -> None:
        md = "---\na:\n  b:\n    c:\n      d: deep\n---\n# Body"
        result = parse_agirails_md(md)
        assert result.frontmatter["a"]["b"]["c"]["d"] == "deep"

    def test_large_body(self) -> None:
        large_body = "# Title\n" + "Lorem ipsum dolor sit amet.\n" * 1000
        md = f"---\nname: test\n---\n{large_body}"
        result = compute_config_hash(md)
        import re

        assert re.match(r"^0x[a-f0-9]{64}$", result.config_hash)

    def test_empty_frontmatter_throws(self) -> None:
        # YAML parses empty content as None, which should throw
        with pytest.raises(ValueError):
            parse_agirails_md("---\n\n---\n# Body")

    def test_preserves_none_values(self) -> None:
        assert canonicalize(None) is None

    def test_preserves_primitive_values(self) -> None:
        assert canonicalize("hello") == "hello"
        assert canonicalize(42) == 42
        assert canonicalize(True) is True

    def test_handles_empty_objects_and_arrays(self) -> None:
        assert canonicalize({}) == {}
        assert canonicalize([]) == []
