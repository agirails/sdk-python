"""
Tests for agirails.wallet.keystore -- AIP-13 keystore auto-resolution.

Coverage:
  1. Env var resolution (ACTP_PRIVATE_KEY)
  2. Base64 keystore resolution
  3. File keystore resolution
  4. Cache TTL expiration
  5. Fail-closed policy (mainnet fails, testnet warns, mock silent)
  6. Path traversal prevention
  7. Null byte rejection
  8. Missing password error
  9. Invalid base64 error
  10. Cache clearing
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from eth_account import Account

from agirails.wallet.keystore import (
    CACHE_TTL_S,
    ResolvePrivateKeyOptions,
    _clear_cache,
    get_cached_address,
    resolve_private_key,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Well-known test private key (Anvil default #0 -- NOT a secret)
TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_ADDRESS = Account.from_key(TEST_PRIVATE_KEY).address

# Second test key for multi-cache scenarios
TEST_PRIVATE_KEY_2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
TEST_ADDRESS_2 = Account.from_key(TEST_PRIVATE_KEY_2).address

# Keystore password
TEST_PASSWORD = "test-password-123"


def _create_keystore_json(private_key: str, password: str) -> str:
    """Create an encrypted keystore JSON string from a private key."""
    keystore = Account.encrypt(private_key, password)
    return json.dumps(keystore)


def _create_keystore_b64(private_key: str, password: str) -> str:
    """Create base64-encoded encrypted keystore from a private key."""
    ks_json = _create_keystore_json(private_key, password)
    return base64.b64encode(ks_json.encode("utf-8")).decode("utf-8")


@pytest.fixture(autouse=True)
def clean_env_and_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear caches and relevant env vars before each test."""
    _clear_cache()
    # Remove all ACTP env vars to ensure clean slate
    for var in [
        "ACTP_PRIVATE_KEY",
        "ACTP_KEYSTORE_BASE64",
        "ACTP_KEY_PASSWORD",
        "ACTP_NETWORK",
        "ACTP_DIR",
    ]:
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# 1. Env var resolution (ACTP_PRIVATE_KEY)
# ---------------------------------------------------------------------------


class TestEnvVarResolution:
    """Tests for ACTP_PRIVATE_KEY resolution path."""

    async def test_resolves_from_env_var_mock_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")
        result = await resolve_private_key(options=options)
        assert result == TEST_PRIVATE_KEY

    async def test_resolves_from_env_var_testnet(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="testnet")
        result = await resolve_private_key(options=options)
        assert result == TEST_PRIVATE_KEY

    async def test_trims_whitespace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", f"  {TEST_PRIVATE_KEY}  ")
        options = ResolvePrivateKeyOptions(network="mock")
        result = await resolve_private_key(options=options)
        assert result == TEST_PRIVATE_KEY

    async def test_invalid_key_format_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", "not-a-key")
        options = ResolvePrivateKeyOptions(network="mock")
        with pytest.raises(ValueError, match="Invalid private key"):
            await resolve_private_key(options=options)

    async def test_env_var_takes_priority_over_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ACTP_PRIVATE_KEY (path 1) takes priority over file keystore (path 3)."""
        # Create a keystore file with a DIFFERENT key
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY_2, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)

        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)
        options = ResolvePrivateKeyOptions(network="mock")
        result = await resolve_private_key(str(tmp_path), options=options)
        assert result == TEST_PRIVATE_KEY  # env var wins


# ---------------------------------------------------------------------------
# 2. Base64 keystore resolution
# ---------------------------------------------------------------------------


class TestBase64KeystoreResolution:
    """Tests for ACTP_KEYSTORE_BASE64 resolution path."""

    async def test_resolves_from_base64_keystore(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        result = await resolve_private_key()
        assert result is not None
        # Verify the resolved key produces the same address
        assert Account.from_key(result).address == TEST_ADDRESS

    async def test_base64_takes_priority_over_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ACTP_KEYSTORE_BASE64 (path 2) takes priority over file keystore (path 3)."""
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY_2, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)

        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        result = await resolve_private_key(str(tmp_path))
        assert result is not None
        assert Account.from_key(result).address == TEST_ADDRESS  # base64 wins

    async def test_base64_with_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Base64 with embedded whitespace/newlines should still work."""
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        # Insert newlines like a multi-line env var
        chunked = "\n".join(b64[i : i + 40] for i in range(0, len(b64), 40))
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", chunked)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        result = await resolve_private_key()
        assert result is not None
        assert Account.from_key(result).address == TEST_ADDRESS


# ---------------------------------------------------------------------------
# 3. File keystore resolution
# ---------------------------------------------------------------------------


class TestFileKeystoreResolution:
    """Tests for .actp/keystore.json resolution path."""

    async def test_resolves_from_file_keystore(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        result = await resolve_private_key(str(tmp_path))
        assert result is not None
        assert Account.from_key(result).address == TEST_ADDRESS

    async def test_returns_none_when_no_keystore(
        self, tmp_path: Path
    ) -> None:
        """Returns None when no keystore file exists and no env vars set."""
        result = await resolve_private_key(str(tmp_path))
        assert result is None

    async def test_actp_dir_env_override(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ACTP_DIR env var overrides the default .actp directory."""
        custom_dir = tmp_path / "custom-actp"
        custom_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY, TEST_PASSWORD)
        (custom_dir / "keystore.json").write_text(ks_json)
        monkeypatch.setenv("ACTP_DIR", str(custom_dir))
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        result = await resolve_private_key()
        assert result is not None
        assert Account.from_key(result).address == TEST_ADDRESS


# ---------------------------------------------------------------------------
# 4. Cache TTL expiration
# ---------------------------------------------------------------------------


class TestCacheTTL:
    """Tests for 30-minute cache TTL."""

    async def test_cache_hit_within_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Second call returns cached value without re-validation."""
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")

        result1 = await resolve_private_key(options=options)
        # Keep env var set -- cache avoids re-deriving address from key
        result2 = await resolve_private_key(options=options)
        assert result1 == result2 == TEST_PRIVATE_KEY

        # Verify address is also cached
        assert get_cached_address() == TEST_ADDRESS

    async def test_cache_expires_after_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After TTL expires, cache miss returns None (env var removed)."""
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")

        await resolve_private_key(options=options)

        # Simulate TTL expiration by patching time.time
        future_time = time.time() + CACHE_TTL_S + 1
        monkeypatch.delenv("ACTP_PRIVATE_KEY")
        with patch("agirails.wallet.keystore.time") as mock_time:
            mock_time.time.return_value = future_time
            result = await resolve_private_key(options=options)
        assert result is None

    async def test_base64_cache_expires(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        await resolve_private_key()

        monkeypatch.delenv("ACTP_KEYSTORE_BASE64")
        monkeypatch.delenv("ACTP_KEY_PASSWORD")

        future_time = time.time() + CACHE_TTL_S + 1
        with patch("agirails.wallet.keystore.time") as mock_time:
            mock_time.time.return_value = future_time
            result = await resolve_private_key()
        assert result is None

    async def test_file_cache_expires(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        await resolve_private_key(str(tmp_path))

        # Remove keystore file and password
        (actp_dir / "keystore.json").unlink()
        monkeypatch.delenv("ACTP_KEY_PASSWORD")

        future_time = time.time() + CACHE_TTL_S + 1
        with patch("agirails.wallet.keystore.time") as mock_time:
            mock_time.time.return_value = future_time
            result = await resolve_private_key(str(tmp_path))
        # No file, no env vars => None
        assert result is None


# ---------------------------------------------------------------------------
# 5. Fail-closed policy (mainnet fails, testnet warns, mock silent)
# ---------------------------------------------------------------------------


class TestPrivateKeyPolicy:
    """Tests for AIP-13 ACTP_PRIVATE_KEY policy enforcement."""

    async def test_mainnet_hard_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mainnet")
        with pytest.raises(PermissionError, match="not allowed in production"):
            await resolve_private_key(options=options)

    async def test_unknown_network_hard_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unknown/null network fails closed (same as mainnet)."""
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        # No network specified, no ACTP_NETWORK env
        with pytest.raises(PermissionError, match="unknown network"):
            await resolve_private_key()

    async def test_testnet_warns(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="testnet")

        with caplog.at_level("WARNING", logger="agirails.wallet.keystore"):
            await resolve_private_key(options=options)

        assert "deprecated" in caplog.text
        assert "ACTP_KEYSTORE_BASE64" in caplog.text

    async def test_testnet_via_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ACTP_NETWORK=testnet allows ACTP_PRIVATE_KEY."""
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        monkeypatch.setenv("ACTP_NETWORK", "testnet")
        result = await resolve_private_key()
        assert result == TEST_PRIVATE_KEY

    async def test_mock_silent(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")
        with caplog.at_level("WARNING", logger="agirails.wallet.keystore"):
            result = await resolve_private_key(options=options)
        assert result == TEST_PRIVATE_KEY
        assert "deprecated" not in caplog.text


# ---------------------------------------------------------------------------
# 6. Path traversal prevention
# ---------------------------------------------------------------------------


class TestPathTraversalPrevention:
    """Tests for path traversal guard."""

    async def test_rejects_dotdot(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            await resolve_private_key("../../etc")

    async def test_rejects_embedded_dotdot(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            await resolve_private_key("/tmp/foo/../../etc")

    async def test_allows_normal_path(self, tmp_path: Path) -> None:
        """Normal paths without '..' are accepted (returns None = no keystore)."""
        result = await resolve_private_key(str(tmp_path))
        assert result is None


# ---------------------------------------------------------------------------
# 7. Null byte rejection
# ---------------------------------------------------------------------------


class TestNullByteRejection:
    """Tests for null byte injection guard."""

    async def test_rejects_null_byte(self) -> None:
        with pytest.raises(ValueError, match="null byte"):
            await resolve_private_key("/tmp/foo\x00bar")

    async def test_rejects_embedded_null(self) -> None:
        with pytest.raises(ValueError, match="null byte"):
            await resolve_private_key("normal\x00path")


# ---------------------------------------------------------------------------
# 8. Missing password error
# ---------------------------------------------------------------------------


class TestMissingPassword:
    """Tests for missing ACTP_KEY_PASSWORD."""

    async def test_base64_without_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        with pytest.raises(RuntimeError, match="ACTP_KEY_PASSWORD is not set"):
            await resolve_private_key()

    async def test_file_keystore_without_password(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)
        # No ACTP_KEY_PASSWORD set
        with pytest.raises(RuntimeError, match="ACTP_KEY_PASSWORD is not set"):
            await resolve_private_key(str(tmp_path))


# ---------------------------------------------------------------------------
# 9. Invalid base64 error
# ---------------------------------------------------------------------------


class TestInvalidBase64:
    """Tests for invalid ACTP_KEYSTORE_BASE64 values."""

    async def test_valid_base64_but_not_json(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = base64.b64encode(b"this is not json").decode()
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)
        with pytest.raises(ValueError, match="not valid encrypted keystore JSON"):
            await resolve_private_key()

    async def test_valid_json_but_wrong_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", "wrong-password")
        with pytest.raises(RuntimeError, match="Failed to decrypt"):
            await resolve_private_key()


# ---------------------------------------------------------------------------
# 10. Cache clearing
# ---------------------------------------------------------------------------


class TestCacheClearing:
    """Tests for _clear_cache()."""

    async def test_clear_removes_env_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")
        await resolve_private_key(options=options)

        # Verify cached
        assert get_cached_address() == TEST_ADDRESS

        # Clear
        _clear_cache()
        monkeypatch.delenv("ACTP_PRIVATE_KEY")

        # No longer cached
        assert get_cached_address() is None

    async def test_clear_removes_file_cache(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        ks_json = _create_keystore_json(TEST_PRIVATE_KEY, TEST_PASSWORD)
        (actp_dir / "keystore.json").write_text(ks_json)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)

        await resolve_private_key(str(tmp_path))
        assert get_cached_address(str(tmp_path)) == TEST_ADDRESS

        _clear_cache()
        # Remove file so re-resolve returns None
        (actp_dir / "keystore.json").unlink()
        monkeypatch.delenv("ACTP_KEY_PASSWORD")
        assert get_cached_address(str(tmp_path)) is None

    async def test_clear_resets_testnet_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_clear_cache resets the testnet warning flag."""
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="testnet")

        with caplog.at_level("WARNING", logger="agirails.wallet.keystore"):
            await resolve_private_key(options=options)
        assert "deprecated" in caplog.text

        _clear_cache()
        caplog.clear()

        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        with caplog.at_level("WARNING", logger="agirails.wallet.keystore"):
            await resolve_private_key(options=options)
        # Warning should appear again after _clear_cache reset _testnet_warned
        assert "deprecated" in caplog.text


# ---------------------------------------------------------------------------
# Additional: get_cached_address
# ---------------------------------------------------------------------------


class TestGetCachedAddress:
    """Tests for get_cached_address()."""

    async def test_returns_none_before_resolution(self) -> None:
        assert get_cached_address() is None

    async def test_returns_address_after_env_resolution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_PRIVATE_KEY", TEST_PRIVATE_KEY)
        options = ResolvePrivateKeyOptions(network="mock")
        await resolve_private_key(options=options)
        assert get_cached_address() == TEST_ADDRESS

    async def test_returns_address_after_base64_resolution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b64 = _create_keystore_b64(TEST_PRIVATE_KEY, TEST_PASSWORD)
        monkeypatch.setenv("ACTP_KEYSTORE_BASE64", b64)
        monkeypatch.setenv("ACTP_KEY_PASSWORD", TEST_PASSWORD)
        await resolve_private_key()
        addr = get_cached_address()
        assert addr == TEST_ADDRESS
