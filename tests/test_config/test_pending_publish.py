"""Tests for pending_publish module.

Covers:
  - Save/load/delete round-trip
  - Atomic write (tmp + rename)
  - Symlink rejection
  - ACTP_DIR override
  - Chain-scoped file naming
  - Legacy fallback
  - has_pending_publish
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agirails.config.pending_publish import (
    PendingPublishData,
    SecurityError,
    ServiceDescriptorData,
    delete_pending_publish,
    get_actp_dir,
    has_pending_publish,
    load_pending_publish,
    save_pending_publish,
)


# ============================================================================
# Fixtures
# ============================================================================


def _make_pending(network: str = "base-sepolia") -> PendingPublishData:
    """Create a sample PendingPublishData for testing."""
    return PendingPublishData(
        version=1,
        config_hash="0x" + "ab" * 32,
        cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        endpoint="https://my-agent.io/api",
        service_descriptors=[
            ServiceDescriptorData(
                service_type_hash="0x" + "cd" * 32,
                service_type="text-generation",
                schema_uri="https://schema.io/tg",
                min_price="50000",
                max_price="1000000",
                avg_completion_time=120,
                metadata_cid="bafytest",
            ),
        ],
        created_at="2026-02-15T10:00:00+00:00",
        network=network,
    )


# ============================================================================
# Tests: Save / Load / Delete
# ============================================================================


class TestSaveLoadDelete:
    """Test basic save, load, and delete operations."""

    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        pending = _make_pending("base-sepolia")

        save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)
        loaded = load_pending_publish(network="base-sepolia", actp_dir=actp_dir)

        assert loaded is not None
        assert loaded.config_hash == pending.config_hash
        assert loaded.cid == pending.cid
        assert loaded.endpoint == pending.endpoint
        assert loaded.network == "base-sepolia"
        assert len(loaded.service_descriptors) == 1
        assert loaded.service_descriptors[0].service_type == "text-generation"
        assert loaded.service_descriptors[0].min_price == "50000"

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / "new" / "nested" / ".actp")
        pending = _make_pending()

        save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)

        assert os.path.isdir(actp_dir)

    def test_delete_removes_file(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        pending = _make_pending()

        save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)
        assert has_pending_publish(network="base-sepolia", actp_dir=actp_dir)

        delete_pending_publish(network="base-sepolia", actp_dir=actp_dir)
        assert not has_pending_publish(network="base-sepolia", actp_dir=actp_dir)

    def test_delete_nonexistent_is_noop(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        # Should not raise
        delete_pending_publish(network="base-sepolia", actp_dir=actp_dir)

    def test_load_nonexistent_returns_none(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        assert load_pending_publish(network="base-sepolia", actp_dir=actp_dir) is None

    def test_has_pending_publish_false_initially(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        assert not has_pending_publish(network="base-sepolia", actp_dir=actp_dir)


# ============================================================================
# Tests: Atomic Write
# ============================================================================


class TestAtomicWrite:
    """Test atomic write behavior (tmp + rename)."""

    def test_no_tmp_file_left_after_save(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        pending = _make_pending()

        save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)

        # No .tmp file should remain
        files = os.listdir(actp_dir)
        assert not any(f.endswith(".tmp") for f in files), f"Found tmp file: {files}"

    def test_file_mode_is_600(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        pending = _make_pending()

        path = save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)

        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_file_is_valid_json_after_save(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")
        pending = _make_pending()

        path = save_pending_publish(pending, network="base-sepolia", actp_dir=actp_dir)

        with open(path) as f:
            data = json.load(f)

        assert data["version"] == 1
        assert data["configHash"] == pending.config_hash
        assert data["cid"] == pending.cid


# ============================================================================
# Tests: Symlink Rejection
# ============================================================================


class TestSymlinkRejection:
    """Test symlink attack prevention."""

    def test_rejects_symlink_directory(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        symlink_dir = tmp_path / ".actp"
        symlink_dir.symlink_to(real_dir)

        pending = _make_pending()

        with pytest.raises(SecurityError, match="symbolic link"):
            save_pending_publish(pending, network="base-sepolia", actp_dir=str(symlink_dir))

    def test_rejects_symlink_file(self, tmp_path: Path) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()

        # Create real file and symlink to it as the pending-publish file
        real_file = tmp_path / "real.json"
        real_file.write_text("{}")
        target = actp_dir / "pending-publish.base-sepolia.json"
        target.symlink_to(real_file)

        pending = _make_pending()

        with pytest.raises(SecurityError, match="symbolic link"):
            save_pending_publish(pending, network="base-sepolia", actp_dir=str(actp_dir))


# ============================================================================
# Tests: ACTP_DIR Override
# ============================================================================


class TestActpDirOverride:
    """Test ACTP_DIR environment variable override."""

    def test_actp_dir_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        custom_dir = str(tmp_path / "custom-actp")
        monkeypatch.setenv("ACTP_DIR", custom_dir)

        result = get_actp_dir()
        assert result == os.path.abspath(custom_dir)

    def test_explicit_actp_dir_overrides_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACTP_DIR", "/should/not/use/this")
        explicit = str(tmp_path / "explicit")

        result = get_actp_dir(explicit)
        assert result == os.path.abspath(explicit)

    def test_default_is_cwd_actp(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ACTP_DIR", raising=False)
        monkeypatch.chdir(tmp_path)

        result = get_actp_dir()
        assert result == str(tmp_path / ".actp")

    def test_save_load_with_actp_dir_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom_dir = str(tmp_path / "env-actp")
        monkeypatch.setenv("ACTP_DIR", custom_dir)

        pending = _make_pending()
        save_pending_publish(pending, network="base-sepolia", actp_dir=custom_dir)
        loaded = load_pending_publish(network="base-sepolia", actp_dir=custom_dir)

        assert loaded is not None
        assert loaded.config_hash == pending.config_hash


# ============================================================================
# Tests: Chain-Scoped File Naming
# ============================================================================


class TestChainScopedFiles:
    """Test chain-scoped file naming (independent testnet/mainnet)."""

    def test_different_networks_use_different_files(self, tmp_path: Path) -> None:
        actp_dir = str(tmp_path / ".actp")

        sepolia = _make_pending("base-sepolia")
        sepolia.config_hash = "0x" + "11" * 32
        mainnet = _make_pending("base-mainnet")
        mainnet.config_hash = "0x" + "22" * 32

        save_pending_publish(sepolia, network="base-sepolia", actp_dir=actp_dir)
        save_pending_publish(mainnet, network="base-mainnet", actp_dir=actp_dir)

        loaded_sepolia = load_pending_publish(network="base-sepolia", actp_dir=actp_dir)
        loaded_mainnet = load_pending_publish(network="base-mainnet", actp_dir=actp_dir)

        assert loaded_sepolia is not None
        assert loaded_mainnet is not None
        assert loaded_sepolia.config_hash == "0x" + "11" * 32
        assert loaded_mainnet.config_hash == "0x" + "22" * 32

    def test_legacy_fallback(self, tmp_path: Path) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()

        # Write a legacy (unscoped) file
        legacy_path = actp_dir / "pending-publish.json"
        legacy_data = _make_pending().to_dict()
        legacy_data["configHash"] = "0x" + "ff" * 32
        legacy_path.write_text(json.dumps(legacy_data))

        # Load with network should fall back to legacy
        loaded = load_pending_publish(network="base-sepolia", actp_dir=str(actp_dir))
        assert loaded is not None
        assert loaded.config_hash == "0x" + "ff" * 32

    def test_scoped_takes_priority_over_legacy(self, tmp_path: Path) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()

        # Write legacy
        legacy_path = actp_dir / "pending-publish.json"
        legacy_data = _make_pending().to_dict()
        legacy_data["configHash"] = "0xlegacy"
        legacy_path.write_text(json.dumps(legacy_data))

        # Write scoped
        scoped = _make_pending("base-sepolia")
        scoped.config_hash = "0xscoped"
        save_pending_publish(scoped, network="base-sepolia", actp_dir=str(actp_dir))

        loaded = load_pending_publish(network="base-sepolia", actp_dir=str(actp_dir))
        assert loaded is not None
        assert loaded.config_hash == "0xscoped"

    def test_delete_cleans_both_scoped_and_legacy(self, tmp_path: Path) -> None:
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()

        # Create both files
        legacy_path = actp_dir / "pending-publish.json"
        legacy_path.write_text(json.dumps(_make_pending().to_dict()))

        save_pending_publish(
            _make_pending("base-sepolia"),
            network="base-sepolia",
            actp_dir=str(actp_dir),
        )

        delete_pending_publish(network="base-sepolia", actp_dir=str(actp_dir))

        assert not legacy_path.exists()
        assert not (actp_dir / "pending-publish.base-sepolia.json").exists()


# ============================================================================
# Tests: Serialization
# ============================================================================


class TestSerialization:
    """Test PendingPublishData serialization/deserialization."""

    def test_to_dict_camel_case(self) -> None:
        pending = _make_pending()
        d = pending.to_dict()

        assert "configHash" in d
        assert "serviceDescriptors" in d
        assert "createdAt" in d
        assert d["version"] == 1

    def test_from_dict_round_trip(self) -> None:
        pending = _make_pending()
        d = pending.to_dict()
        restored = PendingPublishData.from_dict(d)

        assert restored.config_hash == pending.config_hash
        assert restored.cid == pending.cid
        assert len(restored.service_descriptors) == len(pending.service_descriptors)

    def test_service_descriptor_serialization(self) -> None:
        sd = ServiceDescriptorData(
            service_type_hash="0xabc",
            service_type="echo",
            min_price="100",
            max_price="200",
        )
        d = sd.to_dict()

        assert d["serviceTypeHash"] == "0xabc"
        assert d["serviceType"] == "echo"
        assert d["minPrice"] == "100"
        assert d["maxPrice"] == "200"

        restored = ServiceDescriptorData.from_dict(d)
        assert restored.service_type == "echo"
        assert restored.min_price == "100"
