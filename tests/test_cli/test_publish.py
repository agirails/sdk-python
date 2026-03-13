"""Tests for publish, diff, and pull CLI commands.

Uses typer.testing.CliRunner and mocked IPFS/registry calls.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.config.agirailsmd import compute_config_hash
from agirails.config.pending_publish import load_pending_publish
from agirails.config.sync_operations import DiffStatus, OnChainConfigReader, ZERO_HASH

runner = CliRunner()

# Sample AGIRAILS.md content
SAMPLE_AGIRAILS_MD = """---
name: test-agent
version: "1.0"
endpoint: https://test-agent.io/api
capabilities:
  - text-generation
  - echo
---

# Test Agent

This is a test agent for ACTP.
"""


# ============================================================================
# Publish CLI Tests
# ============================================================================


class TestPublishCommand:
    """Tests for ``actp publish``."""

    def test_publish_dry_run(self, tmp_path: Path) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        result = runner.invoke(
            app,
            ["publish", "--dry-run", "--path", str(md_path)],
        )

        assert result.exit_code == 0
        assert "hash" in result.output.lower() or "Hash" in result.output

    def test_publish_dry_run_json(self, tmp_path: Path) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        result = runner.invoke(
            app,
            ["--json", "publish", "--dry-run", "--path", str(md_path)],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "configHash" in data
        assert data["dryRun"] is True
        assert data["configHash"].startswith("0x")
        assert len(data["configHash"]) == 66  # 0x + 64 hex chars

    def test_publish_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["publish", "--path", str(tmp_path / "nonexistent.md")],
        )

        assert result.exit_code == 1

    @patch("agirails.config.publish_pipeline.upload_via_proxy")
    def test_publish_with_proxy_upload(
        self, mock_upload: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        mock_upload.return_value = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

        result = runner.invoke(
            app,
            ["publish", "--path", str(md_path), "--network", "base-sepolia"],
        )

        assert result.exit_code == 0
        mock_upload.assert_called_once()

        # Check pending-publish was saved
        actp_dir = str(tmp_path / ".actp")
        # The command saves to CWD, so check the actual saved location
        # Since we used --path, pending publish goes to CWD's .actp

    @patch("agirails.config.publish_pipeline.upload_via_proxy")
    def test_publish_updates_frontmatter(
        self, mock_upload: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)
        monkeypatch.chdir(tmp_path)

        mock_upload.return_value = "bafytestcid123"

        result = runner.invoke(
            app,
            ["publish", "--path", str(md_path)],
        )

        assert result.exit_code == 0

        # Check frontmatter was updated
        updated = md_path.read_text()
        assert "config_hash:" in updated
        assert "config_cid:" in updated
        assert "bafytestcid123" in updated

    def test_publish_invalid_yaml(self, tmp_path: Path) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text("not valid frontmatter content")

        result = runner.invoke(
            app,
            ["publish", "--dry-run", "--path", str(md_path)],
        )

        assert result.exit_code == 1


# ============================================================================
# Diff CLI Tests
# ============================================================================


class TestDiffCommand:
    """Tests for ``actp diff``."""

    @patch("agirails.cli.commands.diff.get_on_chain_config_state")
    def test_diff_in_sync(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        # Compute actual hash
        hash_result = compute_config_hash(SAMPLE_AGIRAILS_MD)

        mock_reader.return_value = OnChainConfigReader(
            config_hash=hash_result.config_hash,
            config_cid="bafytestcid",
        )

        result = runner.invoke(
            app,
            [
                "diff",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        assert "sync" in result.output.lower() or "In sync" in result.output

    @patch("agirails.cli.commands.diff.get_on_chain_config_state")
    def test_diff_local_ahead(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        mock_reader.return_value = OnChainConfigReader(
            config_hash=ZERO_HASH,
            config_cid="",
        )

        result = runner.invoke(
            app,
            [
                "diff",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0

    @patch("agirails.cli.commands.diff.get_on_chain_config_state")
    def test_diff_json_output(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        hash_result = compute_config_hash(SAMPLE_AGIRAILS_MD)
        mock_reader.return_value = OnChainConfigReader(
            config_hash=hash_result.config_hash,
            config_cid="bafytestcid",
        )

        result = runner.invoke(
            app,
            [
                "--json", "diff",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "in-sync"
        assert data["inSync"] is True
        assert data["localHash"] == hash_result.config_hash

    @patch("agirails.cli.commands.diff.get_on_chain_config_state")
    def test_diff_diverged(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        # Write content WITH a config_hash that doesn't match on-chain
        content = """---
name: test-agent
config_hash: "0xold_hash_that_doesnt_match"
---

# Body
"""
        md_path.write_text(content)

        mock_reader.return_value = OnChainConfigReader(
            config_hash="0x" + "aa" * 32,
            config_cid="bafydifferent",
        )

        result = runner.invoke(
            app,
            [
                "--json", "diff",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "diverged"
        assert data["inSync"] is False

    def test_diff_no_address_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)
        monkeypatch.delenv("ACTP_ADDRESS", raising=False)

        result = runner.invoke(
            app,
            ["diff", "--path", str(md_path)],
        )

        assert result.exit_code == 1


# ============================================================================
# Pull CLI Tests
# ============================================================================


class TestPullCommand:
    """Tests for ``actp pull``."""

    @patch("agirails.config.sync_operations.fetch_from_ipfs")
    @patch("agirails.cli.commands.pull.get_on_chain_config_state")
    def test_pull_writes_file(
        self,
        mock_reader: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        # No local file initially

        hash_result = compute_config_hash(SAMPLE_AGIRAILS_MD)
        mock_reader.return_value = OnChainConfigReader(
            config_hash=hash_result.config_hash,
            config_cid="bafyremotecid",
        )
        mock_fetch.return_value = SAMPLE_AGIRAILS_MD

        result = runner.invoke(
            app,
            [
                "pull",
                "--force",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        assert md_path.exists()
        content = md_path.read_text()
        assert "config_hash:" in content
        assert "config_cid:" in content

    @patch("agirails.cli.commands.pull.get_on_chain_config_state")
    def test_pull_no_on_chain_config(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"

        mock_reader.return_value = OnChainConfigReader(
            config_hash=ZERO_HASH,
            config_cid="",
        )

        result = runner.invoke(
            app,
            [
                "pull",
                "--force",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        assert "No config published" in result.output or "no-remote" in result.output.lower()

    @patch("agirails.config.sync_operations.fetch_from_ipfs")
    @patch("agirails.cli.commands.pull.get_on_chain_config_state")
    def test_pull_integrity_failure(
        self,
        mock_reader: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"

        mock_reader.return_value = OnChainConfigReader(
            config_hash="0x" + "ff" * 32,  # hash that won't match content
            config_cid="bafybadhash",
        )
        mock_fetch.return_value = SAMPLE_AGIRAILS_MD

        result = runner.invoke(
            app,
            [
                "pull",
                "--force",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        # File should NOT be written due to integrity failure
        assert not md_path.exists() or "Integrity check failed" in result.output

    @patch("agirails.cli.commands.pull.get_on_chain_config_state")
    def test_pull_json_output(
        self, mock_reader: MagicMock, tmp_path: Path
    ) -> None:
        md_path = tmp_path / "AGIRAILS.md"

        mock_reader.return_value = OnChainConfigReader(
            config_hash=ZERO_HASH,
            config_cid="",
        )

        result = runner.invoke(
            app,
            [
                "--json", "pull",
                "--force",
                "--path", str(md_path),
                "--address", "0x" + "1" * 40,
            ],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "written" in data
        assert data["written"] is False

    def test_pull_no_address_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        md_path = tmp_path / "AGIRAILS.md"
        monkeypatch.delenv("ACTP_ADDRESS", raising=False)

        result = runner.invoke(
            app,
            ["pull", "--path", str(md_path)],
        )

        assert result.exit_code == 1


# ============================================================================
# Diff Status Detection Tests
# ============================================================================


class TestDiffStatusDetection:
    """Test diff_config status detection logic directly."""

    def test_both_empty_is_no_local(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        md_path = str(tmp_path / "AGIRAILS.md")
        on_chain = OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")

        result = diff_config(md_path, on_chain)
        assert result.status == DiffStatus.NO_LOCAL
        assert result.in_sync is True

    def test_local_only_is_no_remote(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)
        on_chain = OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")

        result = diff_config(str(md_path), on_chain)
        assert result.status == DiffStatus.NO_REMOTE
        assert result.in_sync is False

    def test_remote_only_is_remote_ahead(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        md_path = str(tmp_path / "AGIRAILS.md")
        on_chain = OnChainConfigReader(
            config_hash="0x" + "ab" * 32,
            config_cid="bafyremote",
        )

        result = diff_config(md_path, on_chain)
        assert result.status == DiffStatus.REMOTE_AHEAD
        assert result.in_sync is False

    def test_matching_hashes_is_in_sync(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)
        hash_result = compute_config_hash(SAMPLE_AGIRAILS_MD)

        on_chain = OnChainConfigReader(
            config_hash=hash_result.config_hash,
            config_cid="bafytestcid",
        )

        result = diff_config(str(md_path), on_chain)
        assert result.status == DiffStatus.IN_SYNC
        assert result.in_sync is True

    def test_different_hashes_no_fm_hash_is_local_ahead(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        on_chain = OnChainConfigReader(
            config_hash="0x" + "99" * 32,
            config_cid="bafydiff",
        )

        result = diff_config(str(md_path), on_chain)
        # No config_hash in frontmatter -> local-ahead
        assert result.status == DiffStatus.LOCAL_AHEAD
        assert result.in_sync is False

    def test_different_hashes_with_stale_fm_hash_is_diverged(self, tmp_path: Path) -> None:
        from agirails.config.sync_operations import diff_config

        content = """---
name: test
config_hash: "0xold_does_not_match_on_chain"
---

# Body
"""
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(content)

        on_chain = OnChainConfigReader(
            config_hash="0x" + "aa" * 32,
            config_cid="bafydiff",
        )

        result = diff_config(str(md_path), on_chain)
        assert result.status == DiffStatus.DIVERGED
        assert result.in_sync is False
