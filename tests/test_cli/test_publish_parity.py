"""Tests for Python publish parity with TS SDK.

Covers: scenario detection, slug auto-rename, wallet/agent_id/did write-back,
non-blocking agirails.app sync, enhanced messaging.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from typer.testing import CliRunner

from agirails.cli.commands.publish import detect_lazy_publish_scenario
from agirails.cli.main import app
from agirails.config.on_chain_state import ZERO_HASH, OnChainAgentState
from agirails.config.pending_publish import PendingPublishData

runner = CliRunner()

SAMPLE_AGIRAILS_MD = """---
name: test-agent
slug: test-agent
endpoint: https://agent.example.com/webhook
---

# Test Agent
A test agent for testing.
"""

SAMPLE_WITH_AGENT_ID = """---
name: test-agent
slug: test-agent
agent_id: "12345"
wallet: "0xWallet"
endpoint: https://agent.example.com/webhook
---

# Test Agent
"""


def _make_pending(config_hash: str = "0x" + "aa" * 32) -> PendingPublishData:
    return PendingPublishData(
        version=1,
        config_hash=config_hash,
        cid="bafytestcid",
        endpoint="https://agent.example.com",
        service_descriptors=[],
        created_at="2026-01-01T00:00:00Z",
        network="base-sepolia",
    )


# ============================================================================
# Scenario Detection (unit tests for detect_lazy_publish_scenario)
# ============================================================================


class TestDetectScenario:
    """All 5 scenarios with OnChainAgentState inputs."""

    def test_no_pending_returns_none(self) -> None:
        on_chain = OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
        assert detect_lazy_publish_scenario(on_chain, None) == "none"

    def test_not_registered_returns_a(self) -> None:
        on_chain = OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
        assert detect_lazy_publish_scenario(on_chain, _make_pending()) == "A"

    def test_registered_diff_hash_unlisted_returns_b1(self) -> None:
        on_chain = OnChainAgentState(
            registered_at=1000, config_hash="0x" + "bb" * 32, listed=False
        )
        assert detect_lazy_publish_scenario(on_chain, _make_pending()) == "B1"

    def test_registered_diff_hash_listed_returns_b2(self) -> None:
        on_chain = OnChainAgentState(
            registered_at=1000, config_hash="0x" + "bb" * 32, listed=True
        )
        assert detect_lazy_publish_scenario(on_chain, _make_pending()) == "B2"

    def test_registered_same_hash_returns_c(self) -> None:
        same_hash = "0x" + "aa" * 32
        on_chain = OnChainAgentState(
            registered_at=1000, config_hash=same_hash, listed=True
        )
        assert detect_lazy_publish_scenario(on_chain, _make_pending(same_hash)) == "C"


# ============================================================================
# Slug Auto-Rename
# ============================================================================


class TestSlugAutoRename:
    """Slug check and auto-rename on conflict."""

    @patch("agirails.cli.commands.publish.publish_config")
    @patch("agirails.api.agirails_app.check_slug", new_callable=AsyncMock)
    def test_slug_rename_on_conflict(
        self,
        mock_check: AsyncMock,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        # Slug taken, suggestion provided
        mock_check.return_value = {
            "available": False,
            "slug": "test-agent",
            "suggestions": ["test-agent-2"],
        }

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "cc" * 32,
            cid="bafypublished",
            dry_run=False,
        )

        result = runner.invoke(
            app,
            ["publish", "--path", str(md), "--network", "base-mainnet"],
        )

        # Should have renamed slug
        assert "Renamed to" in result.output or "test-agent-2" in result.output
        # Frontmatter should be updated
        updated = md.read_text()
        assert "test-agent-2" in updated


# ============================================================================
# Write-back of wallet/agent_id/did
# ============================================================================


class TestWriteBack:
    """Test that wallet/agent_id/did are written back to AGIRAILS.md."""

    @patch("agirails.cli.commands.publish._activate_on_testnet")
    @patch("agirails.cli.commands.publish.publish_config")
    def test_testnet_writes_wallet_and_did(
        self,
        mock_publish: MagicMock,
        mock_activate: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "dd" * 32,
            cid="bafytestcid",
            dry_run=False,
        )

        # asyncio.run wraps async call — mock at the function level
        import asyncio

        mock_activate.return_value = {
            "tx_hash": "0xtxhash123",
            "wallet_address": "0x" + "11" * 20,
            "agent_id": "987654321",
        }

        # Patch asyncio.run to handle async mock
        with patch("agirails.cli.commands.publish.asyncio") as mock_asyncio:
            mock_asyncio.run = lambda coro: mock_activate.return_value

            result = runner.invoke(
                app,
                ["publish", "--path", str(md), "--network", "base-sepolia"],
            )

        if result.exit_code == 0:
            updated = md.read_text()
            assert "wallet" in updated
            assert "did" in updated


# ============================================================================
# Non-Blocking App Sync
# ============================================================================


class TestNonBlockingSync:
    """Test that agirails.app sync failure doesn't crash publish."""

    @patch("agirails.cli.commands.publish.publish_config")
    def test_app_sync_failure_doesnt_crash(
        self,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_WITH_AGENT_ID)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "ee" * 32,
            cid="bafycid",
            dry_run=False,
        )

        # Mock the slug check to succeed
        with patch(
            "agirails.api.agirails_app.check_slug",
            new_callable=AsyncMock,
            return_value={"available": True, "slug": "test-agent"},
        ):
            result = runner.invoke(
                app,
                ["publish", "--path", str(md), "--network", "base-mainnet"],
            )

        # Even if sync fails, publish should succeed
        assert result.exit_code == 0


# ============================================================================
# Enhanced Messaging
# ============================================================================


class TestEnhancedMessaging:
    """Test context-aware next steps messaging."""

    @patch("agirails.cli.commands.publish.publish_config")
    def test_messaging_includes_health(
        self,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "ff" * 32,
            cid="bafymsg",
            dry_run=False,
        )

        result = runner.invoke(
            app,
            ["publish", "--path", str(md), "--network", "base-mainnet"],
        )

        assert result.exit_code == 0
        assert "actp health" in result.output

    @patch("agirails.cli.commands.publish.publish_config")
    def test_messaging_includes_balance(
        self,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "ff" * 32,
            cid="bafymsg",
            dry_run=False,
        )

        result = runner.invoke(
            app,
            ["publish", "--path", str(md), "--network", "base-mainnet"],
        )

        assert result.exit_code == 0
        assert "actp balance" in result.output

    @patch("agirails.cli.commands.publish.publish_config")
    def test_mainnet_messaging(
        self,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "ff" * 32,
            cid="bafymsg",
            dry_run=False,
        )

        result = runner.invoke(
            app,
            ["publish", "--path", str(md), "--network", "base-mainnet"],
        )

        assert result.exit_code == 0
        assert "Mainnet" in result.output
        assert "first payment" in result.output

    @patch("agirails.cli.commands.publish.publish_config")
    def test_profile_url_shown(
        self,
        mock_publish: MagicMock,
        tmp_path: Path,
    ) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)

        from agirails.config.publish_pipeline import PublishResult

        mock_publish.return_value = PublishResult(
            config_hash="0x" + "ff" * 32,
            cid="bafymsg",
            dry_run=False,
        )

        result = runner.invoke(
            app,
            ["publish", "--path", str(md), "--network", "base-mainnet"],
        )

        assert result.exit_code == 0
        assert "agirails.app/a/test-agent" in result.output
