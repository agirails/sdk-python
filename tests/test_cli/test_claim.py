"""Tests for actp claim command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()


class TestClaimCommand:
    """Tests for the claim CLI command."""

    def test_error_when_no_agent_id(self) -> None:
        """Should error when no agent_id is provided."""
        result = runner.invoke(app, ["claim"])
        assert result.exit_code == 1
        assert "agent_id is required" in result.output

    def test_error_when_all_flag_used(self) -> None:
        """Should error when --all is used (not yet implemented)."""
        result = runner.invoke(app, ["claim", "--all"])
        assert result.exit_code == 1
        assert "not yet implemented" in result.output

    def test_error_when_no_private_key(self) -> None:
        """Should error when no private key can be resolved."""
        with patch(
            "agirails.wallet.keystore.resolve_private_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = runner.invoke(app, ["claim", "12345", "--network", "base-sepolia"])
            assert result.exit_code == 1
            assert "No private key found" in result.output or "private key" in result.output.lower()

    def test_happy_path_json(self) -> None:
        """Should claim agent and output JSON on success."""
        fake_key = "0x" + "ab" * 32

        with patch(
            "agirails.wallet.keystore.resolve_private_key",
            new_callable=AsyncMock,
            return_value=fake_key,
        ), patch(
            "agirails.api.agirails_app.get_claim_challenge",
            new_callable=AsyncMock,
            return_value={"challenge": "test-challenge-123"},
        ), patch(
            "agirails.api.agirails_app.claim_agent",
            new_callable=AsyncMock,
            return_value={"claimed": True, "slug": "my-agent"},
        ):
            result = runner.invoke(app, ["claim", "99999", "--network", "base-sepolia", "--json"])
            assert result.exit_code == 0
            assert '"status": "claimed"' in result.output
            assert '"agentId": "99999"' in result.output

    def test_error_when_all_with_json(self) -> None:
        """Should output JSON error when --all is used with --json."""
        result = runner.invoke(app, ["claim", "--all", "--json"])
        assert result.exit_code == 1
        assert "not yet implemented" in result.output
