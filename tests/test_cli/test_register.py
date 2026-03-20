"""Tests for actp register command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()


class TestRegisterCommand:
    """Tests for the register CLI command."""

    def test_deprecation_shown_without_force_legacy(self) -> None:
        """Should show deprecation warning without --force-legacy."""
        result = runner.invoke(app, ["register"])
        assert result.exit_code == 0
        assert "deprecated" in result.output.lower()
        assert "actp publish" in result.output

    def test_exits_zero_without_force_legacy(self) -> None:
        """Should exit 0 without --force-legacy (graceful deprecation)."""
        result = runner.invoke(app, ["register"])
        assert result.exit_code == 0

    def test_json_deprecation_output(self) -> None:
        """Should output JSON deprecation without --force-legacy."""
        result = runner.invoke(app, ["register", "--json"])
        assert result.exit_code == 0
        assert '"deprecated": true' in result.output

    def test_error_when_no_private_key_with_force_legacy(self) -> None:
        """Should error when no private key available with --force-legacy."""
        with patch(
            "agirails.wallet.keystore.resolve_private_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = runner.invoke(
                app, ["register", "--force-legacy", "--network", "base-sepolia"]
            )
            assert result.exit_code == 1
            assert "private key" in result.output.lower() or "No private key" in result.output

    def test_help_flag(self) -> None:
        """Should show help text."""
        result = runner.invoke(app, ["register", "--help"])
        assert result.exit_code == 0
        assert "DEPRECATED" in result.output or "deprecated" in result.output.lower()
