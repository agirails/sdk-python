"""Tests for ``actp repair`` command."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()

FAKE_PRIVATE_KEY = "0x" + "ab" * 32
FAKE_TX_HASH = "0x" + "9" * 64


def _fake_receipt():
    return SimpleNamespace(transaction_hash=FAKE_TX_HASH)


def _fake_registry(**kwargs):
    """Build a MagicMock standing in for AgentRegistry with async methods."""
    reg = MagicMock()
    reg._account = SimpleNamespace(address="0xSIGNER_ADDRESS")
    reg.remove_service_type = AsyncMock(return_value=_fake_receipt())
    reg.update_endpoint = AsyncMock(return_value=_fake_receipt())
    reg.set_active_status = AsyncMock(return_value=_fake_receipt())
    reg.set_listed = AsyncMock(return_value=_fake_receipt())
    for k, v in kwargs.items():
        setattr(reg, k, v)
    return reg


class TestRepairValidation:
    def test_no_action_errors(self):
        result = runner.invoke(app, ["repair", "--yes"])
        assert result.exit_code != 0
        assert "No repair action specified" in result.output

    def test_non_https_endpoint_errors(self):
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ):
            result = runner.invoke(
                app,
                ["repair", "--endpoint", "http://example.com", "--yes"],
            )
        assert result.exit_code != 0
        assert "HTTPS" in result.output

    def test_invalid_bool_flag_errors(self):
        result = runner.invoke(
            app, ["repair", "--active", "maybe", "--yes"]
        )
        assert result.exit_code != 0
        assert "true|false" in result.output

    def test_no_keystore_errors(self):
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = runner.invoke(
                app,
                ["repair", "--active", "true", "--yes", "--json"],
            )
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["ok"] is False
        assert "No wallet" in body["error"]


class TestRepairHappyPaths:
    def test_remove_service(self):
        registry = _fake_registry()
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.repair.AgentRegistry.create",
            new_callable=AsyncMock,
            return_value=registry,
        ):
            result = runner.invoke(
                app,
                [
                    "repair",
                    "--remove-service",
                    "code-review",
                    "--yes",
                    "--json",
                ],
            )

        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["ok"] is True
        assert len(body["txHashes"]) == 1
        assert body["txHashes"][0]["action"] == "remove-service:code-review"
        assert body["txHashes"][0]["txHash"] == FAKE_TX_HASH
        assert registry.remove_service_type.call_count == 1
        # No other methods should have been called.
        assert registry.update_endpoint.call_count == 0
        assert registry.set_active_status.call_count == 0
        assert registry.set_listed.call_count == 0

    def test_multi_action_runs_all_sequentially(self):
        """endpoint + active + listed in one invocation → 3 separate txs."""
        registry = _fake_registry()
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.repair.AgentRegistry.create",
            new_callable=AsyncMock,
            return_value=registry,
        ):
            result = runner.invoke(
                app,
                [
                    "repair",
                    "--endpoint",
                    "https://api.example.com/x402",
                    "--active",
                    "true",
                    "--listed",
                    "false",
                    "--yes",
                    "--json",
                ],
            )

        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert len(body["txHashes"]) == 3
        actions = [t["action"] for t in body["txHashes"]]
        assert actions == [
            "update-endpoint",
            "set-active:True",
            "set-listed:False",
        ]
        assert registry.update_endpoint.call_count == 1
        assert registry.set_active_status.call_count == 1
        assert registry.set_listed.call_count == 1

    def test_set_listed_only_toggles_just_listed(self):
        registry = _fake_registry()
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.repair.AgentRegistry.create",
            new_callable=AsyncMock,
            return_value=registry,
        ):
            result = runner.invoke(
                app, ["repair", "--listed", "true", "--yes", "--json"]
            )
        assert result.exit_code == 0
        registry.set_listed.assert_awaited_once_with(True)
        registry.set_active_status.assert_not_called()
        registry.update_endpoint.assert_not_called()
        registry.remove_service_type.assert_not_called()


class TestRepairConfirmation:
    def test_non_tty_requires_explicit_yes(self):
        """In JSON mode (treated as non-TTY) without --yes, repair refuses."""
        with patch(
            "agirails.cli.commands.repair.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.repair.AgentRegistry.create",
            new_callable=AsyncMock,
            return_value=_fake_registry(),
        ):
            result = runner.invoke(
                app, ["repair", "--active", "true", "--json"]
            )
        assert result.exit_code == 2
        assert "--yes" in result.output
