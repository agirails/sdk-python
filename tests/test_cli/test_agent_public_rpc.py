"""Tests for the `actp agent` public-RPC warning (mirror TS agent.ts:152-159)."""

from __future__ import annotations

import typer
from typer.testing import CliRunner

from agirails.cli.commands.agent import agent, emit_public_rpc_warning

runner = CliRunner()

# `actp agent` registration in main.py is a cli-subsystem export change (see
# export_changes_needed). Until it is wired, exercise the command via a local
# Typer app bound to the same callable so the warning surface is covered.
_app = typer.Typer()
_app.command(name="agent")(agent)


class TestEmitPublicRpcWarning:
    def test_warns_on_public_testnet(self, monkeypatch) -> None:
        monkeypatch.delenv("BASE_SEPOLIA_RPC", raising=False)
        assert emit_public_rpc_warning("base-sepolia") is True

    def test_warns_on_public_mainnet(self, monkeypatch) -> None:
        monkeypatch.delenv("BASE_MAINNET_RPC", raising=False)
        assert emit_public_rpc_warning("base-mainnet") is True

    def test_no_warn_in_mock(self) -> None:
        assert emit_public_rpc_warning("base-sepolia", mock=True) is False

    def test_no_warn_with_rpc_override(self) -> None:
        assert (
            emit_public_rpc_warning("base-sepolia", rpc_override="https://x.rpc")
            is False
        )

    def test_no_warn_with_env_override(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_SEPOLIA_RPC", "https://x.rpc")
        assert emit_public_rpc_warning("base-sepolia") is False

    def test_mainnet_env_var_label(self, monkeypatch, capsys) -> None:
        monkeypatch.delenv("BASE_MAINNET_RPC", raising=False)
        emit_public_rpc_warning("base-mainnet")
        out = capsys.readouterr().out
        assert "BASE_MAINNET_RPC" in out


class TestAgentCommand:
    def test_agent_emits_warning_on_public_rpc(self, tmp_path, monkeypatch) -> None:
        monkeypatch.delenv("BASE_SEPOLIA_RPC", raising=False)
        policy = tmp_path / "policy.json"
        policy.write_text("{}")
        result = runner.invoke(_app, ["--policy", str(policy)])
        assert result.exit_code == 0, result.stdout
        assert "Public RPC in use" in result.stdout

    def test_agent_mock_no_warning(self, tmp_path) -> None:
        policy = tmp_path / "policy.json"
        policy.write_text("{}")
        result = runner.invoke(
            _app, ["--policy", str(policy), "--network", "mock"]
        )
        assert result.exit_code == 0, result.stdout
        assert "Public RPC in use" not in result.stdout
