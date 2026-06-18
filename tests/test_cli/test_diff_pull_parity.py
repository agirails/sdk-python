"""Parity tests for ``actp diff`` / ``actp pull`` argument surface.

Mirrors TS ``src/cli/commands/diff.ts`` / ``pull.ts``:
  * default ``-n/--network`` is ``base-sepolia`` (was ``base-mainnet`` in py)
  * the AGIRAILS.md path is a positional ``[PATH]`` argument (default
    ``./AGIRAILS.md``), while the legacy ``--path`` option still works.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.config.on_chain_state import OnChainConfigState, ZERO_HASH
from agirails.config.sync_operations import DiffResult, DiffStatus, PullResult

runner = CliRunner()

ADDR = "0x" + "1" * 40


def _empty_on_chain() -> OnChainConfigState:
    return OnChainConfigState(config_hash=ZERO_HASH, config_cid="")


def _diff_result() -> DiffResult:
    return DiffResult(
        in_sync=False,
        local_hash=None,
        on_chain_hash=ZERO_HASH,
        on_chain_cid="",
        has_on_chain_config=False,
        has_local_file=False,
        status=DiffStatus.NO_LOCAL,
    )


# ============================================================================
# diff
# ============================================================================


class TestDiffArgs:
    def test_default_network_is_base_sepolia(self) -> None:
        captured = {}

        def _fake_reader(addr, network, rpc_url=None):
            captured["network"] = network
            return _empty_on_chain()

        with patch(
            "agirails.cli.commands.diff.get_on_chain_config_state",
            side_effect=_fake_reader,
        ), patch(
            "agirails.cli.commands.diff.diff_config",
            return_value=_diff_result(),
        ):
            result = runner.invoke(app, ["diff", "--address", ADDR])
        assert result.exit_code == 0, result.stdout
        assert captured["network"] == "base-sepolia"

    def test_positional_path_is_accepted(self) -> None:
        captured = {}

        def _fake_diff(path, on_chain):
            captured["path"] = path
            return _diff_result()

        with patch(
            "agirails.cli.commands.diff.get_on_chain_config_state",
            return_value=_empty_on_chain(),
        ), patch(
            "agirails.cli.commands.diff.diff_config",
            side_effect=_fake_diff,
        ):
            result = runner.invoke(
                app, ["diff", "custom/path/AGIRAILS.md", "--address", ADDR]
            )
        assert result.exit_code == 0, result.stdout
        assert captured["path"] == "custom/path/AGIRAILS.md"

    def test_path_option_overrides_positional(self) -> None:
        captured = {}

        def _fake_diff(path, on_chain):
            captured["path"] = path
            return _diff_result()

        with patch(
            "agirails.cli.commands.diff.get_on_chain_config_state",
            return_value=_empty_on_chain(),
        ), patch(
            "agirails.cli.commands.diff.diff_config",
            side_effect=_fake_diff,
        ):
            result = runner.invoke(
                app,
                ["diff", "positional.md", "--path", "option.md", "--address", ADDR],
            )
        assert result.exit_code == 0, result.stdout
        assert captured["path"] == "option.md"


# ============================================================================
# pull
# ============================================================================


class TestPullArgs:
    def test_default_network_is_base_sepolia(self) -> None:
        captured = {}

        def _fake_reader(addr, network, rpc_url=None):
            captured["network"] = network
            return _empty_on_chain()

        with patch(
            "agirails.cli.commands.pull.get_on_chain_config_state",
            side_effect=_fake_reader,
        ), patch(
            "agirails.cli.commands.pull.pull_config",
            return_value=PullResult(written=False, status="up-to-date"),
        ):
            result = runner.invoke(app, ["pull", "--force", "--address", ADDR])
        assert result.exit_code == 0, result.stdout
        assert captured["network"] == "base-sepolia"

    def test_positional_path_is_accepted(self) -> None:
        captured = {}

        def _fake_pull(path, on_chain, force=False):
            captured["path"] = path
            return PullResult(written=False, status="up-to-date")

        with patch(
            "agirails.cli.commands.pull.get_on_chain_config_state",
            return_value=_empty_on_chain(),
        ), patch(
            "agirails.cli.commands.pull.pull_config",
            side_effect=_fake_pull,
        ):
            result = runner.invoke(
                app,
                ["pull", "out/AGIRAILS.md", "--force", "--address", ADDR],
            )
        assert result.exit_code == 0, result.stdout
        assert captured["path"] == "out/AGIRAILS.md"
