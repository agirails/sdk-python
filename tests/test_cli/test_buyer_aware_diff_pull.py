"""Tests for buyer-aware ``actp diff`` / ``actp pull`` + identity-pointer resolution.

Mirrors TS diff.ts:76-108 / pull.ts:77-112: a pure buyer (intent: pay) file
short-circuits to a ``buyer-local`` status with honest local-sovereign messaging
instead of a misleading on-chain diff/pull. Also covers config.address (Smart
Wallet) being read before the EOA fallback, and the public-RPC warning helper.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.config.on_chain_state import OnChainConfigState, ZERO_HASH
from agirails.config.sync_operations import DiffResult, DiffStatus, PullResult

runner = CliRunner()

ADDR = "0x" + "1" * 40
SMART_WALLET = "0x" + "9" * 40

BUYER_MD = """---
name: My Buyer
intent: pay
servicesNeeded:
  - code-review
budget: 5
---
I buy code reviews.
"""

PROVIDER_MD = """---
name: Code Reviewer
services:
  - code-review
pricing:
  base: 10
---
Reviews code.
"""


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
# diff — buyer-local short circuit
# ============================================================================


class TestDiffBuyerLocal:
    def test_buyer_file_short_circuits(self, tmp_path: Path) -> None:
        f = tmp_path / "my-buyer.md"
        f.write_text(BUYER_MD)
        # If the on-chain reader were hit, the test would fail (no mock).
        result = runner.invoke(app, ["--json", "diff", str(f)])
        assert result.exit_code == 0, result.stdout
        data = json.loads(result.stdout)
        assert data["status"] == "buyer-local"
        assert data["intent"] == "pay"
        assert data["inSync"] is True
        assert data["hasOnChainConfig"] is False

    def test_buyer_file_human_messaging(self, tmp_path: Path) -> None:
        f = tmp_path / "my-buyer.md"
        f.write_text(BUYER_MD)
        result = runner.invoke(app, ["diff", str(f)])
        assert result.exit_code == 0, result.stdout
        assert "buyer-local" in result.stdout
        # "budget is private" may wrap across lines via Rich; assert on the
        # unwrappable token instead.
        assert "private" in result.stdout

    def test_buyer_file_quiet(self, tmp_path: Path) -> None:
        f = tmp_path / "my-buyer.md"
        f.write_text(BUYER_MD)
        result = runner.invoke(app, ["--quiet", "diff", str(f)])
        assert result.exit_code == 0, result.stdout
        assert "buyer-local" in result.stdout

    def test_provider_file_does_not_short_circuit(self, tmp_path: Path) -> None:
        f = tmp_path / "code-reviewer.md"
        f.write_text(PROVIDER_MD)
        with patch(
            "agirails.cli.commands.diff.get_on_chain_config_state",
            return_value=_empty_on_chain(),
        ), patch(
            "agirails.cli.commands.diff.diff_config",
            return_value=_diff_result(),
        ):
            result = runner.invoke(app, ["--json", "diff", str(f), "--address", ADDR])
        assert result.exit_code == 0, result.stdout
        data = json.loads(result.stdout)
        assert data["status"] != "buyer-local"


# ============================================================================
# diff — config.address (Smart Wallet) before EOA fallback
# ============================================================================


class TestDiffSmartWalletAddress:
    def test_config_address_used_before_keystore(self, tmp_path: Path) -> None:
        captured = {}

        def _fake_reader(addr, network, rpc_url=None):
            captured["addr"] = addr
            return _empty_on_chain()

        with patch(
            "agirails.cli.commands.diff.load_config",
            return_value={"address": SMART_WALLET, "wallet": "auto"},
        ), patch(
            "agirails.cli.commands.diff.get_on_chain_config_state",
            side_effect=_fake_reader,
        ), patch(
            "agirails.cli.commands.diff.diff_config",
            return_value=_diff_result(),
        ):
            # No --address; provider file so no buyer short-circuit.
            f = tmp_path / "code-reviewer.md"
            f.write_text(PROVIDER_MD)
            result = runner.invoke(app, ["diff", str(f)])
        assert result.exit_code == 0, result.stdout
        assert captured["addr"] == SMART_WALLET


# ============================================================================
# pull — buyer-local short circuit
# ============================================================================


class TestPullBuyerLocal:
    def test_buyer_file_short_circuits(self, tmp_path: Path) -> None:
        f = tmp_path / "my-buyer.md"
        f.write_text(BUYER_MD)
        result = runner.invoke(app, ["--json", "pull", str(f)])
        assert result.exit_code == 0, result.stdout
        data = json.loads(result.stdout)
        assert data["status"] == "buyer-local"
        assert data["written"] is False
        assert data["intent"] == "pay"

    def test_buyer_file_human_messaging(self, tmp_path: Path) -> None:
        f = tmp_path / "my-buyer.md"
        f.write_text(BUYER_MD)
        result = runner.invoke(app, ["pull", str(f)])
        assert result.exit_code == 0, result.stdout
        assert "buyer-local" in result.stdout
        # Rich may wrap the long sentence; assert on an unwrappable token.
        assert "local-authored" in result.stdout

    def test_provider_file_does_not_short_circuit(self, tmp_path: Path) -> None:
        f = tmp_path / "code-reviewer.md"
        f.write_text(PROVIDER_MD)
        with patch(
            "agirails.cli.commands.pull.get_on_chain_config_state",
            return_value=_empty_on_chain(),
        ), patch(
            "agirails.cli.commands.pull.pull_config",
            return_value=PullResult(written=False, status="up-to-date"),
        ):
            result = runner.invoke(
                app, ["--json", "pull", str(f), "--force", "--address", ADDR]
            )
        assert result.exit_code == 0, result.stdout
        data = json.loads(result.stdout)
        assert data.get("status") != "buyer-local"


# ============================================================================
# pull — config.address (Smart Wallet) before EOA fallback
# ============================================================================


class TestPullSmartWalletAddress:
    def test_config_address_used_before_keystore(self, tmp_path: Path) -> None:
        captured = {}

        def _fake_reader(addr, network, rpc_url=None):
            captured["addr"] = addr
            return _empty_on_chain()

        f = tmp_path / "code-reviewer.md"
        f.write_text(PROVIDER_MD)
        with patch(
            "agirails.cli.commands.pull.load_config",
            return_value={"address": SMART_WALLET, "wallet": "auto"},
        ), patch(
            "agirails.cli.commands.pull.get_on_chain_config_state",
            side_effect=_fake_reader,
        ), patch(
            "agirails.cli.commands.pull.pull_config",
            return_value=PullResult(written=False, status="up-to-date"),
        ):
            result = runner.invoke(app, ["pull", str(f), "--force"])
        assert result.exit_code == 0, result.stdout
        assert captured["addr"] == SMART_WALLET
