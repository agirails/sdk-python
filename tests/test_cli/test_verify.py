"""Tests for ``actp verify`` command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.config.on_chain_state import OnChainConfigState, ZERO_HASH

runner = CliRunner()


MINIMAL_MD = """\
---
name: Test Agent
slug: test-agent
description: An agent under test.
mode: testnet
wallet: "0x1234567890123456789012345678901234567890"
---

# Test Agent
"""


@pytest.fixture
def md_on_disk(tmp_path: Path) -> Path:
    md = tmp_path / "AGIRAILS.md"
    md.write_text(MINIMAL_MD, encoding="utf-8")
    return md


def _hash_for(content: str) -> str:
    from agirails.config.agirailsmd import compute_config_hash
    return compute_config_hash(content).config_hash


# ============================================================================
# Input routing
# ============================================================================


class TestInputRouting:
    def test_reads_file(self, md_on_disk: Path):
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid=""
            ),
        ):
            result = runner.invoke(app, ["verify", str(md_on_disk), "--json"])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["valid"] is True
        assert body["trustTier"] == "chain-verified"

    def test_missing_file_errors(self):
        result = runner.invoke(app, ["verify", "/no/such/file.md"])
        assert result.exit_code != 0

    def test_empty_stdin_errors(self):
        result = runner.invoke(app, ["verify", "-"], input="")
        assert result.exit_code == 2
        assert "No input" in result.output

    @respx.mock
    def test_reads_url(self):
        respx.get("https://example.com/agent.md").mock(
            return_value=httpx.Response(200, text=MINIMAL_MD)
        )
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid=""
            ),
        ):
            result = runner.invoke(
                app, ["verify", "https://example.com/agent.md", "--json"]
            )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["trustTier"] == "chain-verified"


# ============================================================================
# On-chain matching
# ============================================================================


class TestOnChainMatching:
    def test_published_when_chain_is_zero(self, md_on_disk: Path):
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=ZERO_HASH, config_cid=""
            ),
        ):
            result = runner.invoke(app, ["verify", str(md_on_disk), "--json"])
        body = json.loads(result.output)
        assert body["trustTier"] == "published"
        assert body["valid"] is True

    def test_mismatch_makes_invalid_and_exit_nonzero(self, md_on_disk: Path):
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash="0x" + "1" * 64,  # not matching local
                config_cid="",
            ),
        ):
            result = runner.invoke(app, ["verify", str(md_on_disk), "--json"])
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["valid"] is False
        assert body["onChain"]["match"] is False

    def test_unverified_when_no_wallet_and_no_address(self, tmp_path: Path):
        md = tmp_path / "AGIRAILS.md"
        md.write_text(
            "---\nname: A\nslug: a\n---\n\nbody\n", encoding="utf-8"
        )
        result = runner.invoke(app, ["verify", str(md), "--json"])
        body = json.loads(result.output)
        assert body["trustTier"] == "unverified"
        assert body["onChain"]["checked"] is False

    def test_address_override_used(self, md_on_disk: Path):
        captured: dict = {}

        def fake_state(*, address, network, rpc_url=None):
            captured["address"] = address
            return OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid=""
            )

        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            side_effect=fake_state,
        ):
            result = runner.invoke(
                app,
                [
                    "verify",
                    str(md_on_disk),
                    "--address",
                    "0xabcdef0123456789abcdef0123456789abcdef01",
                    "--json",
                ],
            )
        assert result.exit_code == 0
        # Override took precedence over the frontmatter wallet.
        assert (
            captured["address"]
            == "0xabcdef0123456789abcdef0123456789abcdef01"
        )


# ============================================================================
# IPFS verification
# ============================================================================


class TestIpfsVerification:
    @respx.mock
    def test_ipfs_match_when_gateway_returns_same_content(self, md_on_disk: Path):
        respx.get("https://ipfs.io/ipfs/bafyTest").mock(
            return_value=httpx.Response(200, text=MINIMAL_MD)
        )
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid="bafyTest"
            ),
        ):
            result = runner.invoke(
                app, ["verify", str(md_on_disk), "--json"]
            )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["ipfs"]["checked"] is True
        assert body["ipfs"]["match"] is True
        assert body["ipfs"]["cid"] == "bafyTest"

    @respx.mock
    def test_ipfs_failure_doesnt_invalidate_chain_match(self, md_on_disk: Path):
        # All gateways return 503.
        respx.get(url__regex=r"https://.*ipfs.*").mock(
            return_value=httpx.Response(503)
        )
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid="bafyXYZ"
            ),
        ):
            result = runner.invoke(
                app, ["verify", str(md_on_disk), "--json"]
            )
        # Chain matched → still valid, even if IPFS fetch fails.
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["valid"] is True
        assert body["ipfs"]["checked"] is True
        assert body["ipfs"]["match"] is False


# ============================================================================
# Reputation
# ============================================================================


class TestReputation:
    @respx.mock
    def test_reputation_fetch_included(self, md_on_disk: Path):
        respx.get(
            "https://agirails.app/a/test-agent/test-agent.reputation.json"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "reputation_score": 87,
                    "completed_transactions": 42,
                    "success_rate": 95.2,
                    "total_volume_usdc": "1234.56",
                },
            )
        )
        with patch(
            "agirails.cli.commands.verify.get_on_chain_config_state",
            return_value=OnChainConfigState(
                config_hash=_hash_for(MINIMAL_MD), config_cid=""
            ),
        ):
            result = runner.invoke(
                app,
                ["verify", str(md_on_disk), "--reputation", "--json"],
            )
        body = json.loads(result.output)
        assert body["reputation"]["score"] == 87
        assert body["reputation"]["completed"] == 42
        assert body["reputation"]["volume"] == "1234.56"
