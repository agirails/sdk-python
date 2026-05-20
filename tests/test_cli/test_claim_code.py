"""Tests for ``actp claim-code`` command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()


AGIRAILS_MD_WITH_AGENT_ID = """\
---
agent_id: 12345
name: Test Agent
slug: test-agent
description: An agent under test.
mode: testnet
---

# Test Agent
"""

AGIRAILS_MD_WITHOUT_AGENT_ID = """\
---
name: Test Agent
slug: test-agent
description: An agent that hasn't been published yet.
---

# Test Agent
"""

FAKE_PRIVATE_KEY = "0x" + "ab" * 32


@pytest.fixture
def temp_agirails_md(tmp_path: Path) -> Path:
    """A tmpdir-scoped AGIRAILS.md with a real agent_id."""
    md = tmp_path / "AGIRAILS.md"
    md.write_text(AGIRAILS_MD_WITH_AGENT_ID, encoding="utf-8")
    return md


class TestClaimCodeCommand:
    def test_errors_when_file_missing(self, tmp_path: Path):
        # No AGIRAILS.md anywhere; pointer at a non-existent path.
        result = runner.invoke(
            app, ["claim-code", str(tmp_path / "missing.md")]
        )
        assert result.exit_code == 2
        assert "not found" in result.output

    def test_errors_when_no_agent_id_in_frontmatter(self, tmp_path: Path):
        md = tmp_path / "AGIRAILS.md"
        md.write_text(AGIRAILS_MD_WITHOUT_AGENT_ID, encoding="utf-8")
        result = runner.invoke(app, ["claim-code", str(md)])
        assert result.exit_code == 2
        assert "No agent_id" in result.output

    def test_errors_when_no_keystore(self, temp_agirails_md):
        with patch(
            "agirails.cli.commands.claim_code.resolve_private_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = runner.invoke(
                app, ["claim-code", str(temp_agirails_md), "--json"]
            )
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["ok"] is False
        assert "wallet credentials" in body["error"].lower()

    def test_happy_path_json(self, temp_agirails_md):
        """End-to-end with mocked keystore + API."""
        captured: dict = {}

        async def fake_request_claim_code(params):
            captured["params"] = params
            return {"claimCode": "ABCD-1234"}

        with patch(
            "agirails.cli.commands.claim_code.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.claim_code.request_claim_code",
            side_effect=fake_request_claim_code,
        ):
            result = runner.invoke(
                app, ["claim-code", str(temp_agirails_md), "--json"]
            )

        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["ok"] is True
        assert body["claimCode"] == "ABCD-1234"
        assert body["claimUrl"] == "https://agirails.app/claim?code=ABCD-1234"
        assert body["agentId"] == "12345"

        params = captured["params"]
        # Wire payload was built with the right shape.
        assert params.agent_id == "12345"
        # Default network is testnet → base-sepolia.
        assert params.network == "base-sepolia"
        # Signature has the right length (132 chars w/ 0x prefix).
        assert params.signature.startswith("0x") and len(params.signature) == 132
        # Message includes the agent id and chain name.
        assert "agirails-claim-code:12345:base-sepolia:" in params.message

    def test_quiet_mode_emits_only_code(self, temp_agirails_md):
        with patch(
            "agirails.cli.commands.claim_code.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.claim_code.request_claim_code",
            new_callable=AsyncMock,
            return_value={"claimCode": "WXYZ-9999"},
        ):
            result = runner.invoke(
                app, ["claim-code", str(temp_agirails_md), "--quiet"]
            )
        assert result.exit_code == 0
        # In quiet mode, output is just the code (plus trailing newline).
        assert result.output.strip() == "WXYZ-9999"

    def test_smart_wallet_signer_field_set_when_wallet_differs(self, tmp_path: Path):
        """When AGIRAILS.md declares a wallet != signer EOA, both addresses
        ship to the server."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(
            """---
agent_id: 99
wallet: "0x1234567890123456789012345678901234567890"
---

# Agent
""",
            encoding="utf-8",
        )

        captured: dict = {}

        async def fake_request_claim_code(params):
            captured["params"] = params
            return {"claimCode": "SW-1"}

        with patch(
            "agirails.cli.commands.claim_code.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_PRIVATE_KEY,
        ), patch(
            "agirails.cli.commands.claim_code.request_claim_code",
            side_effect=fake_request_claim_code,
        ):
            result = runner.invoke(
                app, ["claim-code", str(md), "--json"]
            )

        assert result.exit_code == 0
        params = captured["params"]
        assert params.wallet.lower() == "0x1234567890123456789012345678901234567890"
        # signer = the EOA recovered from the private key (lowercase compare)
        assert params.signer is not None
        assert (
            params.signer.lower()
            != "0x1234567890123456789012345678901234567890"
        )
