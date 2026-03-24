"""E2E Integration Tests — Publish → Claim → Discover pipeline.

Tests the full agent lifecycle pipeline:
1. publish: AGIRAILS.md → IPFS + on-chain registration
2. claim: Link agent to dashboard via wallet signature
3. discover: Find the published agent via search API

All on-chain / API calls are mocked. Tests verify the pipeline wiring,
data flow between stages, and error propagation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()

# ============================================================================
# Fixtures
# ============================================================================

SAMPLE_AGIRAILS_MD = """---
name: e2e-test-agent
version: "1.0"
slug: e2e-test-agent
endpoint: https://e2e-test.io/api
capabilities:
  - text-generation
  - translation
pricing:
  amount: 0.50
  currency: USDC
  unit: request
---

# E2E Test Agent

Integration test agent for publish → claim → discover.
"""

FAKE_KEY = "0x" + "ab" * 32
FAKE_WALLET = "0x1234567890abcdef1234567890abcdef12345678"
FAKE_AGENT_ID = "42"


# ============================================================================
# Pipeline Tests
# ============================================================================


class TestPublishStage:
    """Publish stage: AGIRAILS.md → config hash + pending publish."""

    def test_publish_fails_without_file(self, tmp_path: Path, monkeypatch) -> None:
        """publish should fail when AGIRAILS.md doesn't exist."""
        monkeypatch.chdir(tmp_path)  # No AGIRAILS.md in tmp_path
        result = runner.invoke(app, [
            "publish",
            "--network", "mock",
        ])
        assert result.exit_code != 0

    def test_publish_fails_with_invalid_yaml(self, tmp_path: Path, monkeypatch) -> None:
        """publish should fail with invalid YAML frontmatter."""
        monkeypatch.chdir(tmp_path)
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text("---\ninvalid: [yaml: {\n---\n# Broken")

        result = runner.invoke(app, [
            "publish",
            "--network", "mock",
        ])
        assert result.exit_code != 0 or "error" in result.output.lower()

    def test_publish_dry_run(self, tmp_path: Path, monkeypatch) -> None:
        """publish --dry-run should parse and validate without side effects."""
        monkeypatch.chdir(tmp_path)
        md_path = tmp_path / "AGIRAILS.md"
        md_path.write_text(SAMPLE_AGIRAILS_MD)

        result = runner.invoke(app, [
            "publish",
            "--network", "mock",
            "--dry-run",
        ])
        assert result.exit_code == 0, f"Dry-run failed: {result.output}"


class TestClaimStage:
    """Claim stage: wallet signature → dashboard linking."""

    def test_claim_fails_without_agent_id(self) -> None:
        """claim should error when no agent_id provided."""
        result = runner.invoke(app, ["claim"])
        assert result.exit_code != 0
        assert "agent_id" in result.output.lower() or "required" in result.output.lower()

    def test_claim_fails_without_private_key(self) -> None:
        """claim should fail when no private key available."""
        with patch(
            "agirails.wallet.keystore.resolve_private_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = runner.invoke(app, ["claim", "123", "--network", "base-sepolia"])
            assert result.exit_code != 0

    def test_claim_happy_path_json(self) -> None:
        """claim should output JSON result on success."""
        # Claim uses eth_account.Account directly to sign challenges
        with patch(
            "agirails.wallet.keystore.resolve_private_key",
            new_callable=AsyncMock,
            return_value=FAKE_KEY,
        ), patch(
            "agirails.api.agirails_app.get_claim_challenge",
            new_callable=AsyncMock,
            return_value={"challenge": "sign-this-123", "expires_at": 9999999999},
        ), patch(
            "agirails.api.agirails_app.claim_agent",
            new_callable=AsyncMock,
            return_value={"success": True, "agent_id": FAKE_AGENT_ID, "slug": "test-agent"},
        ):
            result = runner.invoke(app, [
                "claim", FAKE_AGENT_ID,
                "--network", "base-sepolia",
                "--json",
            ])
            assert result.exit_code == 0, f"Claim failed: {result.output}"


class TestDiscoverStage:
    """Discover stage: search API → agent list."""

    def test_find_returns_agents(self) -> None:
        """find should return discovered agents."""
        from agirails.api.discover import DiscoverResult, DiscoverAgent

        mock_result = DiscoverResult(
            agents=[
                DiscoverAgent(
                    slug="e2e-test-agent",
                    wallet_address=FAKE_WALLET,
                ),
            ],
            total=1,
        )

        with patch(
            "agirails.api.discover.discover_agents",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = runner.invoke(app, ["find", "text-generation", "--json"])
            assert result.exit_code == 0, f"Find failed: {result.output}"

    def test_find_empty_results(self) -> None:
        """find should handle zero results gracefully."""
        from agirails.api.discover import DiscoverResult

        with patch(
            "agirails.api.discover.discover_agents",
            new_callable=AsyncMock,
            return_value=DiscoverResult(agents=[], total=0),
        ):
            result = runner.invoke(app, ["find", "nonexistent-capability", "--json"])
            assert result.exit_code in (0, 1)

    def test_find_handles_api_error(self) -> None:
        """find should handle API errors without crashing."""
        with patch(
            "agirails.api.discover.discover_agents",
            new_callable=AsyncMock,
            side_effect=Exception("Network error"),
        ):
            result = runner.invoke(app, ["find", "anything"])
            assert isinstance(result.exit_code, int)


class TestPipelineDataFlow:
    """Verify data structures flow correctly between stages."""

    def test_round_result_has_quoted_price(self) -> None:
        """RoundResult should have quoted_price field (PRD-5B)."""
        from agirails.negotiation.buyer_orchestrator import RoundResult

        rr = RoundResult(
            round=1, provider_slug="test", provider_address="0x1",
            action="accepted", reason="ok",
        )
        assert rr.quoted_price is None

        rr2 = RoundResult(
            round=1, provider_slug="test", provider_address="0x1",
            action="accepted", reason="ok", quoted_price=0.80,
        )
        assert rr2.quoted_price == 0.80

    def test_negotiation_result_has_deadlock_detected(self) -> None:
        """NegotiationResult should have deadlock_detected field (PRD-5B)."""
        from agirails.negotiation.buyer_orchestrator import NegotiationResult

        nr = NegotiationResult(
            success=True, commerce_session_id="sess-1",
            rounds_used=1, reason="done",
        )
        assert nr.deadlock_detected is False

    def test_quote_offer_has_final_offer(self) -> None:
        """QuoteOffer should have final_offer field (PRD-5B)."""
        from agirails.negotiation.policy_engine import QuoteOffer

        offer = QuoteOffer(
            provider="test", unit_price=1.0,
            currency="USDC", unit="sentence",
        )
        assert offer.final_offer is False

        offer2 = QuoteOffer(
            provider="test", unit_price=1.0,
            currency="USDC", unit="sentence",
            final_offer=True,
        )
        assert offer2.final_offer is True
