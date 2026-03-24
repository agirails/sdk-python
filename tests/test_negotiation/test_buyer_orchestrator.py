"""Tests for BuyerOrchestrator — deadlock detection (PRD-5B)."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from agirails.negotiation.buyer_orchestrator import (
    BuyerOrchestrator,
    NegotiationResult,
    OrchestratorConfig,
    RoundResult,
)
from agirails.negotiation.policy_engine import (
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    Selection,
)
from agirails.runtime.base import CreateTransactionParams


# ============================================================================
# Fixtures
# ============================================================================


def make_policy(rounds_max: int = 3, quote_ttl: str = "5s") -> BuyerPolicy:
    return BuyerPolicy(
        task="translation.fr_en",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=1.0, currency="USDC", unit="sentence"),
            max_daily_spend=MaxDailySpend(amount=100.0, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=rounds_max, quote_ttl=quote_ttl),
        selection=Selection(
            min_reputation=50,
            prioritize=["quality", "price"],
        ),
    )


def mock_agent(slug: str, price: float, reputation: float, address: str) -> dict:
    return {
        "slug": slug,
        "wallet_address": address,
        "published_config": {
            "pricing": {"amount": price, "currency": "USDC", "unit": "sentence"},
        },
        "stats": {
            "reputation_score": reputation,
            "completed_transactions": 10,
            "failed_transactions": 0,
            "success_rate": 95,
            "total_gmv_usdc": "100",
            "avg_completion_time_seconds": 60,
        },
    }


class MockTransaction:
    def __init__(self, tx_id: str, state: str, amount: int, **kwargs: Any):
        self.id = tx_id
        self.state = state
        self.amount = amount
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockRuntime:
    """Simple mock runtime for testing."""

    def __init__(self) -> None:
        self._transactions: Dict[str, MockTransaction] = {}
        self._counter = 0
        self._link_escrow_calls = 0
        self._link_escrow_fail_until = 0

    async def create_transaction(self, params: CreateTransactionParams) -> str:
        self._counter += 1
        tx_id = f"0x{self._counter:064d}"
        amount = int(params.amount) if isinstance(params.amount, str) else params.amount
        self._transactions[tx_id] = MockTransaction(
            tx_id=tx_id,
            state="INITIATED",
            amount=amount,
            provider=params.provider,
            requester=params.requester,
        )
        return tx_id

    async def link_escrow(self, tx_id: str, amount: str) -> str:
        self._link_escrow_calls += 1
        if self._link_escrow_calls <= self._link_escrow_fail_until:
            raise RuntimeError("Simulated escrow failure")
        tx = self._transactions.get(tx_id)
        if tx:
            tx.state = "COMMITTED"
        return tx_id

    async def transition_state(self, tx_id: str, new_state: str, proof: str = "") -> None:
        tx = self._transactions.get(tx_id)
        if tx:
            tx.state = new_state

    async def get_transaction(self, tx_id: str) -> Optional[MockTransaction]:
        return self._transactions.get(tx_id)

    async def get_all_transactions(self) -> List[MockTransaction]:
        return list(self._transactions.values())

    async def release_escrow(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def get_escrow_balance(self, *args: Any, **kwargs: Any) -> str:
        return "0"

    @property
    def time(self) -> Any:
        class T:
            @staticmethod
            def now() -> int:
                return int(time.time())
        return T()

    def set_auto_quote(self, enabled: bool = True) -> None:
        """Make all newly created transactions auto-transition to QUOTED."""
        if enabled:
            orig = self.create_transaction

            async def auto_quote(params: CreateTransactionParams) -> str:
                tx_id = await orig(params)
                self._transactions[tx_id].state = "QUOTED"
                return tx_id

            self.create_transaction = auto_quote  # type: ignore


# Mock discover API
def make_discover_mock(agents: List[dict]):
    """Create a mock for discover_agents that returns given agents."""

    @dataclass
    class MockDiscoverResult:
        agents: list
        total: int

    async def mock_discover(*args: Any, **kwargs: Any) -> MockDiscoverResult:
        # Convert dicts to objects with attribute access
        result_agents = []
        for a in agents:
            agent = type("Agent", (), {})()
            agent.slug = a["slug"]
            agent.wallet_address = a["wallet_address"]

            pc = type("PC", (), {})()
            pricing = type("Pricing", (), {})()
            pricing.amount = a["published_config"]["pricing"]["amount"]
            pricing.currency = a["published_config"]["pricing"]["currency"]
            pricing.unit = a["published_config"]["pricing"]["unit"]
            pc.pricing = pricing
            agent.published_config = pc

            stats = type("Stats", (), {})()
            s = a["stats"]
            stats.reputation_score = s["reputation_score"]
            stats.completed_transactions = s["completed_transactions"]
            stats.failed_transactions = s.get("failed_transactions", 0)
            stats.success_rate = s["success_rate"]
            stats.total_gmv_usdc = s.get("total_gmv_usdc", "0")
            stats.avg_completion_time_seconds = s.get("avg_completion_time_seconds")
            agent.stats = stats

            result_agents.append(agent)

        return MockDiscoverResult(agents=result_agents, total=len(result_agents))

    return mock_discover


# ============================================================================
# Tests
# ============================================================================


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="orchestrator-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestDeadlockDetection:
    """PRD-5B: Deadlock detection tests."""

    @pytest.mark.asyncio
    async def test_quoted_price_tracked_on_accepted_round(self, tmp_dir: str):
        """quoted_price should be populated on accepted rounds."""
        agents = [mock_agent("agent-a", 0.80, 90, "0xA")]
        runtime = MockRuntime()
        runtime.set_auto_quote(True)

        with patch(
            "agirails.negotiation.buyer_orchestrator.discover_agents",
            make_discover_mock(agents),
        ):
            orchestrator = BuyerOrchestrator(
                make_policy(), runtime, "0xBuyer", tmp_dir
            )
            result = await orchestrator.negotiate(
                OrchestratorConfig(poll_interval_ms=50)
            )

        assert result.success is True
        assert result.rounds[0].quoted_price is not None
        assert isinstance(result.rounds[0].quoted_price, float)

    @pytest.mark.asyncio
    async def test_deadlock_detected_same_price(self, tmp_dir: str):
        """Deadlock detected when consecutive providers quote same price."""
        agents = [
            mock_agent("agent-a", 0.80, 90, "0xA"),
            mock_agent("agent-b", 0.80, 85, "0xB"),
        ]
        runtime = MockRuntime()
        runtime.set_auto_quote(True)
        runtime._link_escrow_fail_until = 1  # First escrow fails, second succeeds

        with patch(
            "agirails.negotiation.buyer_orchestrator.discover_agents",
            make_discover_mock(agents),
        ):
            orchestrator = BuyerOrchestrator(
                make_policy(), runtime, "0xBuyer", tmp_dir
            )
            result = await orchestrator.negotiate(
                OrchestratorConfig(poll_interval_ms=50)
            )

        assert result.success is True
        assert result.rounds_used == 2
        assert result.deadlock_detected is True
        assert result.rounds[0].quoted_price is not None
        assert result.rounds[1].quoted_price is not None

    @pytest.mark.asyncio
    async def test_no_deadlock_different_prices(self, tmp_dir: str):
        """No deadlock when providers quote different prices."""
        agents = [
            mock_agent("agent-cheap", 0.50, 90, "0xCheap"),
            mock_agent("agent-expensive", 0.80, 85, "0xExpensive"),
        ]
        runtime = MockRuntime()
        runtime.set_auto_quote(True)
        runtime._link_escrow_fail_until = 1

        with patch(
            "agirails.negotiation.buyer_orchestrator.discover_agents",
            make_discover_mock(agents),
        ):
            orchestrator = BuyerOrchestrator(
                make_policy(), runtime, "0xBuyer", tmp_dir
            )
            result = await orchestrator.negotiate(
                OrchestratorConfig(poll_interval_ms=50)
            )

        assert result.success is True
        assert result.deadlock_detected is False

    @pytest.mark.asyncio
    async def test_deadlock_in_failure_reason(self, tmp_dir: str):
        """Deadlock mentioned in reason when all candidates exhausted."""
        agents = [
            mock_agent("agent-a", 0.80, 90, "0xA"),
            mock_agent("agent-b", 0.80, 85, "0xB"),
        ]
        runtime = MockRuntime()
        runtime.set_auto_quote(True)
        # All escrows fail
        runtime._link_escrow_fail_until = 999

        with patch(
            "agirails.negotiation.buyer_orchestrator.discover_agents",
            make_discover_mock(agents),
        ):
            orchestrator = BuyerOrchestrator(
                make_policy(), runtime, "0xBuyer", tmp_dir
            )
            result = await orchestrator.negotiate(
                OrchestratorConfig(poll_interval_ms=50)
            )

        assert result.success is False
        assert result.deadlock_detected is True
        assert "price deadlock" in result.reason


    @pytest.mark.asyncio
    async def test_final_offer_set_on_deadlock(self, tmp_dir: str):
        """final_offer should be True on QuoteOffer when deadlock detected."""
        agents = [
            mock_agent("agent-a", 0.80, 90, "0xA"),
            mock_agent("agent-b", 0.80, 85, "0xB"),
            mock_agent("agent-c", 0.80, 80, "0xC"),
        ]
        runtime = MockRuntime()
        runtime.set_auto_quote(True)
        runtime._link_escrow_fail_until = 2  # First two escrows fail, third succeeds

        captured_offers = []
        original_validate = None

        with patch(
            "agirails.negotiation.buyer_orchestrator.discover_agents",
            make_discover_mock(agents),
        ):
            from agirails.negotiation.policy_engine import PolicyEngine

            original_validate = PolicyEngine.validate

            def spy_validate(self_pe, offer):
                captured_offers.append(offer)
                return original_validate(self_pe, offer)

            PolicyEngine.validate = spy_validate

            try:
                orchestrator = BuyerOrchestrator(
                    make_policy(rounds_max=5), runtime, "0xBuyer", tmp_dir
                )
                result = await orchestrator.negotiate(
                    OrchestratorConfig(poll_interval_ms=50)
                )
            finally:
                PolicyEngine.validate = original_validate

        assert result.success is True
        assert result.rounds_used == 3
        # First offer: no deadlock yet
        assert captured_offers[0].final_offer is False
        # Third offer: deadlock was detected after rounds 1+2 quoted same price
        assert captured_offers[2].final_offer is True


class TestQuoteOfferFinalOffer:
    """PRD-5B: final_offer field on QuoteOffer."""

    def test_final_offer_defaults_false(self):
        from agirails.negotiation.policy_engine import QuoteOffer

        offer = QuoteOffer(
            provider="test",
            unit_price=1.0,
            currency="USDC",
            unit="sentence",
        )
        assert offer.final_offer is False

    def test_final_offer_can_be_set(self):
        from agirails.negotiation.policy_engine import QuoteOffer

        offer = QuoteOffer(
            provider="test",
            unit_price=1.0,
            currency="USDC",
            unit="sentence",
            final_offer=True,
        )
        assert offer.final_offer is True
