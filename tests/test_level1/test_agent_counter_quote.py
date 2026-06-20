"""Parity tests for the Agent counter-offer QUOTED anchoring seam.

P1 parity (TS Agent.ts:1504-1565): when a pricing strategy decides
"counter-offer", the Agent must ANCHOR the provider's ideal price as a QUOTED
transition on-chain — either via the injected ProviderOrchestrator
(runtime.submit_quote, canonical AIP-2 QuoteMessage) OR the legacy ad-hoc
keccak256 hash transition — not silently no-op.

Agent.__init__ constructs asyncio primitives; tests are async so an event loop
exists (same constraint as the sibling level1 tests).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from eth_hash.auto import keccak

from agirails.level1.agent import Agent
from agirails.level1.config import AgentConfig, ServiceConfig
from agirails.level1.job import Job
from agirails.level1.pricing import CostModel, PricingStrategy


def _job(budget: float = 1.5, service: str = "echo") -> Job:
    return Job(
        id="0x" + "ab" * 32,
        service=service,
        input={},
        budget=budget,
        deadline=datetime.now() + timedelta(hours=1),
        requester="0x" + "12" * 20,
    )


def _tx(amount: str = "1500000", tx_id: str = "0x" + "ab" * 32):
    return SimpleNamespace(
        id=tx_id,
        amount=amount,
        requester="0x" + "12" * 20,
        deadline=int((datetime.now() + timedelta(hours=1)).timestamp()),
        service_description="",
        dispute_window=172800,
    )


def _counter_offer_agent() -> Agent:
    agent = Agent(AgentConfig(name="agent"))

    async def h(job, ctx):
        return {}

    # budget 1.50 is above cost 1.00 but below price 2.00 → counter-offer.
    agent.provide(
        ServiceConfig(
            name="echo",
            pricing=PricingStrategy(
                cost=CostModel(base=1.0),
                margin=0.5,  # price = 1.0 / 0.5 = 2.00
                below_price="counter-offer",
            ),
        ),
        handler=h,
    )
    return agent


class _FakeStandard:
    def __init__(self) -> None:
        self.calls: list = []

    async def transition_state(self, tx_id, new_state, proof=None):
        self.calls.append((tx_id, new_state, proof))


class _FakeClient:
    def __init__(self, chain_id: int = 84532) -> None:
        self.standard = _FakeStandard()
        self.runtime = SimpleNamespace(config=SimpleNamespace(chain_id=chain_id))


class _RecordingOrchestrator:
    """Captures the IncomingRequest + provider DID handed to quote()."""

    def __init__(self) -> None:
        self.calls: list = []

    async def quote(self, req, provider_did):
        self.calls.append((req, provider_did))
        decision = SimpleNamespace(action="quote", reason="ok")
        return SimpleNamespace(decision=decision, quote=object(), channel_error=None)


# ---------------------------------------------------------------------------
# Legacy hash path (no orchestrator configured)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_counter_offer_anchors_legacy_quoted_hash() -> None:
    agent = _counter_offer_agent()
    agent._client = _FakeClient()  # type: ignore[assignment]

    accepted = await agent._should_auto_accept(
        _job(), agent._services["echo"], _tx()
    )
    assert accepted is False

    calls = agent._client.standard.calls  # type: ignore[union-attr]
    assert len(calls) == 1
    tx_id, new_state, proof = calls[0]
    assert tx_id == "0x" + "ab" * 32
    assert new_state == "QUOTED"
    assert isinstance(proof, str) and proof.startswith("0x")
    # 32-byte ABI-encoded bytes32 proof → 0x + 64 hex chars.
    assert len(proof) == 66


@pytest.mark.asyncio
async def test_legacy_hash_is_byte_identical_to_ts_shape() -> None:
    agent = _counter_offer_agent()
    client = _FakeClient()
    agent._client = client  # type: ignore[assignment]

    await agent._should_auto_accept(_job(), agent._services["echo"], _tx())

    _, _, proof = client.standard.calls[0]
    # Reconstruct the canonical TS JSON.stringify shape:
    # {txId, providerIdealPrice, actualEscrow, provider}. price = 2.00 → 2_000_000.
    expected_json = json.dumps(
        {
            "txId": "0x" + "ab" * 32,
            "providerIdealPrice": "2000000",
            "actualEscrow": "1500000",
            "provider": agent.address,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected_hash = "0x" + keccak(expected_json.encode("utf-8")).hex()
    # proof is the bytes32 ABI-encoding of the hash → the trailing 32 bytes
    # equal the hash bytes.
    assert proof[2:] == expected_hash[2:]


@pytest.mark.asyncio
async def test_counter_offer_with_no_client_is_noop() -> None:
    # Guard: no client → cannot transition. Must not raise.
    agent = _counter_offer_agent()
    agent._client = None
    accepted = await agent._should_auto_accept(
        _job(), agent._services["echo"], _tx()
    )
    assert accepted is False


# ---------------------------------------------------------------------------
# Orchestrator path (BYO-brain seam)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_counter_offer_routes_through_orchestrator() -> None:
    agent = _counter_offer_agent()
    client = _FakeClient(chain_id=8453)
    agent._client = client  # type: ignore[assignment]
    orch = _RecordingOrchestrator()
    agent.set_provider_orchestrator(orch)

    accepted = await agent._should_auto_accept(
        _job(), agent._services["echo"], _tx()
    )
    assert accepted is False

    # Orchestrator was consulted; legacy transition_state was NOT used.
    assert client.standard.calls == []
    assert len(orch.calls) == 1
    req, provider_did = orch.calls[0]
    assert req.tx_id == "0x" + "ab" * 32
    assert req.consumer == f"did:ethr:8453:{'0x' + '12' * 20}"
    assert req.offered_amount == "1500000"
    # max_price set to provider ideal price ($2.00) so the band check passes.
    assert req.max_price == "2000000"
    assert req.service_type == "echo"
    assert req.currency == "USDC"
    assert provider_did == f"did:ethr:8453:{agent.address}"


@pytest.mark.asyncio
async def test_orchestrator_failure_is_swallowed() -> None:
    agent = _counter_offer_agent()
    agent._client = _FakeClient()  # type: ignore[assignment]

    class _BoomOrchestrator:
        async def quote(self, req, provider_did):
            raise RuntimeError("orchestrator down")

    agent.set_provider_orchestrator(_BoomOrchestrator())
    # Must not raise out of the decision path.
    accepted = await agent._should_auto_accept(
        _job(), agent._services["echo"], _tx()
    )
    assert accepted is False


@pytest.mark.asyncio
async def test_find_service_type_for_tx_fallbacks() -> None:
    agent = Agent(AgentConfig(name="agent"))
    # No services → 'general'.
    assert agent._find_service_type_for_tx(_tx()) == "general"

    async def h(job, ctx):
        return {}

    agent.provide(ServiceConfig(name="alpha"), handler=h)
    # Unrouted tx (empty service_description) with one registered service →
    # falls back to the first registered name.
    assert agent._find_service_type_for_tx(_tx()) == "alpha"
