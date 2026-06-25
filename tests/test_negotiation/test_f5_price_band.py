"""F-5: BuyerOrchestrator pre-escrow price-band check (parity with TS)."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from agirails.negotiation.buyer_orchestrator import BuyerOrchestrator
from agirails.negotiation.policy_engine import (
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    Selection,
)
from agirails.protocol.agent_registry import ServiceDescriptor


def _policy(task: str = "translation.fr_en") -> BuyerPolicy:
    return BuyerPolicy(
        task=task,
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=1.0, currency="USDC", unit="sentence"),
            max_daily_spend=MaxDailySpend(amount=100.0, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=3, quote_ttl="5s"),
        selection=Selection(min_reputation=50, prioritize=["quality", "price"]),
    )


class _FakeRegistry:
    """Minimal stand-in for AgentRegistry.get_service_descriptors."""

    def __init__(self, descriptors, raise_: bool = False) -> None:
        self._descriptors = descriptors
        self._raise = raise_

    async def get_service_descriptors(self, address: str):
        if self._raise:
            raise RuntimeError("rpc down")
        return self._descriptors


def _band(min_usd: float = 0.5, max_usd: float = 2.0, task: str = "translation.fr_en"):
    # service_type_hash is auto-computed from service_type in __post_init__
    return ServiceDescriptor(
        service_type=task,
        min_price=int(min_usd * 1_000_000),
        max_price=int(max_usd * 1_000_000),
    )


def _orch(tmp_path, agent_registry):
    return BuyerOrchestrator(
        policy=_policy(),
        runtime=Mock(),
        requester_address="0xBuyer",
        actp_dir=str(tmp_path),
        agent_registry=agent_registry,
    )


def _units(usd: float) -> str:
    return str(int(usd * 1_000_000))


@pytest.mark.asyncio
async def test_f5_in_band_allows(tmp_path):
    orch = _orch(tmp_path, _FakeRegistry([_band()]))
    allowed, reason = await orch._check_provider_price_band("0xP", _units(1.0))
    assert allowed is True
    assert reason is None


@pytest.mark.asyncio
async def test_f5_below_band_rejects(tmp_path):
    orch = _orch(tmp_path, _FakeRegistry([_band(min_usd=0.5)]))
    allowed, reason = await orch._check_provider_price_band("0xP", _units(0.10))
    assert allowed is False
    assert reason is not None and "price band" in reason


@pytest.mark.asyncio
async def test_f5_above_band_rejects(tmp_path):
    orch = _orch(tmp_path, _FakeRegistry([_band(max_usd=2.0)]))
    allowed, reason = await orch._check_provider_price_band("0xP", _units(5.0))
    assert allowed is False
    assert reason is not None and "price band" in reason


@pytest.mark.asyncio
async def test_f5_no_registry_fails_open(tmp_path):
    orch = _orch(tmp_path, None)
    allowed, reason = await orch._check_provider_price_band("0xP", _units(99.0))
    assert allowed is True
    assert reason is None


@pytest.mark.asyncio
async def test_f5_registry_read_error_fails_open(tmp_path):
    orch = _orch(tmp_path, _FakeRegistry([], raise_=True))
    allowed, reason = await orch._check_provider_price_band("0xP", _units(99.0))
    assert allowed is True
    assert reason is None


@pytest.mark.asyncio
async def test_f5_no_matching_descriptor_fails_open(tmp_path):
    # registry only publishes a band for a DIFFERENT service → fail-open
    orch = _orch(tmp_path, _FakeRegistry([_band(task="summarization")]))
    allowed, reason = await orch._check_provider_price_band("0xP", _units(99.0))
    assert allowed is True
    assert reason is None


@pytest.mark.asyncio
async def test_f5_unparseable_amount_fails_open(tmp_path):
    orch = _orch(tmp_path, _FakeRegistry([_band()]))
    allowed, reason = await orch._check_provider_price_band("0xP", "not-a-number")
    assert allowed is True
    assert reason is None
