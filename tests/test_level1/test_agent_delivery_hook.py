"""Parity tests for the Agent AIP-16 delivery hook + zero-config auto-wire.

Mirrors TS maybePublishDeliveryEnvelope / ensureAip16AutoWire
(Agent.ts:2151-2412):
  * ACTP_DELIVERY_CHANNEL=v1 gate (off => no-op)
  * dependency gate (all four delivery deps required)
  * per-service delivery.mode == 'channel' (and 'none' skips)
  * idempotency: tx state MUST be COMMITTED
  * build + publish a public-v1 envelope on the channel
  * channel/builder failures are swallowed (never raised)
  * config fields captured + smart_wallet_nonce threaded
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from eth_account import Account

from agirails.delivery.mock_delivery_channel import MockDeliveryChannel
from agirails.level1.agent import Agent
from agirails.level1.config import (
    DEFAULT_DELIVERY_CONFIG,
    AgentConfig,
    DeliveryServiceConfig,
    ServiceConfig,
)
from agirails.level1.job import Job
from datetime import datetime, timedelta


_KERNEL = "0x" + "11" * 20
_CHAIN_ID = 84532


def _signer():
    # Deterministic test key (NOT a real account).
    return Account.from_key("0x" + "11" * 32)


def _job(service: str = "echo", tx_id: str = "0x" + "ab" * 32) -> Job:
    return Job(
        id=tx_id,
        service=service,
        input={},
        budget=1.0,
        deadline=datetime.now() + timedelta(hours=1),
        requester="0x" + "12" * 20,
        metadata={"disputeWindow": 172800},
    )


class _FakeRuntime:
    """Minimal runtime exposing get_transaction with a fixed state."""

    def __init__(self, state: str = "COMMITTED"):
        self._state = state

    async def get_transaction(self, tx_id):
        return SimpleNamespace(id=tx_id, state=self._state)


def _agent_with_delivery(channel, *, state="COMMITTED", smart_wallet_nonce=None):
    signer = _signer()
    cfg = AgentConfig(
        name="provider",
        delivery_channel=channel,
        delivery_signer=signer,
        kernel_address=_KERNEL,
        chain_id=_CHAIN_ID,
        smart_wallet_nonce=smart_wallet_nonce,
    )
    agent = Agent(cfg)

    async def h(job, ctx):
        return {"echo": True}

    agent.provide("echo", handler=h)
    # Wire a fake client so the idempotency state read works.
    agent._client = SimpleNamespace(runtime=_FakeRuntime(state))
    return agent, signer


# ============================================================================
# Feature-flag gate
# ============================================================================


@pytest.mark.asyncio
async def test_flag_off_is_noop(monkeypatch):
    monkeypatch.delenv("ACTP_DELIVERY_CHANNEL", raising=False)
    channel = MockDeliveryChannel()
    agent, _ = _agent_with_delivery(channel)

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})

    # No envelope published when the flag is off.
    envs = await channel.get_envelopes()
    assert envs == []


@pytest.mark.asyncio
async def test_missing_dep_is_noop(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    # No signer/kernel/chain -> dependency gate disables the hook.
    cfg = AgentConfig(name="provider", network="mock", delivery_channel=channel)
    agent = Agent(cfg)

    async def h(job, ctx):
        return {}

    agent.provide("echo", handler=h)
    agent._client = SimpleNamespace(runtime=_FakeRuntime("COMMITTED"))

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})
    envs = await channel.get_envelopes()
    assert envs == []


# ============================================================================
# Public envelope publish (happy path)
# ============================================================================


@pytest.mark.asyncio
async def test_public_envelope_published(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    agent, signer = _agent_with_delivery(channel)

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})

    envs = await channel.get_envelopes()
    assert len(envs) == 1
    wire = envs[0]
    assert wire["signed"]["scheme"] == "public-v1"
    assert wire["signed"]["txId"] == "0x" + "ab" * 32
    assert wire["signed"]["chainId"] == _CHAIN_ID
    assert wire["signed"]["kernelAddress"] == _KERNEL
    assert wire["signed"]["signerAddress"].lower() == signer.address.lower()
    # public body is plaintext UTF-8 JSON (NOT hex).
    assert wire["body"] == '{"echo":true}'
    # Default smart_wallet_nonce is 0.
    assert wire["signed"]["smartWalletNonce"] == 0


@pytest.mark.asyncio
async def test_smart_wallet_nonce_threaded(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    agent, _ = _agent_with_delivery(channel, smart_wallet_nonce=7)

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})
    envs = await channel.get_envelopes()
    assert envs[0]["signed"]["smartWalletNonce"] == 7


# ============================================================================
# Idempotency: only publishes when tx state is COMMITTED
# ============================================================================


@pytest.mark.asyncio
async def test_non_committed_state_skips_publish(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    agent, _ = _agent_with_delivery(channel, state="IN_PROGRESS")

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})
    envs = await channel.get_envelopes()
    assert envs == []


# ============================================================================
# Per-service delivery.mode gate
# ============================================================================


@pytest.mark.asyncio
async def test_delivery_mode_none_skips_publish(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    signer = _signer()
    cfg = AgentConfig(
        name="provider",
        delivery_channel=channel,
        delivery_signer=signer,
        kernel_address=_KERNEL,
        chain_id=_CHAIN_ID,
    )
    agent = Agent(cfg)

    async def h(job, ctx):
        return {}

    agent.provide(
        ServiceConfig(name="echo", delivery=DeliveryServiceConfig(mode="none")),
        handler=h,
    )
    agent._client = SimpleNamespace(runtime=_FakeRuntime("COMMITTED"))

    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})
    envs = await channel.get_envelopes()
    assert envs == []


# ============================================================================
# Channel publish failure is swallowed
# ============================================================================


class _BoomChannel(MockDeliveryChannel):
    async def publish_envelope(self, envelope):
        raise RuntimeError("relay down")


@pytest.mark.asyncio
async def test_publish_failure_swallowed(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = _BoomChannel()
    agent, _ = _agent_with_delivery(channel)

    # MUST NOT raise — settlement is the source of truth.
    await agent._maybe_publish_delivery_envelope(_job(), {"echo": True})


# ============================================================================
# Zero-config auto-wire (4.6.1)
# ============================================================================


@pytest.mark.asyncio
async def test_auto_wire_fills_kernel_and_chain(monkeypatch):
    monkeypatch.setenv("ACTP_DELIVERY_CHANNEL", "v1")
    channel = MockDeliveryChannel()
    signer = _signer()
    # Omit kernel/chain — auto-wire should derive them from the network config.
    cfg = AgentConfig(
        name="provider",
        network="testnet",
        delivery_channel=channel,
        delivery_signer=signer,
    )
    agent = Agent(cfg)
    await agent._ensure_aip16_auto_wire()

    assert agent._kernel_address is not None
    assert isinstance(agent._chain_id, int)


@pytest.mark.asyncio
async def test_auto_wire_noop_when_flag_off(monkeypatch):
    monkeypatch.delenv("ACTP_DELIVERY_CHANNEL", raising=False)
    cfg = AgentConfig(name="provider", network="testnet")
    agent = Agent(cfg)
    await agent._ensure_aip16_auto_wire()
    # Flag off -> no deps filled.
    assert agent._delivery_channel is None
    assert agent._kernel_address is None
    assert agent._chain_id is None


# ============================================================================
# Config plumbing + defaults
# ============================================================================


@pytest.mark.asyncio
async def test_config_fields_captured():
    signer = _signer()
    channel = MockDeliveryChannel()
    cfg = AgentConfig(
        name="provider",
        delivery_channel=channel,
        delivery_signer=signer,
        kernel_address=_KERNEL,
        chain_id=_CHAIN_ID,
        smart_wallet_nonce=3,
    )
    agent = Agent(cfg)
    assert agent._delivery_channel is channel
    assert agent._delivery_signer is signer
    assert agent._kernel_address == _KERNEL
    assert agent._chain_id == _CHAIN_ID
    assert agent._smart_wallet_nonce == 3


def test_default_delivery_config_is_channel_public():
    assert DEFAULT_DELIVERY_CONFIG.mode == "channel"
    assert DEFAULT_DELIVERY_CONFIG.privacy == "public"
