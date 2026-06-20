"""ProviderOrchestrator — channel-driven (3.5.0) tests, TS-parity.

Mirrors sdk-js/src/negotiation/ProviderOrchestrator.test.ts:
  - evaluate_request quote/skip
  - quote() full flow (on-chain anchor + channel post + channelError)
  - start() auto-accept / auto-reject(walk) / auto-requote(concede) / walk-after-budget
  - start() guard errors + stop() idempotence
  - counter_decider BYO-brain hook (decision override; verify stays mandatory)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from eth_account import Account

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.negotiation.negotiation_channel import (
    COUNTERACCEPT_ENVELOPE,
    COUNTEROFFER_ENVELOPE,
    QUOTE_ENVELOPE,
    MockChannel,
    MockChannelConfig,
    NegotiationMessage,
)
from agirails.negotiation.provider_orchestrator import (
    ProviderOrchestrator,
    ProviderOrchestratorConfig,
)
from agirails.negotiation.provider_policy import (
    IncomingRequest,
    PriceTerm,
    ProviderPolicy,
    ProviderPricing,
)
from agirails.runtime.mock_runtime import MockRuntime

KERNEL = "0x1234567890123456789012345678901234567890"
CHAIN_ID = 84_532


def base_policy(**over) -> ProviderPolicy:
    fields = dict(
        services=["code-review"],
        pricing=ProviderPricing(
            min_acceptable=PriceTerm(amount=5, currency="USDC", unit="job"),
            ideal_price=PriceTerm(amount=7, currency="USDC", unit="job"),
        ),
        quote_ttl="15m",
    )
    fields.update(over)
    return ProviderPolicy(**fields)


@pytest.fixture
async def env():
    tmp = tempfile.mkdtemp(prefix="provider-orch-")
    runtime = MockRuntime(state_directory=Path(tmp) / ".actp")
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    yield {
        "runtime": runtime,
        "provider_acct": provider_acct,
        "buyer_acct": buyer_acct,
        "provider_did": provider_did,
        "consumer_did": consumer_did,
        "channel": channel,
    }
    await channel.close()
    await runtime.reset()


def make_orch(env, **policy_over) -> ProviderOrchestrator:
    return ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(**policy_over),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            provider_did=env["provider_did"],
            negotiation_channel=env["channel"],
        )
    )


async def make_incoming_tx(env, amount: str):
    from agirails.runtime.base import CreateTransactionParams

    tx_id = await env["runtime"].create_transaction(
        CreateTransactionParams(
            provider=env["provider_acct"].address,
            requester=env["buyer_acct"].address,
            amount=amount,
            deadline=int(__import__("time").time()) + 3600,
            service_description="code-review",
        )
    )
    req = IncomingRequest(
        tx_id=tx_id,
        consumer=env["consumer_did"],
        offered_amount=amount,
        max_price="10000000",
        deadline=int(__import__("time").time()) + 3600,
        service_type="code-review",
        currency="USDC",
        unit="job",
    )
    return req, tx_id


def build_buyer_counter(env, tx_id, quote_amount, counter_amount, nm=None):
    builder = CounterOfferBuilder(
        private_key=env["buyer_acct"].key.hex(),
        nonce_manager=nm or MessageNonceManager(),
    )
    return builder.build(
        CounterOfferParams(
            txId=tx_id,
            consumer=env["consumer_did"],
            provider=env["provider_did"],
            quoteAmount=quote_amount,
            counterAmount=counter_amount,
            maxPrice="10000000",
            inReplyTo="0x" + "b" * 64,
            chainId=CHAIN_ID,
            kernelAddress=KERNEL,
        )
    )


async def wait_for_channel_message(channel, tx_id, mtype, timeout_s=1.5):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        await channel.drain()
        for m in channel.get_messages_for_tx_id(tx_id):
            if m.envelope.type == mtype:
                return m
        await asyncio.sleep(0.01)
    return None


async def wait_for_nth_quote(channel, tx_id, n, timeout_s=1.5):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        await channel.drain()
        quotes = [
            m
            for m in channel.get_messages_for_tx_id(tx_id)
            if m.envelope.type == QUOTE_ENVELOPE
        ]
        if len(quotes) >= n:
            return quotes[n - 1]
        await asyncio.sleep(0.01)
    return None


# ============================================================================
# evaluate_request
# ============================================================================


@pytest.mark.asyncio
async def test_evaluate_request_quotes_when_policy_passes(env):
    orch = make_orch(env)
    decision = orch.evaluate_request(
        IncomingRequest(
            tx_id="0x" + "a" * 64,
            consumer=env["consumer_did"],
            offered_amount="5000000",
            max_price="10000000",
            deadline=int(__import__("time").time()) + 3600,
            service_type="code-review",
            currency="USDC",
            unit="job",
        )
    )
    assert decision.action == "quote"
    assert decision.amount_base_units == "7000000"  # ideal $7


@pytest.mark.asyncio
async def test_evaluate_request_skips_on_policy_violation(env):
    orch = make_orch(env)
    decision = orch.evaluate_request(
        IncomingRequest(
            tx_id="0x" + "a" * 64,
            consumer=env["consumer_did"],
            offered_amount="5000000",
            max_price="10000000",
            deadline=int(__import__("time").time()) + 3600,
            service_type="translation",
            currency="USDC",
            unit="job",
        )
    )
    assert decision.action == "skip"


# ============================================================================
# quote() full flow
# ============================================================================


@pytest.mark.asyncio
async def test_quote_anchors_on_chain_and_posts_on_channel(env):
    orch = make_orch(env)
    req, tx_id = await make_incoming_tx(env, "5000000")
    result = await orch.quote(req, env["provider_did"])
    assert result.decision.action == "quote"
    assert result.quote is not None
    assert result.channel_error is None
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "QUOTED"
    await env["channel"].drain()
    posted = env["channel"].get_messages_for_tx_id(tx_id)
    assert len(posted) == 1
    assert posted[0].envelope.type == QUOTE_ENVELOPE


@pytest.mark.asyncio
async def test_quote_returns_channel_error_but_on_chain_succeeds(env):
    class FailingChannel:
        async def post(self, *a, **k):
            raise RuntimeError("relay 500")

        def subscribe_tx_id(self, *a, **k):
            from agirails.negotiation.negotiation_channel import Subscription

            return Subscription(unsubscribe=lambda: None)

        def subscribe_agent(self, *a, **k):
            from agirails.negotiation.negotiation_channel import Subscription

            return Subscription(unsubscribe=lambda: None)

    orch = ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            provider_did=env["provider_did"],
            negotiation_channel=FailingChannel(),
        )
    )
    req, tx_id = await make_incoming_tx(env, "5000000")
    result = await orch.quote(req, env["provider_did"])
    assert result.channel_error is not None
    assert "relay 500" in result.channel_error
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "QUOTED"  # on-chain still happened


# ============================================================================
# start() — multi-round auto-respond
# ============================================================================


@pytest.mark.asyncio
async def test_start_auto_accepts_counter_at_or_above_floor(env):
    orch = make_orch(env)
    req, tx_id = await make_incoming_tx(env, "5000000")
    await orch.quote(req, env["provider_did"])
    sub = await orch.start()

    counter = build_buyer_counter(env, tx_id, "7000000", "6000000")  # $6 ≥ floor $5
    await env["channel"].post(
        tx_id, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=counter)
    )

    accept = await wait_for_channel_message(
        env["channel"], tx_id, COUNTERACCEPT_ENVELOPE, 1.5
    )
    assert accept is not None
    assert accept.envelope.message.acceptedAmount == "6000000"
    assert accept.envelope.message.txId == tx_id
    sub.unsubscribe()


@pytest.mark.asyncio
async def test_start_auto_rejects_below_floor_walk(env):
    orch = make_orch(env)
    req, tx_id = await make_incoming_tx(env, "5000000")
    await orch.quote(req, env["provider_did"])
    sub = await orch.start()

    counter = build_buyer_counter(env, tx_id, "7000000", "3000000")  # $3 < floor $5
    await env["channel"].post(
        tx_id, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=counter)
    )
    # No response should be posted within window.
    await asyncio.sleep(0.3)
    await env["channel"].drain()
    msgs = env["channel"].get_messages_for_tx_id(tx_id)
    accepts = [m for m in msgs if m.envelope.type == COUNTERACCEPT_ENVELOPE]
    quotes = [m for m in msgs if m.envelope.type == QUOTE_ENVELOPE]
    assert accepts == []
    assert len(quotes) == 1  # only the original quote, no re-quote
    sub.unsubscribe()


@pytest.mark.asyncio
async def test_start_auto_requotes_concede(env):
    orch = make_orch(env, counter_strategy="concede", concede_pct=50, max_requotes=2)
    req, tx_id = await make_incoming_tx(env, "5000000")
    await orch.quote(req, env["provider_did"])  # initial quote at $7 (ideal)
    sub = await orch.start()

    # last quote $7, floor $5, gap $2, concede 50% → re-quote $6.
    counter = build_buyer_counter(env, tx_id, "7000000", "3000000")
    await env["channel"].post(
        tx_id, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=counter)
    )
    requoted = await wait_for_nth_quote(env["channel"], tx_id, 2, 1.5)
    assert requoted is not None
    assert requoted.envelope.message.quoted_amount == "6000000"
    sub.unsubscribe()


@pytest.mark.asyncio
async def test_start_walks_after_exhausting_requote_budget(env):
    orch = make_orch(env, counter_strategy="concede", concede_pct=50, max_requotes=1)
    req, tx_id = await make_incoming_tx(env, "5000000")
    await orch.quote(req, env["provider_did"])
    sub = await orch.start()
    nm = MessageNonceManager()  # shared so the two counters have distinct nonces

    c1 = build_buyer_counter(env, tx_id, "7000000", "3000000", nm=nm)
    await env["channel"].post(
        tx_id, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=c1)
    )
    await wait_for_nth_quote(env["channel"], tx_id, 2, 1.5)

    c2 = build_buyer_counter(env, tx_id, "6000000", "3500000", nm=nm)
    await env["channel"].post(
        tx_id, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=c2)
    )
    await asyncio.sleep(0.3)
    await env["channel"].drain()
    quotes = [
        m
        for m in env["channel"].get_messages_for_tx_id(tx_id)
        if m.envelope.type == QUOTE_ENVELOPE
    ]
    assert len(quotes) == 2  # initial + 1 re-quote, no third
    sub.unsubscribe()


@pytest.mark.asyncio
async def test_start_without_provider_did_raises(env):
    orch = ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            negotiation_channel=env["channel"],
        )
    )
    with pytest.raises(ValueError, match="provider_did"):
        await orch.start()


@pytest.mark.asyncio
async def test_start_without_channel_raises(env):
    orch = ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            provider_did=env["provider_did"],
        )
    )
    with pytest.raises(ValueError, match="negotiation_channel"):
        await orch.start()


@pytest.mark.asyncio
async def test_stop_is_idempotent(env):
    orch = make_orch(env)
    await orch.start()
    orch.stop()
    orch.stop()  # no raise


# ============================================================================
# counter_decider — BYO-brain hook
# ============================================================================


@pytest.mark.asyncio
async def test_counter_decider_consulted_instead_of_builtin(env):
    from agirails.negotiation.provider_policy import CounterContext, CounterDecision

    calls: list[CounterContext] = []

    def decider(ctx: CounterContext) -> CounterDecision:
        calls.append(ctx)
        return CounterDecision(action="accept", reason="stub says yes")

    orch = ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            provider_did=env["provider_did"],
            negotiation_channel=env["channel"],
            counter_decider=decider,
        )
    )
    _, tx_id = await make_incoming_tx(env, "5000000")
    # $3 below the $5 floor — built-in policy would reject; decider says accept.
    counter = build_buyer_counter(env, tx_id, "7000000", "3000000")

    decision = await orch.evaluate_counter(counter)

    assert decision.action == "accept"
    assert decision.reason == "stub says yes"
    assert len(calls) == 1
    assert calls[0].counter.counterAmount == "3000000"
    assert calls[0].policy.pricing.min_acceptable.amount == 5


@pytest.mark.asyncio
async def test_counter_decider_verify_runs_before_decider(env):
    from agirails.negotiation.provider_policy import CounterContext, CounterDecision

    ran = {"called": False}

    def decider(ctx: CounterContext) -> CounterDecision:
        ran["called"] = True
        return CounterDecision(action="accept", reason="should never run")

    orch = ProviderOrchestrator(
        ProviderOrchestratorConfig(
            policy=base_policy(),
            runtime=env["runtime"],
            private_key=env["provider_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            provider_did=env["provider_did"],
            negotiation_channel=env["channel"],
            counter_decider=decider,
        )
    )
    _, tx_id = await make_incoming_tx(env, "5000000")
    counter = build_buyer_counter(env, tx_id, "7000000", "6000000")
    # Tamper the amount after signing → EIP-712 signature no longer matches.
    counter.counterAmount = "1000000"

    with pytest.raises(Exception):
        await orch.evaluate_counter(counter)
    assert ran["called"] is False
