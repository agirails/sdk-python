"""BuyerOrchestrator — channel-driven (3.5.0) AIP-2.1 negotiation tests.

Mirrors sdk-js/src/negotiation/BuyerOrchestrator.channel.test.ts:
  - accept-at-quote (no counter)
  - walk reject above target
  - single counter → provider accepts
  - multi-round counter → re-quote → counter → accept
  - counter timeout → CANCELLED
  - subscription cleanup at terminal outcome
  - CounterAccept binding mismatch
  - on-chain hash mismatch
  - partial negotiation context constructor guard
  - re-quote maxPrice substitution attack
  - decideQuote BYO-brain hook
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Optional

import pytest
from eth_account import Account

from agirails.builders.counter_accept import CounterAcceptBuilder, CounterAcceptParams
from agirails.builders.counter_offer import CounterOfferBuilder, MessageNonceManager
from agirails.builders.quote import QuoteBuilder, QuoteParams
from agirails.negotiation.buyer_orchestrator import (
    BuyerNegotiationContext,
    BuyerOrchestrator,
    OrchestratorConfig,
)
from agirails.negotiation.negotiation_channel import (
    COUNTERACCEPT_ENVELOPE,
    COUNTEROFFER_ENVELOPE,
    QUOTE_ENVELOPE,
    MockChannel,
    MockChannelConfig,
    NegotiationMessage,
)
from agirails.negotiation.policy_engine import (
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    Selection,
)
from agirails.runtime.mock_runtime import MockRuntime

KERNEL = "0x1234567890123456789012345678901234567890"
CHAIN_ID = 84_532


class _TargetUnitPrice:
    def __init__(self, amount: float):
        self.amount = amount
        self.currency = "USDC"
        self.unit = "job"


def make_policy(
    rounds_per_provider: Optional[int] = None,
    counter_strategy: Optional[str] = None,
    counter_response_ttl_seconds: Optional[int] = None,
    target_amount: Optional[float] = None,
) -> BuyerPolicy:
    neg = Negotiation(rounds_max=1, quote_ttl="1m")
    # The channel-driven loop reads these via getattr (TS parity: optional
    # negotiation fields not yet on the base dataclass).
    if rounds_per_provider is not None:
        neg.rounds_per_provider = rounds_per_provider  # type: ignore[attr-defined]
    if counter_strategy is not None:
        neg.counter_strategy = counter_strategy  # type: ignore[attr-defined]
    if counter_response_ttl_seconds is not None:
        neg.counter_response_ttl_seconds = counter_response_ttl_seconds  # type: ignore[attr-defined]
    policy = BuyerPolicy(
        task="code-review",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=10, currency="USDC", unit="job"),
            max_daily_spend=MaxDailySpend(amount=100, currency="USDC"),
        ),
        negotiation=neg,
        selection=Selection(prioritize=["price"]),
    )
    if target_amount is not None:
        policy.target_unit_price = _TargetUnitPrice(target_amount)  # type: ignore[attr-defined]
    return policy


def discover_mock(provider_address: str):
    async def _mock(*a, **k):
        agent = type("Agent", (), {})()
        agent.slug = "test-provider"
        agent.wallet_address = provider_address
        pc = type("PC", (), {})()
        pricing = type("Pricing", (), {})()
        pricing.amount = "5"
        pricing.currency = "USDC"
        pricing.unit = "job"
        pc.pricing = pricing
        agent.published_config = pc
        stats = type("Stats", (), {})()
        stats.reputation_score = 80
        stats.success_rate = 95
        stats.avg_completion_time_seconds = 60
        stats.completed_transactions = 100
        stats.failed_transactions = 0
        stats.total_gmv_usdc = "100"
        agent.stats = stats
        return type("Result", (), {"agents": [agent], "total": 1})()

    return _mock


@pytest.fixture
async def env():
    tmp = tempfile.mkdtemp(prefix="buyer-orch-channel-")
    runtime = MockRuntime(state_directory=Path(tmp) / ".actp")
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    provider_nm = MessageNonceManager()
    first_quote_by_tx: set[str] = set()
    yield {
        "tmp": tmp,
        "runtime": runtime,
        "provider_acct": provider_acct,
        "buyer_acct": buyer_acct,
        "provider_did": provider_did,
        "consumer_did": consumer_did,
        "channel": channel,
        "provider_nm": provider_nm,
        "first_quote_by_tx": first_quote_by_tx,
    }
    await channel.close()
    await runtime.reset()


async def post_provider_quote(env, tx_id, quoted_amount, max_price="10000000"):
    qb = QuoteBuilder(account=env["provider_acct"], nonce_manager=_NMAdapter(env["provider_nm"]))
    quote = qb.build(
        QuoteParams(
            tx_id=tx_id,
            provider=env["provider_did"],
            consumer=env["consumer_did"],
            quoted_amount=quoted_amount,
            original_amount="5000000",
            max_price=max_price,
            chain_id=CHAIN_ID,
            kernel_address=KERNEL,
        )
    )
    if tx_id not in env["first_quote_by_tx"]:
        await env["runtime"].submit_quote(tx_id, quote)
        env["first_quote_by_tx"].add(tx_id)
    await env["channel"].post(
        tx_id, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
    )
    return quote


class _NMAdapter:
    def __init__(self, nm):
        self._nm = nm

    def get_next_nonce(self, mt):
        return self._nm.get_next_nonce(mt)

    def record_nonce(self, mt, n):
        self._nm.record_nonce(mt, n)


async def await_tx_id(env, timeout_s=4.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        all_tx = await env["runtime"].get_all_transactions()
        if all_tx:
            return all_tx[0].id
        await asyncio.sleep(0.02)
    raise AssertionError("Timed out waiting for createTransaction")


def make_buyer_orch(env, **policy_over) -> BuyerOrchestrator:
    return BuyerOrchestrator(
        make_policy(**policy_over),
        env["runtime"],
        env["buyer_acct"].address,
        env["tmp"],
        BuyerNegotiationContext(
            private_key=env["buyer_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
            negotiation_channel=env["channel"],
        ),
    )


async def wait_for_channel_message(channel, tx_id, mtype, timeout_s=3.0, exclude=()):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        await channel.drain()
        for m in channel.get_messages_for_tx_id(tx_id):
            if m.envelope.type == mtype and m.envelope.message.signature not in exclude:
                return m
        await asyncio.sleep(0.02)
    return None


def _patch_discover(env):
    import unittest.mock as mock

    return mock.patch(
        "agirails.negotiation.buyer_orchestrator.discover_agents",
        discover_mock(env["provider_acct"].address),
    )


# ============================================================================
# accept-at-quote (no counter needed)
# ============================================================================


@pytest.mark.asyncio
async def test_accepts_quote_at_or_below_target(env):
    await env["runtime"].mint_tokens(env["buyer_acct"].address, "100000000")
    with _patch_discover(env):
        orch = make_buyer_orch(env, target_amount=8)
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")  # $7 ≤ $8 target → accept
        result = await neg_task
    assert result.success is True
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.amount == "7000000"
    assert tx.state.value == "COMMITTED"


# ============================================================================
# walk reject (above target, walk strategy)
# ============================================================================


@pytest.mark.asyncio
async def test_rejects_quote_above_target_walk(env):
    with _patch_discover(env):
        orch = make_buyer_orch(
            env, rounds_per_provider=3, counter_strategy="walk", target_amount=5
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")  # $7 > $5 target, walk → reject
        result = await neg_task
    assert result.success is False
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "CANCELLED"


# ============================================================================
# single counter → provider accepts
# ============================================================================


@pytest.mark.asyncio
async def test_single_counter_provider_accepts(env):
    await env["runtime"].mint_tokens(env["buyer_acct"].address, "100000000")
    with _patch_discover(env):
        orch = make_buyer_orch(
            env,
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_amount=5,
            counter_response_ttl_seconds=5,
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")

        buyer_counter = await wait_for_channel_message(
            env["channel"], tx_id, COUNTEROFFER_ENVELOPE, 3.0
        )
        assert buyer_counter is not None
        assert buyer_counter.envelope.message.counterAmount == "6000000"  # midpoint($7,$5)

        accept = CounterAcceptBuilder(
            private_key=env["provider_acct"].key.hex(),
            nonce_manager=MessageNonceManager(),
        ).build(
            CounterAcceptParams(
                txId=tx_id,
                provider=env["provider_did"],
                consumer=env["consumer_did"],
                acceptedAmount="6000000",
                inReplyTo=CounterOfferBuilder().compute_hash(
                    buyer_counter.envelope.message
                ),
                chainId=CHAIN_ID,
                kernelAddress=KERNEL,
            )
        )
        await env["channel"].post(
            tx_id, NegotiationMessage(type=COUNTERACCEPT_ENVELOPE, message=accept)
        )
        result = await neg_task
    assert result.success is True
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.amount == "6000000"
    assert tx.state.value == "COMMITTED"


# ============================================================================
# multi-round counter → re-quote → counter → accept
# ============================================================================


@pytest.mark.asyncio
async def test_multi_round_counter_requote_counter_accept(env):
    await env["runtime"].mint_tokens(env["buyer_acct"].address, "100000000")
    with _patch_discover(env):
        orch = make_buyer_orch(
            env,
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_amount=5,
            counter_response_ttl_seconds=5,
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)

        # Round 1: provider quotes $9, buyer counters midpoint($9,$5)=$7.
        await post_provider_quote(env, tx_id, "9000000")
        c1 = await wait_for_channel_message(env["channel"], tx_id, COUNTEROFFER_ENVELOPE, 3.0)
        assert c1.envelope.message.counterAmount == "7000000"

        # Round 2: provider re-quotes $8, buyer counters midpoint($8,$5)=$6.5.
        await post_provider_quote(env, tx_id, "8000000")
        c2 = await wait_for_channel_message(
            env["channel"], tx_id, COUNTEROFFER_ENVELOPE, 3.0,
            exclude=(c1.envelope.message.signature,),
        )
        assert c2.envelope.message.counterAmount == "6500000"

        # Round 3 (last): provider re-quotes $6.5 — budget exhausted, accept.
        await post_provider_quote(env, tx_id, "6500000")
        result = await neg_task
    assert result.success is True
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.amount == "6500000"
    assert tx.state.value == "COMMITTED"


# ============================================================================
# counter timeout (provider doesn't respond)
# ============================================================================


@pytest.mark.asyncio
async def test_cancels_when_provider_does_not_respond(env):
    with _patch_discover(env):
        orch = make_buyer_orch(
            env,
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_amount=5,
            counter_response_ttl_seconds=1,
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")
        # Provider never responds → timeout → CANCELLED.
        result = await neg_task
    assert result.success is False
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "CANCELLED"


# ============================================================================
# memory hygiene: subscription cleaned up
# ============================================================================


@pytest.mark.asyncio
async def test_closes_subscription_at_terminal_outcome(env):
    await env["runtime"].mint_tokens(env["buyer_acct"].address, "100000000")
    with _patch_discover(env):
        orch = make_buyer_orch(env, target_amount=8)
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")
        await neg_task
    assert env["channel"].active_subscription_count() == 0
    assert tx_id not in orch._inbound_queues
    assert tx_id not in orch._active_subscriptions


# ============================================================================
# CounterAccept binding mismatch
# ============================================================================


@pytest.mark.asyncio
async def test_rejects_counteraccept_amount_mismatch(env):
    with _patch_discover(env):
        orch = make_buyer_orch(
            env,
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_amount=5,
            counter_response_ttl_seconds=3,
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")
        buyer_counter = await wait_for_channel_message(
            env["channel"], tx_id, COUNTEROFFER_ENVELOPE, 3.0
        )
        # Greedy provider tries to commit at $7 instead of buyer's $6 counter.
        malicious = CounterAcceptBuilder(
            private_key=env["provider_acct"].key.hex(),
            nonce_manager=MessageNonceManager(),
        ).build(
            CounterAcceptParams(
                txId=tx_id,
                provider=env["provider_did"],
                consumer=env["consumer_did"],
                acceptedAmount="7000000",  # mismatch — buyer's counter was $6m
                inReplyTo=CounterOfferBuilder().compute_hash(
                    buyer_counter.envelope.message
                ),
                chainId=CHAIN_ID,
                kernelAddress=KERNEL,
            )
        )
        await env["channel"].post(
            tx_id, NegotiationMessage(type=COUNTERACCEPT_ENVELOPE, message=malicious)
        )
        result = await neg_task
    assert result.success is False
    last_round = result.rounds[-1]
    assert last_round.action == "error"
    assert "binding mismatch" in last_round.reason


# ============================================================================
# hash mismatch (channel quote != on-chain)
# ============================================================================


@pytest.mark.asyncio
async def test_rejects_when_channel_quote_does_not_match_on_chain_hash(env):
    with _patch_discover(env):
        orch = make_buyer_orch(
            env, rounds_per_provider=3, counter_strategy="walk", target_amount=5
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)

        # Anchor on-chain with quote A, post DIFFERENT quote B on channel.
        quote_a = QuoteBuilder(
            account=env["provider_acct"], nonce_manager=MessageNonceManager()
        ).build(
            QuoteParams(
                tx_id=tx_id, provider=env["provider_did"], consumer=env["consumer_did"],
                quoted_amount="5000000", original_amount="5000000", max_price="10000000",
                chain_id=CHAIN_ID, kernel_address=KERNEL,
            )
        )
        await env["runtime"].submit_quote(tx_id, quote_a)
        quote_b = QuoteBuilder(
            account=env["provider_acct"], nonce_manager=MessageNonceManager()
        ).build(
            QuoteParams(
                tx_id=tx_id, provider=env["provider_did"], consumer=env["consumer_did"],
                quoted_amount="7000000", original_amount="5000000", max_price="10000000",
                chain_id=CHAIN_ID, kernel_address=KERNEL,
            )
        )
        await env["channel"].post(
            tx_id, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote_b)
        )
        result = await neg_task
    assert result.success is False
    last_round = result.rounds[-1]
    assert last_round.action == "error"
    assert "hash mismatch" in last_round.reason.lower()


# ============================================================================
# constructor validates partial negotiation context
# ============================================================================


def test_partial_negotiation_context_raises(env):
    base = (make_policy(), env["runtime"], env["buyer_acct"].address, env["tmp"])
    with pytest.raises(ValueError, match="private_key"):
        BuyerOrchestrator(
            *base,
            BuyerNegotiationContext(
                negotiation_channel=env["channel"], kernel_address=KERNEL, chain_id=CHAIN_ID
            ),
        )
    with pytest.raises(ValueError, match="kernel_address"):
        BuyerOrchestrator(
            *base,
            BuyerNegotiationContext(
                negotiation_channel=env["channel"],
                private_key=env["buyer_acct"].key.hex(),
                chain_id=CHAIN_ID,
            ),
        )
    with pytest.raises(ValueError, match="chain_id"):
        BuyerOrchestrator(
            *base,
            BuyerNegotiationContext(
                negotiation_channel=env["channel"],
                private_key=env["buyer_acct"].key.hex(),
                kernel_address=KERNEL,
            ),
        )
    # No channel at all → no raise (fixed-price flow allowed)
    BuyerOrchestrator(*base, BuyerNegotiationContext())
    # Full context → no raise
    BuyerOrchestrator(
        *base,
        BuyerNegotiationContext(
            negotiation_channel=env["channel"],
            private_key=env["buyer_acct"].key.hex(),
            kernel_address=KERNEL,
            chain_id=CHAIN_ID,
        ),
    )


# ============================================================================
# re-quote maxPrice substitution attack
# ============================================================================


@pytest.mark.asyncio
async def test_rejects_requote_maxprice_substitution(env):
    with _patch_discover(env):
        orch = make_buyer_orch(
            env,
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_amount=5,
            counter_response_ttl_seconds=5,
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "9000000")  # first quote, maxPrice $10
        await wait_for_channel_message(env["channel"], tx_id, COUNTEROFFER_ENVELOPE, 3.0)
        # Poisoned re-quote: maxPrice raised $10 → $50. Valid sig, must reject.
        await post_provider_quote(env, tx_id, "8000000", max_price="50000000")
        result = await neg_task
    assert result.success is False
    last_round = result.rounds[-1]
    assert last_round.action == "error"
    assert "maxprice" in last_round.reason.lower()
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "CANCELLED"


# ============================================================================
# decideQuote BYO-brain hook
# ============================================================================


@pytest.mark.asyncio
async def test_decide_quote_hook_overrides_builtin(env):
    await env["runtime"].mint_tokens(env["buyer_acct"].address, "100000000")
    seen: list[str] = []

    from agirails.negotiation.decision_engine import QuoteEvaluation

    def brain(q, p, r):
        seen.append(q.quoted_amount)
        return QuoteEvaluation(action="reject", reason="brain vetoes")

    with _patch_discover(env):
        orch = BuyerOrchestrator(
            make_policy(target_amount=8),
            env["runtime"],
            env["buyer_acct"].address,
            env["tmp"],
            BuyerNegotiationContext(
                private_key=env["buyer_acct"].key.hex(),
                kernel_address=KERNEL,
                chain_id=CHAIN_ID,
                negotiation_channel=env["channel"],
                decide_quote=brain,
            ),
        )
        neg_task = asyncio.ensure_future(
            orch.negotiate(OrchestratorConfig(poll_interval_ms=50))
        )
        tx_id = await await_tx_id(env)
        await post_provider_quote(env, tx_id, "7000000")  # default path → accept; brain → reject
        result = await neg_task
    assert "7000000" in seen
    assert result.success is False
    tx = await env["runtime"].get_transaction(tx_id)
    assert tx.state.value == "CANCELLED"
