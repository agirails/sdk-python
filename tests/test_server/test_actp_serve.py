"""End-to-end tests for ``actp serve`` daemon (server package).

Covers policy loading, policy_engine verdicts, QuoteChannelHandler
validation/verification/dedup, and the FastAPI surface via TestClient.
"""

from __future__ import annotations

import time

import pytest
from eth_account import Account

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.server.app import create_app
from agirails.server.policy import (
    PLATFORM_MIN_BASE_UNITS,
    PricingPolicy,
    ProviderPolicy,
    load_policy_from_dict,
)
from agirails.server.policy_engine import (
    VerdictAction,
    evaluate_counter,
)
from agirails.server.quote_channel import (
    HandlerContext,
    InMemoryDedupStore,
    QuoteChannelHandler,
    build_channel_path,
)

# Lazy import — FastAPI TestClient lives behind the optional dep.
fastapi_testclient_module = pytest.importorskip("fastapi.testclient")
TestClient = fastapi_testclient_module.TestClient


# ============================================================================
# Fixtures
# ============================================================================

KERNEL = "0x" + "A" * 40
CHAIN_ID = 84532
TX_ID = "0x" + "a" * 64
QUOTE_HASH = "0x" + "b" * 64


@pytest.fixture
def buyer():
    return Account.create()


@pytest.fixture
def provider():
    return Account.create()


@pytest.fixture
def basic_policy():
    return ProviderPolicy(
        pricing=PricingPolicy(
            min_acceptable_amount=500_000,  # $0.50
            ideal_amount=1_000_000,  # $1.00
        ),
        services=["text-generation"],
        counter_strategy="walk",
    )


def _make_counter(
    buyer_acct, provider_acct, counter_amount: str = "800000", **overrides
):
    nm = MessageNonceManager()
    builder = CounterOfferBuilder(
        private_key=buyer_acct.key.hex(), nonce_manager=nm
    )
    params = CounterOfferParams(
        txId=TX_ID,
        consumer=f"did:ethr:84532:{buyer_acct.address}",
        provider=f"did:ethr:84532:{provider_acct.address}",
        quoteAmount=overrides.get("quoteAmount", "1500000"),
        counterAmount=counter_amount,
        maxPrice=overrides.get("maxPrice", "2000000"),
        inReplyTo=QUOTE_HASH,
        chainId=overrides.get("chainId", CHAIN_ID),
        kernelAddress=KERNEL,
    )
    return builder.build(params)


def _counter_to_wire(message) -> dict:
    return {"type": "agirails.counteroffer.v1", "message": message.to_dict()}


# ============================================================================
# Policy
# ============================================================================


class TestProviderPolicy:
    def test_invariant_ideal_ge_floor(self):
        with pytest.raises(ValueError, match="ideal_amount must be >="):
            PricingPolicy(min_acceptable_amount=600_000, ideal_amount=500_000)

    def test_invariant_floor_above_platform_min(self):
        with pytest.raises(ValueError, match="platform minimum"):
            PricingPolicy(min_acceptable_amount=100, ideal_amount=200)

    def test_load_from_dict(self):
        policy = load_policy_from_dict(
            {
                "services": ["text-generation", "summarization"],
                "pricing": {
                    "min_acceptable": {"amount": 500_000},
                    "ideal_price": {"amount": 1_000_000},
                },
                "quote_ttl": "15m",
                "counter_strategy": "concede",
                "concede_pct": 25,
            }
        )
        assert policy.pricing.min_acceptable_amount == 500_000
        assert policy.pricing.ideal_amount == 1_000_000
        assert policy.quote_ttl_seconds == 900
        assert policy.counter_strategy == "concede"
        assert policy.concede_pct == 25
        assert "text-generation" in policy.services


# ============================================================================
# Policy engine
# ============================================================================


class TestPolicyEngine:
    def test_accept_at_or_above_ideal(self, buyer, provider, basic_policy):
        msg = _make_counter(buyer, provider, counter_amount="1000000")
        verdict = evaluate_counter(msg, basic_policy)
        assert verdict.action == VerdictAction.ACCEPT
        assert verdict.recommended_amount == 1_000_000

    def test_reject_below_floor(self, buyer, provider, basic_policy):
        msg = _make_counter(buyer, provider, counter_amount="200000")
        verdict = evaluate_counter(msg, basic_policy)
        assert verdict.action == VerdictAction.REJECT
        assert "below provider floor" in verdict.reason

    def test_walk_strategy_rejects_in_band(
        self, buyer, provider, basic_policy
    ):
        msg = _make_counter(buyer, provider, counter_amount="700000")
        verdict = evaluate_counter(msg, basic_policy)
        assert verdict.action == VerdictAction.REJECT
        assert "strategy='walk'" in verdict.reason

    def test_concede_strategy_recommends_intermediate(
        self, buyer, provider
    ):
        policy = ProviderPolicy(
            pricing=PricingPolicy(
                min_acceptable_amount=500_000, ideal_amount=1_000_000
            ),
            counter_strategy="concede",
            concede_pct=30,
        )
        msg = _make_counter(
            buyer, provider, counter_amount="600000", quoteAmount="1500000"
        )
        verdict = evaluate_counter(msg, policy, last_quote_amount=1_000_000)
        assert verdict.action == VerdictAction.COUNTER
        # next = 1_000_000 - (1_000_000 - 500_000) * 30 / 100 = 850_000
        assert verdict.recommended_amount == 850_000


# ============================================================================
# QuoteChannelHandler
# ============================================================================


class TestQuoteChannelHandler:
    def test_handle_accepts_valid_counter(self, buyer, provider):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        result = handler.handle(
            _counter_to_wire(counter),
            HandlerContext(path_chain_id=CHAIN_ID, path_tx_id=TX_ID),
        )
        assert result.status == 201
        assert result.body["accepted"] is True
        assert result.parsed_message is not None

    def test_rejects_unknown_chain(self, buyer, provider):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        # Path says chain 1 but message has chain 84532 → URL-binding fail
        result = handler.handle(
            _counter_to_wire(counter),
            HandlerContext(path_chain_id=1, path_tx_id=TX_ID),
        )
        assert result.status == 400
        assert "chainId mismatch" in result.body["reason"]

    def test_rejects_tx_id_mismatch(self, buyer, provider):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        result = handler.handle(
            _counter_to_wire(counter),
            HandlerContext(
                path_chain_id=CHAIN_ID, path_tx_id="0x" + "f" * 64
            ),
        )
        assert result.status == 400
        assert "txId mismatch" in result.body["reason"]

    def test_rejects_bad_signature(self, buyer, provider):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        wire = _counter_to_wire(counter)
        # Replace signature with a syntactically-valid but recovery-failing sig
        wire["message"]["signature"] = "0x" + "1" * 130
        result = handler.handle(
            wire,
            HandlerContext(path_chain_id=CHAIN_ID, path_tx_id=TX_ID),
        )
        assert result.status == 401
        assert "signature" in result.body["reason"].lower() or \
            "recover" in result.body["reason"].lower()

    def test_rejects_expired(self, buyer, provider, monkeypatch):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        wire = _counter_to_wire(counter)
        # Fast-forward beyond expiresAt + grace
        future = counter.expiresAt + 1000
        import agirails.server.quote_channel as qc_mod
        monkeypatch.setattr(qc_mod.time, "time", lambda: future)
        result = handler.handle(
            wire,
            HandlerContext(path_chain_id=CHAIN_ID, path_tx_id=TX_ID),
        )
        assert result.status == 410
        assert "expired" in result.body["reason"].lower()

    def test_dedup_returns_duplicate_on_replay(self, buyer, provider):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        counter = _make_counter(buyer, provider)
        wire = _counter_to_wire(counter)
        ctx = HandlerContext(path_chain_id=CHAIN_ID, path_tx_id=TX_ID)
        first = handler.handle(wire, ctx)
        second = handler.handle(wire, ctx)
        assert first.status == 201
        assert first.body.get("duplicate") is False
        assert second.status == 200
        assert second.body.get("duplicate") is True

    def test_rejects_wrong_message_type(self):
        handler = QuoteChannelHandler({CHAIN_ID: KERNEL})
        result = handler.handle(
            {"type": "agirails.quote.v1", "message": {}},
            HandlerContext(path_chain_id=CHAIN_ID, path_tx_id=TX_ID),
        )
        assert result.status == 400
        assert "agirails.counteroffer.v1" in result.body["reason"]


class TestInMemoryDedupStore:
    def test_record_once_returns_recorded_then_duplicate(self):
        store = InMemoryDedupStore()
        assert store.record_once("k", 60_000) == "recorded"
        assert store.record_once("k", 60_000) == "duplicate"

    def test_expired_keys_can_be_re_recorded(self):
        store = InMemoryDedupStore()
        # TTL 0 → effectively immediately expired.
        store.record_once("k", 0)
        # Small sleep to push past now.
        time.sleep(0.01)
        assert store.record_once("k", 60_000) == "recorded"


# ============================================================================
# FastAPI surface
# ============================================================================


class TestFastAPIApp:
    def _client(self, policy):
        app = create_app(
            policy=policy,
            kernel_address_by_chain_id={CHAIN_ID: KERNEL},
            signer_address="0x" + "9" * 40,
        )
        return TestClient(app)

    def test_health(self, basic_policy):
        client = self._client(basic_policy)
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["service"] == "actp-serve"
        assert CHAIN_ID in body["chains"]

    def test_post_counter_accepted_at_or_above_ideal(
        self, buyer, provider, basic_policy
    ):
        """201 + accepted=true (transport) + verdict.action=ACCEPT (business)."""
        client = self._client(basic_policy)
        counter = _make_counter(buyer, provider, counter_amount="1100000")
        r = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_counter_to_wire(counter),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["accepted"] is True  # message accepted FOR PROCESSING
        assert body["verdict"]["action"] == "ACCEPT"  # policy verdict
        assert body["verdict"]["recommended_amount"] == "1100000"

    def test_post_counter_below_floor_returns_201_with_reject_verdict(
        self, buyer, provider, basic_policy
    ):
        """Handler-level acceptance (sig + path + TTL + dedup OK) is
        orthogonal to the business-level policy verdict. Buyer reads
        both: HTTP status confirms transport, ``verdict`` confirms
        whether the provider agrees to the price."""
        client = self._client(basic_policy)
        # 700000 is above platform min but inside policy's negotiation
        # band [500000, 1000000); strategy="walk" → policy REJECT.
        counter = _make_counter(buyer, provider, counter_amount="700000")
        r = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_counter_to_wire(counter),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["accepted"] is True
        assert body["verdict"]["action"] == "REJECT"
        assert "strategy='walk'" in body["verdict"]["reason"]
        assert body["verdict"]["recommended_amount"] is None

    def test_post_counter_concede_returns_counter_verdict(
        self, buyer, provider
    ):
        """In concede mode the verdict carries the next price the
        provider should re-quote."""
        from agirails.server.policy import PricingPolicy, ProviderPolicy

        concede_policy = ProviderPolicy(
            pricing=PricingPolicy(
                min_acceptable_amount=500_000, ideal_amount=1_000_000
            ),
            counter_strategy="concede",
            concede_pct=30,
        )
        client = self._client(concede_policy)
        counter = _make_counter(
            buyer, provider, counter_amount="600000", quoteAmount="1500000"
        )
        r = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_counter_to_wire(counter),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["verdict"]["action"] == "COUNTER"
        # concede from ideal (1_000_000) toward floor (500_000) at 30%
        # → 1_000_000 - 500_000 * 0.3 = 850_000
        assert body["verdict"]["recommended_amount"] == "850000"

    def test_post_bad_json_returns_400(self, basic_policy):
        client = self._client(basic_policy)
        r = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400

    def test_post_unknown_chain_returns_400(
        self, buyer, provider, basic_policy
    ):
        client = self._client(basic_policy)
        counter = _make_counter(buyer, provider)
        # Build the path with a chain that's not configured. Need a
        # counter whose message also reports that chain, otherwise we
        # trip the chainId-mismatch check first.
        bogus_chain = 999_999
        # The builder enforces a hardcoded chain allow-list; assert that
        # an unknown-chain path *with* a real counter message trips
        # the URL-binding check.
        r = client.post(
            build_channel_path(bogus_chain, TX_ID),
            json=_counter_to_wire(counter),
        )
        assert r.status_code == 400
