"""Parity tests for negotiation/verify_quote_on_chain.py.

Mirrors sdk-js/src/negotiation/verifyQuoteOnChain.test.ts: both matchers
(canonical AIP-2 hash + legacy Agent.ts:1035 ad-hoc shape) + source tagging.
The canonical hash path reuses the ported AIP-2 QuoteBuilder.compute_hash
(builders/quote.py), and the legacy path reconstructs the exact
keccak256(JSON.stringify({txId, providerIdealPrice, actualEscrow, provider}))
shape the TS test signs against.
"""

from __future__ import annotations

import json

from eth_account import Account
from eth_hash.auto import keccak

from agirails.builders.quote import QuoteBuilder, QuoteMessage, QuoteParams
from agirails.negotiation.buyer_orchestrator import (
    BuyerOrchestrator,
    RequoteGuardViolation,
)
from agirails.negotiation.verify_quote_on_chain import verify_quote_hash_on_chain

KERNEL = "0x1234567890123456789012345678901234567890"
TX_ID = "0x" + "a" * 64


def _build_canonical_quote(account) -> QuoteMessage:
    """Mirror verifyQuoteOnChain.test.ts:14-26 buildCanonicalQuote()."""
    qb = QuoteBuilder(account=account)
    return qb.build(
        QuoteParams(
            tx_id=TX_ID,
            provider=f"did:ethr:84532:{account.address}",
            consumer="did:ethr:84532:0x2222222222222222222222222222222222222222",
            quoted_amount="7000000",
            original_amount="5000000",
            max_price="10000000",
            chain_id=84532,
            kernel_address=KERNEL,
        )
    )


def _legacy_hash(quote: QuoteMessage, provider_address: str, actual_escrow: str) -> str:
    """Replicate Agent.ts:1035-1038 / TS test:50-56 legacy shape hash.

    JS JSON.stringify produces compact (no-space) JSON in insertion order;
    json.dumps(separators=(",", ":")) matches it byte-for-byte.
    """
    legacy_shape = {
        "txId": quote.tx_id,
        "providerIdealPrice": quote.quoted_amount,
        "actualEscrow": actual_escrow,
        "provider": provider_address,
    }
    s = json.dumps(legacy_shape, separators=(",", ":"), ensure_ascii=True)
    return "0x" + keccak(s.encode("utf-8")).hex()


class TestVerifyQuoteHashOnChain:
    def test_matches_canonical_aip2(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        expected = QuoteBuilder().compute_hash(quote)

        result = verify_quote_hash_on_chain(quote, expected)
        assert result.match is True
        assert result.source == "aip2"
        assert result.canonical_hash == expected

    def test_matches_legacy(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        provider_address = acct.address
        actual_escrow = "5000000"  # tx.amount at QUOTED time
        legacy_hash = _legacy_hash(quote, provider_address, actual_escrow)

        result = verify_quote_hash_on_chain(
            quote,
            legacy_hash,
            provider_address=provider_address,
            actual_escrow=actual_escrow,
        )
        assert result.match is True
        assert result.source == "legacy"
        assert result.legacy_hash == legacy_hash

    def test_no_match_for_garbage(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        garbage = "0x" + "f" * 64
        result = verify_quote_hash_on_chain(
            quote,
            garbage,
            provider_address=acct.address,
            actual_escrow="5000000",
        )
        assert result.match is False
        assert result.source is None

    def test_skips_legacy_without_inputs(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        legacy_hash = _legacy_hash(quote, acct.address, "5000000")

        # No provider_address/actual_escrow → only canonical tried → no match.
        result = verify_quote_hash_on_chain(quote, legacy_hash)
        assert result.match is False
        assert result.canonical_hash is not None
        assert result.legacy_hash is None

    def test_canonical_hash_signer_independent(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        assert QuoteBuilder().compute_hash(quote) == QuoteBuilder().compute_hash(quote)


class TestBuyerOrchestratorAnchors:
    """Re-quote MITM guards (TS BuyerOrchestrator.ts:780-844) exposed on the
    buyer for the channel-driven path + tests."""

    def test_verify_first_quote_delegates(self):
        acct = Account.create()
        quote = _build_canonical_quote(acct)
        expected = QuoteBuilder().compute_hash(quote)
        result = BuyerOrchestrator.verify_first_quote_on_chain(quote, expected)
        assert result.match is True
        assert result.source == "aip2"

    def test_requote_anchors_hold(self):
        acct = Account.create()
        first = _build_canonical_quote(acct)
        # Same provider + same maxPrice → no violation.
        second = _build_canonical_quote(acct)
        second.provider = first.provider
        second.max_price = first.max_price
        assert BuyerOrchestrator.check_requote_anchors(second, first) is None

    def test_requote_provider_switch_caught(self):
        acct = Account.create()
        first = _build_canonical_quote(acct)
        second = _build_canonical_quote(acct)
        second.provider = "did:ethr:84532:0x9999999999999999999999999999999999999999"
        second.max_price = first.max_price
        violation = BuyerOrchestrator.check_requote_anchors(second, first)
        assert isinstance(violation, RequoteGuardViolation)
        assert violation.rule == "provider_mismatch"

    def test_requote_max_price_inflation_caught(self):
        acct = Account.create()
        first = _build_canonical_quote(acct)
        second = _build_canonical_quote(acct)
        second.provider = first.provider
        # Attacker inflates the ceiling mid-negotiation (P0 audit finding).
        second.max_price = "99000000"
        violation = BuyerOrchestrator.check_requote_anchors(second, first)
        assert isinstance(violation, RequoteGuardViolation)
        assert violation.rule == "max_price_mismatch"
