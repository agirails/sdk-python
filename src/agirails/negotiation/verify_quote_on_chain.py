"""
verify_quote_on_chain: cross-reference a received QuoteMessage against
the hash a provider committed on-chain via ``transitionState(QUOTED, …)``.

Python port of ``sdk-js/src/negotiation/verifyQuoteOnChain.ts`` (lines
1-101), byte-for-byte. AIP-2.1 §3.6 (legacy compatibility). Two matchers,
tried in order:

  1. ``'aip2'``:   canonical EIP-712 hash: ``keccak256(canonicalJson(
                   QuoteMessage minus signature))``. This is what
                   AIP-2.1-compliant providers emit. Computed via
                   :meth:`agirails.builders.quote.QuoteBuilder.compute_hash`,
                   which mirrors TS ``QuoteBuilder.computeHash`` exactly.
  2. ``'legacy'``: ad-hoc hash from Agent.ts:1035-1038 (the counter-offer
                   pricing path that shipped before the formal AIP-2.1
                   submitQuote runtime method). Hash is::

                       keccak256(JSON.stringify({
                         txId, providerIdealPrice, actualEscrow, provider
                       }))

                   where ``providerIdealPrice`` is the provider's intended
                   sell price in USDC base units (string), ``actualEscrow``
                   is ``tx.amount`` (the buyer-offered amount), and
                   ``provider`` is the provider's EOA address. This path is
                   used only when the SDK-authored hash can't be
                   reconstructed (e.g. pre-AIP-2.1 agents still running).

Both paths return a ``{ source, match: True }`` tagged result so the
orchestrator + telemetry can see how many transactions are still coming
through the legacy path. The legacy matcher is observability-tagged
technical debt; planned removal in 2 SDK minor releases per the AIP-2.1
migration schedule.

BuyerOrchestrator uses this on counter-round 0 as the anchored MITM
defense (substitution detection): a buyer must not commit to a quote whose
canonical hash does not match what the provider anchored on-chain at QUOTED.

@module negotiation/verify_quote_on_chain
@see sdk-js/src/negotiation/verifyQuoteOnChain.ts
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, Optional

from eth_hash.auto import keccak

from agirails.builders.quote import QuoteBuilder, QuoteMessage
from agirails.utils.canonical_json import canonical_json_dumps

# 'aip2' | 'legacy' — which matcher accepted the on-chain hash.
VerifySource = Literal["aip2", "legacy"]


@dataclass(frozen=True)
class VerifyOnChainResult:
    """Result of :func:`verify_quote_hash_on_chain` (mirrors TS ``VerifyOnChainResult``)."""

    match: bool
    #: Which matcher accepted the hash. Only set when ``match is True``.
    source: Optional[VerifySource] = None
    #: Expected hash per the canonical matcher, for debugging mismatches.
    canonical_hash: Optional[str] = None
    #: Expected legacy hash (same purpose).
    legacy_hash: Optional[str] = None


def verify_quote_hash_on_chain(
    quote: QuoteMessage,
    on_chain_hash: str,
    *,
    provider_address: Optional[str] = None,
    actual_escrow: Optional[str] = None,
) -> VerifyOnChainResult:
    """Cross-reference an off-chain :class:`QuoteMessage` against the hash
    stored on chain at QUOTED.

    Passing ``provider_address`` and ``actual_escrow`` enables the legacy
    fallback. Omit them on fresh deployments where legacy is impossible.

    Mirrors TS ``verifyQuoteHashOnChain`` (verifyQuoteOnChain.ts:61-101).

    Args:
        quote: signed QuoteMessage received off-chain.
        on_chain_hash: hash committed on-chain at QUOTED.
        provider_address: provider's EOA address (needed for legacy).
        actual_escrow: ``tx.amount`` at QUOTED time (needed for legacy).
    """
    # 1. Canonical AIP-2 match. Hasher is signer-independent so a verify-only
    #    QuoteBuilder (no account) is fine — same as TS using a throwaway
    #    wallet for QuoteBuilder.computeHash.
    hasher = QuoteBuilder()
    canonical_hash = hasher.compute_hash(quote)
    if canonical_hash.lower() == on_chain_hash.lower():
        return VerifyOnChainResult(match=True, source="aip2", canonical_hash=canonical_hash)

    # 2. Legacy Agent.ts:1033-1038 match. Only attempted when we have the
    #    legacy inputs — without them the fallback is impossible by
    #    construction (which is fine — old providers will simply fail
    #    verification and the orchestrator will cancel the tx).
    legacy_hash: Optional[str] = None
    if provider_address and actual_escrow:
        # The legacy hash uses `providerIdealPrice` (what provider WANTED to
        # charge) rather than the `quotedAmount` from the off-chain message —
        # at the counter-offer pricing path, those are the same value (see
        # Agent.ts:1034). We reconstruct the legacy shape with the off-chain
        # quote's `quotedAmount` as the ideal price.
        #
        # The string fed to keccak MUST be byte-identical to JS
        # JSON.stringify({txId, providerIdealPrice, actualEscrow, provider}):
        # no spaces, insertion order preserved, ASCII. json.dumps with
        # separators=(",", ":") and ensure_ascii=True matches.
        legacy_shape = {
            "txId": quote.tx_id,
            "providerIdealPrice": quote.quoted_amount,
            "actualEscrow": actual_escrow,
            "provider": provider_address,
        }
        legacy_str = json.dumps(legacy_shape, separators=(",", ":"), ensure_ascii=True)
        legacy_hash = "0x" + keccak(legacy_str.encode("utf-8")).hex()
        if legacy_hash.lower() == on_chain_hash.lower():
            return VerifyOnChainResult(
                match=True,
                source="legacy",
                canonical_hash=canonical_hash,
                legacy_hash=legacy_hash,
            )

    return VerifyOnChainResult(
        match=False, canonical_hash=canonical_hash, legacy_hash=legacy_hash
    )


__all__ = [
    "VerifySource",
    "VerifyOnChainResult",
    "verify_quote_hash_on_chain",
]
