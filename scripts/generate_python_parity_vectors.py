#!/usr/bin/env python3
"""Python-side parity vector generator (mirror of generate_parity_vectors.js).

Signs AIP-2.1 CounterOffer + CounterAccept messages with the Python
SDK's builders using DETERMINISTIC inputs (same private keys, same
pinned timestamps as the TS generator). Emits JSON vectors to:

    tests/fixtures/cross_sdk/python_signed_*.json

The companion JS verifier (scripts/verify_python_vectors.js) loads
each fixture, runs ``verifyTypedData`` from the TS SDK, and asserts:

  1. Recovered signer == expectedSigner
  2. TS-side computeHash(message) == expectedHash

If either check fails, the SDKs have drifted on EIP-712 type
ordering, struct encoding, or canonical-JSON key ordering.

Run from the python-sdk-v2 directory:

    python3 scripts/generate_python_parity_vectors.py

Then verify the output by running the JS verifier:

    NODE_PATH=../sdk-js/node_modules node scripts/verify_python_vectors.js
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

from eth_account import Account

# Same deterministic test keys as the TS-side generator. NEVER use for
# anything real — they're hard-coded so vectors reproduce byte-for-byte
# across both SDKs.
BUYER_KEY = "0x" + "11" * 32
PROVIDER_KEY = "0x" + "22" * 32

buyer = Account.from_key(BUYER_KEY)
provider = Account.from_key(PROVIDER_KEY)

KERNEL = "0x" + "A" * 40
TX_ID = "0x" + "a" * 64
QUOTE_HASH = "0x" + "b" * 64
CHAIN_ID = 84532
FIXED_NOW_SEC = 1_700_000_000


def _pin_time():
    """Pin time.time() so counteredAt / acceptedAt match the TS frozen
    Date.now (= 1_700_000_000_000 ms == 1_700_000_000 sec)."""
    return patch(
        "agirails.builders.counter_offer.time.time", return_value=FIXED_NOW_SEC
    )


def build_counter_offer_vector(label, justification=None):
    from agirails.builders.counter_offer import (
        CounterOfferBuilder,
        CounterOfferJustification,
        CounterOfferParams,
        MessageNonceManager,
    )

    just = None
    if justification:
        just = CounterOfferJustification(
            reason=justification.get("reason"),
            market_rate=justification.get("marketRate"),
            breakdown=justification.get("breakdown") or {},
        )

    with _pin_time():
        nm = MessageNonceManager()
        builder = CounterOfferBuilder(private_key=BUYER_KEY, nonce_manager=nm)
        msg = builder.build(
            CounterOfferParams(
                txId=TX_ID,
                consumer=f"did:ethr:{CHAIN_ID}:{buyer.address}",
                provider=f"did:ethr:{CHAIN_ID}:{provider.address}",
                quoteAmount="1500000",
                counterAmount="800000",
                maxPrice="2000000",
                inReplyTo=QUOTE_HASH,
                chainId=CHAIN_ID,
                kernelAddress=KERNEL,
                expiresAt=FIXED_NOW_SEC + 3600,
                justification=just,
            )
        )
        expected_hash = builder.compute_hash(msg)

    return {
        "label": label,
        "fixtureKind": "counter_offer",
        "kernelAddress": KERNEL,
        "expectedSigner": buyer.address,
        "expectedHash": expected_hash,
        "message": msg.to_dict(),
    }


def build_counter_accept_vector(label, chain_id=CHAIN_ID):
    from agirails.builders.counter_accept import (
        CounterAcceptBuilder,
        CounterAcceptParams,
    )
    from agirails.builders.counter_offer import MessageNonceManager
    import agirails.builders.counter_accept as ca_mod

    with patch.object(ca_mod.time, "time", return_value=FIXED_NOW_SEC):
        nm = MessageNonceManager()
        builder = CounterAcceptBuilder(private_key=PROVIDER_KEY, nonce_manager=nm)
        msg = builder.build(
            CounterAcceptParams(
                txId=TX_ID,
                provider=f"did:ethr:{chain_id}:{provider.address}",
                consumer=f"did:ethr:{chain_id}:{buyer.address}",
                acceptedAmount="800000",
                inReplyTo=QUOTE_HASH,
                chainId=chain_id,
                kernelAddress=KERNEL,
            )
        )
        expected_hash = builder.compute_hash(msg)

    return {
        "label": label,
        "fixtureKind": "counter_accept",
        "kernelAddress": KERNEL,
        "expectedSigner": provider.address,
        "expectedHash": expected_hash,
        "message": msg.to_dict(),
    }


def main():
    out_dir = Path(__file__).parent.parent / "tests" / "fixtures" / "cross_sdk"
    out_dir.mkdir(parents=True, exist_ok=True)

    fixtures = [
        build_counter_offer_vector("python_signed_counter_offer_basic"),
        build_counter_offer_vector(
            "python_signed_counter_offer_with_justification",
            justification={
                "reason": "market rate is lower",
                "marketRate": 0.75,
                "breakdown": {"observed_quotes": 3},
            },
        ),
        build_counter_accept_vector("python_signed_counter_accept_basic"),
        build_counter_accept_vector(
            "python_signed_counter_accept_mainnet", chain_id=8453
        ),
    ]

    for f in fixtures:
        path = out_dir / f"{f['label']}.json"
        path.write_text(json.dumps(f, indent=2) + "\n")
        print(f"wrote {path.relative_to(Path.cwd())}")

    manifest = {
        "generated_by": "agirails.builders (CounterOfferBuilder + CounterAcceptBuilder)",
        "python_sdk_version": __import__("agirails").__version__,
        "pinned_now_sec": FIXED_NOW_SEC,
        "buyer_address": buyer.address,
        "provider_address": provider.address,
        "fixtures": [f["label"] for f in fixtures],
    }
    manifest_path = out_dir / "python_signed_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {manifest_path.relative_to(Path.cwd())}")


if __name__ == "__main__":
    main()
