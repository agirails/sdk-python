"""
AIP-16 Delivery — Per-Builder Nonce Key Constants (Python port).

Mirrors sdk-js/src/delivery/nonce-keys.ts. Two SEPARATE nonce spaces, one for
the buyer-signed *setup* and one for the provider-signed *envelope*, both
distinct from the AIP-4 delivery-proof key (``agirails.delivery.v1``).

These are plain string constants intended to be passed into whatever nonce
counter the caller uses (the v1 schemas have no signed ``nonce`` field, so
they are an audit/future-compat hook only — see setup_builder.py).

Cite: sdk-js/src/delivery/nonce-keys.ts:73 / :86.
"""

from __future__ import annotations

from typing import Literal

# TS nonce-keys.ts:73 — DELIVERY_NONCE_KEY_SETUP
DELIVERY_NONCE_KEY_SETUP: Literal["agirails.delivery.setup.v1"] = "agirails.delivery.setup.v1"

# TS nonce-keys.ts:86 — DELIVERY_NONCE_KEY_ENVELOPE
DELIVERY_NONCE_KEY_ENVELOPE: Literal["agirails.delivery.envelope.v1"] = (
    "agirails.delivery.envelope.v1"
)

# TS nonce-keys.ts:95 — DeliveryNonceKey union
DeliveryNonceKey = Literal["agirails.delivery.setup.v1", "agirails.delivery.envelope.v1"]


__all__ = [
    "DELIVERY_NONCE_KEY_SETUP",
    "DELIVERY_NONCE_KEY_ENVELOPE",
    "DeliveryNonceKey",
]
