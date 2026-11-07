"""Translate evaluator quote metadata into immutable per-payment expectations."""

import re
from collections.abc import Mapping
from typing import Any, NoReturn

from agirails.dispute.receipt_authorization import _validate_quote_transport


def _reject(message: str) -> NoReturn:
    raise ValueError(message)


def _term(sources, *, amount=False, address=False):
    values = []
    for source, key in sources:
        if key not in source:
            continue
        value = source[key]
        if not isinstance(value, str) or not value:
            _reject("Invalid declared quote term: " + key)
        if amount:
            if not value.isascii() or not value.isdecimal():
                _reject("Invalid quoted base-unit amount")
            try:
                value = str(int(value))
            except ValueError:
                _reject("Invalid quoted base-unit amount")
        if address and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is None:
            _reject("Invalid quoted address")
        values.append(value.lower() if address else value)
    if values and any(v != values[0] for v in values):
        _reject("Contradictory quote terms")
    return values[0] if values else None


def accepted_quote_terms(quote: dict[str, Any], chain_id: int) -> Mapping[str, str]:
    _validate_quote_transport(quote, chain_id)
    economics, x402 = quote.get("quote", {}), quote.get("x402", {})
    if not isinstance(economics, dict) or not isinstance(x402, dict):
        _reject("Invalid quote economics or x402 metadata")
    nonce = _term([(quote, "disputeNonce")])
    if nonce is None:
        _reject("Missing quote disputeNonce")
    for source in [economics, x402, x402.get("commit", {})]:
        if not isinstance(source, dict):
            _reject("Invalid quote commitment")
        if "disputeNonce" in source and source["disputeNonce"] != nonce:
            _reject("Contradictory quote disputeNonce")
    terms = {"network": f"eip155:{chain_id}", "nonce": nonce}
    fields = {
        "amount": ([(economics, "amount"), (x402, "amount"), (x402, "maxAmountRequired")], True),
        "asset": ([(economics, "asset"), (x402, "asset")], False),
        "pay_to": ([(economics, "payTo"), (x402, "payTo"), (x402, "recipient")], False),
    }
    for name, (sources, is_amount) in fields.items():
        value = _term(sources, amount=is_amount, address=not is_amount)
        if value is not None:
            terms[name] = value
    return terms
