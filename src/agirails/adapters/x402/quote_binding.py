"""Per-request accepted x402 terms, checked before any payment side effect."""

import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Optional

from agirails.types.x402 import X402QuoteMismatchError

_FIELDS = frozenset({"amount", "asset", "pay_to", "network", "nonce"})


def _amount(value: Any) -> Optional[int]:
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def snapshot_quote(value: Any, request_body: Optional[str]) -> Optional[Mapping[str, str]]:
    """Copy scalar terms before await; validate the actual outgoing quote nonce."""
    if value is None:
        return None
    if not isinstance(value, Mapping) or not value or set(value) - _FIELDS:
        raise X402QuoteMismatchError("Invalid accepted_quote fields")
    copied = dict(value)
    if any(not isinstance(v, str) or not v for v in copied.values()):
        raise X402QuoteMismatchError("Accepted quote terms must be nonempty strings")
    if "amount" in copied and _amount(copied["amount"]) is None:
        raise X402QuoteMismatchError("Invalid accepted quote amount")
    for field in ["asset", "pay_to"]:
        if field in copied and re.fullmatch(r"0x[0-9a-fA-F]{40}", copied[field]) is None:
            raise X402QuoteMismatchError("Invalid accepted quote address")
    if "network" in copied and re.fullmatch(r"eip155:[1-9][0-9]*", copied["network"]) is None:
        raise X402QuoteMismatchError("Accepted quote network must be canonical CAIP-2")
    if "nonce" in copied:
        try:
            body = json.loads(request_body) if request_body is not None else None
        except (ValueError, TypeError):
            body = None
        if not isinstance(body, dict) or body.get("disputeNonce") != copied["nonce"]:
            raise X402QuoteMismatchError("Request disputeNonce differs from accepted quote")
    return MappingProxyType(copied)


def matches_quote(requirement: Mapping[str, Any], quote: Mapping[str, str]) -> bool:
    """Match defined economics and any advertised evaluator nonce commitments.

    EIP-3009 and Permit2 signing nonces remain independently random; they are
    not the evaluator's opaque disputeNonce.
    """
    if "network" in quote and requirement.get("network") != quote["network"]:
        return False
    for field, wire in [("asset", "asset"), ("pay_to", "payTo")]:
        if field in quote:
            offered = requirement.get(wire)
            if not isinstance(offered, str) or offered.lower() != quote[field].lower():
                return False
    if "amount" in quote:
        offered = _amount(requirement.get("amount"))
        if offered is None or offered != _amount(quote["amount"]):
            return False
    if "nonce" in quote:
        sources = [requirement]
        extra = requirement.get("extra")
        if isinstance(extra, dict):
            sources.append(extra)
        for source in list(sources):
            if "commit" in source:
                if not isinstance(source["commit"], dict):
                    return False
                sources.append(source["commit"])
        if any("disputeNonce" in s and s["disputeNonce"] != quote["nonce"] for s in sources):
            return False
    return True


def validate_wallet_network(wallet: Any, quote: Optional[Mapping[str, str]]) -> None:
    """Require the configured wallet chain for a network-bound payment."""
    if quote is None or "network" not in quote:
        return
    try:
        info = wallet.get_wallet_info()
        chain_id = (
            info.get("chain_id") if isinstance(info, Mapping) else getattr(info, "chain_id", None)
        )
    except Exception as error:
        raise X402QuoteMismatchError("Cannot determine quoted payment wallet chain") from error
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise X402QuoteMismatchError("Quoted payments require a valid wallet chain_id")
    if quote["network"] != f"eip155:{chain_id}":
        raise X402QuoteMismatchError("Wallet chain differs from accepted quote network")
