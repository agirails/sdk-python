"""
Wave-3 integration: wallet providers expose sign_typed_data, enabling the
native x402 v2 EIP-3009 flow end-to-end. The EOA path must be BYTE-IDENTICAL
to TS (@x402/evm) — proven against the same golden vector as the adapter.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from eth_account import Account

from agirails.adapters.x402.eip3009 import EIP3009Authorization, sign_eip3009_authorization
from agirails.adapters.x402_adapter import _WalletProviderSigner
from agirails.wallet import AutoWalletProvider, EOAWalletProvider

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cross_sdk" / "wave3_x402.json"


@pytest.fixture(scope="module")
def gv() -> dict:
    with open(FIXTURE) as f:
        return json.load(f)["eip3009"]


def _auth(gv: dict) -> EIP3009Authorization:
    a = gv["authorization"]
    return EIP3009Authorization(
        from_address=a["from"], to=a["to"], value=a["value"],
        valid_after=a["validAfter"], valid_before=a["validBefore"], nonce=a["nonce"],
    )


def test_eoa_provider_sign_typed_data_is_byte_exact(gv: dict) -> None:
    """EOAWalletProvider.sign_typed_data -> x402 EIP-3009 sig == TS golden."""
    provider = EOAWalletProvider(gv["privateKey"], w3=MagicMock(), chain_id=gv["domain"]["chainId"])
    signer = _WalletProviderSigner(provider)
    sig = sign_eip3009_authorization(signer, _auth(gv), gv["domain"])
    assert sig == gv["signature"], "x402 v2 sig via EOAWalletProvider diverged from TS"


def test_eoa_provider_sign_typed_data_direct(gv: dict) -> None:
    """The raw provider.sign_typed_data(full_message) also matches (no bridge)."""
    provider = EOAWalletProvider(gv["privateKey"], w3=MagicMock(), chain_id=84532)
    # Reuse the adapter's own message construction by signing via the bridge,
    # then confirm a direct provider call over the same typed-data matches.
    from agirails.adapters.x402.eip3009 import _EIP712_DOMAIN_TYPE, AUTHORIZATION_TYPES
    from eth_utils import to_checksum_address

    a = gv["authorization"]
    full_message = {
        "domain": dict(gv["domain"]),
        "types": dict(AUTHORIZATION_TYPES, EIP712Domain=_EIP712_DOMAIN_TYPE),
        "primaryType": "TransferWithAuthorization",
        "message": {
            "from": to_checksum_address(a["from"]),
            "to": to_checksum_address(a["to"]),
            "value": int(a["value"]),
            "validAfter": int(a["validAfter"]),
            "validBefore": int(a["validBefore"]),
            "nonce": bytes.fromhex(a["nonce"][2:]),
        },
    }
    sig = provider.sign_typed_data(full_message)
    assert sig == gv["signature"]


def test_auto_wallet_provider_signs_with_owner(gv: dict) -> None:
    """AutoWalletProvider.sign_typed_data signs with the owner EOA (Permit2/ERC-1271 path)."""
    cfg = MagicMock()
    cfg.private_key = gv["privateKey"]
    # Construct a bare AutoWalletProvider with only the fields sign_typed_data needs.
    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._private_key = gv["privateKey"]
    signer = _WalletProviderSigner(provider)
    sig = sign_eip3009_authorization(signer, _auth(gv), gv["domain"])
    # Owner EOA == fixture signer here, so it matches the golden vector.
    assert sig == gv["signature"]
    assert Account.from_key(gv["privateKey"]).address.lower() == gv["signerAddress"].lower()
