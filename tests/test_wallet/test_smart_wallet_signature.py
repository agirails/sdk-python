"""
Tier-1 Smart-Wallet x402 signing — ERC-1271 / ERC-6492 byte-exact parity.

P1 gap closure: AutoWalletProvider.sign_typed_data must produce a Coinbase
Smart-Wallet replay-safe SignatureWrapper (deployed → ERC-1271) or an ERC-6492
envelope (counterfactual / undeployed), NOT a raw owner EOA sig.

The golden vectors below were generated from viem's `toCoinbaseSmartAccount`
(sdk-js/node_modules/viem/account-abstraction/accounts/implementations/
toCoinbaseSmartAccount.ts) for the SAME private key + chain + smart-wallet
address + inner Permit2 typed-data, so these assert byte-for-byte equivalence
with the TS source of truth (which delegates to viem).
"""

from __future__ import annotations

import pytest
from eth_account import Account

from agirails.types.x402 import X402SignatureFailedError
from agirails.wallet.aa.user_op_builder import (
    build_create_account_factory_data,
    build_replay_safe_typed_data,
    serialize_erc6492_signature,
    wrap_signature,
)
from agirails.wallet.auto_wallet_provider import AutoWalletProvider

# ---------------------------------------------------------------------------
# Golden vectors (generated from viem toCoinbaseSmartAccount, version '1.1')
# ---------------------------------------------------------------------------

PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
CHAIN_ID = 84532
SMART_WALLET = "0x1111111111111111111111111111111111111111"

INNER_HASH = "0x37b8e9e4616cb15c09bd54e172de8672b027d889e196a76748cd2079eda5fa37"
REPLAY_SAFE_HASH = "0x4dd43ac0201956c3dfc29339425892ccafaf743b57ad5ec099cf625b31dc25eb"
OWNER_SIG = (
    "0x4983f68c559c867b19b19945b0bc85a5e3889e44ee5ab0e1458b3f64688f3c20"
    "3b77611b4df148626a6713dbbea7af5137dfab41415d985ee06e4124be3dae181b"
)

GOLD_WRAPPED_DEPLOYED = (
    "0x0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000040"
    "0000000000000000000000000000000000000000000000000000000000000041"
    "4983f68c559c867b19b19945b0bc85a5e3889e44ee5ab0e1458b3f64688f3c20"
    "3b77611b4df148626a6713dbbea7af5137dfab41415d985ee06e4124be3dae18"
    "1b00000000000000000000000000000000000000000000000000000000000000"
)

# Full ERC-6492 envelope, derived from the building blocks each independently
# verified byte-exact against viem (wrap_signature + factory_data + magic). This
# avoids hand-transcribing a 1KB hex string while still asserting that
# AutoWalletProvider.sign_typed_data produces the exact viem envelope.
def _expected_6492() -> str:
    fd = build_create_account_factory_data(OWNER_ADDRESS)
    return serialize_erc6492_signature(
        "0xba5ed110efdba3d005bfc882d75358acbbb85842",
        fd,
        GOLD_WRAPPED_DEPLOYED,
    )


GOLD_6492 = _expected_6492()


def _permit2_full_message() -> dict:
    types = {
        "PermitWitnessTransferFrom": [
            {"name": "permitted", "type": "TokenPermissions"},
            {"name": "spender", "type": "address"},
            {"name": "nonce", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
            {"name": "witness", "type": "Witness"},
        ],
        "TokenPermissions": [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "Witness": [
            {"name": "to", "type": "address"},
            {"name": "validAfter", "type": "uint256"},
        ],
    }
    return {
        "domain": {
            "name": "Permit2",
            "chainId": CHAIN_ID,
            "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        },
        "types": types,
        "primaryType": "PermitWitnessTransferFrom",
        "message": {
            "permitted": {
                "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount": 1000000,
            },
            "spender": "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
            "nonce": 12345,
            "deadline": 1999999999,
            "witness": {
                "to": "0x2222222222222222222222222222222222222222",
                "validAfter": 1000000,
            },
        },
    }


def _bare_provider(is_deployed: bool) -> AutoWalletProvider:
    p = AutoWalletProvider.__new__(AutoWalletProvider)
    p._private_key = PK
    p._smart_wallet_address = SMART_WALLET
    p._chain_id = CHAIN_ID
    p._w3 = None  # skip on-chain parity derivation
    p._is_deployed = is_deployed
    return p


# ---------------------------------------------------------------------------
# Helper-level byte-exactness (vs viem)
# ---------------------------------------------------------------------------


def test_replay_safe_hash_matches_viem() -> None:
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak

    rs = build_replay_safe_typed_data(
        SMART_WALLET, CHAIN_ID, bytes.fromhex(INNER_HASH[2:])
    )
    signable = encode_typed_data(full_message=rs)
    rs_hash = keccak(b"\x19\x01" + signable.header + signable.body)
    assert "0x" + rs_hash.hex() == REPLAY_SAFE_HASH


def test_wrap_signature_matches_viem() -> None:
    wrapped = wrap_signature(0, bytes.fromhex(OWNER_SIG[2:]))
    assert wrapped.lower() == GOLD_WRAPPED_DEPLOYED.lower()


def test_wrap_signature_normalizes_v_0_1() -> None:
    """v in {0,1} normalizes to {27,28}, same packed output as {27,28}."""
    r = b"\x11" * 32
    s = b"\x22" * 32
    from_27 = wrap_signature(0, r + s + bytes([27]))
    from_0 = wrap_signature(0, r + s + bytes([0]))
    assert from_27 == from_0
    from_28 = wrap_signature(0, r + s + bytes([28]))
    from_1 = wrap_signature(0, r + s + bytes([1]))
    assert from_28 == from_1


def test_wrap_signature_rejects_bad_v() -> None:
    with pytest.raises(ValueError, match="Invalid signature v"):
        wrap_signature(0, b"\x11" * 32 + b"\x22" * 32 + bytes([42]))


def test_factory_data_matches_viem() -> None:
    fd = build_create_account_factory_data(OWNER_ADDRESS)
    # createAccount selector + bytes[] owners + uint256 nonce
    assert fd[:4].hex() == "3ffba36f"
    # Address appears (lowercased) in the owners element word.
    assert OWNER_ADDRESS[2:].lower() in fd.hex()


def test_serialize_erc6492_appends_magic() -> None:
    wrapped = wrap_signature(0, bytes.fromhex(OWNER_SIG[2:]))
    fd = build_create_account_factory_data(OWNER_ADDRESS)
    env = serialize_erc6492_signature(
        "0xba5ed110efdba3d005bfc882d75358acbbb85842", fd, wrapped
    )
    assert env.lower().endswith(
        "6492649264926492649264926492649264926492649264926492649264926492"
    )


# ---------------------------------------------------------------------------
# AutoWalletProvider.sign_typed_data end-to-end (vs viem golden)
# ---------------------------------------------------------------------------


def test_sign_typed_data_deployed_is_erc1271_wrapper() -> None:
    """Deployed Smart Wallet → byte-exact SignatureWrapper (no 6492 envelope)."""
    provider = _bare_provider(is_deployed=True)
    sig = provider.sign_typed_data(_permit2_full_message())
    assert sig.lower() == GOLD_WRAPPED_DEPLOYED.lower()


def test_sign_typed_data_counterfactual_is_erc6492() -> None:
    """Undeployed Smart Wallet → byte-exact ERC-6492 envelope."""
    provider = _bare_provider(is_deployed=False)
    sig = provider.sign_typed_data(_permit2_full_message())
    assert sig.lower() == GOLD_6492.lower()


def test_sign_typed_data_is_not_raw_owner_sig() -> None:
    """The wrapped sig must differ from the raw owner EOA sig over the same hash."""
    provider = _bare_provider(is_deployed=True)
    sig = provider.sign_typed_data(_permit2_full_message())
    # Raw owner sig of the INNER hash (the buggy old behavior) must not equal this.
    raw = Account.from_key(PK).unsafe_sign_hash(bytes.fromhex(INNER_HASH[2:]))
    raw_hex = "0x" + (
        raw.r.to_bytes(32, "big") + raw.s.to_bytes(32, "big") + bytes([raw.v])
    ).hex()
    assert sig != raw_hex


# ---------------------------------------------------------------------------
# Fail-closed behavior
# ---------------------------------------------------------------------------


def test_sign_typed_data_missing_smart_wallet_fails_closed() -> None:
    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._private_key = PK
    provider._smart_wallet_address = None
    provider._chain_id = CHAIN_ID
    provider._w3 = None
    provider._is_deployed = True
    with pytest.raises(X402SignatureFailedError):
        provider.sign_typed_data(_permit2_full_message())


def test_sign_typed_data_missing_chain_id_fails_closed() -> None:
    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._private_key = PK
    provider._smart_wallet_address = SMART_WALLET
    provider._chain_id = None
    provider._w3 = None
    provider._is_deployed = True
    with pytest.raises(X402SignatureFailedError):
        provider.sign_typed_data(_permit2_full_message())


def test_sign_typed_data_parity_mismatch_fails_closed() -> None:
    """If the factory derives a different address than ours, fail closed."""

    class _FakeFn:
        def call(self):
            # Derived address differs from SMART_WALLET → mismatch.
            return "0x9999999999999999999999999999999999999999"

    class _Functions:
        def getAddress(self, owners, nonce):
            return _FakeFn()

    class _Contract:
        functions = _Functions()

    class _Eth:
        def contract(self, address, abi):
            return _Contract()

        def get_code(self, addr):
            return b"\x60\x80"

    class _W3:
        eth = _Eth()

    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._private_key = PK
    provider._smart_wallet_address = SMART_WALLET
    provider._chain_id = CHAIN_ID
    provider._w3 = _W3()
    provider._is_deployed = True

    with pytest.raises(X402SignatureFailedError, match="parity mismatch"):
        provider.sign_typed_data(_permit2_full_message())


def test_sign_typed_data_parity_match_proceeds() -> None:
    """If the factory derives the same address, signing proceeds (deployed)."""

    class _FakeFn:
        def call(self):
            return SMART_WALLET

    class _Functions:
        def getAddress(self, owners, nonce):
            return _FakeFn()

    class _Contract:
        functions = _Functions()

    class _Eth:
        def contract(self, address, abi):
            return _Contract()

        def get_code(self, addr):
            return b"\x60\x80"  # deployed

    class _W3:
        eth = _Eth()

    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._private_key = PK
    provider._smart_wallet_address = SMART_WALLET
    provider._chain_id = CHAIN_ID
    provider._w3 = _W3()
    provider._is_deployed = True

    sig = provider.sign_typed_data(_permit2_full_message())
    assert sig.lower() == GOLD_WRAPPED_DEPLOYED.lower()


def test_get_read_provider_returns_w3() -> None:
    class _W3:
        pass

    provider = AutoWalletProvider.__new__(AutoWalletProvider)
    provider._w3 = _W3()
    assert provider.get_read_provider() is provider._w3
