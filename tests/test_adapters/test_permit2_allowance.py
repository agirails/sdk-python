"""
P2 gap closure: x402 Permit2 approve path reads on-chain allowance first.

`read_permit2_allowance_is_set` mirrors TS X402Adapter.readPermit2AllowanceIsSet
(X402Adapter.ts:680-712): read USDC.allowance(owner, PERMIT2) before sponsoring
a redundant approve. Treat >= half MAX_UINT256 as "already approved"; fail open
to "submit the approve" on any error / missing provider so we never skip a
needed approve.
"""

from __future__ import annotations

from agirails.adapters.x402.permit2 import (
    PERMIT2_ADDRESS,
    _ALLOWANCE_APPROVED_THRESHOLD,
    _ALLOWANCE_SELECTOR,
    read_permit2_allowance_is_set,
)

OWNER = "0x1111111111111111111111111111111111111111"
TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
MAX_UINT256 = (1 << 256) - 1


class _Web3Like:
    """Web3.py-style provider exposing eth.call -> bytes."""

    def __init__(self, ret):
        self._ret = ret
        self.last_tx = None

        outer = self

        class _Eth:
            def call(self, tx):
                outer.last_tx = tx
                return outer._ret

        self.eth = _Eth()


class _EthersLike:
    """ethers-style provider exposing call -> hex str."""

    def __init__(self, ret):
        self._ret = ret
        self.last_tx = None

    def call(self, tx):
        self.last_tx = tx
        return self._ret


def test_selector_is_canonical() -> None:
    assert "0x" + _ALLOWANCE_SELECTOR.hex() == "0xdd62ed3e"


def test_threshold_is_half_max() -> None:
    assert _ALLOWANCE_APPROVED_THRESHOLD == (1 << 255)


def test_max_allowance_is_approved() -> None:
    w3 = _Web3Like(MAX_UINT256.to_bytes(32, "big"))
    assert read_permit2_allowance_is_set(w3, OWNER, TOKEN) is True


def test_calldata_shape_matches_ts() -> None:
    w3 = _Web3Like(MAX_UINT256.to_bytes(32, "big"))
    read_permit2_allowance_is_set(w3, OWNER, TOKEN)
    data = w3.last_tx["data"]
    # 0xdd62ed3e + owner(32) + permit2(32)
    assert data.startswith("0xdd62ed3e")
    assert OWNER[2:].lower() in data
    assert PERMIT2_ADDRESS[2:].lower() in data
    assert w3.last_tx["to"].lower() == TOKEN.lower()


def test_zero_allowance_not_approved() -> None:
    w3 = _Web3Like((0).to_bytes(32, "big"))
    assert read_permit2_allowance_is_set(w3, OWNER, TOKEN) is False


def test_half_minus_one_not_approved() -> None:
    w3 = _Web3Like(((1 << 255) - 1).to_bytes(32, "big"))
    assert read_permit2_allowance_is_set(w3, OWNER, TOKEN) is False


def test_exactly_half_is_approved() -> None:
    w3 = _Web3Like((1 << 255).to_bytes(32, "big"))
    assert read_permit2_allowance_is_set(w3, OWNER, TOKEN) is True


def test_ethers_style_hex_result_approved() -> None:
    el = _EthersLike("0x" + MAX_UINT256.to_bytes(32, "big").hex())
    assert read_permit2_allowance_is_set(el, OWNER, TOKEN) is True


def test_none_provider_returns_false() -> None:
    assert read_permit2_allowance_is_set(None, OWNER, TOKEN) is False


def test_empty_result_returns_false() -> None:
    assert read_permit2_allowance_is_set(_EthersLike("0x"), OWNER, TOKEN) is False
    assert read_permit2_allowance_is_set(_Web3Like(b""), OWNER, TOKEN) is False


def test_call_failure_fails_open_to_submit() -> None:
    """Any error → False (submit the approve), never silently skip it."""

    class _Raiser:
        @property
        def eth(self):
            raise RuntimeError("rpc down")

    assert read_permit2_allowance_is_set(_Raiser(), OWNER, TOKEN) is False


def test_custom_spender() -> None:
    spender = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
    w3 = _Web3Like(MAX_UINT256.to_bytes(32, "big"))
    read_permit2_allowance_is_set(w3, OWNER, TOKEN, spender=spender)
    assert spender[2:].lower() in w3.last_tx["data"]
