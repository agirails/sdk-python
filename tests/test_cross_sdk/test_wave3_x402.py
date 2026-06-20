"""
Wave-3 native x402 v2 (EIP-3009) byte-exactness vs TS 4.8.0.

Asserts the Python x402 v2 signing primitives produce output BYTE-IDENTICAL to
@x402/evm (the engine the TS X402Adapter uses). The golden vector in
tests/fixtures/cross_sdk/wave3_x402.json was generated deterministically from
@x402/evm's exact-scheme EIP-3009 signer. A failure means a Python buyer and a
TS/x402 seller could not interoperate.

Oracle facts proven here:
- sign_eip3009_authorization(account, authorization, domain) == fixture signature
  byte-for-byte, and recovers to signerAddress.
- The EIP-712 digest matches the fixture digest.
- build_eip3009_payload reproduces the full x402 payment payload (validAfter =
  now-600, validBefore = now+maxTimeoutSeconds, x402Version 2).
- encode_x_payment_header reproduces the X-PAYMENT header base64 (scheme 'exact',
  network 'base-sepolia', compact JSON).
- The one-time Permit2 approve tx uses selector 0x095ea7b3 + MAX_UINT256.
"""

import base64
import json
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from agirails.adapters.x402.eip3009 import (
    AUTHORIZATION_TYPES,
    EIP3009Authorization,
    PaymentRequirements,
    build_eip3009_payload,
    chain_id_for_network,
    encode_x_payment_header,
    sign_eip3009_authorization,
)
from agirails.adapters.x402.permit2 import (
    PERMIT2_ADDRESS,
    create_permit2_approval_tx,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cross_sdk" / "wave3_x402.json"


def _fx() -> dict:
    with open(FIXTURE) as f:
        return json.load(f)


def _auth(d: dict) -> EIP3009Authorization:
    return EIP3009Authorization(
        from_address=d["from"],
        to=d["to"],
        value=d["value"],
        valid_after=d["validAfter"],
        valid_before=d["validBefore"],
        nonce=d["nonce"],
    )


class TestEIP3009Schema:
    def test_authorization_types_field_order(self) -> None:
        fx = _fx()
        assert (
            AUTHORIZATION_TYPES["TransferWithAuthorization"]
            == fx["eip3009"]["authorizationTypes"]["TransferWithAuthorization"]
        )


class TestSignatureByteExact:
    def test_signature_matches_fixture(self) -> None:
        fx = _fx()
        e = fx["eip3009"]
        account = Account.from_key(e["privateKey"])
        sig = sign_eip3009_authorization(account, _auth(e["authorization"]), e["domain"])
        assert sig == e["signature"]

    def test_signature_recovers_to_signer(self) -> None:
        fx = _fx()
        e = fx["eip3009"]
        account = Account.from_key(e["privateKey"])
        sig = sign_eip3009_authorization(account, _auth(e["authorization"]), e["domain"])

        message = {
            "from": e["authorization"]["from"],
            "to": e["authorization"]["to"],
            "value": int(e["authorization"]["value"]),
            "validAfter": int(e["authorization"]["validAfter"]),
            "validBefore": int(e["authorization"]["validBefore"]),
            "nonce": bytes.fromhex(e["authorization"]["nonce"][2:]),
        }
        full = {
            "domain": e["domain"],
            "types": dict(
                AUTHORIZATION_TYPES,
                EIP712Domain=[
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
            ),
            "primaryType": "TransferWithAuthorization",
            "message": message,
        }
        signable = encode_typed_data(full_message=full)
        recovered = Account.recover_message(signable, signature=sig)
        assert recovered.lower() == e["signerAddress"].lower()

    def test_eip712_digest_matches_fixture(self) -> None:
        fx = _fx()
        e = fx["eip3009"]
        message = {
            "from": e["authorization"]["from"],
            "to": e["authorization"]["to"],
            "value": int(e["authorization"]["value"]),
            "validAfter": int(e["authorization"]["validAfter"]),
            "validBefore": int(e["authorization"]["validBefore"]),
            "nonce": bytes.fromhex(e["authorization"]["nonce"][2:]),
        }
        full = {
            "domain": e["domain"],
            "types": dict(
                AUTHORIZATION_TYPES,
                EIP712Domain=[
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
            ),
            "primaryType": "TransferWithAuthorization",
            "message": message,
        }
        s = encode_typed_data(full_message=full)
        digest = keccak(b"\x19" + s.version + s.header + s.body)
        assert "0x" + digest.hex() == e["digest"]


class TestBuildPayload:
    def test_full_payload_reproduces_fixture(self) -> None:
        fx = _fx()
        e = fx["eip3009"]
        account = Account.from_key(e["privateKey"])

        # Pin time so validAfter = now - 600 == fixture validAfter.
        valid_after = int(e["authorization"]["validAfter"])
        now = valid_after + 600
        max_timeout = int(e["authorization"]["validBefore"]) - now

        req = PaymentRequirements(
            pay_to=e["authorization"]["to"],
            amount=e["authorization"]["value"],
            asset=e["domain"]["verifyingContract"],
            network="eip155:84532",
            max_timeout_seconds=max_timeout,
            extra_name=e["domain"]["name"],
            extra_version=e["domain"]["version"],
        )
        payload = build_eip3009_payload(
            account, req, now=now, nonce=e["authorization"]["nonce"]
        )
        assert payload["x402Version"] == 2
        assert payload["payload"]["signature"] == e["signature"]
        auth = payload["payload"]["authorization"]
        assert auth["validAfter"] == e["authorization"]["validAfter"]
        assert auth["validBefore"] == e["authorization"]["validBefore"]
        assert auth["nonce"] == e["authorization"]["nonce"]
        assert auth["value"] == e["authorization"]["value"]

    def test_payload_matches_x402_payment_payload_fixture(self) -> None:
        fx = _fx()
        e = fx["eip3009"]
        account = Account.from_key(e["privateKey"])
        valid_after = int(e["authorization"]["validAfter"])
        now = valid_after + 600
        max_timeout = int(e["authorization"]["validBefore"]) - now
        req = PaymentRequirements(
            pay_to=e["authorization"]["to"],
            amount=e["authorization"]["value"],
            asset=e["domain"]["verifyingContract"],
            network="eip155:84532",
            max_timeout_seconds=max_timeout,
            extra_name=e["domain"]["name"],
            extra_version=e["domain"]["version"],
        )
        payload = build_eip3009_payload(
            account, req, now=now, nonce=e["authorization"]["nonce"]
        )
        expected = fx["x402_payment_payload"]
        assert payload["x402Version"] == expected["x402Version"]
        assert payload["payload"]["signature"] == expected["payload"]["signature"]
        # `to` is checksummed by build (getAddress) — compare case-insensitively.
        got = payload["payload"]["authorization"]
        exp = expected["payload"]["authorization"]
        assert got["from"].lower() == exp["from"].lower()
        assert got["to"].lower() == exp["to"].lower()
        for k in ("value", "validAfter", "validBefore", "nonce"):
            assert got[k] == exp[k]


class TestXPaymentHeader:
    def test_header_structure_matches_fixture(self) -> None:
        fx = _fx()
        header = encode_x_payment_header(
            fx["x402_payment_payload"]["payload"], "base-sepolia"
        )
        assert header == fx["x_payment_header_b64"]

    def test_header_decodes_to_expected_envelope(self) -> None:
        fx = _fx()
        header = encode_x_payment_header(
            fx["x402_payment_payload"]["payload"], "base-sepolia"
        )
        padded = header + "=" * (-len(header) % 4)
        decoded = json.loads(base64.b64decode(padded).decode("utf-8"))
        assert decoded["x402Version"] == 2
        assert decoded["scheme"] == "exact"
        assert decoded["network"] == "base-sepolia"
        assert (
            decoded["payload"]["signature"] == fx["eip3009"]["signature"]
        )


class TestChainId:
    def test_caip2_and_alias(self) -> None:
        assert chain_id_for_network("eip155:84532") == 84532
        assert chain_id_for_network("base-sepolia") == 84532
        assert chain_id_for_network("eip155:8453") == 8453
        assert chain_id_for_network("base-mainnet") == 8453


class TestPermit2ApprovalTx:
    def test_selector_and_max_uint(self) -> None:
        fx = _fx()
        usdc = fx["constants"]["usdcBaseSepolia"]
        tx = create_permit2_approval_tx(usdc)
        # approve(address,uint256) selector
        assert tx.data[:10] == "0x095ea7b3"
        # spender = PERMIT2_ADDRESS, amount = MAX_UINT256
        assert PERMIT2_ADDRESS[2:].lower() in tx.data.lower()
        assert tx.data.endswith("f" * 64)
        assert tx.to.lower() == usdc.lower()
