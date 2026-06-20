"""
Wave-5 AIP-7 §6 ReceiptWriteV2 byte-exactness vs TS 4.8.0.

Asserts the Python ``receipts/push.py`` V2 EIP-712 signing produces output
BYTE-IDENTICAL to ``sdk-js/src/receipts/push.ts``. The golden vector in
tests/fixtures/cross_sdk/wave5_receipts.json was generated from the TS dist
(ethers signTypedData over RECEIPT_WRITE_DOMAIN_V2 + RECEIPT_WRITE_TYPES_V2).
A failure means a Python agent could not produce a receipt signature the
Platform's V2 POST handler accepts.

Oracle facts proven here:
- RECEIPT_WRITE_TYPES_V2 field order/types == fixture (immutable typeHash).
- RECEIPT_WRITE_DOMAIN_V2 == {name:"AGIRAILS Receipts", version:"2"}.
- The EIP-712 digest of the fixture payload == fixture digest byte-for-byte.
- _sign_receipt_write_v2 over the fixture payload == fixture signature, and
  recovers to signerAddress.
- chain_id_for_network: base-sepolia->84532, base-mainnet->8453.
"""

import json
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from agirails.receipts.push import (
    RECEIPT_WRITE_DOMAIN_V2,
    RECEIPT_WRITE_TYPES_V2,
    _sign_receipt_write_v2,
    chain_id_for_network,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cross_sdk" / "wave5_receipts.json"


def _fx() -> dict:
    with open(FIXTURE) as f:
        return json.load(f)["receipt_write_v2"]


def _full_message(fx: dict) -> dict:
    """Reconstruct the exact full EIP-712 message from the fixture payload."""
    p = fx["payload"]
    domain = {
        "name": fx["domain"]["name"],
        "version": fx["domain"]["version"],
        "chainId": fx["domain"]["chainId"],
    }
    message = {
        "signerAddress": p["signerAddress"],
        "participantRole": p["participantRole"],
        "providerAddress": p["providerAddress"],
        "requesterAddress": p["requesterAddress"],
        "kernelAddress": p["kernelAddress"],
        "txId": p["txId"],
        "network": p["network"],
        "amountWei": int(p["amountWei"]),
        "feeWei": int(p["feeWei"]),
        "netWei": int(p["netWei"]),
        "serviceHash": p["serviceHash"],
        "nonce": p["nonce"],
        "issuedAt": int(p["issuedAt"]),
    }
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "ReceiptWriteV2": fx["types"]["ReceiptWriteV2"],
        },
        "primaryType": "ReceiptWriteV2",
        "domain": domain,
        "message": message,
    }


class TestReceiptWriteV2Schema:
    def test_domain_matches_fixture(self) -> None:
        fx = _fx()
        assert RECEIPT_WRITE_DOMAIN_V2["name"] == fx["domain"]["name"]
        assert RECEIPT_WRITE_DOMAIN_V2["version"] == fx["domain"]["version"]
        assert RECEIPT_WRITE_DOMAIN_V2 == {
            "name": "AGIRAILS Receipts",
            "version": "2",
        }

    def test_types_field_order_immutable(self) -> None:
        fx = _fx()
        assert (
            RECEIPT_WRITE_TYPES_V2["ReceiptWriteV2"]
            == fx["types"]["ReceiptWriteV2"]
        )

    def test_field_count_is_thirteen(self) -> None:
        assert len(RECEIPT_WRITE_TYPES_V2["ReceiptWriteV2"]) == 13


class TestChainId:
    def test_network_mapping(self) -> None:
        assert chain_id_for_network("base-sepolia") == 84532
        assert chain_id_for_network("base-mainnet") == 8453


class TestDigestByteExact:
    def test_eip712_digest_matches_fixture(self) -> None:
        fx = _fx()
        s = encode_typed_data(full_message=_full_message(fx))
        digest = "0x" + keccak(b"\x19" + s.version + s.header + s.body).hex()
        assert digest == fx["digest"]


class TestSignatureByteExact:
    def test_signature_matches_fixture(self) -> None:
        fx = _fx()
        account = Account.from_key(fx["privateKey"])
        sig = _sign_receipt_write_v2(account, fx["payload"], fx["payload"]["network"])
        assert sig == fx["signature"]

    def test_signature_recovers_to_signer(self) -> None:
        fx = _fx()
        account = Account.from_key(fx["privateKey"])
        sig = _sign_receipt_write_v2(account, fx["payload"], fx["payload"]["network"])
        s = encode_typed_data(full_message=_full_message(fx))
        recovered = Account.recover_message(s, signature=sig)
        assert recovered == fx["signerAddress"]
        assert recovered.lower() == fx["payload"]["signerAddress"].lower()

    def test_account_address_matches_signer(self) -> None:
        fx = _fx()
        account = Account.from_key(fx["privateKey"])
        assert account.address == fx["signerAddress"]
