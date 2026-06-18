"""
Wave-2 AIP-16 delivery core byte-exactness vs TS 4.8.0.

Asserts the Python delivery crypto/EIP-712 core produces output BYTE-IDENTICAL
to the TS delivery surface. Golden vectors generated deterministically by
sdk-js/scripts/gen-wave2-delivery-vectors.cjs (real TS functions). A failure
means a Python and a TS agent could not exchange/verify encrypted delivery
envelopes.
"""

import json
from pathlib import Path

import pytest
from eth_account import Account

from agirails.delivery import (
    body_hash,
    bytes_from_hex,
    decrypt_body,
    derive_session_key,
    derive_shared_secret,
    public_key_from_private,
    recover_envelope_signer,
    recover_setup_signer,
    seal_with_nonce,
    sign_envelope,
    sign_setup,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cross_sdk" / "wave2_delivery.json"


@pytest.fixture(scope="module")
def gv() -> dict:
    with open(FIXTURE) as f:
        return json.load(f)


def _b(h: str) -> bytes:
    return bytes_from_hex(h)


class TestX25519ECDH:
    def test_public_key_from_private(self, gv: dict) -> None:
        e = gv["ecdh"]
        assert "0x" + public_key_from_private(_b(e["privA"])).hex() == e["pubA"]
        assert "0x" + public_key_from_private(_b(e["privB"])).hex() == e["pubB"]

    def test_shared_secret_matches_ts(self, gv: dict) -> None:
        e = gv["ecdh"]
        shared = derive_shared_secret(_b(e["privA"]), _b(e["pubB"]))
        assert "0x" + shared.hex() == e["sharedSecret"]

    def test_shared_secret_symmetric(self, gv: dict) -> None:
        e = gv["ecdh"]
        a = derive_shared_secret(_b(e["privA"]), _b(e["pubB"]))
        b = derive_shared_secret(_b(e["privB"]), _b(e["pubA"]))
        assert a == b


class TestHKDFSessionKey:
    def test_v1(self, gv: dict) -> None:
        v = gv["hkdf"]["v1"]
        key = derive_session_key(_b(v["sharedSecret"]), v["txId"])
        assert "0x" + key.hex() == v["sessionKey"]

    def test_v2(self, gv: dict) -> None:
        v = gv["hkdf"]["v2"]
        key = derive_session_key(_b(v["sharedSecret"]), v["txId"])
        assert "0x" + key.hex() == v["sessionKey"]


class TestAESGCM:
    def test_seal_with_aad_matches_ts(self, gv: dict) -> None:
        a = gv["aes_gcm"]
        res = seal_with_nonce(a["plaintext"], _b(a["sessionKey"]), _b(a["nonce"]), _b(a["aad"]))
        assert "0x" + res.ciphertext.hex() == a["with_aad"]["ciphertext"]
        assert "0x" + res.tag.hex() == a["with_aad"]["tag"]

    def test_seal_without_aad_matches_ts(self, gv: dict) -> None:
        a = gv["aes_gcm"]
        res = seal_with_nonce(a["plaintext"], _b(a["sessionKey"]), _b(a["nonce"]), None)
        assert "0x" + res.ciphertext.hex() == a["without_aad"]["ciphertext"]
        assert "0x" + res.tag.hex() == a["without_aad"]["tag"]

    def test_decrypt_ts_ciphertext_roundtrips(self, gv: dict) -> None:
        a = gv["aes_gcm"]
        pt = decrypt_body(
            _b(a["with_aad"]["ciphertext"]),
            _b(a["sessionKey"]),
            _b(a["nonce"]),
            _b(a["with_aad"]["tag"]),
            _b(a["aad"]),
        )
        assert pt.decode("utf-8") == a["plaintext"]

    def test_wrong_aad_fails_closed(self, gv: dict) -> None:
        from agirails.delivery import DeliveryCryptoError

        a = gv["aes_gcm"]
        with pytest.raises(DeliveryCryptoError):
            decrypt_body(
                _b(a["with_aad"]["ciphertext"]),
                _b(a["sessionKey"]),
                _b(a["nonce"]),
                _b(a["with_aad"]["tag"]),
                b"\x00" * 52,  # wrong AAD
            )


class TestBodyHash:
    def test_public_plaintext(self, gv: dict) -> None:
        a = gv["aes_gcm"]
        assert body_hash(a["plaintext"]) == gv["body_hash"]["public_plaintext"]

    def test_encrypted_ciphertext(self, gv: dict) -> None:
        ct = _b(gv["aes_gcm"]["with_aad"]["ciphertext"])
        assert body_hash(ct) == gv["body_hash"]["encrypted_ciphertext"]


class TestDeliveryEIP712:
    def test_setup_signature_matches_ts(self, gv: dict) -> None:
        e = gv["eip712"]
        acct = Account.from_key(e["privateKey"])
        sig = sign_setup(acct, e["setup"]["payload"], e["setup"]["payload"]["kernelAddress"])
        assert sig == e["setup"]["signature"], "DeliverySetup EIP-712 signature diverged from TS"

    def test_setup_recover(self, gv: dict) -> None:
        e = gv["eip712"]
        rec = recover_setup_signer(e["setup"]["payload"], e["setup"]["signature"], e["setup"]["payload"]["kernelAddress"])
        assert rec.lower() == e["signerAddress"].lower()

    def test_envelope_signature_matches_ts(self, gv: dict) -> None:
        e = gv["eip712"]
        acct = Account.from_key(e["privateKey"])
        sig = sign_envelope(acct, e["envelope"]["payload"], e["envelope"]["payload"]["kernelAddress"])
        assert sig == e["envelope"]["signature"], "DeliveryEnvelope EIP-712 signature diverged from TS"

    def test_envelope_recover(self, gv: dict) -> None:
        e = gv["eip712"]
        rec = recover_envelope_signer(e["envelope"]["payload"], e["envelope"]["signature"], e["envelope"]["payload"]["kernelAddress"])
        assert rec.lower() == e["signerAddress"].lower()

    def test_h4_smart_wallet_nonce_none_normalizes_to_zero(self, gv: dict) -> None:
        e = gv["eip712"]
        acct = Account.from_key(e["privateKey"])
        payload = dict(e["setup"]["payload"])
        payload["smartWalletNonce"] = None  # H4: undefined -> 0
        sig = sign_setup(acct, payload, payload["kernelAddress"])
        assert sig == e["setup"]["signature"]
