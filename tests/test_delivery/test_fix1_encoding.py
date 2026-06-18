"""FIX-1 body-encoding tests (AIP-16 Phase 3.5).

Asserts the scheme-dependent ``wire.body`` encoding (envelopeBuilder.ts:25):
  - public-v1: body is the plaintext UTF-8 JSON STRING (NOT hex);
    payloadHash = keccak256(utf8(body)).
  - x25519-aes256gcm-v1: body is 0x-hex of the raw ciphertext;
    payloadHash = keccak256(rawCiphertextBytes).
"""

from __future__ import annotations

from eth_account import Account

from agirails.delivery import (
    BuildEncryptedEnvelopeParams,
    BuildPublicEnvelopeParams,
    DeliveryEnvelopeBuilder,
)
from agirails.delivery.crypto import body_hash, bytes_from_hex
from agirails.delivery.keys import generate_ephemeral_key_pair

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
CHAIN = 84532
TXID = "0x" + "ab" * 32
PROVIDER = Account.from_key("0x" + "22" * 32)


def test_public_body_is_plaintext_json_not_hex() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    payload = {"result": "ok", "n": 1}
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload=payload,
        )
    )
    wire = res["wire"]
    # Body is the plaintext JSON string itself — NOT 0x-hex.
    assert wire["body"] == '{"result":"ok","n":1}'
    assert not wire["body"].startswith("0x")
    # payloadHash = keccak256(utf8(body)).
    assert wire["signed"]["payloadHash"] == body_hash(wire["body"])
    # bodyBytes are the plaintext UTF-8 bytes.
    assert res["bodyBytes"] == wire["body"].encode("utf-8")


def test_encrypted_body_is_hex_ciphertext() -> None:
    buyer_kp = generate_ephemeral_key_pair()
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_encrypted(
        BuildEncryptedEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"secret": "x"},
            buyer_ephemeral_pubkey="0x" + buyer_kp.public_key.hex(),
        )
    )
    wire = res["wire"]
    # Body is 0x-hex of the raw ciphertext bytes.
    assert wire["body"].startswith("0x")
    decoded = bytes_from_hex(wire["body"])
    assert decoded == res["bodyBytes"]
    # payloadHash = keccak256(rawCiphertextBytes).
    assert wire["signed"]["payloadHash"] == body_hash(decoded)
    # Hashing the hex *string* would be a DIFFERENT digest (regression guard).
    assert wire["signed"]["payloadHash"] != body_hash(wire["body"])
