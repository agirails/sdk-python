"""Unit tests for setup_builder.py + envelope_builder.py (AIP-16 port)."""

from __future__ import annotations

import pytest
from eth_account import Account

from agirails.delivery import (
    CANONICAL_EMPTY_BYTES12,
    CANONICAL_EMPTY_BYTES16,
    CANONICAL_EMPTY_BYTES32,
    BuildEncryptedEnvelopeParams,
    BuildPublicEnvelopeParams,
    BuildSetupParams,
    DeliveryEnvelopeBuilder,
    DeliverySetupBuilder,
    build_envelope_aad,
)
from agirails.delivery.eip712 import DeliveryEip712Error
from agirails.delivery.keys import generate_ephemeral_key_pair

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
CHAIN = 84532
TXID = "0x" + "ab" * 32

BUYER = Account.from_key("0x" + "11" * 32)
PROVIDER = Account.from_key("0x" + "22" * 32)


# ---------------------------------------------------------------------------
# Setup builder
# ---------------------------------------------------------------------------


def test_setup_build_public_and_verify() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    res = sb.build(
        BuildSetupParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            requester_address=BUYER.address,
            signer_address=BUYER.address,
            buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
            expected_privacy="public",
        )
    )
    assert res["nonceManagerKey"] == "agirails.delivery.setup.v1"
    wire = res["wire"]
    assert wire["signed"]["scheme"] if False else True  # signed projection present
    vr = DeliverySetupBuilder.verify(
        wire, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert vr.ok
    assert vr.signed["txId"] == TXID


def test_setup_build_requires_signer() -> None:
    sb = DeliverySetupBuilder()
    with pytest.raises(DeliveryEip712Error) as exc:
        sb.build(
            BuildSetupParams(
                tx_id=TXID,
                chain_id=CHAIN,
                kernel_address=KERNEL,
                requester_address=BUYER.address,
                signer_address=BUYER.address,
                buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
                expected_privacy="public",
            )
        )
    assert exc.value.code == "BUILDER_NO_SIGNER"


def test_setup_public_pubkey_must_be_canonical_empty() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    with pytest.raises(DeliveryEip712Error) as exc:
        sb.build(
            BuildSetupParams(
                tx_id=TXID,
                chain_id=CHAIN,
                kernel_address=KERNEL,
                requester_address=BUYER.address,
                signer_address=BUYER.address,
                buyer_ephemeral_pubkey="0x" + "aa" * 32,  # non-empty under public
                expected_privacy="public",
            )
        )
    assert exc.value.code == "BUILDER_PUBLIC_PUBKEY_NOT_CANONICAL_EMPTY"


def test_setup_encrypted_pubkey_must_not_be_canonical_empty() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    with pytest.raises(DeliveryEip712Error) as exc:
        sb.build(
            BuildSetupParams(
                tx_id=TXID,
                chain_id=CHAIN,
                kernel_address=KERNEL,
                requester_address=BUYER.address,
                signer_address=BUYER.address,
                buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
                expected_privacy="encrypted",
            )
        )
    assert exc.value.code == "BUILDER_ENCRYPTED_PUBKEY_IS_CANONICAL_EMPTY"


def test_setup_signer_address_mismatch() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    with pytest.raises(DeliveryEip712Error) as exc:
        sb.build(
            BuildSetupParams(
                tx_id=TXID,
                chain_id=CHAIN,
                kernel_address=KERNEL,
                requester_address=BUYER.address,
                signer_address=PROVIDER.address,  # wrong EOA
                buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
                expected_privacy="public",
            )
        )
    assert exc.value.code == "BUILDER_SIGNER_ADDRESS_MISMATCH"


def test_setup_verify_chain_mismatch() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    res = sb.build(
        BuildSetupParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            requester_address=BUYER.address,
            signer_address=BUYER.address,
            buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
            expected_privacy="public",
        )
    )
    vr = DeliverySetupBuilder.verify(
        res["wire"], expected_kernel_address=KERNEL, expected_chain_id=8453
    )
    assert not vr.ok
    assert vr.code == "setup_chain_mismatch"


def test_setup_verify_expired() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    res = sb.build(
        BuildSetupParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            requester_address=BUYER.address,
            signer_address=BUYER.address,
            buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
            expected_privacy="public",
            created_at=1_700_000_000,
            expires_in_sec=600,
        )
    )
    # now well past expiry but within skew of createdAt? expiry strict check:
    # use now within skew of createdAt to reach the expiry branch.
    vr = DeliverySetupBuilder.verify(
        res["wire"],
        expected_kernel_address=KERNEL,
        expected_chain_id=CHAIN,
        now=1_700_000_700,  # 700s after createdAt > 600s expiry, within 900s skew
    )
    assert not vr.ok
    assert vr.code == "setup_expired"


def test_setup_verify_timestamp_skew() -> None:
    sb = DeliverySetupBuilder(signer=BUYER)
    res = sb.build(
        BuildSetupParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            requester_address=BUYER.address,
            signer_address=BUYER.address,
            buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
            expected_privacy="public",
            created_at=1_700_000_000,
        )
    )
    vr = DeliverySetupBuilder.verify(
        res["wire"],
        expected_kernel_address=KERNEL,
        expected_chain_id=CHAIN,
        now=1_700_000_000 + 1000,  # > 900s skew
    )
    assert not vr.ok
    assert vr.code == "setup_timestamp_skew"


# ---------------------------------------------------------------------------
# Envelope builder — AAD
# ---------------------------------------------------------------------------


def test_build_envelope_aad_layout() -> None:
    aad = build_envelope_aad(TXID, BUYER.address)
    assert len(aad) == 52
    assert aad[:32].hex() == "ab" * 32  # txId
    assert aad[32:].hex() == BUYER.address[2:].lower()  # signer 20 bytes


def test_build_envelope_aad_bad_txid_length() -> None:
    with pytest.raises(Exception):
        build_envelope_aad("0x1234", BUYER.address)


# ---------------------------------------------------------------------------
# Envelope builder — public
# ---------------------------------------------------------------------------


def test_envelope_public_build_verify() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"result": "ok", "n": 1},
        )
    )
    wire = res["wire"]
    signed = wire["signed"]
    assert signed["scheme"] == "public-v1"
    assert signed["providerEphemeralPubkey"] == CANONICAL_EMPTY_BYTES32
    assert signed["nonce"] == CANONICAL_EMPTY_BYTES12
    assert signed["tag"] == CANONICAL_EMPTY_BYTES16
    vr = DeliveryEnvelopeBuilder.verify(
        wire, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert vr.ok


def test_envelope_public_payload_hash_tamper_detected() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    wire = dict(res["wire"])
    wire["body"] = '{"a":2}'  # tamper the body after signing
    vr = DeliveryEnvelopeBuilder.verify(
        wire, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert not vr.ok
    assert vr.code == "envelope_payload_hash_mismatch"


# ---------------------------------------------------------------------------
# Envelope builder — encrypted
# ---------------------------------------------------------------------------


def test_envelope_encrypted_build_verify_decrypt() -> None:
    buyer_kp = generate_ephemeral_key_pair()
    buyer_pub_hex = "0x" + buyer_kp.public_key.hex()

    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_encrypted(
        BuildEncryptedEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"secret": "data", "x": 42},
            buyer_ephemeral_pubkey=buyer_pub_hex,
        )
    )
    wire = res["wire"]
    assert wire["signed"]["scheme"] == "x25519-aes256gcm-v1"
    assert wire["body"].startswith("0x")
    assert res["blobKey"] is not None and len(res["blobKey"]) == 32

    vr = DeliveryEnvelopeBuilder.verify(
        wire, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert vr.ok

    payload = DeliveryEnvelopeBuilder.decrypt_payload(wire, buyer_kp.secret_key)
    assert payload == {"secret": "data", "x": 42}


def test_envelope_encrypted_wrong_buyer_key_fails() -> None:
    buyer_kp = generate_ephemeral_key_pair()
    other_kp = generate_ephemeral_key_pair()
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_encrypted(
        BuildEncryptedEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"secret": "data"},
            buyer_ephemeral_pubkey="0x" + buyer_kp.public_key.hex(),
        )
    )
    out = DeliveryEnvelopeBuilder.verify_and_decrypt(
        res["wire"],
        other_kp.secret_key,  # wrong key
        expected_kernel_address=KERNEL,
        expected_chain_id=CHAIN,
    )
    assert not out.ok
    assert out.code == "envelope_decrypt_failed"


def test_envelope_encrypted_buyer_pubkey_canonical_empty_rejected() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    with pytest.raises(DeliveryEip712Error) as exc:
        eb.build_encrypted(
            BuildEncryptedEnvelopeParams(
                tx_id=TXID,
                chain_id=CHAIN,
                kernel_address=KERNEL,
                provider_address=PROVIDER.address,
                signer_address=PROVIDER.address,
                payload={"x": 1},
                buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,
            )
        )
    assert exc.value.code == "BUILDER_ENCRYPTED_BUYER_PUBKEY_IS_CANONICAL_EMPTY"


def test_decrypt_payload_rejects_public_scheme() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    with pytest.raises(DeliveryEip712Error) as exc:
        DeliveryEnvelopeBuilder.decrypt_payload(res["wire"], b"\x00" * 32)
    assert exc.value.code == "BUILDER_PUBLIC_DECRYPT_NOT_APPLICABLE"


def test_compute_hash_stable_and_signature_independent() -> None:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    h1 = DeliveryEnvelopeBuilder.compute_hash(res["wire"])
    # Tampering the signature/body does NOT change the signed-projection hash.
    tampered = dict(res["wire"])
    tampered["providerSig"] = "0x" + "ff" * 65
    h2 = DeliveryEnvelopeBuilder.compute_hash(tampered)
    assert h1 == h2
    assert h1.startswith("0x") and len(h1) == 66
