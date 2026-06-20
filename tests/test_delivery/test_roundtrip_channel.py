"""Full end-to-end delivery round-trip through MockDeliveryChannel.

Flow (both schemes):
  buyer builds + posts setup  ->  provider reads setup, builds + posts envelope
  ->  buyer reads envelope, verifies signature, recovers the plaintext.

Asserts the recovered payload equals the original and that signatures verify
end-to-end. Covers public-v1 AND x25519-aes256gcm-v1.
"""

from __future__ import annotations

import asyncio

import pytest
from eth_account import Account

from agirails.delivery import (
    CANONICAL_EMPTY_BYTES32,
    BuildEncryptedEnvelopeParams,
    BuildPublicEnvelopeParams,
    BuildSetupParams,
    DeliveryEnvelopeBuilder,
    DeliverySetupBuilder,
    MockDeliveryChannel,
)
from agirails.delivery.keys import generate_ephemeral_key_pair

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
CHAIN = 84532
TXID = "0x" + "ab" * 32

BUYER = Account.from_key("0x" + "11" * 32)
PROVIDER = Account.from_key("0x" + "22" * 32)


async def _drain() -> None:
    """Let deferred fan-out / replay microtasks run."""
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_public_roundtrip_through_mock_channel() -> None:
    channel = MockDeliveryChannel()

    # --- buyer publishes a public setup ---
    sb = DeliverySetupBuilder(signer=BUYER)
    setup = sb.build(
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

    received_setups = []
    setup_sub = await channel.subscribe_setups(
        TXID, lambda w: received_setups.append(w)
    )
    await channel.publish_setup(setup["wire"])
    await _drain()
    assert len(received_setups) == 1

    # --- provider reads setup, verifies it, builds + posts a public envelope ---
    seen_setup = received_setups[0]
    sv = DeliverySetupBuilder.verify(
        seen_setup, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert sv.ok

    original = {"result": "delivered", "items": [1, 2, 3]}
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    env = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload=original,
        )
    )

    received_envs = []
    env_sub = await channel.subscribe_envelopes(
        TXID, lambda w: received_envs.append(w)
    )
    await channel.publish_envelope(env["wire"])
    await _drain()
    assert len(received_envs) == 1

    # --- buyer opens the envelope, recovers the plaintext ---
    out = DeliveryEnvelopeBuilder.verify_and_decrypt(
        received_envs[0],
        b"\x00" * 32,  # unused for public
        expected_kernel_address=KERNEL,
        expected_chain_id=CHAIN,
    )
    assert out.ok
    assert out.payload == original

    setup_sub.close()
    env_sub.close()
    await channel.close()


@pytest.mark.asyncio
async def test_encrypted_roundtrip_through_mock_channel() -> None:
    channel = MockDeliveryChannel()

    # --- buyer generates an ephemeral keypair + publishes an encrypted setup ---
    buyer_kp = generate_ephemeral_key_pair()
    buyer_pub_hex = "0x" + buyer_kp.public_key.hex()

    sb = DeliverySetupBuilder(signer=BUYER)
    setup = sb.build(
        BuildSetupParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            requester_address=BUYER.address,
            signer_address=BUYER.address,
            buyer_ephemeral_pubkey=buyer_pub_hex,
            expected_privacy="encrypted",
        )
    )

    received_setups = []
    setup_sub = await channel.subscribe_setups(
        TXID, lambda w: received_setups.append(w)
    )
    await channel.publish_setup(setup["wire"])
    await _drain()
    assert len(received_setups) == 1

    # --- provider reads buyer pubkey from setup, builds encrypted envelope ---
    seen_setup = received_setups[0]
    sv = DeliverySetupBuilder.verify(
        seen_setup, expected_kernel_address=KERNEL, expected_chain_id=CHAIN
    )
    assert sv.ok
    buyer_pub_from_setup = sv.signed["buyerEphemeralPubkey"]

    original = {"secret": "encrypted payload", "value": 9999, "nested": {"k": "v"}}
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    env = eb.build_encrypted(
        BuildEncryptedEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload=original,
            buyer_ephemeral_pubkey=buyer_pub_from_setup,
        )
    )

    received_envs = []
    env_sub = await channel.subscribe_envelopes(
        TXID, lambda w: received_envs.append(w)
    )
    await channel.publish_envelope(env["wire"])
    await _drain()
    assert len(received_envs) == 1

    # --- buyer opens the envelope with its ephemeral PRIVATE key ---
    out = DeliveryEnvelopeBuilder.verify_and_decrypt(
        received_envs[0],
        buyer_kp.secret_key,
        expected_kernel_address=KERNEL,
        expected_chain_id=CHAIN,
    )
    assert out.ok
    assert out.payload == original

    setup_sub.close()
    env_sub.close()
    await channel.close()


@pytest.mark.asyncio
async def test_mock_channel_replay_on_subscribe() -> None:
    """Subscribers receive the full historical set (publish-then-subscribe)."""
    channel = MockDeliveryChannel()
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    env = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    # Publish BEFORE any subscriber exists.
    await channel.publish_envelope(env["wire"])

    received = []
    sub = await channel.subscribe_envelopes(TXID, lambda w: received.append(w))
    await _drain()
    assert len(received) == 1  # replayed
    sub.close()
    await channel.close()


@pytest.mark.asyncio
async def test_mock_channel_subscriber_error_isolation() -> None:
    """A throwing subscriber must not prevent a healthy one from receiving."""
    channel = MockDeliveryChannel()

    def bad(_w):
        raise RuntimeError("boom")

    good_received = []
    bad_sub = await channel.subscribe_envelopes(TXID, bad)
    good_sub = await channel.subscribe_envelopes(
        TXID, lambda w: good_received.append(w)
    )

    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    env = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    await channel.publish_envelope(env["wire"])
    await _drain()
    assert len(good_received) == 1  # healthy subscriber unaffected

    bad_sub.close()
    good_sub.close()
    await channel.close()


@pytest.mark.asyncio
async def test_mock_channel_rejects_tampered_envelope_on_publish() -> None:
    """Channel verifies on publish (dedup-after-verify): a tampered body is rejected."""
    channel = MockDeliveryChannel()
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    env = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    tampered = dict(env["wire"])
    tampered["body"] = '{"a":2}'  # invalidates payloadHash binding
    with pytest.raises(RuntimeError) as exc:
        await channel.publish_envelope(tampered)
    assert "envelope_payload_hash_mismatch" in str(exc.value)
    await channel.close()
