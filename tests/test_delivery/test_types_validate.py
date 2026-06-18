"""Unit tests for delivery/types.py + delivery/validate.py (AIP-16 port)."""

from __future__ import annotations

import pytest

from agirails.delivery import (
    CANONICAL_EMPTY_BYTES12,
    CANONICAL_EMPTY_BYTES16,
    CANONICAL_EMPTY_BYTES32,
    DELIVERY_NONCE_KEY_ENVELOPE,
    DELIVERY_NONCE_KEY_SETUP,
    is_canonical_empty_bytes12,
    is_canonical_empty_bytes16,
    is_canonical_empty_bytes32,
    is_valid_address,
    is_valid_bytes12,
    is_valid_bytes16,
    is_valid_bytes32,
    is_valid_privacy,
    is_valid_role,
    is_valid_scheme,
    is_valid_uint_string,
    validate_envelope_signed,
    validate_envelope_wire,
    validate_scheme_consistency,
    validate_setup_signed,
    validate_setup_wire,
)

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
TXID = "0x" + "ab" * 32
SIG = "0x" + "11" * 65  # 65-byte signature shape


# ---------------------------------------------------------------------------
# Canonical-empty constants
# ---------------------------------------------------------------------------


def test_canonical_empty_constants_lengths() -> None:
    assert CANONICAL_EMPTY_BYTES32 == "0x" + "00" * 32
    assert CANONICAL_EMPTY_BYTES12 == "0x" + "00" * 12
    assert CANONICAL_EMPTY_BYTES16 == "0x" + "00" * 16


def test_nonce_keys() -> None:
    assert DELIVERY_NONCE_KEY_SETUP == "agirails.delivery.setup.v1"
    assert DELIVERY_NONCE_KEY_ENVELOPE == "agirails.delivery.envelope.v1"
    assert DELIVERY_NONCE_KEY_SETUP != DELIVERY_NONCE_KEY_ENVELOPE


# ---------------------------------------------------------------------------
# Primitive validators
# ---------------------------------------------------------------------------


def test_is_valid_bytes_lengths() -> None:
    assert is_valid_bytes32("0x" + "a" * 64)
    assert not is_valid_bytes32("0x" + "a" * 63)
    assert is_valid_bytes12("0x" + "a" * 24)
    assert not is_valid_bytes12("0x" + "a" * 23)
    assert is_valid_bytes16("0x" + "a" * 32)
    assert not is_valid_bytes16("0x" + "a" * 31)


def test_is_valid_address_lowercase_and_checksum() -> None:
    assert is_valid_address(KERNEL)  # good checksum
    assert is_valid_address(KERNEL.lower())  # all lowercase
    assert is_valid_address("0x" + KERNEL[2:].upper())  # all uppercase
    # Mixed-case with wrong checksum must be rejected (ethers.isAddress parity).
    bad = "0x469CBADBACFFE096270594F0a31f0EEC53753411"
    assert not is_valid_address(bad)
    assert not is_valid_address("notanaddress")


def test_is_valid_uint_string() -> None:
    assert is_valid_uint_string("0")
    assert is_valid_uint_string("12345")
    assert not is_valid_uint_string("01")  # leading zero
    assert not is_valid_uint_string("-1")
    assert not is_valid_uint_string(5)  # not a string


def test_scheme_privacy_role_validators() -> None:
    assert is_valid_scheme("public-v1")
    assert is_valid_scheme("x25519-aes256gcm-v1")
    assert not is_valid_scheme("nope")
    assert is_valid_privacy("public") and is_valid_privacy("encrypted")
    assert not is_valid_privacy("secret")
    assert is_valid_role("provider") and is_valid_role("requester")
    assert not is_valid_role("relay")


def test_canonical_empty_checks() -> None:
    assert is_canonical_empty_bytes32(CANONICAL_EMPTY_BYTES32)
    assert is_canonical_empty_bytes12(CANONICAL_EMPTY_BYTES12)
    assert is_canonical_empty_bytes16(CANONICAL_EMPTY_BYTES16)
    assert not is_canonical_empty_bytes32("0x" + "11" * 32)


# ---------------------------------------------------------------------------
# Setup signed / wire validators
# ---------------------------------------------------------------------------


def _good_setup_signed() -> dict:
    return {
        "version": 1,
        "txId": TXID,
        "chainId": 84532,
        "kernelAddress": KERNEL,
        "requesterAddress": KERNEL,
        "signerAddress": KERNEL,
        "buyerEphemeralPubkey": CANONICAL_EMPTY_BYTES32,
        "acceptedChannels": ["agirails-relay-v1"],
        "expectedPrivacy": "public",
        "createdAt": 1_700_000_000,
        "expiresAt": 1_700_003_600,
        "smartWalletNonce": 0,
    }


def test_validate_setup_signed_ok() -> None:
    assert validate_setup_signed(_good_setup_signed()).ok


@pytest.mark.parametrize(
    "mutate,expected_error",
    [
        (lambda s: s.update(version=2), "setup_version_invalid"),
        (lambda s: s.update(txId="0x1234"), "setup_txid_invalid"),
        (lambda s: s.update(chainId=0), "setup_chain_id_invalid"),
        (lambda s: s.update(kernelAddress="0xbad"), "setup_kernel_address_invalid"),
        (lambda s: s.update(expectedPrivacy="weird"), "setup_expected_privacy_invalid"),
        (lambda s: s.update(acceptedChannels=[]), "setup_accepted_channels_invalid"),
        (lambda s: s.update(expiresAt=s["createdAt"]), "expiresAt_before_createdAt"),
    ],
)
def test_validate_setup_signed_failures(mutate, expected_error) -> None:
    s = _good_setup_signed()
    mutate(s)
    result = validate_setup_signed(s)
    assert not result.ok
    assert result.error == expected_error


def test_validate_setup_signed_not_object() -> None:
    assert validate_setup_signed("nope").error == "setup_signed_not_object"


def test_validate_setup_wire_ok_and_sig() -> None:
    wire = {"signed": _good_setup_signed(), "requesterSig": SIG}
    assert validate_setup_wire(wire).ok
    bad = {"signed": _good_setup_signed(), "requesterSig": "0x1234"}
    assert validate_setup_wire(bad).error == "setup_requester_sig_invalid"


# ---------------------------------------------------------------------------
# Envelope signed / wire validators + scheme consistency
# ---------------------------------------------------------------------------


def _good_public_envelope_signed() -> dict:
    return {
        "version": 1,
        "txId": TXID,
        "chainId": 84532,
        "kernelAddress": KERNEL,
        "providerAddress": KERNEL,
        "signerAddress": KERNEL,
        "scheme": "public-v1",
        "providerEphemeralPubkey": CANONICAL_EMPTY_BYTES32,
        "nonce": CANONICAL_EMPTY_BYTES12,
        "payloadHash": "0x" + "cd" * 32,
        "tag": CANONICAL_EMPTY_BYTES16,
        "createdAt": 1_700_000_000,
        "smartWalletNonce": 0,
    }


def _good_encrypted_envelope_signed() -> dict:
    return {
        "version": 1,
        "txId": TXID,
        "chainId": 84532,
        "kernelAddress": KERNEL,
        "providerAddress": KERNEL,
        "signerAddress": KERNEL,
        "scheme": "x25519-aes256gcm-v1",
        "providerEphemeralPubkey": "0x" + "22" * 32,
        "nonce": "0x" + "33" * 12,
        "payloadHash": "0x" + "cd" * 32,
        "tag": "0x" + "44" * 16,
        "createdAt": 1_700_000_000,
        "smartWalletNonce": 0,
    }


def test_validate_envelope_signed_public_ok() -> None:
    assert validate_envelope_signed(_good_public_envelope_signed()).ok


def test_validate_envelope_signed_encrypted_ok() -> None:
    assert validate_envelope_signed(_good_encrypted_envelope_signed()).ok


def test_scheme_consistency_public_requires_canonical_empty() -> None:
    s = _good_public_envelope_signed()
    s["nonce"] = "0x" + "33" * 12  # non-empty nonce under public-v1
    result = validate_scheme_consistency(s)
    assert not result.ok
    assert result.error == "envelope_public_nonce_not_canonical_empty"


def test_scheme_consistency_encrypted_rejects_canonical_empty() -> None:
    s = _good_encrypted_envelope_signed()
    s["providerEphemeralPubkey"] = CANONICAL_EMPTY_BYTES32
    result = validate_scheme_consistency(s)
    assert not result.ok
    assert result.error == "envelope_encrypted_pubkey_is_canonical_empty"


def test_validate_envelope_wire_ok_and_body() -> None:
    wire = {
        "signed": _good_public_envelope_signed(),
        "body": "{}",
        "providerSig": SIG,
    }
    assert validate_envelope_wire(wire).ok
    wire_empty = {**wire, "body": ""}
    assert validate_envelope_wire(wire_empty).error == "envelope_body_invalid"
