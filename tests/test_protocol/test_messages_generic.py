"""Parity tests for the generic ACTPMessage surface on MessageSigner.

Covers sign_message / sign_quote_request / sign_quote_response /
verify_message(_or_raise) + ReceivedNonceTracker integration, mirroring
sdk-js/src/protocol/MessageSigner.ts.
"""

import pytest
from eth_account import Account

from agirails.errors import SignatureVerificationError
from agirails.protocol.messages import (
    ACTP_MESSAGE_TYPE_DEFINITION,
    QUOTE_REQUEST_TYPE_DEFINITION,
    QUOTE_RESPONSE_TYPE_DEFINITION,
    MessageSigner,
)
from agirails.utils.received_nonce_tracker import (
    InMemoryReceivedNonceTracker,
    SetBasedReceivedNonceTracker,
)


SECURE_NONCE = "0x" + "a1b2c3d4e5f6071829304a5b6c7d8e9f" * 2  # high-entropy bytes32


def _make_signer(nonce_tracker=None) -> MessageSigner:
    acct = Account.create()
    return MessageSigner(
        private_key=acct.key.hex(),
        chain_id=84532,
        verifying_contract="0x" + "11" * 20,
        nonce_tracker=nonce_tracker,
    )


def _msg(signer: MessageSigner, nonce: str = SECURE_NONCE, **payload) -> dict:
    base = {
        "type": "quote.request",
        "version": "1.0",
        "from": signer.address,
        "to": "0x" + "22" * 20,
        "timestamp": 1700000000,
        "nonce": nonce,
    }
    base.update(payload)
    return base


class TestTypeDefinitions:
    """The EIP-712 type defs must be byte-identical to eip712.ts."""

    def test_actp_message_type(self) -> None:
        names = [t["name"] for t in ACTP_MESSAGE_TYPE_DEFINITION]
        assert names == ["type", "version", "from", "to", "timestamp", "nonce", "payload"]
        assert ACTP_MESSAGE_TYPE_DEFINITION[-1]["type"] == "bytes"
        assert ACTP_MESSAGE_TYPE_DEFINITION[5]["type"] == "bytes32"  # nonce

    def test_quote_request_type(self) -> None:
        names = [t["name"] for t in QUOTE_REQUEST_TYPE_DEFINITION]
        assert names == [
            "from", "to", "timestamp", "nonce",
            "serviceType", "requirements", "deadline", "disputeWindow",
        ]

    def test_quote_response_type(self) -> None:
        names = [t["name"] for t in QUOTE_RESPONSE_TYPE_DEFINITION]
        assert names == [
            "from", "to", "timestamp", "nonce",
            "requestId", "price", "currency", "deliveryTime", "terms",
        ]


class TestSignMessage:
    def test_sign_and_verify_round_trip(self) -> None:
        signer = _make_signer()
        msg = _msg(signer, service="echo", budget="1000000")
        sig = signer.sign_message(msg)
        assert sig.startswith("0x")
        assert len(sig) == 132  # 0x + 65 bytes
        assert signer.verify_message(msg, sig) is True

    def test_deterministic_payload_order_independent(self) -> None:
        """Payload key order must not change the signature (recursive sort)."""
        signer = _make_signer()
        m1 = _msg(signer, a=1, b=2, c={"y": 1, "x": 2})
        m2 = _msg(signer, c={"x": 2, "y": 1}, b=2, a=1)
        assert signer.sign_message(m1) == signer.sign_message(m2)

    def test_tampered_payload_fails_verify(self) -> None:
        signer = _make_signer()
        msg = _msg(signer, value=1)
        sig = signer.sign_message(msg)
        tampered = dict(msg)
        tampered["value"] = 2
        assert signer.verify_message(tampered, sig) is False

    def test_invalid_nonce_format_raises(self) -> None:
        signer = _make_signer()
        with pytest.raises(ValueError, match="nonce format"):
            signer.sign_message(_msg(signer, nonce="0x1234"))

    def test_missing_nonce_raises(self) -> None:
        signer = _make_signer()
        bad = _msg(signer)
        del bad["nonce"]
        with pytest.raises(ValueError, match="nonce format"):
            signer.sign_message(bad)

    def test_low_entropy_nonce_warns_but_signs(self) -> None:
        """Sequential nonce must warn (not raise) and still produce a signature."""
        signer = _make_signer()
        seq = "0x" + format(5, "064x")
        sig = signer.sign_message(_msg(signer, nonce=seq))
        assert sig.startswith("0x")

    def test_did_from_verifies(self) -> None:
        """A DID `from` (did:ethr:<chainId>:<addr>) must verify against signer."""
        signer = _make_signer()
        did = signer.address_to_did(signer.address)
        msg = _msg(signer, x=1)
        msg["from"] = did
        sig = signer.sign_message(msg)
        assert signer.verify_message(msg, sig) is True


class TestSignQuoteRequestResponse:
    def test_sign_quote_request(self) -> None:
        signer = _make_signer()
        data = {
            "from": signer.address,
            "to": "0x" + "22" * 20,
            "timestamp": 1,
            "nonce": SECURE_NONCE,
            "serviceType": "text-generation",
            "requirements": "{}",
            "deadline": 2,
            "disputeWindow": 3,
        }
        sig = signer.sign_quote_request(data)
        assert sig.startswith("0x") and len(sig) == 132

    def test_sign_quote_response(self) -> None:
        signer = _make_signer()
        data = {
            "from": signer.address,
            "to": "0x" + "22" * 20,
            "timestamp": 1,
            "nonce": SECURE_NONCE,
            "requestId": "0x" + "33" * 32,
            "price": 5,
            "currency": "0x" + "44" * 20,
            "deliveryTime": 10,
            "terms": "net30",
        }
        sig = signer.sign_quote_response(data)
        assert sig.startswith("0x") and len(sig) == 132

    def test_quote_request_recovers_to_signer(self) -> None:
        """Recovering the QuoteRequest signature should yield the signer addr."""
        signer = _make_signer()
        data = {
            "from": signer.address,
            "to": "0x" + "22" * 20,
            "timestamp": 1,
            "nonce": SECURE_NONCE,
            "serviceType": "x",
            "requirements": "{}",
            "deadline": 2,
            "disputeWindow": 3,
        }
        sig = signer.sign_quote_request(data)
        typed = signer._build_typed_data(
            "QuoteRequest", QUOTE_REQUEST_TYPE_DEFINITION, data
        )
        recovered = MessageSigner.recover_signer(typed, sig)
        assert recovered.lower() == signer.address.lower()


class TestDidConversion:
    def test_address_to_did_canonical(self) -> None:
        signer = _make_signer()
        did = signer.address_to_did(signer.address)
        assert did == f"did:ethr:84532:{signer.address}"

    def test_address_to_did_legacy_without_chain(self) -> None:
        acct = Account.create()
        signer = MessageSigner(private_key=acct.key.hex(), chain_id=0)
        did = signer.address_to_did(signer.address)
        assert did == f"did:ethr:{signer.address}"

    def test_did_to_address_canonical(self) -> None:
        addr = "0x" + "ab" * 20
        assert MessageSigner._did_to_address(f"did:ethr:84532:{addr}") == addr

    def test_did_to_address_legacy(self) -> None:
        addr = "0x" + "cd" * 20
        assert MessageSigner._did_to_address(f"did:ethr:{addr}") == addr

    def test_did_to_address_raw(self) -> None:
        addr = "0x" + "ef" * 20
        assert MessageSigner._did_to_address(addr) == addr

    def test_did_to_address_bad_chain_id(self) -> None:
        with pytest.raises(ValueError, match="not a number"):
            MessageSigner._did_to_address("did:ethr:notanum:0x" + "11" * 20)

    def test_address_to_did_invalid(self) -> None:
        signer = _make_signer()
        with pytest.raises(ValueError, match="Invalid Ethereum address"):
            signer.address_to_did("0xnope")


class TestNonceTrackerIntegration:
    def test_replay_detected(self) -> None:
        tracker = InMemoryReceivedNonceTracker()
        signer = _make_signer(nonce_tracker=tracker)
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        assert signer.verify_message(msg, sig) is True
        # Same nonce again -> replay -> False
        assert signer.verify_message(msg, sig) is False

    def test_no_tracker_allows_repeat(self) -> None:
        signer = _make_signer()  # no tracker
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        assert signer.verify_message(msg, sig) is True
        assert signer.verify_message(msg, sig) is True  # no replay protection

    def test_set_based_tracker_replay(self) -> None:
        tracker = SetBasedReceivedNonceTracker()
        signer = _make_signer(nonce_tracker=tracker)
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        assert signer.verify_message(msg, sig) is True
        assert signer.verify_message(msg, sig) is False

    def test_verify_or_raise_signer_mismatch(self) -> None:
        signer = _make_signer()
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        tampered = dict(msg)
        tampered["from"] = "0x" + "99" * 20
        with pytest.raises(SignatureVerificationError):
            signer.verify_message_or_raise(tampered, sig)

    def test_verify_or_raise_replay(self) -> None:
        tracker = InMemoryReceivedNonceTracker()
        signer = _make_signer(nonce_tracker=tracker)
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        signer.verify_message_or_raise(msg, sig)  # first ok
        with pytest.raises(ValueError, match="replay"):
            signer.verify_message_or_raise(msg, sig)

    def test_verify_or_raise_success(self) -> None:
        signer = _make_signer()
        msg = _msg(signer, x=1)
        sig = signer.sign_message(msg)
        # Should not raise
        signer.verify_message_or_raise(msg, sig)
