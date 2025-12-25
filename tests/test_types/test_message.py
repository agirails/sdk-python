"""Tests for EIP-712 message types."""

from __future__ import annotations

import json
import warnings
from datetime import datetime
from unittest.mock import patch

import pytest

from agirails.types.message import (
    EIP712Domain,
    ServiceRequest,
    ServiceResponse,
    DeliveryProof,
    SignedMessage,
    TypedData,
    hash_message,
    create_input_hash,
    create_output_hash,
)


class TestEIP712Domain:
    """Tests for EIP712Domain."""

    def test_default_values(self) -> None:
        """Test domain with default values."""
        domain = EIP712Domain()

        assert domain.name == "ACTP"
        assert domain.version == "1"
        assert domain.chain_id == 84532  # Base Sepolia
        assert domain.verifying_contract == ""
        assert domain.salt is None

    def test_custom_values(self) -> None:
        """Test domain with custom values."""
        domain = EIP712Domain(
            name="MyProtocol",
            version="2",
            chain_id=8453,
            verifying_contract="0x1234567890123456789012345678901234567890",
            salt=bytes.fromhex("abcd" * 16),
        )

        assert domain.name == "MyProtocol"
        assert domain.version == "2"
        assert domain.chain_id == 8453
        assert domain.verifying_contract == "0x1234567890123456789012345678901234567890"
        assert domain.salt == bytes.fromhex("abcd" * 16)

    def test_to_dict_minimal(self) -> None:
        """Test to_dict with minimal domain."""
        domain = EIP712Domain()
        result = domain.to_dict()

        assert result["name"] == "ACTP"
        assert result["version"] == "1"
        assert result["chainId"] == 84532
        assert "verifyingContract" not in result
        assert "salt" not in result

    def test_to_dict_full(self) -> None:
        """Test to_dict with all fields."""
        domain = EIP712Domain(
            verifying_contract="0xContract",
            salt=bytes.fromhex("1234" * 16),
        )
        result = domain.to_dict()

        assert result["verifyingContract"] == "0xContract"
        assert result["salt"] == "1234" * 16

    def test_type_definition_minimal(self) -> None:
        """Test type definition for minimal domain."""
        domain = EIP712Domain()
        types = domain.type_definition

        assert len(types) == 3
        assert {"name": "name", "type": "string"} in types
        assert {"name": "version", "type": "string"} in types
        assert {"name": "chainId", "type": "uint256"} in types

    def test_type_definition_full(self) -> None:
        """Test type definition with all fields."""
        domain = EIP712Domain(
            verifying_contract="0xContract",
            salt=b"0" * 32,
        )
        types = domain.type_definition

        assert len(types) == 5
        assert {"name": "verifyingContract", "type": "address"} in types
        assert {"name": "salt", "type": "bytes32"} in types


class TestServiceRequest:
    """Tests for ServiceRequest."""

    def test_basic_creation(self) -> None:
        """Test creating a service request."""
        request = ServiceRequest(
            service="echo",
            input_hash="0x1234",
            budget=1000000,
            deadline=1234567890,
        )

        assert request.service == "echo"
        assert request.input_hash == "0x1234"
        assert request.budget == 1000000
        assert request.deadline == 1234567890
        assert request.requester == ""
        assert request.provider == ""
        assert request.nonce == 0

    def test_full_creation(self) -> None:
        """Test with all fields."""
        request = ServiceRequest(
            service="compute",
            input_hash="0xabcd",
            budget=5000000,
            deadline=9999999999,
            requester="0xRequester",
            provider="0xProvider",
            nonce=42,
        )

        assert request.requester == "0xRequester"
        assert request.provider == "0xProvider"
        assert request.nonce == 42

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        request = ServiceRequest(
            service="test",
            input_hash="0x5678",
            budget=100,
            deadline=1000,
            requester="0xReq",
            provider="0xProv",
            nonce=5,
        )
        result = request.to_dict()

        assert result["service"] == "test"
        assert result["inputHash"] == "0x5678"
        assert result["budget"] == 100
        assert result["deadline"] == 1000
        assert result["requester"] == "0xReq"
        assert result["provider"] == "0xProv"
        assert result["nonce"] == 5

    def test_type_definition(self) -> None:
        """Test type definition is correct."""
        assert ServiceRequest.TYPE_NAME == "ServiceRequest"
        assert len(ServiceRequest.TYPE_DEFINITION) == 7


class TestServiceResponse:
    """Tests for ServiceResponse."""

    def test_basic_creation(self) -> None:
        """Test creating a service response."""
        response = ServiceResponse(
            request_id="0xtx123",
            output_hash="0xoutput",
            status=200,
        )

        assert response.request_id == "0xtx123"
        assert response.output_hash == "0xoutput"
        assert response.status == 200
        assert response.provider == ""
        # timestamp should be set automatically
        assert response.timestamp > 0

    def test_post_init_sets_timestamp(self) -> None:
        """Test that timestamp is set if not provided."""
        before = int(datetime.now().timestamp())
        response = ServiceResponse(
            request_id="0x",
            output_hash="0x",
            status=0,
        )
        after = int(datetime.now().timestamp())

        assert before <= response.timestamp <= after + 1

    def test_explicit_timestamp(self) -> None:
        """Test that explicit timestamp is used."""
        response = ServiceResponse(
            request_id="0x",
            output_hash="0x",
            status=0,
            timestamp=1234567890,
        )

        assert response.timestamp == 1234567890

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        response = ServiceResponse(
            request_id="0xreq",
            output_hash="0xout",
            status=201,
            provider="0xProv",
            timestamp=9999,
        )
        result = response.to_dict()

        assert result["requestId"] == "0xreq"
        assert result["outputHash"] == "0xout"
        assert result["status"] == 201
        assert result["provider"] == "0xProv"
        assert result["timestamp"] == 9999


class TestDeliveryProof:
    """Tests for DeliveryProof."""

    def test_basic_creation(self) -> None:
        """Test creating a delivery proof."""
        proof = DeliveryProof(
            transaction_id="0xtx",
            output_hash="0xhash",
        )

        assert proof.transaction_id == "0xtx"
        assert proof.output_hash == "0xhash"
        assert proof.attestation_uid == ""
        assert proof.provider == ""
        assert proof.timestamp > 0

    def test_full_creation(self) -> None:
        """Test with all fields."""
        proof = DeliveryProof(
            transaction_id="0xtx123",
            output_hash="0xhash456",
            attestation_uid="0xeas789",
            provider="0xProvider",
            timestamp=1000000,
        )

        assert proof.attestation_uid == "0xeas789"
        assert proof.provider == "0xProvider"
        assert proof.timestamp == 1000000

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        proof = DeliveryProof(
            transaction_id="0xtx",
            output_hash="0xhash",
            attestation_uid="0xuid",
            provider="0xprov",
            timestamp=5000,
        )
        result = proof.to_dict()

        assert result["transactionId"] == "0xtx"
        assert result["outputHash"] == "0xhash"
        assert result["attestationUid"] == "0xuid"
        assert result["provider"] == "0xprov"
        assert result["timestamp"] == 5000


class TestSignedMessage:
    """Tests for SignedMessage."""

    def test_basic_creation(self) -> None:
        """Test creating an unsigned message."""
        domain = EIP712Domain()
        message = SignedMessage(
            domain=domain,
            message={"key": "value"},
            message_type="TestMessage",
        )

        assert message.domain == domain
        assert message.message == {"key": "value"}
        assert message.message_type == "TestMessage"
        assert message.signature == ""
        assert message.signer == ""

    def test_is_signed_false(self) -> None:
        """Test is_signed returns False for unsigned message."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
        )

        assert message.is_signed is False

    def test_is_signed_true(self) -> None:
        """Test is_signed returns True for signed message."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
            signature="0xsig",
            signer="0xaddr",
        )

        assert message.is_signed is True

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        domain = EIP712Domain(chain_id=1)
        message = SignedMessage(
            domain=domain,
            message={"data": 123},
            message_type="DataMessage",
            signature="0xsignature",
            signer="0xsigner",
        )
        result = message.to_dict()

        assert result["domain"]["chainId"] == 1
        assert result["message"] == {"data": 123}
        assert result["messageType"] == "DataMessage"
        assert result["signature"] == "0xsignature"
        assert result["signer"] == "0xsigner"

    def test_verify_unsigned_returns_false(self) -> None:
        """Test verify returns False for unsigned message."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
        )

        assert message.verify() is False

    def test_verify_wrong_signer_returns_false(self) -> None:
        """Test verify returns False when signer doesn't match."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
            signature="0xsig",
            signer="0xactual",
        )

        assert message.verify(expected_signer="0xexpected") is False

    def test_verify_emits_warning(self) -> None:
        """Test verify emits warning about not being cryptographic."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
            signature="0xsig",
            signer="0xsigner",
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = message.verify()

            assert result is True
            assert len(w) == 1
            assert "does not perform cryptographic verification" in str(w[0].message)

    def test_verify_case_insensitive_signer(self) -> None:
        """Test verify handles case-insensitive signer comparison."""
        message = SignedMessage(
            domain=EIP712Domain(),
            message={},
            message_type="Test",
            signature="0xsig",
            signer="0xABCDEF",
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert message.verify(expected_signer="0xabcdef") is True


class TestTypedData:
    """Tests for TypedData."""

    def test_from_request(self) -> None:
        """Test creating TypedData from ServiceRequest."""
        domain = EIP712Domain()
        request = ServiceRequest(
            service="test",
            input_hash="0x123",
            budget=100,
            deadline=1000,
        )

        typed_data = TypedData.from_request(request, domain)

        assert typed_data.primary_type == "ServiceRequest"
        assert "ServiceRequest" in typed_data.types
        assert "EIP712Domain" in typed_data.types
        assert typed_data.message["service"] == "test"

    def test_from_response(self) -> None:
        """Test creating TypedData from ServiceResponse."""
        domain = EIP712Domain()
        response = ServiceResponse(
            request_id="0xreq",
            output_hash="0xout",
            status=200,
            timestamp=5000,
        )

        typed_data = TypedData.from_response(response, domain)

        assert typed_data.primary_type == "ServiceResponse"
        assert "ServiceResponse" in typed_data.types
        assert typed_data.message["requestId"] == "0xreq"

    def test_from_proof(self) -> None:
        """Test creating TypedData from DeliveryProof."""
        domain = EIP712Domain()
        proof = DeliveryProof(
            transaction_id="0xtx",
            output_hash="0xhash",
            timestamp=3000,
        )

        typed_data = TypedData.from_proof(proof, domain)

        assert typed_data.primary_type == "DeliveryProof"
        assert "DeliveryProof" in typed_data.types
        assert typed_data.message["transactionId"] == "0xtx"

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        domain = EIP712Domain()
        request = ServiceRequest(
            service="svc",
            input_hash="0x",
            budget=0,
            deadline=0,
        )
        typed_data = TypedData.from_request(request, domain)

        result = typed_data.to_dict()

        assert "types" in result
        assert "primaryType" in result
        assert "domain" in result
        assert "message" in result
        assert result["primaryType"] == "ServiceRequest"


class TestHashFunctions:
    """Tests for hash utility functions."""

    def test_hash_message_deterministic(self) -> None:
        """Test hash_message returns consistent results."""
        message = {"a": 1, "b": 2}

        hash1 = hash_message(message)
        hash2 = hash_message(message)

        assert hash1 == hash2
        assert hash1.startswith("0x")

    def test_hash_message_different_for_different_input(self) -> None:
        """Test different messages produce different hashes."""
        hash1 = hash_message({"a": 1})
        hash2 = hash_message({"a": 2})

        assert hash1 != hash2

    def test_hash_message_order_independent(self) -> None:
        """Test hash is consistent regardless of key order."""
        hash1 = hash_message({"a": 1, "b": 2})
        hash2 = hash_message({"b": 2, "a": 1})

        assert hash1 == hash2

    def test_create_input_hash_string(self) -> None:
        """Test create_input_hash with string input."""
        result = create_input_hash("test input")

        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_create_input_hash_dict(self) -> None:
        """Test create_input_hash with dict input."""
        result = create_input_hash({"key": "value"})

        assert result.startswith("0x")
        assert len(result) == 66

    def test_create_input_hash_deterministic(self) -> None:
        """Test create_input_hash returns consistent results."""
        data = {"input": "data", "nested": {"key": "value"}}

        hash1 = create_input_hash(data)
        hash2 = create_input_hash(data)

        assert hash1 == hash2

    def test_create_output_hash_same_as_input(self) -> None:
        """Test create_output_hash uses same algorithm as create_input_hash."""
        data = "test data"

        input_hash = create_input_hash(data)
        output_hash = create_output_hash(data)

        assert input_hash == output_hash
