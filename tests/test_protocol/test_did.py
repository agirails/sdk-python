"""Tests for DID Manager and related functionality."""

import pytest

from agirails.types.did import (
    AgentDID,
    DIDDocument,
    is_valid_did,
    parse_did,
)
from agirails.protocol.did import (
    DIDManager,
    DIDResolver,
    VerificationMethod,
    ServiceEndpoint,
    create_did_from_address,
    did_to_address,
)


class TestAgentDID:
    """Tests for AgentDID class."""

    def test_create_did(self) -> None:
        """Test creating a DID."""
        did = AgentDID(
            method="agirails",
            network="base-sepolia",
            identifier="0x" + "a" * 40,
        )

        assert did.method == "agirails"
        assert did.network == "base-sepolia"
        assert did.identifier == "0x" + "a" * 40

    def test_str_representation(self) -> None:
        """Test string representation."""
        did = AgentDID(
            method="agirails",
            network="base-sepolia",
            identifier="0x" + "a" * 40,
        )

        assert str(did) == f"did:agirails:base-sepolia:0x{'a' * 40}"

    def test_from_string(self) -> None:
        """Test parsing DID from string."""
        did_string = f"did:agirails:base-sepolia:0x{'b' * 40}"
        did = AgentDID.from_string(did_string)

        assert did.method == "agirails"
        assert did.network == "base-sepolia"
        assert did.identifier == "0x" + "b" * 40

    def test_from_string_invalid(self) -> None:
        """Test parsing invalid DID string."""
        with pytest.raises(ValueError):
            AgentDID.from_string("not-a-valid-did")

    def test_from_address(self) -> None:
        """Test creating DID from address."""
        address = "0x" + "c" * 40
        did = AgentDID.from_address(address, network="base")

        assert did.method == "agirails"
        assert did.network == "base"
        assert did.identifier == address

    def test_from_address_without_0x(self) -> None:
        """Test creating DID from address without 0x prefix."""
        address = "a" * 40
        did = AgentDID.from_address(address)

        assert did.identifier == "0x" + "a" * 40

    def test_equality(self) -> None:
        """Test DID equality."""
        did1 = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)
        did2 = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)
        did3 = AgentDID(method="agirails", network="base", identifier="0x" + "b" * 40)

        assert did1 == did2
        assert did1 != did3

    def test_hash(self) -> None:
        """Test DID is hashable."""
        did = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)

        # Should be hashable
        hash(did)

        # Should work in sets
        did_set = {did}
        assert did in did_set

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        did = AgentDID(method="agirails", network="base-sepolia", identifier="0x" + "a" * 40)
        d = did.to_dict()

        assert d["method"] == "agirails"
        assert d["network"] == "base-sepolia"
        assert d["identifier"] == "0x" + "a" * 40
        assert "did" in d


class TestDIDDocument:
    """Tests for DIDDocument class."""

    def test_create_document(self) -> None:
        """Test creating a DID Document."""
        did = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)

        doc = DIDDocument(id=did)

        assert doc.id == did
        assert doc.controller == did  # Defaults to self
        assert doc.created is not None

    def test_document_with_all_fields(self) -> None:
        """Test creating document with all fields."""
        did = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)

        doc = DIDDocument(
            id=did,
            verification_method=[
                {"id": f"{did}#key-1", "type": "EcdsaSecp256k1VerificationKey2019"}
            ],
            authentication=[f"{did}#key-1"],
            service=[
                {"id": f"{did}#api", "type": "AgentAPI", "serviceEndpoint": "https://api.example.com"}
            ],
            metadata={"version": 1},
        )

        assert doc.verification_method is not None
        assert len(doc.verification_method) == 1
        assert doc.authentication is not None
        assert doc.service is not None

    def test_to_dict(self) -> None:
        """Test converting to W3C format."""
        did = AgentDID(method="agirails", network="base", identifier="0x" + "a" * 40)
        doc = DIDDocument(id=did)

        d = doc.to_dict()

        assert "@context" in d
        assert d["id"] == str(did)
        assert "controller" in d

    def test_from_dict(self) -> None:
        """Test creating from dictionary."""
        did_string = f"did:agirails:base:0x{'a' * 40}"
        data = {
            "id": did_string,
            "controller": did_string,
            "verificationMethod": [
                {"id": f"{did_string}#key-1", "type": "test"}
            ],
        }

        doc = DIDDocument.from_dict(data)

        assert str(doc.id) == did_string
        assert doc.verification_method is not None


class TestDIDValidation:
    """Tests for DID validation functions."""

    def test_is_valid_did(self) -> None:
        """Test DID validation."""
        # Valid DIDs
        assert is_valid_did(f"did:agirails:base-sepolia:0x{'a' * 40}") is True
        assert is_valid_did(f"did:eth:mainnet:0x{'b' * 40}") is True
        assert is_valid_did(f"did:key:local:abcdef") is True

        # Invalid DIDs
        assert is_valid_did("not-a-did") is False
        assert is_valid_did("did:invalid") is False
        assert is_valid_did("") is False

    def test_parse_did(self) -> None:
        """Test DID parsing."""
        result = parse_did(f"did:agirails:base-sepolia:0x{'a' * 40}")

        assert result is not None
        method, network, identifier = result
        assert method == "agirails"
        assert network == "base-sepolia"
        assert identifier == "0x" + "a" * 40

    def test_parse_did_invalid(self) -> None:
        """Test parsing invalid DID."""
        result = parse_did("invalid-did")
        assert result is None


class TestDIDManager:
    """Tests for DIDManager class."""

    def test_create_manager(self) -> None:
        """Test creating DID manager."""
        manager = DIDManager(network="base-sepolia")
        assert manager is not None
        assert manager.address is None  # No private key

    def test_create_did(self) -> None:
        """Test creating DID from address."""
        manager = DIDManager(network="base-sepolia")
        did = manager.create_did(address="0x" + "a" * 40)

        assert str(did) == f"did:agirails:base-sepolia:0x{'a' * 40}"

    def test_create_did_without_address_raises(self) -> None:
        """Test creating DID without address raises error."""
        manager = DIDManager(network="base")

        with pytest.raises(ValueError) as exc_info:
            manager.create_did()

        assert "address" in str(exc_info.value).lower()

    def test_create_did_document(self) -> None:
        """Test creating DID document."""
        manager = DIDManager(network="base-sepolia")
        did = AgentDID.from_address("0x" + "a" * 40, network="base-sepolia")

        doc = manager.create_did_document(
            did=did,
            endpoint="https://api.example.com",
            service_types=["echo", "translation"],
        )

        assert doc.id == did
        assert doc.verification_method is not None
        assert doc.service is not None
        assert len(doc.service) == 3  # API + 2 service types


class TestDIDResolver:
    """Tests for DIDResolver class."""

    def test_create_resolver(self) -> None:
        """Test creating resolver."""
        resolver = DIDResolver()
        assert resolver is not None

    def test_cache_operations(self) -> None:
        """Test cache operations."""
        resolver = DIDResolver(cache_ttl=60)

        # Initially empty
        resolver.clear_cache()

        # No cache hit
        did = f"did:agirails:base:0x{'a' * 40}"
        cached = resolver._get_from_cache(did)
        assert cached is None

    def test_clear_cache(self) -> None:
        """Test clearing cache."""
        resolver = DIDResolver()
        resolver.clear_cache()  # Should not raise


class TestVerificationMethod:
    """Tests for VerificationMethod class."""

    def test_create_method(self) -> None:
        """Test creating verification method."""
        method = VerificationMethod(
            id="did:example:123#key-1",
            type_="EcdsaSecp256k1VerificationKey2019",
            controller="did:example:123",
            public_key_hex="0x" + "a" * 64,
        )

        assert method.id == "did:example:123#key-1"
        assert method.type_ == "EcdsaSecp256k1VerificationKey2019"

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        method = VerificationMethod(
            id="did:example:123#key-1",
            type_="EcdsaSecp256k1VerificationKey2019",
            controller="did:example:123",
        )

        d = method.to_dict()
        assert d["id"] == "did:example:123#key-1"
        assert d["type"] == "EcdsaSecp256k1VerificationKey2019"


class TestServiceEndpoint:
    """Tests for ServiceEndpoint class."""

    def test_create_endpoint(self) -> None:
        """Test creating service endpoint."""
        endpoint = ServiceEndpoint(
            id="did:example:123#api",
            type_="AgentAPI",
            service_endpoint="https://api.example.com",
        )

        assert endpoint.id == "did:example:123#api"
        assert endpoint.type_ == "AgentAPI"
        assert endpoint.service_endpoint == "https://api.example.com"

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        endpoint = ServiceEndpoint(
            id="did:example:123#api",
            type_="AgentAPI",
            service_endpoint="https://api.example.com",
            description="Main API endpoint",
        )

        d = endpoint.to_dict()
        assert d["id"] == "did:example:123#api"
        assert d["serviceEndpoint"] == "https://api.example.com"
        assert d["description"] == "Main API endpoint"


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_did_from_address(self) -> None:
        """Test create_did_from_address helper."""
        did = create_did_from_address("0x" + "a" * 40, network="base-sepolia")

        assert did == f"did:agirails:base-sepolia:0x{'a' * 40}"

    def test_did_to_address(self) -> None:
        """Test did_to_address helper."""
        did = f"did:agirails:base-sepolia:0x{'a' * 40}"
        address = did_to_address(did)

        assert address == "0x" + "a" * 40

    def test_did_to_address_invalid(self) -> None:
        """Test did_to_address with invalid DID."""
        address = did_to_address("invalid-did")
        assert address is None
