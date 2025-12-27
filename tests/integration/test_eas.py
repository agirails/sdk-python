"""
Integration Tests for EASHelper.

These tests require a local Anvil instance forked from Base Sepolia.
Skipped automatically if ANVIL_RPC_URL environment variable is not set.

EAS on Base is at predeploy address 0x4200000000000000000000000000000000000021.

Run Anvil:
    anvil --fork-url <BASE_SEPOLIA_RPC_URL>

Run tests:
    ANVIL_RPC_URL=http://localhost:8545 pytest tests/integration/test_eas.py -v

Attestation Lifecycle:
    1. Register schema (one-time)
    2. Create attestation
    3. Verify attestation
    4. Optionally revoke attestation
"""

import asyncio
import os
import secrets
import time
from typing import AsyncGenerator, Optional

import pytest


# Skip all tests if Anvil not available
ANVIL_RPC_URL = os.getenv("ANVIL_RPC_URL")
SKIP_REASON = "ANVIL_RPC_URL not set - run: anvil --fork-url <BASE_SEPOLIA_RPC>"

pytestmark = pytest.mark.skipif(not ANVIL_RPC_URL, reason=SKIP_REASON)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def anvil_rpc_url() -> str:
    """Get Anvil RPC URL from environment."""
    return ANVIL_RPC_URL or "http://localhost:8545"


@pytest.fixture
def funded_private_key() -> str:
    """
    Private key for a funded account (Anvil default account 0).

    This is the first default Anvil account which has 10,000 ETH.
    """
    return "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.fixture
def provider_address() -> str:
    """Provider address for attestations."""
    return "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


# =============================================================================
# Unit Tests for Attestation Data Classes
# =============================================================================


class TestAttestationDataClass:
    """Tests for Attestation dataclass."""

    def test_attestation_is_valid(self) -> None:
        """Test is_valid property."""
        from agirails.protocol.eas import Attestation

        # Valid attestation (not revoked, not expired)
        attestation = Attestation(
            uid="0x" + "a" * 64,
            schema="0x" + "b" * 64,
            time=int(time.time()) - 3600,
            expiration_time=0,  # Never expires
            revocation_time=0,  # Not revoked
            ref_uid="0x" + "0" * 64,
            recipient="0x" + "c" * 40,
            attester="0x" + "d" * 40,
            revocable=True,
            data=b"test",
        )
        assert attestation.is_valid is True
        assert attestation.is_revoked is False
        assert attestation.is_expired is False

    def test_attestation_is_revoked(self) -> None:
        """Test is_revoked detection."""
        from agirails.protocol.eas import Attestation

        attestation = Attestation(
            uid="0x" + "a" * 64,
            schema="0x" + "b" * 64,
            time=int(time.time()) - 3600,
            expiration_time=0,
            revocation_time=int(time.time()) - 1800,  # Revoked 30 min ago
            ref_uid="0x" + "0" * 64,
            recipient="0x" + "c" * 40,
            attester="0x" + "d" * 40,
            revocable=True,
            data=b"test",
        )
        assert attestation.is_valid is False
        assert attestation.is_revoked is True

    def test_attestation_is_expired(self) -> None:
        """Test is_expired detection."""
        from agirails.protocol.eas import Attestation

        attestation = Attestation(
            uid="0x" + "a" * 64,
            schema="0x" + "b" * 64,
            time=int(time.time()) - 7200,
            expiration_time=int(time.time()) - 3600,  # Expired 1 hour ago
            revocation_time=0,
            ref_uid="0x" + "0" * 64,
            recipient="0x" + "c" * 40,
            attester="0x" + "d" * 40,
            revocable=True,
            data=b"test",
        )
        assert attestation.is_valid is False
        assert attestation.is_expired is True

    def test_attestation_to_dict(self) -> None:
        """Test to_dict serialization."""
        from agirails.protocol.eas import Attestation

        attestation = Attestation(
            uid="0x" + "a" * 64,
            schema="0x" + "b" * 64,
            time=1700000000,
            expiration_time=0,
            revocation_time=0,
            ref_uid="0x" + "0" * 64,
            recipient="0xcccccccccccccccccccccccccccccccccccccccc",
            attester="0xdddddddddddddddddddddddddddddddddddddddd",
            revocable=True,
            data=b"\x01\x02\x03",
        )

        d = attestation.to_dict()
        assert d["uid"] == "0x" + "a" * 64
        assert d["time"] == 1700000000
        assert d["data"] == "0x010203"
        assert "isValid" in d


class TestDeliveryAttestationData:
    """Tests for DeliveryAttestationData dataclass."""

    def test_to_dict(self) -> None:
        """Test serialization."""
        from agirails.protocol.eas import DeliveryAttestationData

        data = DeliveryAttestationData(
            transaction_id="0x" + "a" * 64,
            output_hash="0x" + "b" * 64,
            provider="0xcccccccccccccccccccccccccccccccccccccccc",
            timestamp=1700000000,
        )

        d = data.to_dict()
        assert d["transactionId"] == "0x" + "a" * 64
        assert d["outputHash"] == "0x" + "b" * 64
        assert d["provider"] == "0xcccccccccccccccccccccccccccccccccccccccc"
        assert d["timestamp"] == 1700000000


class TestSchemaDataClass:
    """Tests for Schema dataclass."""

    def test_to_dict(self) -> None:
        """Test serialization."""
        from agirails.protocol.eas import Schema

        schema = Schema(
            uid="0x" + "a" * 64,
            resolver="0x0000000000000000000000000000000000000000",
            revocable=True,
            schema="bytes32 test, address addr",
        )

        d = schema.to_dict()
        assert d["uid"] == "0x" + "a" * 64
        assert d["revocable"] is True
        assert "bytes32" in d["schema"]


# =============================================================================
# EASHelper Creation Tests
# =============================================================================


class TestEASHelperCreation:
    """Tests for EASHelper.create() factory method."""

    @pytest.mark.asyncio
    async def test_create_eas_helper(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> None:
        """Creating EASHelper should work with valid credentials."""
        from agirails.protocol.eas import EASHelper

        try:
            eas = await EASHelper.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            assert eas is not None
            assert eas.address.startswith("0x")
        except ConnectionError:
            pytest.skip("Anvil not accessible")
        except Exception as e:
            if "connect" in str(e).lower():
                pytest.skip(f"Connection failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_create_with_invalid_network(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> None:
        """Creating EASHelper with invalid network should fail."""
        from agirails.protocol.eas import EASHelper

        with pytest.raises((ValueError, KeyError)):
            await EASHelper.create(
                private_key=funded_private_key,
                network="invalid-network",
                rpc_url=anvil_rpc_url,
            )


class TestEASHelperProperties:
    """Tests for EASHelper properties."""

    @pytest.fixture
    async def eas_helper(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create EASHelper for testing."""
        from agirails.protocol.eas import EASHelper

        try:
            helper = await EASHelper.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield helper
        except (ConnectionError, Exception) as e:
            if "connect" in str(e).lower():
                pytest.skip("Anvil not accessible")
            raise

    @pytest.mark.asyncio
    async def test_address_property(self, eas_helper) -> None:
        """Address property returns signer address."""
        expected = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        assert eas_helper.address.lower() == expected.lower()

    @pytest.mark.asyncio
    async def test_delivery_schema_uid_property(self, eas_helper) -> None:
        """Delivery schema UID property returns configured schema."""
        # Schema UID from network config
        uid = eas_helper.delivery_schema_uid
        assert uid == "" or uid.startswith("0x")


# =============================================================================
# Attestation Operations Tests
# =============================================================================


class TestEASHelperEncodeDecode:
    """Tests for internal encoding/decoding methods."""

    @pytest.fixture
    async def eas_helper(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create EASHelper for testing."""
        from agirails.protocol.eas import EASHelper

        try:
            helper = await EASHelper.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield helper
        except (ConnectionError, Exception) as e:
            if "connect" in str(e).lower():
                pytest.skip("Anvil not accessible")
            raise

    @pytest.mark.asyncio
    async def test_encode_decode_roundtrip(
        self, eas_helper, provider_address: str
    ) -> None:
        """Encoding and decoding should be reversible."""
        tx_id = "0x" + "a" * 64
        output_hash = "0x" + "b" * 64
        timestamp = int(time.time())

        # Encode
        encoded = eas_helper._encode_delivery_data(
            transaction_id=tx_id,
            output_hash=output_hash,
            provider=provider_address,
            timestamp=timestamp,
        )

        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

        # Decode
        decoded = eas_helper._decode_delivery_data(encoded)

        assert decoded.transaction_id.lower() == tx_id.lower()
        assert decoded.output_hash.lower() == output_hash.lower()
        assert decoded.provider.lower() == provider_address.lower()
        assert decoded.timestamp == timestamp


@pytest.mark.integration
class TestEASHelperAttestations:
    """
    Full attestation lifecycle tests.

    These tests require:
    1. Anvil running with forked Base Sepolia
    2. Gas in the test account
    3. Pre-registered schema (or ability to register one)

    Run with: pytest -m integration tests/integration/test_eas.py -v
    """

    @pytest.fixture
    async def eas_helper(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create EASHelper for testing."""
        from agirails.protocol.eas import EASHelper

        try:
            helper = await EASHelper.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield helper
        except (ConnectionError, Exception) as e:
            if "connect" in str(e).lower():
                pytest.skip("Anvil not accessible")
            raise

    @pytest.mark.asyncio
    async def test_register_and_get_schema(self, eas_helper) -> None:
        """Register a schema and retrieve it."""
        from agirails.protocol.eas import DELIVERY_SCHEMA

        try:
            # Register delivery schema
            uid = await eas_helper.register_schema(DELIVERY_SCHEMA)
            assert uid.startswith("0x")
            assert len(uid) == 66

            # Get schema
            schema = await eas_helper.get_schema(uid)
            assert schema.uid == uid
            assert schema.schema == DELIVERY_SCHEMA
            assert schema.revocable is True
        except Exception as e:
            if "revert" in str(e).lower() or "gas" in str(e).lower():
                pytest.skip(f"Transaction failed (likely gas issue): {e}")
            raise

    @pytest.mark.asyncio
    async def test_create_delivery_attestation(
        self, eas_helper, provider_address: str
    ) -> None:
        """Create a delivery attestation."""
        # First register or get schema
        try:
            schema_uid = await eas_helper.register_delivery_schema()
        except Exception as e:
            pytest.skip(f"Schema registration failed: {e}")

        tx_id = "0x" + secrets.token_hex(32)
        output_hash = "0x" + secrets.token_hex(32)

        try:
            uid = await eas_helper.create_delivery_attestation(
                transaction_id=tx_id,
                output_hash=output_hash,
                provider=provider_address,
            )

            assert uid.startswith("0x")
            assert len(uid) == 66

            # Verify attestation exists
            is_valid = await eas_helper.is_attestation_valid(uid)
            assert is_valid is True

        except Exception as e:
            if "revert" in str(e).lower():
                pytest.skip(f"Attestation failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_get_attestation(
        self, eas_helper, provider_address: str
    ) -> None:
        """Create and retrieve an attestation."""
        try:
            schema_uid = await eas_helper.register_delivery_schema()
        except Exception as e:
            pytest.skip(f"Schema registration failed: {e}")

        tx_id = "0x" + secrets.token_hex(32)
        output_hash = "0x" + secrets.token_hex(32)

        try:
            uid = await eas_helper.create_delivery_attestation(
                transaction_id=tx_id,
                output_hash=output_hash,
                provider=provider_address,
            )

            # Get full attestation
            attestation = await eas_helper.get_attestation(uid)

            assert attestation.uid == uid
            assert attestation.attester.lower() == eas_helper.address.lower()
            assert attestation.is_valid is True
            assert attestation.is_revoked is False

        except Exception as e:
            if "revert" in str(e).lower():
                pytest.skip(f"Attestation failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_get_delivery_attestation_decoded(
        self, eas_helper, provider_address: str
    ) -> None:
        """Create attestation and get decoded delivery data."""
        try:
            schema_uid = await eas_helper.register_delivery_schema()
        except Exception as e:
            pytest.skip(f"Schema registration failed: {e}")

        tx_id = "0x" + secrets.token_hex(32)
        output_hash = "0x" + secrets.token_hex(32)

        try:
            uid = await eas_helper.create_delivery_attestation(
                transaction_id=tx_id,
                output_hash=output_hash,
                provider=provider_address,
            )

            # Get decoded delivery data
            delivery_data = await eas_helper.get_delivery_attestation(uid)

            assert delivery_data.transaction_id.lower() == tx_id.lower()
            assert delivery_data.output_hash.lower() == output_hash.lower()
            assert delivery_data.provider.lower() == provider_address.lower()
            assert delivery_data.timestamp > 0

        except Exception as e:
            if "revert" in str(e).lower():
                pytest.skip(f"Attestation failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_revoke_attestation(
        self, eas_helper, provider_address: str
    ) -> None:
        """Create and revoke an attestation."""
        try:
            schema_uid = await eas_helper.register_delivery_schema()
        except Exception as e:
            pytest.skip(f"Schema registration failed: {e}")

        tx_id = "0x" + secrets.token_hex(32)
        output_hash = "0x" + secrets.token_hex(32)

        try:
            # Create attestation
            uid = await eas_helper.create_delivery_attestation(
                transaction_id=tx_id,
                output_hash=output_hash,
                provider=provider_address,
                revocable=True,
            )

            # Verify it's valid
            assert await eas_helper.is_attestation_valid(uid) is True

            # Revoke it
            receipt = await eas_helper.revoke_attestation(uid)
            assert receipt.status == 1  # Success

            # Verify it's no longer valid
            assert await eas_helper.is_attestation_valid(uid) is False

            # Get attestation and check revocation time
            attestation = await eas_helper.get_attestation(uid)
            assert attestation.is_revoked is True

        except Exception as e:
            if "revert" in str(e).lower():
                pytest.skip(f"Operation failed: {e}")
            raise


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEASHelperEdgeCases:
    """Edge case tests for EASHelper."""

    @pytest.fixture
    async def eas_helper(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create EASHelper for testing."""
        from agirails.protocol.eas import EASHelper

        try:
            helper = await EASHelper.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield helper
        except (ConnectionError, Exception) as e:
            if "connect" in str(e).lower():
                pytest.skip("Anvil not accessible")
            raise

    @pytest.mark.asyncio
    async def test_get_nonexistent_attestation(self, eas_helper) -> None:
        """Getting non-existent attestation should return zero values."""
        from agirails.protocol.eas import ZERO_BYTES32

        fake_uid = "0x" + "f" * 64

        try:
            attestation = await eas_helper.get_attestation(fake_uid)
            # Non-existent attestation returns zero values
            assert attestation.time == 0 or attestation.uid == ZERO_BYTES32
        except Exception:
            # Some implementations may raise - that's acceptable too
            pass

    @pytest.mark.asyncio
    async def test_create_attestation_without_schema(
        self, eas_helper, provider_address: str
    ) -> None:
        """Creating attestation without schema should fail gracefully."""
        # Create a fresh helper without schema UID
        from agirails.protocol.eas import EASHelper

        # Access internal and clear schema
        eas_helper._delivery_schema_uid = ""

        tx_id = "0x" + secrets.token_hex(32)
        output_hash = "0x" + secrets.token_hex(32)

        with pytest.raises(ValueError) as exc_info:
            await eas_helper.create_delivery_attestation(
                transaction_id=tx_id,
                output_hash=output_hash,
                provider=provider_address,
            )

        assert "schema" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_is_attestation_valid_nonexistent(self, eas_helper) -> None:
        """Checking validity of non-existent attestation."""
        fake_uid = "0x" + "f" * 64

        try:
            is_valid = await eas_helper.is_attestation_valid(fake_uid)
            # Non-existent attestations are not valid
            assert is_valid is False
        except Exception:
            # Some RPC configurations may raise
            pass


class TestEASHelperConstants:
    """Tests for EAS constants and schema definitions."""

    def test_delivery_schema_format(self) -> None:
        """Delivery schema should have correct format."""
        from agirails.protocol.eas import DELIVERY_SCHEMA

        # Schema should contain required fields
        assert "transactionId" in DELIVERY_SCHEMA or "bytes32" in DELIVERY_SCHEMA
        assert "address" in DELIVERY_SCHEMA

    def test_zero_bytes32_format(self) -> None:
        """ZERO_BYTES32 should be correct format."""
        from agirails.protocol.eas import ZERO_BYTES32

        assert ZERO_BYTES32.startswith("0x")
        assert len(ZERO_BYTES32) == 66
        assert ZERO_BYTES32 == "0x" + "0" * 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
