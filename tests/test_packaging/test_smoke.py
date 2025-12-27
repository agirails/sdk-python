"""
Packaging Smoke Tests - Day 3 Gate List.

Gate List Requirements:
- CI matrix tests (Python 3.9-3.11)
- Packaging smoke tests (wheel, sdist, install)
- Verify all imports work correctly
- Version verification

These tests validate the SDK can be installed and used correctly.
"""

from __future__ import annotations

import importlib
import re
import sys
from typing import List, Tuple

import pytest


class TestImportSmoke:
    """Tests that all public modules can be imported."""

    def test_import_main_package(self):
        """Smoke: Main package imports successfully."""
        import agirails

        assert agirails is not None
        assert hasattr(agirails, "__version__")
        assert hasattr(agirails, "__version_info__")

    def test_version_format(self):
        """Smoke: Version follows semver format."""
        import agirails

        # Check version string format (X.Y.Z)
        assert re.match(r"^\d+\.\d+\.\d+", agirails.__version__)

        # Check version tuple
        assert isinstance(agirails.__version_info__, tuple)
        assert len(agirails.__version_info__) >= 3
        assert all(isinstance(v, int) for v in agirails.__version_info__[:3])

    def test_version_consistency(self):
        """Smoke: version.py and __init__.py versions match."""
        from agirails import __version__, __version_info__
        from agirails.version import __version__ as version_version
        from agirails.version import __version_info__ as version_info

        assert __version__ == version_version
        assert __version_info__ == version_info

    def test_import_client(self):
        """Smoke: Client module imports successfully."""
        from agirails import ACTPClient, ACTPClientConfig, ACTPClientInfo, ACTPClientMode

        assert ACTPClient is not None
        assert ACTPClientConfig is not None
        assert ACTPClientInfo is not None
        assert ACTPClientMode is not None

    def test_import_adapters(self):
        """Smoke: Adapter modules import successfully."""
        from agirails import (
            BaseAdapter,
            BasicAdapter,
            BasicPayParams,
            BasicPayResult,
            CheckStatusResult,
            StandardAdapter,
            StandardTransactionParams,
            TransactionDetails,
        )

        assert BasicAdapter is not None
        assert StandardAdapter is not None

    def test_import_runtime(self):
        """Smoke: Runtime modules import successfully."""
        from agirails import (
            MockRuntime,
            MockStateManager,
            MockTransaction,
            MockEscrow,
            MockState,
            State,
            CreateTransactionParams,
        )

        assert MockRuntime is not None
        assert MockStateManager is not None
        assert State is not None

    def test_import_errors(self):
        """Smoke: Error modules import successfully."""
        from agirails import (
            ACTPError,
            TransactionNotFoundError,
            InvalidStateTransitionError,
            EscrowNotFoundError,
            DeadlinePassedError,
            DisputeWindowActiveError,
            ContractPausedError,
            InsufficientBalanceError,
            ValidationError,
            InvalidAddressError,
            InvalidAmountError,
            NetworkError,
            StorageError,
        )

        # Verify inheritance
        assert issubclass(TransactionNotFoundError, ACTPError)
        assert issubclass(ValidationError, ACTPError)
        assert issubclass(InvalidAddressError, ValidationError)

    def test_import_utilities(self):
        """Smoke: Utility modules import successfully."""
        from agirails import (
            timing_safe_equal,
            validate_path,
            is_valid_address,
            safe_json_parse,
            LRUCache,
            Logger,
            Semaphore,
            RateLimiter,
        )

        assert timing_safe_equal is not None
        assert LRUCache is not None

    def test_import_security_nonce(self):
        """Smoke: Security nonce utilities import (PARITY)."""
        from agirails import (
            generate_secure_nonce,
            is_valid_nonce,
            generate_secure_nonces,
        )

        assert generate_secure_nonce is not None
        assert is_valid_nonce is not None

    def test_import_attestation_tracker(self):
        """Smoke: Attestation tracker utilities import (PARITY)."""
        from agirails import (
            IUsedAttestationTracker,
            InMemoryUsedAttestationTracker,
            FileBasedUsedAttestationTracker,
            create_used_attestation_tracker,
        )

        assert InMemoryUsedAttestationTracker is not None

    def test_import_nonce_tracker(self):
        """Smoke: Nonce tracker utilities import (PARITY)."""
        from agirails import (
            NonceValidationResult,
            IReceivedNonceTracker,
            InMemoryReceivedNonceTracker,
            SetBasedReceivedNonceTracker,
            create_received_nonce_tracker,
        )

        assert InMemoryReceivedNonceTracker is not None

    def test_import_helpers(self):
        """Smoke: Helper utilities import successfully."""
        from agirails import (
            USDC,
            Deadline,
            Address,
            Bytes32,
            StateHelper,
            parse_usdc,
            format_usdc,
            shorten_address,
        )

        assert USDC is not None
        assert parse_usdc is not None

    def test_import_validation(self):
        """Smoke: Validation utilities import successfully."""
        from agirails import (
            validate_address,
            validate_amount,
            validate_deadline,
            validate_tx_id,
            validate_bytes32,
        )

        assert validate_address is not None

    def test_import_canonical_json(self):
        """Smoke: Canonical JSON utilities import successfully."""
        from agirails import (
            canonical_json_dumps,
            compute_type_hash,
            hash_struct,
            compute_domain_separator,
        )

        assert canonical_json_dumps is not None

    def test_import_level0(self):
        """Smoke: Level 0 API imports successfully."""
        from agirails import (
            ServiceDirectory,
            ServiceEntry,
            ServiceQuery,
            Provider,
            ProviderConfig,
            provide,
            request,
        )

        assert ServiceDirectory is not None
        assert provide is not None
        assert request is not None

    def test_import_level1(self):
        """Smoke: Level 1 API imports successfully."""
        from agirails import (
            Agent,
            AgentConfig,
            AgentBehavior,
            AgentStatus,
            Job,
            JobContext,
            ServiceConfig,
        )

        assert Agent is not None
        assert AgentConfig is not None

    def test_import_types(self):
        """Smoke: Type definitions import successfully."""
        from agirails import (
            AgentDID,
            DIDDocument,
            Transaction,
            TransactionState,
            EIP712Domain,
            ServiceRequest,
            ServiceResponse,
            DeliveryProof,
            DeliveryProofMessage,
        )

        assert DeliveryProofMessage is not None

    def test_import_protocol(self):
        """Smoke: Protocol modules import successfully."""
        from agirails import (
            MessageSigner,
            hash_typed_data,
            create_typed_data,
            ProofGenerator,
            MerkleProof,
            DIDManager,
            DIDResolver,
            create_did_from_address,
        )

        assert MessageSigner is not None
        assert ProofGenerator is not None

    def test_import_builders(self):
        """Smoke: Builder modules import successfully."""
        from agirails import (
            DeliveryProofBuilder,
            QuoteBuilder,
        )

        assert DeliveryProofBuilder is not None
        assert QuoteBuilder is not None


class TestPythonCompatibility:
    """Tests for Python version compatibility."""

    def test_python_version_supported(self):
        """Smoke: Current Python version is supported (3.9+)."""
        assert sys.version_info >= (3, 9), "Python 3.9+ required"

    def test_python_39_features(self):
        """Smoke: Python 3.9 features work correctly."""
        # Dict union operator (3.9+)
        d1 = {"a": 1}
        d2 = {"b": 2}
        merged = d1 | d2
        assert merged == {"a": 1, "b": 2}

        # Type hints with generics (3.9+)
        from typing import List, Dict

        def fn(x: list[int]) -> dict[str, int]:
            return {str(v): v for v in x}

        result = fn([1, 2, 3])
        assert result == {"1": 1, "2": 2, "3": 3}

    def test_typing_extensions_fallback(self):
        """Smoke: typing_extensions provides fallback for older Python."""
        # TypedDict should work in 3.9+
        from typing import TypedDict

        class Config(TypedDict):
            name: str
            value: int

        config: Config = {"name": "test", "value": 42}
        assert config["name"] == "test"


class TestModuleAvailability:
    """Tests for module availability and feature flags."""

    def test_has_messages_flag(self):
        """Smoke: HAS_MESSAGES flag indicates messages capability."""
        from agirails import HAS_MESSAGES

        assert isinstance(HAS_MESSAGES, bool)

    def test_has_web3_protocol_flag(self):
        """Smoke: HAS_WEB3_PROTOCOL flag indicates web3 capability."""
        from agirails import HAS_WEB3_PROTOCOL

        assert isinstance(HAS_WEB3_PROTOCOL, bool)

    def test_optional_web3_imports(self):
        """Smoke: Web3-dependent imports work when web3 is available."""
        from agirails import HAS_WEB3_PROTOCOL

        if HAS_WEB3_PROTOCOL:
            from agirails import (
                ACTPKernel,
                EscrowVault,
                EventMonitor,
                NonceManager,
                EASHelper,
                AgentRegistry,
            )

            assert ACTPKernel is not None
        else:
            # Should still import without error, just None
            import agirails

            # These may not exist if web3 is not installed
            pass


class TestAllExports:
    """Tests that __all__ is complete and correct."""

    def test_all_exports_importable(self):
        """Smoke: All items in __all__ are importable."""
        import agirails

        failed_imports: List[str] = []

        for name in agirails.__all__:
            try:
                obj = getattr(agirails, name)
                assert obj is not None or name.startswith("HAS_")
            except AttributeError:
                # Some exports might be conditional (HAS_WEB3_PROTOCOL)
                if not name.startswith("HAS_"):
                    failed_imports.append(name)

        # Allow some conditional exports to fail
        conditional_exports = {
            "ACTPKernel",
            "TransactionView",
            "EscrowVault",
            "CreateEscrowParams",
            "EscrowInfo",
            "generate_escrow_id",
            "EventMonitor",
            "EventFilter",
            "EventType",
            "ACTPEvent",
            "TransactionCreatedEvent",
            "StateTransitionedEvent",
            "EscrowCreatedEvent",
            "EscrowPayoutEvent",
            "NonceManager",
            "NonceManagerPool",
            "EASHelper",
            "Attestation",
            "DeliveryAttestationData",
            "Schema",
            "DELIVERY_SCHEMA",
            "ZERO_BYTES32",
            "AgentRegistry",
            "AgentProfile",
            "ServiceDescriptor",
            "compute_service_type_hash",
        }

        actual_failures = [f for f in failed_imports if f not in conditional_exports]
        assert len(actual_failures) == 0, f"Failed to import: {actual_failures}"

    def test_no_private_exports(self):
        """Smoke: __all__ doesn't expose private names (except dunders)."""
        import agirails

        # Dunder names like __version__ are public API, not private
        private_exports = [
            name for name in agirails.__all__
            if name.startswith("_") and not name.startswith("__")
        ]
        assert len(private_exports) == 0, f"Private names in __all__: {private_exports}"


class TestFunctionalSmoke:
    """Functional smoke tests to verify basic SDK operation."""

    def test_generate_secure_nonce_works(self):
        """Smoke: Can generate secure nonces."""
        from agirails import generate_secure_nonce, is_valid_nonce

        nonce = generate_secure_nonce()
        assert is_valid_nonce(nonce)
        assert len(nonce) == 66  # 0x + 64 hex

    def test_parse_usdc_works(self):
        """Smoke: USDC parsing works correctly."""
        from agirails import parse_usdc, format_usdc

        # Parse various formats
        assert parse_usdc(100) == 100000000
        assert parse_usdc("100") == 100000000
        assert parse_usdc("100.50") == 100500000
        assert parse_usdc("$100") == 100000000

        # Format back
        assert format_usdc(100000000) == "100.00"
        assert format_usdc(100500000) == "100.50"

    def test_validate_address_works(self):
        """Smoke: Address validation works correctly."""
        from agirails import is_valid_address, validate_address, InvalidAddressError

        valid = "0x" + "ab" * 20
        invalid = "0x123"

        assert is_valid_address(valid)
        assert not is_valid_address(invalid)

        # validate_address should not raise for valid
        validate_address(valid)

        # Should raise for invalid
        with pytest.raises(InvalidAddressError):
            validate_address(invalid)

    def test_canonical_json_works(self):
        """Smoke: Canonical JSON serialization works."""
        from agirails import canonical_json_dumps

        # Canonical JSON sorts keys alphabetically for deterministic hashing
        data = {"service": "test", "input": {"b": 2, "a": 1}}
        result = canonical_json_dumps(data)

        assert '"service":"test"' in result
        # Keys are sorted: "input" comes before "service" alphabetically
        assert result.index("input") < result.index("service")
        # Nested keys are also sorted: "a" before "b"
        assert '"a":1' in result
        assert result.index('"a":1') < result.index('"b":2')

    def test_lru_cache_works(self):
        """Smoke: LRU cache works correctly."""
        from agirails import LRUCache

        cache: LRUCache[str, int] = LRUCache(max_size=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)

        assert cache.get("a") == 1
        assert cache.get("b") == 2

        # Add new item, should evict oldest
        cache.set("d", 4)
        # "c" was least recently used (a and b were accessed)
        assert cache.get("c") is None
        assert cache.get("d") == 4

    @pytest.mark.asyncio
    async def test_mock_runtime_works(self):
        """Smoke: MockRuntime can create and manage transactions."""
        from agirails import MockRuntime, CreateTransactionParams, State

        runtime = MockRuntime()

        # Create a transaction
        tx_id = await runtime.create_transaction(
            CreateTransactionParams(
                requester="0x" + "11" * 20,
                provider="0x" + "22" * 20,
                amount="100000000",  # 100 USDC
                deadline=9999999999,
                dispute_window=86400,
                service_description="0x" + "00" * 32,
            )
        )

        assert tx_id is not None
        assert tx_id.startswith("0x")

        # Get transaction
        tx = await runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.state == State.INITIATED

    @pytest.mark.asyncio
    async def test_attestation_tracker_works(self):
        """Smoke: Attestation tracker prevents replay."""
        from agirails import InMemoryUsedAttestationTracker

        tracker = InMemoryUsedAttestationTracker()
        attestation = "0x" + "ab" * 32
        tx1 = "0x" + "11" * 32
        tx2 = "0x" + "22" * 32

        # First use should succeed
        result1 = await tracker.record_usage(attestation, tx1)
        assert result1 is True

        # Same attestation for different tx should fail
        result2 = await tracker.record_usage(attestation, tx2)
        assert result2 is False

        # Same attestation for same tx should succeed (idempotent)
        result3 = await tracker.record_usage(attestation, tx1)
        assert result3 is True
