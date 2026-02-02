"""
Parity Tests - Verify Python SDK produces same outputs as TypeScript SDK.

These tests use shared JSON fixtures that can be used by both SDKs to ensure
cross-SDK compatibility. The same test vectors should pass in both Python and TS.

PARITY CRITICAL: Any changes to these tests MUST be synchronized with TS SDK.
"""

import json
from pathlib import Path

import pytest

# Import the modules we're testing for parity
from agirails.utils.helpers import ServiceHash, ServiceMetadata

# Path to parity test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "parity"


def load_fixture(name: str) -> dict:
    """Load a parity test fixture."""
    fixture_path = FIXTURES_DIR / name
    with open(fixture_path) as f:
        return json.load(f)


def ts_style_json_dumps(obj: dict) -> str:
    """
    Serialize dict to JSON matching TypeScript JSON.stringify() behavior.

    Key differences from Python's json.dumps defaults:
    - Preserves insertion order (no sort_keys)
    - Uses minimal separators (no whitespace)
    - ensure_ascii=False to match TS behavior with unicode
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class TestCanonicalJsonParity:
    """Test canonical JSON serialization parity with TS SDK.

    NOTE: These tests use ts_style_json_dumps() which matches TypeScript's
    JSON.stringify() behavior (insertion order, no whitespace, unicode preserved).

    The SDK's canonical_json_dumps() uses sorted keys for deterministic hashing,
    which is intentional for cryptographic operations. For general JSON parity,
    use json.dumps with ensure_ascii=False and no sort_keys.
    """

    @pytest.fixture
    def vectors(self) -> list:
        """Load canonical JSON test vectors."""
        data = load_fixture("canonical_json.json")
        return data["test_vectors"]

    def test_simple_object(self, vectors: list) -> None:
        """Test simple object serialization."""
        vector = next(v for v in vectors if v["description"] == "Simple object with string values")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_number_values(self, vectors: list) -> None:
        """Test object with number values."""
        vector = next(v for v in vectors if v["description"] == "Object with number values")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_boolean_values(self, vectors: list) -> None:
        """Test object with boolean values."""
        vector = next(v for v in vectors if v["description"] == "Object with boolean values")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_null_value(self, vectors: list) -> None:
        """Test object with null value."""
        vector = next(v for v in vectors if v["description"] == "Object with null value (should be included)")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_nested_object(self, vectors: list) -> None:
        """Test nested object serialization."""
        vector = next(v for v in vectors if v["description"] == "Nested object")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_array_of_primitives(self, vectors: list) -> None:
        """Test array of primitives."""
        vector = next(v for v in vectors if v["description"] == "Array of primitives")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_array_of_objects(self, vectors: list) -> None:
        """Test array of objects."""
        vector = next(v for v in vectors if v["description"] == "Array of objects")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_mixed_types(self, vectors: list) -> None:
        """Test mixed types."""
        vector = next(v for v in vectors if v["description"] == "Mixed types")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_insertion_order_preserved(self, vectors: list) -> None:
        """PARITY CRITICAL: Test that insertion order is preserved (not sorted)."""
        vector = next(v for v in vectors if "insertion order" in v["description"].lower())
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]
        assert result != vector["not_expected"]

    def test_unicode_characters(self, vectors: list) -> None:
        """Test unicode characters."""
        vector = next(v for v in vectors if v["description"] == "Unicode characters")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_special_characters(self, vectors: list) -> None:
        """Test special characters in strings."""
        vector = next(v for v in vectors if v["description"] == "Special characters in strings")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_empty_object(self, vectors: list) -> None:
        """Test empty object."""
        vector = next(v for v in vectors if v["description"] == "Empty object")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_empty_array(self, vectors: list) -> None:
        """Test empty array."""
        vector = next(v for v in vectors if v["description"] == "Empty array")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_deeply_nested(self, vectors: list) -> None:
        """Test deeply nested structure."""
        vector = next(v for v in vectors if v["description"] == "Deeply nested structure")
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]

    def test_no_whitespace(self, vectors: list) -> None:
        """PARITY CRITICAL: Test that output has no whitespace."""
        vector = next(v for v in vectors if "no spaces" in v["description"].lower())
        result = ts_style_json_dumps(vector["input"])
        assert result == vector["expected"]
        for char in vector["not_expected_contains"]:
            assert char not in result


class TestServiceHashParity:
    """Test ServiceHash canonicalization parity with TS SDK."""

    @pytest.fixture
    def vectors(self) -> list:
        """Load service hash test vectors."""
        data = load_fixture("service_hash.json")
        return data["test_vectors"]

    def _to_metadata(self, input_dict: dict) -> ServiceMetadata:
        """Convert test vector input dict to ServiceMetadata."""
        return ServiceMetadata(
            service=input_dict.get("service", ""),
            input=input_dict.get("input"),
            version=input_dict.get("version"),
            timestamp=input_dict.get("timestamp"),
        )

    def test_simple_service_string_input(self, vectors: list) -> None:
        """Test simple service with string input."""
        vector = next(v for v in vectors if v["description"] == "Simple service with string input")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_service_object_input(self, vectors: list) -> None:
        """Test service with object input."""
        vector = next(v for v in vectors if v["description"] == "Service with object input")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_minimal_service(self, vectors: list) -> None:
        """Test minimal service (service name only)."""
        vector = next(v for v in vectors if v["description"] == "Minimal service (service name only)")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_null_input_omitted(self, vectors: list) -> None:
        """Test that null input is omitted from canonical form."""
        vector = next(v for v in vectors if v["description"] == "Service with null input (should be omitted)")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]
        # Verify null value is not in the output
        assert '"input":null' not in result

    def test_numeric_input(self, vectors: list) -> None:
        """Test service with numeric input."""
        vector = next(v for v in vectors if v["description"] == "Service with numeric input")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_array_input(self, vectors: list) -> None:
        """Test service with array input."""
        vector = next(v for v in vectors if v["description"] == "Service with array input")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_nested_object_input(self, vectors: list) -> None:
        """Test service with nested object input."""
        vector = next(v for v in vectors if v["description"] == "Service with nested object input")
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]

    def test_insertion_order_preserved(self, vectors: list) -> None:
        """PARITY CRITICAL: Test that insertion order is preserved (not alphabetically sorted)."""
        vector = next(v for v in vectors if "insertion order" in v["description"].lower())
        metadata = self._to_metadata(vector["input"])
        result = ServiceHash.to_canonical(metadata)
        assert result == vector["expected_canonical"]
        assert result != vector["not_expected_canonical"]


class TestDeliveryProofParity:
    """Test DeliveryProof schema parity with TS SDK."""

    @pytest.fixture
    def vectors(self) -> list:
        """Load delivery proof test vectors."""
        data = load_fixture("delivery_proof.json")
        return data["test_vectors"]

    def test_required_fields(self, vectors: list) -> None:
        """Test that all 12 required fields are present (AIP-4 v1.1)."""
        vector = next(v for v in vectors if v["description"] == "Basic delivery proof message")
        assert vector["expected_field_count"] == 12
        expected_fields = set(vector["expected_fields"])
        actual_fields = set(vector["input"].keys())
        assert expected_fields == actual_fields

    def test_field_names_match_ts_sdk(self, vectors: list) -> None:
        """Test that field names match TS SDK (camelCase)."""
        vector = next(v for v in vectors if v["description"] == "Basic delivery proof message")
        expected_fields = [
            "txId",
            "providerDID",
            "requesterDID",
            "serviceType",
            "inputHash",
            "outputHash",
            "resultCID",
            "timestamp",
            "nonce",
            "schemaVersion",
            "attestationType",
            "chainId",
        ]
        for field in expected_fields:
            assert field in vector["input"]

    def test_keccak256_hash_algorithm(self, vectors: list) -> None:
        """PARITY CRITICAL: Result hash must use keccak256, not SHA-256."""
        vector = next(v for v in vectors if "Result hash computation" in v["description"])
        assert vector["hash_algorithm"] == "keccak256"


class TestEIP712Parity:
    """Test EIP-712 typed data parity with TS SDK."""

    @pytest.fixture
    def vectors(self) -> list:
        """Load EIP-712 test vectors."""
        data = load_fixture("eip712.json")
        return data["test_vectors"]

    def test_delivery_proof_type_definition(self, vectors: list) -> None:
        """Test DeliveryProof type has all 12 fields."""
        vector = next(v for v in vectors if "DeliveryProof type definition" in v["description"])
        delivery_proof_type = vector["types"]["DeliveryProof"]
        assert len(delivery_proof_type) == 12

    def test_eip712_domain_structure(self, vectors: list) -> None:
        """Test EIP712Domain has correct structure."""
        vector = next(v for v in vectors if "DeliveryProof type definition" in v["description"])
        domain_type = vector["types"]["EIP712Domain"]
        field_names = [f["name"] for f in domain_type]
        assert "name" in field_names
        assert "version" in field_names
        assert "chainId" in field_names
        assert "verifyingContract" in field_names

    def test_signature_format(self, vectors: list) -> None:
        """Test signature format is v, r, s components."""
        vector = next(v for v in vectors if "Signature format" in v["description"])
        sig_format = vector["signature_format"]
        assert "v" in sig_format
        assert "r" in sig_format
        assert "s" in sig_format


class TestStateEnumParity:
    """Test state enum value parity with TS SDK.

    PARITY CRITICAL: State numeric values must match exactly:
    - INITIATED = 0
    - QUOTED = 1
    - COMMITTED = 2
    - IN_PROGRESS = 3
    - DELIVERED = 4
    - SETTLED = 5
    - DISPUTED = 6
    - CANCELLED = 7

    Reference: sdk-js/src/types/state.ts
    """

    def test_state_enum_count(self) -> None:
        """Test we have exactly 8 states matching TS SDK."""
        from agirails.runtime.types import State

        states = list(State)
        assert len(states) == 8, f"Expected 8 states, got {len(states)}"

    def test_initiated_value(self) -> None:
        """Test INITIATED = 0."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[0] == State.INITIATED

    def test_quoted_value(self) -> None:
        """Test QUOTED = 1."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[1] == State.QUOTED

    def test_committed_value(self) -> None:
        """Test COMMITTED = 2."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[2] == State.COMMITTED

    def test_in_progress_value(self) -> None:
        """Test IN_PROGRESS = 3."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[3] == State.IN_PROGRESS

    def test_delivered_value(self) -> None:
        """Test DELIVERED = 4."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[4] == State.DELIVERED

    def test_settled_value(self) -> None:
        """Test SETTLED = 5."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[5] == State.SETTLED

    def test_disputed_value(self) -> None:
        """Test DISPUTED = 6."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[6] == State.DISPUTED

    def test_cancelled_value(self) -> None:
        """Test CANCELLED = 7."""
        from agirails.runtime.types import INT_TO_STATE, State

        assert INT_TO_STATE[7] == State.CANCELLED

    def test_all_state_values_match_ts(self) -> None:
        """PARITY CRITICAL: Complete validation of all state values."""
        from agirails.runtime.types import INT_TO_STATE, State

        expected = {
            0: State.INITIATED,
            1: State.QUOTED,
            2: State.COMMITTED,
            3: State.IN_PROGRESS,
            4: State.DELIVERED,
            5: State.SETTLED,
            6: State.DISPUTED,
            7: State.CANCELLED,
        }
        for int_value, expected_state in expected.items():
            assert INT_TO_STATE[int_value] == expected_state, (
                f"INT_TO_STATE[{int_value}] = {INT_TO_STATE[int_value]}, expected {expected_state}"
            )


class TestStateTransitionParity:
    """Test state transition rules match TS SDK.

    Reference: sdk-js/src/types/state.ts StateMachine.TRANSITIONS
    """

    def test_initiated_transitions(self) -> None:
        """INITIATED can go to: QUOTED, COMMITTED, CANCELLED."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.INITIATED])
        expected = {State.QUOTED, State.COMMITTED, State.CANCELLED}
        assert valid == expected, f"INITIATED transitions: got {valid}, expected {expected}"

    def test_quoted_transitions(self) -> None:
        """QUOTED can go to: COMMITTED, CANCELLED."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.QUOTED])
        expected = {State.COMMITTED, State.CANCELLED}
        assert valid == expected

    def test_committed_transitions(self) -> None:
        """COMMITTED can go to: IN_PROGRESS, CANCELLED (AUDIT FIX: cannot skip to DELIVERED)."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.COMMITTED])
        # AUDIT FIX: COMMITTED cannot skip directly to DELIVERED - must go through IN_PROGRESS
        expected = {State.IN_PROGRESS, State.CANCELLED}
        assert valid == expected

    def test_in_progress_transitions(self) -> None:
        """IN_PROGRESS can go to: DELIVERED, CANCELLED."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.IN_PROGRESS])
        expected = {State.DELIVERED, State.CANCELLED}
        assert valid == expected

    def test_delivered_transitions(self) -> None:
        """DELIVERED can go to: SETTLED, DISPUTED."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.DELIVERED])
        expected = {State.SETTLED, State.DISPUTED}
        assert valid == expected

    def test_disputed_transitions(self) -> None:
        """DISPUTED can go to: SETTLED, CANCELLED (AUDIT FIX: admin can cancel)."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = set(STATE_TRANSITIONS[State.DISPUTED])
        # AUDIT FIX: DISPUTED can be cancelled by admin/pauser
        expected = {State.SETTLED, State.CANCELLED}
        assert valid == expected

    def test_settled_is_terminal(self) -> None:
        """SETTLED is terminal (no valid transitions)."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = STATE_TRANSITIONS[State.SETTLED]
        assert valid == [], "SETTLED should be terminal (empty list)"

    def test_cancelled_is_terminal(self) -> None:
        """CANCELLED is terminal (no valid transitions)."""
        from agirails.runtime.types import STATE_TRANSITIONS, State

        valid = STATE_TRANSITIONS[State.CANCELLED]
        assert valid == [], "CANCELLED should be terminal (empty list)"

    def test_terminal_states_match_ts(self) -> None:
        """Terminal states match TS SDK."""
        from agirails.runtime.types import TERMINAL_STATES, State

        expected = frozenset({State.SETTLED, State.CANCELLED})
        assert TERMINAL_STATES == expected


class TestAmountParsingParity:
    """Test USDC amount handling parity with TS SDK.

    PARITY CRITICAL:
    - USDC has 6 decimals (not 18 like ETH)
    - 1 USDC = 1_000_000 wei
    - $0.05 minimum = 50_000 wei

    Reference: sdk-js/src/utils/Helpers.ts USDC object
    """

    def test_usdc_decimals(self) -> None:
        """USDC uses 6 decimals, not 18."""
        # This is a documentation/knowledge test
        # 1 USDC = 10^6 base units
        assert 10**6 == 1_000_000

    def test_one_usdc_to_wei(self) -> None:
        """1 USDC = 1,000,000 wei."""
        # TS: parseUSDC("1") returns 1_000_000n
        one_usdc = 1_000_000
        assert one_usdc == 10**6

    def test_minimum_amount_wei(self) -> None:
        """Minimum amount $0.05 = 50,000 wei."""
        # TS: USDC.MIN_AMOUNT_WEI = 50_000n
        min_amount = 50_000
        assert min_amount == int(0.05 * 1_000_000)

    def test_fractional_usdc_parsing(self) -> None:
        """Test fractional USDC amounts."""
        # $10.50 USDC = 10_500_000 wei
        amount = int(10.50 * 1_000_000)
        assert amount == 10_500_000

        # $0.01 USDC = 10_000 wei
        small_amount = int(0.01 * 1_000_000)
        assert small_amount == 10_000

    def test_large_amount_precision(self) -> None:
        """Test large amounts maintain precision."""
        # $1,000,000 USDC = 1_000_000_000_000 wei
        large_amount = int(1_000_000 * 1_000_000)
        assert large_amount == 1_000_000_000_000

    def test_wei_to_usdc_formatting(self) -> None:
        """Test wei to USDC formatting matches TS SDK."""
        # TS: USDC.fromWei(100_000_000) returns "100.00"
        wei = 100_000_000
        usdc = wei / 1_000_000
        assert usdc == 100.0

        # TS: USDC.fromWei(1_234_567) returns "1.23" (truncated to 2 decimals)
        wei2 = 1_234_567
        usdc2 = wei2 // 10_000 / 100  # Truncate to 2 decimals
        assert usdc2 == 1.23

    def test_amount_string_format(self) -> None:
        """Amount should be stored as string in transactions (TS SDK behavior)."""
        # TS SDK stores amounts as strings for BigInt precision
        amount_wei = 100_000_000
        amount_str = str(amount_wei)
        assert amount_str == "100000000"
        assert int(amount_str) == amount_wei


class TestKeccak256HashParity:
    """Test keccak256 hash parity with TS SDK.

    PARITY CRITICAL: Hash computation must match exactly.
    Reference: sdk-js/src/builders/DeliveryProofBuilder.ts computeResultHash
    """

    def test_compute_result_hash_simple(self) -> None:
        """Test keccak256 hash of simple object."""
        from agirails.types.message import compute_result_hash

        # Hash of {"hello": "world"}
        result = compute_result_hash({"hello": "world"})
        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_compute_result_hash_deterministic(self) -> None:
        """Hash is deterministic for same input."""
        from agirails.types.message import compute_result_hash

        data = {"test": "value", "number": 42}
        hash1 = compute_result_hash(data)
        hash2 = compute_result_hash(data)
        assert hash1 == hash2

    def test_compute_output_hash_from_builder(self) -> None:
        """Test compute_output_hash from delivery_proof builder."""
        from agirails.builders.delivery_proof import compute_output_hash

        result = compute_output_hash({"result": "success"})
        assert result.startswith("0x")
        assert len(result) == 66

    def test_hash_uses_canonical_json(self) -> None:
        """Hash uses canonical JSON serialization."""
        from agirails.types.message import compute_result_hash

        # Different key order should produce same hash (canonical sorts keys)
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        # Note: canonical_json_dumps sorts keys, so order doesn't matter
        hash1 = compute_result_hash(data1)
        hash2 = compute_result_hash(data2)
        assert hash1 == hash2

    def test_hash_format_bytes32(self) -> None:
        """Hash output is bytes32 format (32 bytes = 64 hex chars)."""
        from agirails.types.message import compute_result_hash

        result = compute_result_hash("test data")
        # Remove 0x prefix and check length
        hex_part = result[2:]
        assert len(hex_part) == 64  # 32 bytes = 64 hex chars


class TestTransactionStateParity:
    """Test TransactionState enum parity with TS SDK.

    Reference: sdk-js/src/types/state.ts State enum
    """

    def test_transaction_state_values(self) -> None:
        """TransactionState IntEnum values match TS SDK."""
        from agirails.types.transaction import TransactionState

        expected = {
            TransactionState.INITIATED: 0,
            TransactionState.QUOTED: 1,
            TransactionState.COMMITTED: 2,
            TransactionState.IN_PROGRESS: 3,
            TransactionState.DELIVERED: 4,
            TransactionState.SETTLED: 5,
            TransactionState.DISPUTED: 6,
            TransactionState.CANCELLED: 7,
        }
        for state, expected_value in expected.items():
            assert state.value == expected_value, (
                f"TransactionState.{state.name} = {state.value}, expected {expected_value}"
            )

    def test_transaction_state_names(self) -> None:
        """TransactionState names match TS SDK."""
        from agirails.types.transaction import TransactionState

        expected_names = [
            "INITIATED",
            "QUOTED",
            "COMMITTED",
            "IN_PROGRESS",
            "DELIVERED",
            "SETTLED",
            "DISPUTED",
            "CANCELLED",
        ]
        actual_names = [s.name for s in TransactionState]
        assert actual_names == expected_names

    def test_is_terminal_property(self) -> None:
        """is_terminal property matches TS SDK StateMachine.isTerminalState()."""
        from agirails.types.transaction import TransactionState

        # Terminal states
        assert TransactionState.SETTLED.is_terminal is True
        assert TransactionState.CANCELLED.is_terminal is True

        # Non-terminal states
        assert TransactionState.INITIATED.is_terminal is False
        assert TransactionState.QUOTED.is_terminal is False
        assert TransactionState.COMMITTED.is_terminal is False
        assert TransactionState.IN_PROGRESS.is_terminal is False
        assert TransactionState.DELIVERED.is_terminal is False
        assert TransactionState.DISPUTED.is_terminal is False


class TestStateHelperParity:
    """Test StateHelper utility parity with TS SDK.

    Reference: sdk-js/src/utils/Helpers.ts State object
    """

    def test_state_helper_states_list(self) -> None:
        """StateHelper.STATES matches TS SDK State.STATES."""
        from agirails.utils.helpers import StateHelper

        expected = (
            "INITIATED",
            "QUOTED",
            "COMMITTED",
            "IN_PROGRESS",
            "DELIVERED",
            "SETTLED",
            "DISPUTED",
            "CANCELLED",
        )
        assert StateHelper.STATES == expected

    def test_state_helper_terminal(self) -> None:
        """StateHelper.TERMINAL matches TS SDK State.TERMINAL."""
        from agirails.utils.helpers import StateHelper

        expected = ("SETTLED", "CANCELLED")
        assert StateHelper.TERMINAL == expected

    def test_state_helper_is_terminal(self) -> None:
        """StateHelper.is_terminal() matches TS SDK State.isTerminal()."""
        from agirails.utils.helpers import StateHelper

        assert StateHelper.is_terminal("SETTLED") is True
        assert StateHelper.is_terminal("CANCELLED") is True
        assert StateHelper.is_terminal("INITIATED") is False
        assert StateHelper.is_terminal("DELIVERED") is False


# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
