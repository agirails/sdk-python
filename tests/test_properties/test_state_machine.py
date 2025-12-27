"""
Property-Based Tests for ACTP State Machine.

Uses Hypothesis for property-based testing to verify invariants that must
always hold regardless of input values. These tests complement unit tests
by exploring edge cases that humans might not think of.

CRITICAL INVARIANTS:
1. State values are monotonically increasing (no backwards transitions)
2. Terminal states have no valid transitions
3. All state integers are in range [0, 7]
4. State transitions are deterministic
"""

import pytest
from hypothesis import given, settings, assume, example
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, precondition

from agirails.runtime.types import (
    State,
    STATE_TRANSITIONS,
    TERMINAL_STATES,
    INT_TO_STATE,
    is_valid_transition,
    is_terminal_state,
)
from agirails.types.transaction import TransactionState, is_valid_transition as tx_is_valid_transition


# Strategy for generating valid state names
state_names_strategy = st.sampled_from([s.value for s in State])

# Strategy for generating state integers
state_int_strategy = st.integers(min_value=0, max_value=7)

# Strategy for generating invalid state integers
invalid_state_int_strategy = st.one_of(
    st.integers(max_value=-1),
    st.integers(min_value=8),
)

# Strategy for generating USDC amounts in wei
usdc_wei_strategy = st.integers(min_value=0, max_value=10**18)  # Up to 10^12 USDC

# Strategy for generating valid USDC amounts (above minimum)
valid_usdc_amount_strategy = st.integers(min_value=50_000, max_value=10**18)


class TestStateEnumProperties:
    """Property-based tests for State enum."""

    @given(state_int_strategy)
    def test_all_int_values_map_to_state(self, int_value: int) -> None:
        """All integers 0-7 map to a valid state."""
        state = INT_TO_STATE[int_value]
        assert state is not None
        assert isinstance(state, State)

    @given(state_names_strategy)
    def test_all_state_names_are_valid(self, state_name: str) -> None:
        """All state names correspond to valid State enum values."""
        state = State(state_name)
        assert state.value == state_name

    @given(state_names_strategy, state_names_strategy)
    def test_transition_validation_is_deterministic(
        self, from_state: str, to_state: str
    ) -> None:
        """Transition validation always returns same result for same inputs."""
        result1 = is_valid_transition(from_state, to_state)
        result2 = is_valid_transition(from_state, to_state)
        assert result1 == result2

    @given(state_names_strategy)
    def test_terminal_states_have_no_transitions(self, state_name: str) -> None:
        """Terminal states cannot transition to any other state."""
        if state_name in [s.value for s in TERMINAL_STATES]:
            # No valid transitions from terminal state
            for target in State:
                assert not is_valid_transition(state_name, target.value)


class TestStateTransitionProperties:
    """Property-based tests for state transitions."""

    @given(state_int_strategy, state_int_strategy)
    def test_no_backwards_transitions(self, from_int: int, to_int: int) -> None:
        """State values should only increase or remain same (with expected exceptions)."""
        from_state = INT_TO_STATE[from_int]
        to_state = INT_TO_STATE[to_int]

        # If transition is valid, verify it's not going backwards
        # Exceptions that are valid "backwards" transitions:
        # - CANCELLED (7) can come from earlier states
        # - SETTLED (5) can come from DISPUTED (6) - dispute resolution
        if is_valid_transition(from_state, to_state):
            if to_state not in (State.CANCELLED, State.SETTLED):
                assert to_int >= from_int, (
                    f"Invalid backwards transition: {from_state.value} ({from_int}) -> "
                    f"{to_state.value} ({to_int})"
                )

    @given(state_names_strategy)
    def test_state_has_explicit_transition_list(self, state_name: str) -> None:
        """Every state has an explicit transition list (possibly empty)."""
        state = State(state_name)
        assert state in STATE_TRANSITIONS
        transitions = STATE_TRANSITIONS[state]
        assert isinstance(transitions, list)

    @given(state_names_strategy)
    @example("SETTLED")
    @example("CANCELLED")
    def test_terminal_state_symmetry(self, state_name: str) -> None:
        """Terminal states are exactly those with empty transition lists."""
        state = State(state_name)
        is_terminal = state in TERMINAL_STATES
        has_no_transitions = len(STATE_TRANSITIONS[state]) == 0
        assert is_terminal == has_no_transitions


class TestTransactionStateProperties:
    """Property-based tests for TransactionState enum."""

    @given(state_int_strategy)
    def test_transaction_state_int_mapping(self, int_value: int) -> None:
        """All integers 0-7 map to valid TransactionState values."""
        state = TransactionState(int_value)
        assert state.value == int_value

    @given(st.sampled_from(list(TransactionState)))
    def test_is_terminal_property_correct(self, state: TransactionState) -> None:
        """is_terminal property correctly identifies terminal states."""
        is_terminal = state.is_terminal
        expected_terminal = state in (TransactionState.SETTLED, TransactionState.CANCELLED)
        assert is_terminal == expected_terminal


class TestAmountProperties:
    """Property-based tests for USDC amount handling."""

    @given(usdc_wei_strategy)
    def test_amount_to_string_and_back(self, amount: int) -> None:
        """Converting amount to string and back preserves value."""
        amount_str = str(amount)
        recovered = int(amount_str)
        assert recovered == amount

    @given(valid_usdc_amount_strategy)
    def test_valid_amounts_above_minimum(self, amount: int) -> None:
        """All valid amounts are at or above minimum ($0.05 = 50,000 wei)."""
        assert amount >= 50_000

    @given(st.decimals(min_value=0, max_value=1_000_000, places=2))
    def test_usdc_to_wei_precision(self, usdc_amount) -> None:
        """Converting USDC to wei maintains precision for valid decimal places."""
        # Skip invalid decimals
        assume(not usdc_amount.is_nan() and not usdc_amount.is_infinite())

        wei = int(usdc_amount * 1_000_000)
        recovered_usdc = wei / 1_000_000

        # Should match to 2 decimal places
        expected = float(round(usdc_amount, 2))
        assert abs(recovered_usdc - expected) < 0.0001


class TestHashingProperties:
    """Property-based tests for hashing functions."""

    @given(st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False, allow_infinity=False)),
        min_size=0,
        max_size=10,
    ))
    def test_hash_is_deterministic(self, data: dict) -> None:
        """Hashing same data always produces same result."""
        from agirails.types.message import compute_result_hash

        hash1 = compute_result_hash(data)
        hash2 = compute_result_hash(data)
        assert hash1 == hash2

    @given(st.text(min_size=1, max_size=100))
    def test_hash_format_is_bytes32(self, data: str) -> None:
        """All hashes are properly formatted as bytes32."""
        from agirails.types.message import compute_result_hash

        result = compute_result_hash(data)
        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    @given(st.text(min_size=1), st.text(min_size=1))
    def test_different_inputs_produce_different_hashes(
        self, data1: str, data2: str
    ) -> None:
        """Different inputs should (almost always) produce different hashes."""
        assume(data1 != data2)

        from agirails.types.message import compute_result_hash

        hash1 = compute_result_hash(data1)
        hash2 = compute_result_hash(data2)
        # Collision probability is negligible for keccak256
        assert hash1 != hash2


class TestServiceHashProperties:
    """Property-based tests for ServiceHash canonicalization."""

    @given(st.text(min_size=1, max_size=50))
    def test_canonical_json_is_deterministic(self, service_name: str) -> None:
        """Canonical JSON for same input is always identical."""
        from agirails.utils.helpers import ServiceHash, ServiceMetadata

        metadata = ServiceMetadata(service=service_name)
        canonical1 = ServiceHash.to_canonical(metadata)
        canonical2 = ServiceHash.to_canonical(metadata)
        assert canonical1 == canonical2

    @given(
        st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=["Cs"])),
        st.one_of(st.none(), st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=["Cs"]))),
    )
    def test_hash_includes_service_name(self, service: str, input_data) -> None:
        """Hash depends on service name - different services produce different hashes."""
        from agirails.utils.helpers import ServiceHash, ServiceMetadata

        meta1 = ServiceMetadata(service=service, input=input_data)
        meta2 = ServiceMetadata(service=service + "_different", input=input_data)

        hash1 = ServiceHash.hash(meta1)
        hash2 = ServiceHash.hash(meta2)
        assert hash1 != hash2


class ACTPStateMachineTest(RuleBasedStateMachine):
    """
    Stateful testing for ACTP state machine.

    Uses Hypothesis RuleBasedStateMachine to simulate realistic transaction
    lifecycles and verify invariants are maintained throughout.
    """

    def __init__(self) -> None:
        super().__init__()
        self.current_state = State.INITIATED
        self.state_history: list[State] = [State.INITIATED]

    @rule()
    def transition_to_quoted(self) -> None:
        """Transition to QUOTED state."""
        if is_valid_transition(self.current_state, State.QUOTED):
            self.current_state = State.QUOTED
            self.state_history.append(State.QUOTED)

    @rule()
    def transition_to_committed(self) -> None:
        """Transition to COMMITTED state."""
        if is_valid_transition(self.current_state, State.COMMITTED):
            self.current_state = State.COMMITTED
            self.state_history.append(State.COMMITTED)

    @rule()
    def transition_to_in_progress(self) -> None:
        """Transition to IN_PROGRESS state."""
        if is_valid_transition(self.current_state, State.IN_PROGRESS):
            self.current_state = State.IN_PROGRESS
            self.state_history.append(State.IN_PROGRESS)

    @rule()
    def transition_to_delivered(self) -> None:
        """Transition to DELIVERED state."""
        if is_valid_transition(self.current_state, State.DELIVERED):
            self.current_state = State.DELIVERED
            self.state_history.append(State.DELIVERED)

    @rule()
    def transition_to_settled(self) -> None:
        """Transition to SETTLED state."""
        if is_valid_transition(self.current_state, State.SETTLED):
            self.current_state = State.SETTLED
            self.state_history.append(State.SETTLED)

    @rule()
    def transition_to_disputed(self) -> None:
        """Transition to DISPUTED state."""
        if is_valid_transition(self.current_state, State.DISPUTED):
            self.current_state = State.DISPUTED
            self.state_history.append(State.DISPUTED)

    @rule()
    def transition_to_cancelled(self) -> None:
        """Transition to CANCELLED state."""
        if is_valid_transition(self.current_state, State.CANCELLED):
            self.current_state = State.CANCELLED
            self.state_history.append(State.CANCELLED)

    @invariant()
    def state_is_valid(self) -> None:
        """Current state is always a valid State enum value."""
        assert self.current_state in State

    @invariant()
    def terminal_states_are_final(self) -> None:
        """Once in terminal state, no further transitions possible."""
        if self.current_state in TERMINAL_STATES:
            assert len(STATE_TRANSITIONS[self.current_state]) == 0

    @invariant()
    def state_history_follows_transitions(self) -> None:
        """All state transitions in history are valid."""
        for i in range(1, len(self.state_history)):
            from_state = self.state_history[i - 1]
            to_state = self.state_history[i]
            assert to_state in STATE_TRANSITIONS[from_state], (
                f"Invalid transition in history: {from_state} -> {to_state}"
            )


# Run the stateful test
TestACTPStateMachine = ACTPStateMachineTest.TestCase


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
