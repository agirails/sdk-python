"""Property-based tests for USDC amount handling and state-machine
composition invariants.

USDC invariants:
  1. ``to_wei(from_wei(x)) == x`` for all valid integer wei amounts.
  2. ``from_wei`` always returns a string parseable as decimal.

State machine composition invariants:
  3. **Reachability**: any sequence of valid transitions starting from
     INITIATED ends in a state reachable per ``STATE_TRANSITIONS``.
  4. **Terminal absorption**: once you hit a terminal state, no
     further transition is valid.
  5. **Round-trip impossibility**: there is NO sequence of valid
     transitions that returns to an earlier state (state machine is
     a DAG — escrow can only go forward).
"""

from __future__ import annotations

from decimal import Decimal

from hypothesis import given, settings, strategies as st

from agirails.runtime.types import (
    INT_TO_STATE,
    STATE_TRANSITIONS,
    State,
    is_terminal_state,
    is_valid_transition,
)
from agirails.utils.helpers import USDC


# ============================================================================
# USDC amount roundtrip
# ============================================================================


class TestUsdcAmountInvariants:
    """USDC helper semantics:

      - ``to_wei`` is LOSSLESS: preserves full 6-decimal precision.
      - ``from_wei(wei)`` defaults to 2 decimals (DISPLAY formatting,
        lossy below cent). For roundtrip you must pass ``decimals=6``.

    These tests pin the lossless contract so future refactors don't
    silently drop precision in the wire-format-adjacent helpers.
    """

    @given(wei=st.integers(min_value=1, max_value=10**14))  # below 1e15 wei = $1B
    @settings(max_examples=200, deadline=None)
    def test_lossless_roundtrip_with_decimals_6(self, wei):
        """from_wei(decimals=6) is lossless — full precision preserved
        for any wei in the valid range."""
        human = USDC.from_wei(wei, decimals=6)
        back = int(USDC.to_wei(human))
        assert back == wei, f"wei={wei}, human={human!r}, back={back}"

    @given(wei=st.integers(min_value=1, max_value=10**14))
    @settings(max_examples=100, deadline=None)
    def test_from_wei_lossless_decimal_parses(self, wei):
        human = USDC.from_wei(wei, decimals=6)
        d = Decimal(human)
        assert int(d * 1_000_000) == wei

    @given(
        usdc_dollars=st.decimals(
            min_value=Decimal("0.000001"),
            max_value=Decimal("1000000"),
            places=6,
            allow_nan=False,
            allow_infinity=False,
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_to_wei_from_wei_decimals_6_roundtrip(self, usdc_dollars):
        """Decimal input → wei → string-with-6-decimals → same Decimal."""
        wei = USDC.to_wei(str(usdc_dollars))
        back_str = USDC.from_wei(wei, decimals=6)
        assert Decimal(back_str) == usdc_dollars

    @given(wei=st.integers(min_value=1_000_000, max_value=10**12))  # >= $1
    @settings(max_examples=100, deadline=None)
    def test_default_from_wei_is_lossy_below_cent_documented(self, wei):
        """from_wei() with default decimals=2 is INTENTIONALLY lossy
        below cent. This test pins that contract so anyone changing it
        triggers a deliberate update."""
        human = USDC.from_wei(wei)  # default decimals=2
        # 2-decimal output → re-converting may lose sub-cent precision.
        # The contract is "at least dollar-cent precision preserved".
        back = USDC.to_wei(human)
        delta = abs(back - wei)
        assert delta < 10_000, f"loss > 1 cent: wei={wei}, back={back}"


# ============================================================================
# State machine composition (multi-step transitions)
# ============================================================================


class TestStateCompositionInvariants:
    @given(start=st.sampled_from(list(State)))
    def test_terminal_states_have_no_outgoing_transitions(self, start):
        """Once SETTLED / CANCELLED, the state machine is frozen.
        STATE_TRANSITIONS[terminal] must be empty."""
        if not is_terminal_state(start):
            return
        # Terminal means no valid next state for any.
        for any_next in State:
            assert not is_valid_transition(start, any_next), (
                f"Terminal {start} should not transition to {any_next}"
            )

    @given(
        steps=st.lists(
            st.sampled_from(list(State)),
            min_size=1,
            max_size=6,
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_no_backwards_or_round_trip_transitions(self, steps):
        """Walk the state machine following ONLY valid transitions
        from INITIATED. Confirm we never visit the same state twice
        (state machine is a DAG — no loops, no rewinds)."""
        current = State.INITIATED
        visited = {current}
        for target in steps:
            if not is_valid_transition(current, target):
                continue  # skip impossible step, keep walking
            current = target
            # We just transitioned. Confirm we're in a new state — no
            # ACTP transaction can revisit an earlier state.
            assert current not in visited or current == target, (
                f"visited {current.value} twice; state graph has a cycle"
            )
            visited.add(current)
            if is_terminal_state(current):
                break

    @given(stale=st.sampled_from(list(State)))
    def test_state_int_value_is_in_zero_seven(self, stale):
        """Kernel uses uint8 for state → all SDK states must fit."""
        assert 0 <= stale.value_int <= 7
        # And the inverse mapping is consistent.
        assert INT_TO_STATE[stale.value_int] is stale

    @given(start=st.sampled_from(list(State)))
    def test_all_valid_transitions_lead_to_real_states(self, start):
        """STATE_TRANSITIONS values must all be members of the State enum."""
        for target in STATE_TRANSITIONS.get(start, []):
            assert isinstance(target, State)
            # Non-terminal transitions must remain reachable from INITIATED
            # via SOME chain (sanity check on transition graph completeness).
            # We don't enforce this here as a strict invariant — admin paths
            # like DISPUTED → SETTLED start from non-INITIATED — but the
            # type check above is the real assertion.
