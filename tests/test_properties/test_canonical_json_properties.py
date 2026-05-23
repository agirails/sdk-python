"""Property-based tests for canonical JSON encoding.

The canonical encoder MUST produce byte-identical output for the same
logical content, regardless of dict key ordering or whitespace. This is
the foundation of cross-SDK message-hash agreement (see B: cross-SDK
parity). If any of these invariants break, the Python SDK silently
diverges from the TS SDK.

Invariants under test:

  1. **Order independence**: ``dump({a:1, b:2}) == dump({b:2, a:1})``.
     Encoder must sort keys deterministically.
  2. **Idempotency**: ``dump(load(dump(x))) == dump(x)``. Re-serializing
     parsed output must yield the same bytes.
  3. **Determinism**: ``dump(x) == dump(x)`` (called twice). No hidden
     state, no random tie-breaking.
  4. **Nested order independence**: same invariant holds recursively.
  5. **String escaping**: unicode is preserved through round-trip.
"""

from __future__ import annotations

import json

from hypothesis import given, settings, strategies as st

from agirails.utils.canonical_json import canonical_json_dumps


# Recursive strategy for JSON-safe values: primitives + nested dicts + lists.
def _json_values():
    return st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-(2**53), max_value=2**53),
            st.floats(allow_nan=False, allow_infinity=False, width=32),
            st.text(min_size=0, max_size=20),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(
                # JSON keys must be strings.
                st.text(min_size=1, max_size=10),
                children,
                max_size=5,
            ),
        ),
        max_leaves=12,
    )


class TestCanonicalJsonInvariants:
    @given(value=_json_values())
    @settings(max_examples=200, deadline=None)
    def test_deterministic(self, value):
        """Same input → same output, every time."""
        a = canonical_json_dumps(value)
        b = canonical_json_dumps(value)
        assert a == b

    @given(value=_json_values())
    @settings(max_examples=200, deadline=None)
    def test_idempotent_through_parse(self, value):
        """dump(load(dump(x))) == dump(x). Re-encoding must not drift."""
        once = canonical_json_dumps(value)
        roundtrip = canonical_json_dumps(json.loads(once))
        assert once == roundtrip

    @given(
        keys=st.lists(st.text(min_size=1, max_size=8), min_size=2, max_size=6, unique=True),
        vals=st.lists(st.integers(min_value=0, max_value=1000), min_size=2, max_size=6),
    )
    @settings(max_examples=100, deadline=None)
    def test_dict_order_independence(self, keys, vals):
        """Encoder must sort dict keys deterministically — different
        insertion order, same canonical bytes."""
        n = min(len(keys), len(vals))
        if n < 2:
            return
        keys, vals = keys[:n], vals[:n]
        forward = dict(zip(keys, vals))
        reverse = dict(zip(reversed(keys), reversed(vals)))
        assert canonical_json_dumps(forward) == canonical_json_dumps(reverse)

    @given(
        inner_keys=st.lists(st.text(min_size=1, max_size=6), min_size=2, max_size=4, unique=True),
        inner_vals=st.lists(st.integers(), min_size=2, max_size=4),
    )
    @settings(max_examples=100, deadline=None)
    def test_nested_dict_order_independence(self, inner_keys, inner_vals):
        """Order independence holds recursively — nested dicts also sorted."""
        n = min(len(inner_keys), len(inner_vals))
        if n < 2:
            return
        inner_keys, inner_vals = inner_keys[:n], inner_vals[:n]
        forward = {"outer": dict(zip(inner_keys, inner_vals))}
        reverse = {"outer": dict(zip(reversed(inner_keys), reversed(inner_vals)))}
        assert canonical_json_dumps(forward) == canonical_json_dumps(reverse)

    @given(s=st.text(min_size=0, max_size=50))
    @settings(max_examples=200, deadline=None)
    def test_unicode_preserved_through_roundtrip(self, s):
        """Strings survive canonical → parse → canonical."""
        encoded = canonical_json_dumps({"text": s})
        decoded = json.loads(encoded)
        assert decoded["text"] == s
