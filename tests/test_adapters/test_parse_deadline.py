"""
Parity tests for BaseAdapter.parse_deadline.

These assert byte/semantically-identical behavior to the TypeScript source of
truth: sdk-js/src/adapters/BaseAdapter.ts:271 (parseDeadline).

TS contract being mirrored:
- ``None``        -> now + DEFAULT_DEADLINE_SECONDS (24h)
- ``int``         -> passed through verbatim as a Unix timestamp
- ``"+Nh"``       -> now + N * 3600
- ``"+Nd"``       -> now + N * 86400
- bounds: hours <= MAX_DEADLINE_HOURS (87600), days <= MAX_DEADLINE_DAYS (3650)
- everything else (bare "24h", "-24h", "invalid", ISO date, out-of-bounds)
  raises ValidationError.
"""

import time

import pytest

from agirails.errors import ValidationError
from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DEADLINE_SECONDS,
    MAX_DEADLINE_HOURS,
    MAX_DEADLINE_DAYS,
)


# A fixed "now" used for every deterministic assertion. This is a real
# near-future-ish Unix timestamp; it is intentionally LARGE so we can also
# exercise the "small int is a literal timestamp" rule.
FIXED_NOW = 1_734_000_000


class _StubTime:
    def __init__(self, value: int) -> None:
        self._value = value

    def now(self) -> int:
        return self._value


class _StubRuntime:
    """Minimal runtime exposing ``.time.now()`` like the mock runtime."""

    def __init__(self, now: int) -> None:
        self.time = _StubTime(now)


@pytest.fixture
def adapter() -> BaseAdapter:
    runtime = _StubRuntime(FIXED_NOW)
    return BaseAdapter(runtime, requester_address="0x" + "a" * 40)


# ---------------------------------------------------------------------------
# Default (None)  — TS BaseAdapter.ts:274-277
# ---------------------------------------------------------------------------

def test_none_returns_now_plus_default(adapter):
    assert adapter.parse_deadline(None, FIXED_NOW) == FIXED_NOW + DEFAULT_DEADLINE_SECONDS


def test_none_uses_runtime_time_when_current_time_omitted(adapter):
    assert adapter.parse_deadline() == FIXED_NOW + DEFAULT_DEADLINE_SECONDS


# ---------------------------------------------------------------------------
# Numeric  — TS BaseAdapter.ts:279-281  (return deadline; literal timestamp)
# ---------------------------------------------------------------------------

def test_int_is_literal_timestamp(adapter):
    # A full Unix timestamp passes through unchanged.
    assert adapter.parse_deadline(1_734_076_400, FIXED_NOW) == 1_734_076_400


def test_small_int_is_literal_timestamp_not_hours(adapter):
    """
    Regression for the prior Python bug: a small int (<=168) used to be
    re-interpreted as "N hours from now". TS treats EVERY number as a literal
    Unix timestamp. 24 must stay 24, NOT now + 24*3600.
    """
    assert adapter.parse_deadline(24, FIXED_NOW) == 24
    assert adapter.parse_deadline(168, FIXED_NOW) == 168
    assert adapter.parse_deadline(0, FIXED_NOW) == 0


def test_int_passthrough_independent_of_now(adapter):
    # Numbers ignore `now` entirely (TS returns deadline directly).
    assert adapter.parse_deadline(42, 999) == 42


# ---------------------------------------------------------------------------
# Relative "+Nh" / "+Nd"  — TS BaseAdapter.ts:284-308
# ---------------------------------------------------------------------------

def test_relative_hours(adapter):
    assert adapter.parse_deadline("+1h", FIXED_NOW) == FIXED_NOW + 3600
    assert adapter.parse_deadline("+24h", FIXED_NOW) == FIXED_NOW + 24 * 3600


def test_relative_days(adapter):
    assert adapter.parse_deadline("+7d", FIXED_NOW) == FIXED_NOW + 7 * 86400
    assert adapter.parse_deadline("+1d", FIXED_NOW) == FIXED_NOW + 86400


def test_relative_uses_runtime_time_when_current_time_omitted():
    runtime = _StubRuntime(FIXED_NOW)
    a = BaseAdapter(runtime, requester_address="0x" + "a" * 40)
    assert a.parse_deadline("+2h") == FIXED_NOW + 2 * 3600


# ---------------------------------------------------------------------------
# Bounds  — TS BaseAdapter.ts:294-304  (10-year cap)
# ---------------------------------------------------------------------------

def test_max_hours_at_bound_ok(adapter):
    assert adapter.parse_deadline(f"+{MAX_DEADLINE_HOURS}h", FIXED_NOW) == (
        FIXED_NOW + MAX_DEADLINE_HOURS * 3600
    )


def test_hours_above_bound_rejected(adapter):
    with pytest.raises(ValidationError) as exc:
        adapter.parse_deadline(f"+{MAX_DEADLINE_HOURS + 1}h", FIXED_NOW)
    assert "Deadline too far in future" in str(exc.value)


def test_max_days_at_bound_ok(adapter):
    assert adapter.parse_deadline(f"+{MAX_DEADLINE_DAYS}d", FIXED_NOW) == (
        FIXED_NOW + MAX_DEADLINE_DAYS * 86400
    )


def test_days_above_bound_rejected(adapter):
    with pytest.raises(ValidationError) as exc:
        adapter.parse_deadline(f"+{MAX_DEADLINE_DAYS + 1}d", FIXED_NOW)
    assert "Deadline too far in future" in str(exc.value)


def test_bounds_are_ten_years():
    # Mirror TS BaseAdapter.ts:62,68 exactly.
    assert MAX_DEADLINE_HOURS == 87600
    assert MAX_DEADLINE_DAYS == 3650


# ---------------------------------------------------------------------------
# Rejections  — TS only accepts /^\+(\d+)(h|d)$/
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        "24h",        # bare relative form — TS requires the "+" prefix
        "7d",         # bare relative form
        "1h",         # bare relative form
        "-24h",       # negative / wrong shape
        "+24m",       # minutes unit not supported
        "+24",        # missing unit
        "+h",         # missing amount
        "++24h",      # double plus
        "+24 h",      # internal whitespace
        "+24H",       # uppercase unit not matched by /(h|d)/
        "invalid",    # garbage
        "",           # empty
        "1734076400",  # numeric STRING is not a number (TS only accepts number type)
        "2026-01-01T00:00:00Z",  # ISO date — no TS twin, must be rejected now
    ],
)
def test_invalid_string_rejected(adapter, bad):
    with pytest.raises(ValidationError) as exc:
        adapter.parse_deadline(bad, FIXED_NOW)
    assert "Invalid deadline format" in str(exc.value)


def test_bool_rejected_not_treated_as_int(adapter):
    # bool is a subclass of int in Python; ensure True/False don't slip through
    # as the 1/0 timestamp the TS `typeof === 'number'` path would never see.
    with pytest.raises(ValidationError):
        adapter.parse_deadline(True, FIXED_NOW)
    with pytest.raises(ValidationError):
        adapter.parse_deadline(False, FIXED_NOW)


# ---------------------------------------------------------------------------
# simulate.py call-site compatibility: parse_deadline(deadline, current_time)
# ---------------------------------------------------------------------------

def test_two_arg_call_signature(adapter):
    ct = int(time.time())
    assert adapter.parse_deadline("+1h", ct) == ct + 3600
    assert adapter.parse_deadline(None, ct) == ct + DEFAULT_DEADLINE_SECONDS
    assert adapter.parse_deadline(ct + 100, ct) == ct + 100
