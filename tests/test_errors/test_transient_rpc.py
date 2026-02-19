"""Tests for TransientRPCError."""

import pytest

from agirails.errors import ACTPError
from agirails.errors.network import NetworkError, TransientRPCError


class TestTransientRPCError:
    def test_inherits_network_error(self):
        err = TransientRPCError("connection dropped")
        assert isinstance(err, NetworkError)
        assert isinstance(err, ACTPError)

    def test_code_is_transient(self):
        err = TransientRPCError("timeout")
        assert err.code == "TRANSIENT_RPC_ERROR"

    def test_stores_cause(self):
        cause = ConnectionError("reset by peer")
        err = TransientRPCError("rpc failed", cause=cause)
        assert err.cause is cause
        assert "ConnectionError" in err.details.get("cause", "")

    def test_endpoint_forwarded(self):
        err = TransientRPCError("timeout", endpoint="https://rpc.base.org")
        assert err.endpoint == "https://rpc.base.org"

    def test_distinguishable_from_permanent_errors(self):
        from agirails.errors.transaction import TransactionNotFoundError

        transient = TransientRPCError("network hiccup")
        permanent = TransactionNotFoundError("0xdead")
        assert isinstance(transient, TransientRPCError)
        assert not isinstance(permanent, TransientRPCError)
