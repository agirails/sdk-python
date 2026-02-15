"""
Tests for ERC-8004 Reputation Reporter.

Uses mock contracts and web3 instances to avoid real RPC calls.
All public methods of ReputationReporter should NEVER throw.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest
from web3 import Web3

from agirails.erc8004.reputation_reporter import ReputationReporter
from agirails.types.erc8004 import (
    ACTP_FEEDBACK_TAGS,
    ReportResult,
    ReputationReporterConfig,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

MOCK_TX_HASH = bytes.fromhex("aa" * 32)
MOCK_RECEIPT = {"transactionHash": MOCK_TX_HASH}
MOCK_SIGNER = "0x" + "ab" * 20


class MockCallable:
    """Simulates a contract function call/build_transaction result."""

    def __init__(self, value: Any = None, *, raises: Optional[Exception] = None):
        self._value = value
        self._raises = raises

    def call(self) -> Any:
        if self._raises:
            raise self._raises
        return self._value

    def build_transaction(self, params: Dict) -> Dict:
        if self._raises:
            raise self._raises
        return {"to": "0x" + "00" * 20, "data": "0x", "gas": 200000, "nonce": 0}


class MockFunctions:
    """Mock for reputation contract.functions."""

    def __init__(
        self,
        *,
        give_feedback_raises: Optional[Exception] = None,
        summaries: Optional[Dict[str, tuple]] = None,
    ):
        self._give_feedback_raises = give_feedback_raises
        self._summaries = summaries or {}
        self.last_feedback_call: Optional[Dict] = None

    def giveFeedback(
        self, agent_id: int, value: int, feedback_hash: bytes, tag1: str
    ) -> MockCallable:
        self.last_feedback_call = {
            "agent_id": agent_id,
            "value": value,
            "feedback_hash": feedback_hash,
            "tag1": tag1,
        }
        return MockCallable(raises=self._give_feedback_raises)

    def getSummary(self, agent_id: int, tag1: str) -> MockCallable:
        key = f"{agent_id}:{tag1}"
        if key in self._summaries:
            return MockCallable(self._summaries[key])
        # Default: no reputation
        return MockCallable((0, 0, 0))


class MockContract:
    def __init__(self, **kwargs: Any):
        self.functions = MockFunctions(**kwargs)


class MockEth:
    """Mock for w3.eth with signing support."""

    def __init__(self, *, send_raises: Optional[Exception] = None):
        self._send_raises = send_raises
        self.account = MagicMock()
        signed = MagicMock()
        signed.raw_transaction = b"\x00" * 32
        self.account.sign_transaction.return_value = signed

    def get_transaction_count(self, address: str) -> int:
        return 0

    def send_raw_transaction(self, raw: bytes) -> bytes:
        if self._send_raises:
            raise self._send_raises
        return MOCK_TX_HASH

    def wait_for_transaction_receipt(self, tx_hash: bytes) -> Dict:
        return MOCK_RECEIPT


class MockW3:
    """Mock Web3 instance."""

    def __init__(self, **kwargs: Any):
        self.eth = MockEth(**kwargs)


def _make_reporter(
    *,
    give_feedback_raises: Optional[Exception] = None,
    send_raises: Optional[Exception] = None,
    summaries: Optional[Dict[str, tuple]] = None,
) -> ReputationReporter:
    """Create a reporter with mock contract and w3."""
    contract = MockContract(
        give_feedback_raises=give_feedback_raises,
        summaries=summaries,
    )
    w3 = MockW3(send_raises=send_raises)
    config = ReputationReporterConfig(
        network="base-sepolia",
        private_key="0x" + "ab" * 32,
    )
    reporter = ReputationReporter(config, contract=contract, w3=w3)
    # Inject a mock account
    account = MagicMock()
    account.address = MOCK_SIGNER
    reporter._account = account
    return reporter


# ---------------------------------------------------------------------------
# Tests: report_settlement
# ---------------------------------------------------------------------------


class TestReportSettlement:
    async def test_success(self):
        reporter = _make_reporter()
        result = await reporter.report_settlement(agent_id="42", tx_id="0xabc123")
        assert result is not None
        assert isinstance(result, ReportResult)
        assert result.agent_id == "42"
        assert result.tag == ACTP_FEEDBACK_TAGS["SETTLED"]
        assert result.feedback_hash  # non-empty

    async def test_local_dedup_prevents_double_report(self):
        reporter = _make_reporter()
        r1 = await reporter.report_settlement(agent_id="42", tx_id="0xabc123")
        assert r1 is not None

        r2 = await reporter.report_settlement(agent_id="42", tx_id="0xabc123")
        assert r2 is None  # Deduplicated

    async def test_feedback_hash_is_keccak256_of_tx_id(self):
        reporter = _make_reporter()
        tx_id = "0xdeadbeef"
        expected_hash = Web3.keccak(text=tx_id).hex()

        result = await reporter.report_settlement(agent_id="1", tx_id=tx_id)
        assert result is not None
        assert result.feedback_hash == expected_hash

    async def test_gives_positive_feedback(self):
        reporter = _make_reporter()
        await reporter.report_settlement(agent_id="42", tx_id="0xabc")
        last_call = reporter._contract.functions.last_feedback_call
        assert last_call is not None
        assert last_call["value"] == 1
        assert last_call["tag1"] == "actp_settled"


# ---------------------------------------------------------------------------
# Tests: report_dispute
# ---------------------------------------------------------------------------


class TestReportDispute:
    async def test_agent_won_gives_positive_feedback(self):
        reporter = _make_reporter()
        result = await reporter.report_dispute(
            agent_id="42", tx_id="0xdispute1", agent_won=True
        )
        assert result is not None
        assert result.tag == ACTP_FEEDBACK_TAGS["DISPUTE_WON"]
        last_call = reporter._contract.functions.last_feedback_call
        assert last_call["value"] == 1

    async def test_agent_lost_gives_negative_feedback(self):
        reporter = _make_reporter()
        result = await reporter.report_dispute(
            agent_id="42", tx_id="0xdispute2", agent_won=False
        )
        assert result is not None
        assert result.tag == ACTP_FEEDBACK_TAGS["DISPUTE_LOST"]
        last_call = reporter._contract.functions.last_feedback_call
        assert last_call["value"] == -1

    async def test_dispute_dedup(self):
        reporter = _make_reporter()
        r1 = await reporter.report_dispute(
            agent_id="42", tx_id="0xdispute3", agent_won=True
        )
        assert r1 is not None
        r2 = await reporter.report_dispute(
            agent_id="42", tx_id="0xdispute3", agent_won=True
        )
        assert r2 is None


# ---------------------------------------------------------------------------
# Tests: get_agent_reputation
# ---------------------------------------------------------------------------


class TestGetAgentReputation:
    async def test_returns_summary(self):
        reporter = _make_reporter(summaries={"42:actp_settled": (10, 2, 12)})
        result = await reporter.get_agent_reputation("42", tag1="actp_settled")
        assert result is not None
        assert result["positive"] == 10
        assert result["negative"] == 2
        assert result["total"] == 12

    async def test_returns_none_on_error(self):
        reporter = _make_reporter()
        # Override getSummary to raise
        original_fn = reporter._contract.functions.getSummary

        def broken_summary(agent_id: int, tag1: str) -> MockCallable:
            return MockCallable(raises=Exception("RPC error"))

        reporter._contract.functions.getSummary = broken_summary
        result = await reporter.get_agent_reputation("42")
        assert result is None

    async def test_empty_tag_returns_overall_summary(self):
        reporter = _make_reporter(summaries={"42:": (5, 1, 6)})
        result = await reporter.get_agent_reputation("42")
        assert result is not None
        assert result["total"] == 6


# ---------------------------------------------------------------------------
# Tests: never throws
# ---------------------------------------------------------------------------


class TestNeverThrows:
    async def test_report_settlement_never_throws_on_send_error(self):
        reporter = _make_reporter(send_raises=Exception("network down"))
        result = await reporter.report_settlement(agent_id="42", tx_id="0xfail1")
        assert result is None  # Returned None, did NOT raise

    async def test_report_dispute_never_throws_on_build_error(self):
        reporter = _make_reporter(give_feedback_raises=Exception("revert"))
        result = await reporter.report_dispute(
            agent_id="42", tx_id="0xfail2", agent_won=True
        )
        assert result is None

    async def test_report_settlement_never_throws_insufficient_funds(self):
        reporter = _make_reporter(
            send_raises=Exception("insufficient funds for gas")
        )
        result = await reporter.report_settlement(agent_id="1", tx_id="0xfail3")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: clear cache
# ---------------------------------------------------------------------------


class TestClearReportedCache:
    async def test_clear_allows_re_report(self):
        reporter = _make_reporter()
        r1 = await reporter.report_settlement(agent_id="42", tx_id="0xclear1")
        assert r1 is not None
        assert reporter.is_reported("0xclear1") is True

        reporter.clear_reported_cache()
        assert reporter.is_reported("0xclear1") is False

        r2 = await reporter.report_settlement(agent_id="42", tx_id="0xclear1")
        assert r2 is not None
