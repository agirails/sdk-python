"""
Tests for ERC-8004 Reputation Reporter.

Uses mock contracts and web3 instances to avoid real RPC calls.
All public methods of ReputationReporter should NEVER throw.

Parity reference (source of truth):
- sdk-js/src/erc8004/ReputationReporter.ts
- sdk-js/src/types/erc8004.ts:252-259 (canonical ABI)
- sdk-js/src/erc8004/ReputationReporter.test.ts

The canonical giveFeedback signature is 8 params:
  giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals,
               string tag1, string tag2, string endpoint,
               string feedbackURI, bytes32 feedbackHash)
getSummary is (uint256, address[], string, string)
  -> (uint256 count, int256 summaryValue, uint8 summaryValueDecimals)
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest
from web3 import Web3

from agirails.erc8004.reputation_reporter import (
    ERC8004_REPUTATION_ABI_CANONICAL,
    ReputationReporter,
)
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
    """Mock for reputation contract.functions (canonical 8-param ABI)."""

    def __init__(
        self,
        *,
        give_feedback_raises: Optional[Exception] = None,
        summaries: Optional[Dict[str, tuple]] = None,
    ):
        self._give_feedback_raises = give_feedback_raises
        self._summaries = summaries or {}
        self.last_feedback_call: Optional[Dict] = None
        self.last_summary_call: Optional[Dict] = None

    def giveFeedback(
        self,
        agent_id: int,
        value: int,
        value_decimals: int,
        tag1: str,
        tag2: str,
        endpoint: str,
        feedback_uri: str,
        feedback_hash: bytes,
    ) -> MockCallable:
        # Canonical 8-param signature, mirroring
        # sdk-js/src/types/erc8004.ts:254.
        self.last_feedback_call = {
            "agent_id": agent_id,
            "value": value,
            "value_decimals": value_decimals,
            "tag1": tag1,
            "tag2": tag2,
            "endpoint": endpoint,
            "feedback_uri": feedback_uri,
            "feedback_hash": feedback_hash,
        }
        return MockCallable(raises=self._give_feedback_raises)

    def getSummary(
        self, agent_id: int, client_addresses: list, tag1: str, tag2: str
    ) -> MockCallable:
        # Canonical 4-arg view: (uint256, address[], string, string)
        self.last_summary_call = {
            "agent_id": agent_id,
            "client_addresses": client_addresses,
            "tag1": tag1,
            "tag2": tag2,
        }
        key = f"{agent_id}:{tag1}"
        if key in self._summaries:
            return MockCallable(self._summaries[key])
        # Default: no reputation -> (count, summaryValue, decimals)
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
# Tests: canonical ABI parity (selector-level)
# ---------------------------------------------------------------------------


class TestCanonicalAbiParity:
    """Verify the ABI fragments match the TS source-of-truth 4-byte selectors."""

    def _selector(self, signature: str) -> str:
        return Web3.keccak(text=signature)[:4].hex()

    def test_give_feedback_selector_matches_ts(self):
        # sdk-js/src/types/erc8004.ts:254
        sig = (
            "giveFeedback(uint256,int128,uint8,string,string,"
            "string,string,bytes32)"
        )
        expected = self._selector(sig)
        give = next(
            f
            for f in ERC8004_REPUTATION_ABI_CANONICAL
            if f["name"] == "giveFeedback"
        )
        types = ",".join(i["type"] for i in give["inputs"])
        actual = self._selector(f"giveFeedback({types})")
        assert types == "uint256,int128,uint8,string,string,string,string,bytes32"
        assert actual == expected

    def test_get_summary_selector_matches_ts(self):
        # sdk-js/src/types/erc8004.ts:257
        sig = "getSummary(uint256,address[],string,string)"
        expected = self._selector(sig)
        get_summary = next(
            f
            for f in ERC8004_REPUTATION_ABI_CANONICAL
            if f["name"] == "getSummary"
        )
        types = ",".join(i["type"] for i in get_summary["inputs"])
        actual = self._selector(f"getSummary({types})")
        assert types == "uint256,address[],string,string"
        assert actual == expected

    def test_revoke_latest_selector_matches_ts(self):
        # sdk-js/src/types/erc8004.ts:255
        sig = "revokeLatest(uint256,uint64)"
        expected = self._selector(sig)
        revoke = next(
            f
            for f in ERC8004_REPUTATION_ABI_CANONICAL
            if f["name"] == "revokeLatest"
        )
        types = ",".join(i["type"] for i in revoke["inputs"])
        actual = self._selector(f"revokeLatest({types})")
        assert types == "uint256,uint64"
        assert actual == expected


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

    async def test_calls_give_feedback_with_canonical_8_params(self):
        # Mirrors ReputationReporter.test.ts:85-95 — exact arg order/values.
        reporter = _make_reporter()
        await reporter.report_settlement(
            agent_id="12345",
            tx_id="0xACTPTransaction123",
            capability="code_generation",
        )
        last = reporter._contract.functions.last_feedback_call
        assert last is not None
        assert last["agent_id"] == 12345
        assert last["value"] == 1  # success
        assert last["value_decimals"] == 0  # binary
        assert last["tag1"] == ACTP_FEEDBACK_TAGS["SETTLED"]
        assert last["tag2"] == "code_generation"  # capability
        assert last["endpoint"] == ""
        assert last["feedback_uri"] == ""
        # feedbackHash = keccak256(utf8(txId))
        assert last["feedback_hash"] == Web3.keccak(text="0xACTPTransaction123")

    async def test_endpoint_and_feedback_uri_threaded(self):
        reporter = _make_reporter()
        await reporter.report_settlement(
            agent_id="7",
            tx_id="0xthread",
            capability="data_analysis",
            endpoint="https://api.example.com",
            feedback_uri="ipfs://bafy123",
        )
        last = reporter._contract.functions.last_feedback_call
        assert last["tag2"] == "data_analysis"
        assert last["endpoint"] == "https://api.example.com"
        assert last["feedback_uri"] == "ipfs://bafy123"


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
        assert last_call["tag1"] == "actp_dispute_won"

    async def test_agent_lost_gives_negative_feedback(self):
        reporter = _make_reporter()
        result = await reporter.report_dispute(
            agent_id="42", tx_id="0xdispute2", agent_won=False
        )
        assert result is not None
        assert result.tag == ACTP_FEEDBACK_TAGS["DISPUTE_LOST"]
        last_call = reporter._contract.functions.last_feedback_call
        assert last_call["value"] == -1
        assert last_call["tag1"] == "actp_dispute_lost"

    async def test_dispute_reason_becomes_feedback_uri_endpoint_empty(self):
        # Mirrors ReputationReporter.ts:343-353 (reason -> feedbackURI,
        # endpoint always '').
        reporter = _make_reporter()
        await reporter.report_dispute(
            agent_id="9",
            tx_id="0xdisputeR",
            agent_won=False,
            capability="translation",
            reason="late delivery",
        )
        last = reporter._contract.functions.last_feedback_call
        assert last["tag2"] == "translation"
        assert last["endpoint"] == ""
        assert last["feedback_uri"] == "late delivery"
        assert last["value_decimals"] == 0

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
    async def test_returns_count_and_score(self):
        # getSummary -> (count, summaryValue, decimals); return {count, score}
        # Mirrors ReputationReporter.test.ts:286-295.
        reporter = _make_reporter(summaries={"42:actp_settled": (100, 50, 0)})
        result = await reporter.get_agent_reputation("42", tag1="actp_settled")
        assert result is not None
        assert result == {"count": 100, "score": 50}

    async def test_calls_getsummary_with_canonical_args(self):
        # Mirrors ReputationReporter.test.ts:297-308 — ([], tag1, '')
        reporter = _make_reporter()
        await reporter.get_agent_reputation("12345", tag1="actp_settled")
        last = reporter._contract.functions.last_summary_call
        assert last["agent_id"] == 12345
        assert last["client_addresses"] == []
        assert last["tag1"] == "actp_settled"
        assert last["tag2"] == ""

    async def test_empty_tag_defaults_to_empty_string(self):
        reporter = _make_reporter(summaries={"42:": (5, 1, 0)})
        result = await reporter.get_agent_reputation("42")
        assert result is not None
        assert result == {"count": 5, "score": 1}
        last = reporter._contract.functions.last_summary_call
        assert last["tag1"] == ""

    async def test_returns_none_on_error(self):
        reporter = _make_reporter()

        def broken_summary(*args: Any) -> MockCallable:
            return MockCallable(raises=Exception("RPC error"))

        reporter._contract.functions.getSummary = broken_summary
        result = await reporter.get_agent_reputation("42")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: get_stats
# ---------------------------------------------------------------------------


class TestGetStats:
    async def test_reports_network_and_count(self):
        reporter = _make_reporter()
        stats = reporter.get_stats()
        assert stats["network"] == "base-sepolia"
        assert stats["reported_count"] == 0

        await reporter.report_settlement(agent_id="1", tx_id="0xs1")
        stats = reporter.get_stats()
        assert stats["reported_count"] == 1


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
