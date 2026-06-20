"""
ERC-8004 Reputation Reporter.

Reports ACTP settlement and dispute outcomes to the ERC-8004 Reputation
Registry on Base L2. All public methods are designed to NEVER throw —
failures are logged and None is returned.

Mirrors the TypeScript source of truth byte-for-byte:
``sdk-js/src/erc8004/ReputationReporter.ts`` and the canonical ABI in
``sdk-js/src/types/erc8004.ts:252-259``.

The on-chain ``giveFeedback`` signature is the canonical ERC-8004 form
(8 params, ``int128`` value, ``uint8`` valueDecimals, tag1/tag2/endpoint/
feedbackURI strings, ``bytes32`` feedbackHash). ``getSummary`` is
``(uint256, address[], string, string) -> (uint256 count, int256
summaryValue, uint8 summaryValueDecimals)``.

Usage:
    >>> from agirails.erc8004 import ReputationReporter
    >>> from agirails.types.erc8004 import ReputationReporterConfig
    >>>
    >>> reporter = ReputationReporter(ReputationReporterConfig(
    ...     network="base-sepolia",
    ...     private_key="0xabc...",
    ... ))
    >>> result = await reporter.report_settlement(agent_id="42", tx_id="0x123...")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Set

from web3 import Web3

from agirails.types.erc8004 import (
    ACTP_FEEDBACK_TAGS,
    ERC8004_DEFAULT_RPC,
    ERC8004_REPUTATION_REGISTRY,
    ReportResult,
    ReputationReporterConfig,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical ERC-8004 Reputation Registry ABI (source of truth)
#
# Mirrors sdk-js/src/types/erc8004.ts:252-259 EXACTLY. Defined locally so this
# module always encodes against the correct 4-byte selectors regardless of the
# (legacy) ABI exported from agirails.types.erc8004. The selectors for these
# fragments must match the deployed canonical Reputation Registry — see the
# TS source of truth for the authoritative signatures.
# ---------------------------------------------------------------------------

ERC8004_REPUTATION_ABI_CANONICAL = [
    # Write — giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "value", "type": "int128"},
            {"name": "valueDecimals", "type": "uint8"},
            {"name": "tag1", "type": "string"},
            {"name": "tag2", "type": "string"},
            {"name": "endpoint", "type": "string"},
            {"name": "feedbackURI", "type": "string"},
            {"name": "feedbackHash", "type": "bytes32"},
        ],
        "name": "giveFeedback",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # Write — revokeLatest(uint256,uint64)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "feedbackIndex", "type": "uint64"},
        ],
        "name": "revokeLatest",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # Read — getSummary(uint256,address[],string,string)
    #     -> (uint256 count, int256 summaryValue, uint8 summaryValueDecimals)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "clientAddresses", "type": "address[]"},
            {"name": "tag1", "type": "string"},
            {"name": "tag2", "type": "string"},
        ],
        "name": "getSummary",
        "outputs": [
            {"name": "count", "type": "uint256"},
            {"name": "summaryValue", "type": "int256"},
            {"name": "summaryValueDecimals", "type": "uint8"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    # Read — readFeedback(uint256,uint64)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "feedbackIndex", "type": "uint64"},
        ],
        "name": "readFeedback",
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "value", "type": "int128"},
                    {"name": "valueDecimals", "type": "uint8"},
                    {"name": "tag1", "type": "string"},
                    {"name": "tag2", "type": "string"},
                    {"name": "isRevoked", "type": "bool"},
                    {"name": "feedbackIndex", "type": "uint64"},
                ],
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


class ReputationReporter:
    """
    Reports ACTP transaction outcomes to the ERC-8004 Reputation Registry.

    All public reporting methods return ``ReportResult | None`` and
    NEVER raise exceptions. Errors are logged via the standard logger.

    Designed to never block or fail the main ACTP flow (mirrors
    ``sdk-js/src/erc8004/ReputationReporter.ts``).
    """

    def __init__(
        self,
        config: Optional[ReputationReporterConfig] = None,
        *,
        contract: Any = None,
        w3: Any = None,
    ) -> None:
        """
        Initialize the reporter.

        Args:
            config: Reporter configuration with signer key and network.
            contract: Optional injected contract instance (for testing).
            w3: Optional injected Web3 instance (for testing).
        """
        self._config = config or ReputationReporterConfig()
        self._reported: Set[str] = set()

        if contract is not None and w3 is not None:
            # Test injection
            self._contract = contract
            self._w3 = w3
            self._account = None
        else:
            rpc_url = self._config.rpc_url or ERC8004_DEFAULT_RPC[self._config.network]
            self._w3 = Web3(Web3.HTTPProvider(rpc_url))
            registry_address = ERC8004_REPUTATION_REGISTRY[self._config.network]
            self._contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(registry_address),
                abi=ERC8004_REPUTATION_ABI_CANONICAL,
            )
            if self._config.private_key:
                from eth_account import Account

                self._account = Account.from_key(self._config.private_key)
            else:
                self._account = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def report_settlement(
        self,
        agent_id: str,
        tx_id: str,
        capability: str = "",
        endpoint: str = "",
        feedback_uri: str = "",
    ) -> Optional[ReportResult]:
        """
        Report a successful ACTP settlement.

        Mirrors ``ReputationReporter.ts:249-303``. Submits the canonical
        8-param ``giveFeedback`` with:

        - value: 1 (positive)
        - valueDecimals: 0 (binary)
        - tag1: 'actp_settled'
        - tag2: capability
        - endpoint: endpoint
        - feedbackURI: feedback_uri
        - feedbackHash: keccak256(txId)

        Args:
            agent_id: The provider agent's token ID.
            tx_id: The ACTP transaction ID (used for feedbackHash + dedup).
            capability: Agent capability (tag2, e.g. 'code_generation').
            endpoint: Service endpoint (optional).
            feedback_uri: Link to transaction details (optional, IPFS/HTTPS).

        Returns:
            ReportResult on success, None on any failure.
        """
        if self.is_reported(tx_id):
            logger.info("Settlement already reported for tx %s", tx_id)
            return None

        tag1 = ACTP_FEEDBACK_TAGS["SETTLED"]
        feedback_hash = self._compute_feedback_hash(tx_id)

        return await self._submit_feedback(
            agent_id=agent_id,
            value=1,
            value_decimals=0,
            tag1=tag1,
            tag2=capability,
            endpoint=endpoint,
            feedback_uri=feedback_uri,
            feedback_hash=feedback_hash,
            tx_id=tx_id,
        )

    async def report_dispute(
        self,
        agent_id: str,
        tx_id: str,
        agent_won: bool,
        capability: str = "",
        reason: str = "",
    ) -> Optional[ReportResult]:
        """
        Report an ACTP dispute outcome.

        Mirrors ``ReputationReporter.ts:320-367``. Submits:

        - value: 1 if agent won, -1 if requester won
        - valueDecimals: 0 (binary)
        - tag1: 'actp_dispute_won' or 'actp_dispute_lost'
        - tag2: capability
        - endpoint: '' (always empty for disputes)
        - feedbackURI: reason (contains dispute reason)
        - feedbackHash: keccak256(txId)

        Args:
            agent_id: The provider agent's token ID.
            tx_id: The ACTP transaction ID.
            agent_won: True if the agent won the dispute, False if lost.
            capability: Agent capability (tag2, optional).
            reason: Dispute reason/details, stored as feedbackURI (optional).

        Returns:
            ReportResult on success, None on any failure.
        """
        if self.is_reported(tx_id):
            logger.info("Dispute already reported for tx %s", tx_id)
            return None

        value = 1 if agent_won else -1
        tag1 = ACTP_FEEDBACK_TAGS["DISPUTE_WON" if agent_won else "DISPUTE_LOST"]
        feedback_hash = self._compute_feedback_hash(tx_id)

        return await self._submit_feedback(
            agent_id=agent_id,
            value=value,
            value_decimals=0,
            tag1=tag1,
            tag2=capability,
            endpoint="",
            feedback_uri=reason,
            feedback_hash=feedback_hash,
            tx_id=tx_id,
        )

    async def get_agent_reputation(
        self,
        agent_id: str,
        tag1: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Read an agent's reputation summary from the registry.

        Mirrors ``ReputationReporter.ts:378-400``. Calls the canonical
        ``getSummary(agentId, [], tag1 or '', '')`` and decodes
        ``(count, summaryValue, summaryValueDecimals)``.

        Args:
            agent_id: The agent's token ID.
            tag1: Optional tag filter (e.g. 'actp_settled').

        Returns:
            Dict with 'count' and 'score', or None on error.
        """
        try:
            result = self._contract.functions.getSummary(
                int(agent_id),
                [],  # clientAddresses (empty = all)
                tag1 or "",
                "",  # tag2
            ).call()
            count = result[0]
            summary_value = result[1]
            return {
                "count": int(count),
                "score": int(summary_value),
            }
        except Exception as exc:
            self._log_error("get_agent_reputation", exc)
            return None

    def is_reported(self, tx_id: str) -> bool:
        """Check if a transaction has already been reported (local dedup)."""
        return tx_id in self._reported

    def clear_reported_cache(self) -> None:
        """Clear the local deduplication cache."""
        self._reported.clear()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get reporter statistics.

        Mirrors ``ReputationReporter.ts:425-430``.

        Returns:
            Dict with 'network' and 'reported_count'.
        """
        return {
            "network": self._config.network,
            "reported_count": len(self._reported),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_feedback_hash(tx_id: str) -> str:
        """
        Compute keccak256 of the transaction ID for use as feedbackHash.

        Byte-identical to TS ``ethers.keccak256(ethers.toUtf8Bytes(txId))``
        — keccak256 over the UTF-8 bytes of the string.
        """
        return Web3.keccak(text=tx_id).hex()

    async def _submit_feedback(
        self,
        agent_id: str,
        value: int,
        value_decimals: int,
        tag1: str,
        tag2: str,
        endpoint: str,
        feedback_uri: str,
        feedback_hash: str,
        tx_id: str,
    ) -> Optional[ReportResult]:
        """
        Build, sign, and send a canonical 8-param giveFeedback transaction.

        Mirrors ``ReputationReporter.ts:275-285`` (settlement) and
        ``ReputationReporter.ts:343-353`` (dispute) argument order.

        Returns ReportResult on success, None on any failure.
        """
        try:
            feedback_hash_bytes = bytes.fromhex(feedback_hash.replace("0x", ""))

            tx = self._contract.functions.giveFeedback(
                int(agent_id),
                value,
                value_decimals,
                tag1,
                tag2,
                endpoint,
                feedback_uri,
                feedback_hash_bytes,
            ).build_transaction(
                {
                    "from": self._account.address if self._account else "0x" + "0" * 40,
                    "gas": self._config.gas_limit,
                    "nonce": self._w3.eth.get_transaction_count(
                        self._account.address if self._account else "0x" + "0" * 40
                    ),
                }
            )

            signed = self._w3.eth.account.sign_transaction(tx, self._config.private_key)
            tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)

            # Mark as reported
            self._reported.add(tx_id)

            return ReportResult(
                tx_hash=receipt["transactionHash"].hex(),
                agent_id=agent_id,
                feedback_hash=feedback_hash,
                tag=tag1,
            )
        except Exception as exc:
            self._log_error("submit_feedback", exc)
            return None

    @staticmethod
    def _log_error(operation: str, exc: Exception) -> None:
        """Log specific error messages based on common failure types."""
        msg = str(exc).lower()
        if "insufficient funds" in msg:
            logger.error(
                "[%s] Insufficient funds for reputation transaction: %s",
                operation,
                exc,
            )
        elif "cannot be the agent owner" in msg or ("owner" in msg and "restrict" in msg):
            logger.error(
                "[%s] Owner restriction — caller cannot be the agent owner: %s",
                operation,
                exc,
            )
        elif "user rejected" in msg or "user denied" in msg:
            logger.warning(
                "[%s] User rejected the transaction: %s",
                operation,
                exc,
            )
        else:
            logger.error(
                "[%s] Reputation report failed: %s",
                operation,
                exc,
            )
