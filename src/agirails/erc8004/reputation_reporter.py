"""
ERC-8004 Reputation Reporter.

Reports ACTP settlement and dispute outcomes to the ERC-8004 Reputation
Registry on Base L2. All public methods are designed to NEVER throw —
failures are logged and None is returned.

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
    ERC8004_REPUTATION_ABI,
    ERC8004_REPUTATION_REGISTRY,
    ReportResult,
    ReputationReporterConfig,
)

logger = logging.getLogger(__name__)


class ReputationReporter:
    """
    Reports ACTP transaction outcomes to the ERC-8004 Reputation Registry.

    All public reporting methods return ``ReportResult | None`` and
    NEVER raise exceptions. Errors are logged via the standard logger.
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
                abi=ERC8004_REPUTATION_ABI,
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
    ) -> Optional[ReportResult]:
        """
        Report a successful ACTP settlement.

        Submits ``giveFeedback(agentId, 1, feedbackHash, 'actp_settled')``
        to the reputation registry.

        Args:
            agent_id: The provider agent's token ID.
            tx_id: The ACTP transaction ID (used for feedbackHash + dedup).

        Returns:
            ReportResult on success, None on any failure.
        """
        if self.is_reported(tx_id):
            logger.info("Settlement already reported for tx %s", tx_id)
            return None

        tag = ACTP_FEEDBACK_TAGS["SETTLED"]
        feedback_hash = self._compute_feedback_hash(tx_id)

        return await self._submit_feedback(
            agent_id=agent_id,
            value=1,
            feedback_hash=feedback_hash,
            tag=tag,
            tx_id=tx_id,
        )

    async def report_dispute(
        self,
        agent_id: str,
        tx_id: str,
        agent_won: bool,
    ) -> Optional[ReportResult]:
        """
        Report an ACTP dispute outcome.

        Args:
            agent_id: The provider agent's token ID.
            tx_id: The ACTP transaction ID.
            agent_won: True if the agent won the dispute, False if lost.

        Returns:
            ReportResult on success, None on any failure.
        """
        if self.is_reported(tx_id):
            logger.info("Dispute already reported for tx %s", tx_id)
            return None

        value = 1 if agent_won else -1
        tag = ACTP_FEEDBACK_TAGS["DISPUTE_WON" if agent_won else "DISPUTE_LOST"]
        feedback_hash = self._compute_feedback_hash(tx_id)

        return await self._submit_feedback(
            agent_id=agent_id,
            value=value,
            feedback_hash=feedback_hash,
            tag=tag,
            tx_id=tx_id,
        )

    async def get_agent_reputation(
        self,
        agent_id: str,
        tag1: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Read an agent's reputation summary from the registry.

        Args:
            agent_id: The agent's token ID.
            tag1: Optional tag filter (e.g. 'actp_settled').

        Returns:
            Dict with 'positive', 'negative', 'total' counts, or None on error.
        """
        try:
            result = self._contract.functions.getSummary(
                int(agent_id),
                tag1 or "",
            ).call()
            return {
                "positive": result[0],
                "negative": result[1],
                "total": result[2],
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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_feedback_hash(tx_id: str) -> str:
        """Compute keccak256 of the transaction ID for use as feedbackHash."""
        return Web3.keccak(text=tx_id).hex()

    async def _submit_feedback(
        self,
        agent_id: str,
        value: int,
        feedback_hash: str,
        tag: str,
        tx_id: str,
    ) -> Optional[ReportResult]:
        """
        Build, sign, and send a giveFeedback transaction.

        Returns ReportResult on success, None on any failure.
        """
        try:
            feedback_hash_bytes = bytes.fromhex(feedback_hash.replace("0x", ""))

            tx = self._contract.functions.giveFeedback(
                int(agent_id),
                value,
                feedback_hash_bytes,
                tag,
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
                tag=tag,
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
        elif "owner" in msg and "restrict" in msg:
            logger.error(
                "[%s] Owner restriction — only authorized callers can report: %s",
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
