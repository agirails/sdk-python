"""
EOAWalletProvider -- Tier 2 (BYOW) wallet implementation.

Wraps a web3 account for traditional EOA signing.
send_batch_transaction() executes calls sequentially (no atomic batching).
This is the backward-compatible path for agents that don't register.

This is a 1:1 port of sdk-js/src/wallet/EOAWalletProvider.ts.
"""

from __future__ import annotations

import logging
from typing import List

from web3 import Web3

from agirails.wallet.auto_wallet_provider import (
    IWalletProvider,
    TransactionReceipt,
    TransactionRequest,
    WalletInfo,
)

logger = logging.getLogger("agirails.wallet.eoa")


class EOAWalletProvider:
    """Tier 2 (BYOW) wallet provider using traditional EOA signing.

    sendBatchTransaction executes calls sequentially (no atomic batching).

    Args:
        private_key: Private key (0x-prefixed hex).
        w3: Web3 instance connected to the target chain.
        chain_id: Chain ID.
    """

    def __init__(self, private_key: str, w3: Web3, chain_id: int) -> None:
        from eth_account import Account

        self._account = Account.from_key(private_key)
        self._w3 = w3
        self._chain_id = chain_id

    def get_address(self) -> str:
        """Get the EOA address."""
        return self._account.address

    async def send_transaction(self, tx: TransactionRequest) -> TransactionReceipt:
        """Send a single transaction via EOA.

        Args:
            tx: Transaction request.

        Returns:
            TransactionReceipt with hash and success.
        """
        nonce = self._w3.eth.get_transaction_count(self._account.address)
        tx_dict = {
            "to": Web3.to_checksum_address(tx.to),
            "data": tx.data,
            "value": int(tx.value) if tx.value else 0,
            "nonce": nonce,
            "gas": 500_000,  # Will be estimated
            "chainId": self._chain_id,
        }

        # Estimate gas
        try:
            tx_dict["gas"] = self._w3.eth.estimate_gas(tx_dict)
        except Exception:
            pass  # Use default

        # Get gas price
        fee_data = self._w3.eth.fee_history(1, "latest", [50])
        base_fee = fee_data["baseFeePerGas"][-1]
        priority_fee = fee_data["reward"][0][0] if fee_data.get("reward") else 1_000_000_000
        tx_dict["maxFeePerGas"] = base_fee * 2 + priority_fee
        tx_dict["maxPriorityFeePerGas"] = priority_fee

        signed = self._account.sign_transaction(tx_dict)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)

        return TransactionReceipt(
            hash=receipt["transactionHash"].hex(),
            success=receipt["status"] == 1,
        )

    async def send_batch_transaction(
        self, txs: List[TransactionRequest]
    ) -> TransactionReceipt:
        """Send multiple transactions sequentially (no atomic batching).

        Fails fast on first failure.

        Args:
            txs: List of transaction requests.

        Returns:
            Last TransactionReceipt.

        Raises:
            ValueError: If no transactions provided.
        """
        if len(txs) == 0:
            raise ValueError("send_batch_transaction requires at least one transaction")

        last_receipt = None
        for tx in txs:
            last_receipt = await self.send_transaction(tx)
            if not last_receipt.success:
                return last_receipt
        return last_receipt  # type: ignore[return-value]

    def get_wallet_info(self) -> WalletInfo:
        """Get wallet metadata."""
        return WalletInfo(
            address=self._account.address,
            tier="eoa",
            supports_batching=False,
            gas_sponsored=False,
            chain_id=self._chain_id,
        )
