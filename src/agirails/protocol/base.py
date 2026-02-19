"""
ContractBase: shared infrastructure for ACTPKernel and EscrowVault.

Eliminates the verbatim duplication of _sign_and_send, _build_tx_params,
_to_bytes32, and _to_receipt that existed in both contract wrappers.

NonceManager integration is optional:
- When nonce_manager is provided: get_nonce() / confirm_nonce() / release_nonce()
  are called automatically inside _build_tx_params() and _sign_and_send().
- When None: falls back to w3.eth.get_transaction_count("pending") — same
  behavior as pre-refactor, backward compat preserved.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from eth_account.signers.local import LocalAccount
from web3 import AsyncWeb3
from web3.contract import AsyncContract
from web3.types import TxReceipt

from agirails.errors.transaction import TransactionError
from agirails.protocol.nonce import NonceManager
from agirails.types.transaction import TransactionReceipt

# Security Note (M-3): Default timeout for transaction receipts (5 minutes)
DEFAULT_TX_WAIT_TIMEOUT = 300.0


class ContractBase:
    """
    Abstract base for ACTPKernel and EscrowVault contract wrappers.

    Owns the transaction lifecycle: build params -> sign -> send -> wait -> receipt.
    Integrates NonceManager when provided, falls back to RPC nonce otherwise.
    """

    def __init__(
        self,
        contract: AsyncContract,
        account: LocalAccount,
        w3: AsyncWeb3,
        chain_id: int,
        *,
        nonce_manager: Optional[NonceManager] = None,
    ) -> None:
        self.contract = contract
        self.account = account
        self.w3 = w3
        self.chain_id = chain_id
        self._nonce_manager = nonce_manager

    async def _build_tx_params(
        self,
        gas_limit: int,
        max_fee_per_gas: Optional[int] = None,
        max_priority_fee_per_gas: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Build EIP-1559 transaction parameters."""
        # Use NonceManager when available; else ask chain directly
        if self._nonce_manager is not None:
            nonce = await self._nonce_manager.get_nonce()
        else:
            # Legacy path: fetch nonce from RPC including unconfirmed transactions
            nonce = await self.w3.eth.get_transaction_count(
                self.account.address, "pending"
            )

        # Get gas prices if not provided
        if max_fee_per_gas is None or max_priority_fee_per_gas is None:
            block = await self.w3.eth.get_block("latest")
            base_fee = block.get("baseFeePerGas", 1_000_000_000)  # 1 gwei fallback

            if max_priority_fee_per_gas is None:
                max_priority_fee_per_gas = 1_000_000_000  # 1 gwei

            if max_fee_per_gas is None:
                # 2x base fee + priority fee
                max_fee_per_gas = (base_fee * 2) + max_priority_fee_per_gas

        return {
            "from": self.account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "chainId": self.chain_id,
        }

    async def _sign_and_send(
        self,
        tx: Dict[str, Any],
        timeout: float = DEFAULT_TX_WAIT_TIMEOUT,
    ) -> TxReceipt:
        """
        Sign and broadcast a transaction, wait for receipt.

        Nonce lifecycle:
        - Pre-broadcast failure  -> release_nonce (nonce never hit the chain)
        - Post-broadcast timeout -> confirm_nonce (tx is in mempool, nonce consumed)
        - Reverted tx (status=0) -> confirm_nonce (revert still consumed nonce)
        - Success (status=1)     -> confirm_nonce

        Security Note (M-3): Uses timeout to prevent indefinite hangs.
        """
        nonce: Optional[int] = tx.get("nonce")

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        try:
            tx_hash = await self.w3.eth.send_raw_transaction(
                signed_tx.raw_transaction
            )
        except Exception:
            # Broadcast failed — release nonce so it can be reused
            if self._nonce_manager is not None and nonce is not None:
                self._nonce_manager.release_nonce(nonce)
            raise

        # Transaction was broadcast — nonce is consumed regardless of outcome
        try:
            receipt = await asyncio.wait_for(
                self.w3.eth.wait_for_transaction_receipt(tx_hash),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # TX is in mempool — nonce is consumed
            if self._nonce_manager is not None and nonce is not None:
                self._nonce_manager.confirm_nonce(nonce)
            raise TransactionError(
                f"Transaction {tx_hash.hex()} timed out after {timeout}s. "
                "Check network congestion and gas settings.",
                tx_id=tx_hash.hex(),
            )

        # Confirm nonce whether tx succeeded or reverted (nonce was used on-chain)
        if self._nonce_manager is not None and nonce is not None:
            self._nonce_manager.confirm_nonce(nonce)

        if receipt["status"] != 1:
            raise TransactionError(
                f"Transaction failed: {tx_hash.hex()}",
                tx_id=tx_hash.hex(),
            )

        return receipt

    def _to_bytes32(self, value: str) -> bytes:
        """Convert hex string to bytes32."""
        if value.startswith("0x"):
            value = value[2:]
        # Pad to 32 bytes if needed
        value = value.zfill(64)
        return bytes.fromhex(value)

    def _to_receipt(self, receipt: TxReceipt) -> TransactionReceipt:
        """Convert web3 receipt to TransactionReceipt."""
        return TransactionReceipt(
            transaction_hash=receipt["transactionHash"].hex()
            if isinstance(receipt["transactionHash"], bytes)
            else receipt["transactionHash"],
            block_number=receipt["blockNumber"],
            block_hash=receipt["blockHash"].hex()
            if isinstance(receipt["blockHash"], bytes)
            else receipt["blockHash"],
            gas_used=receipt["gasUsed"],
            effective_gas_price=receipt.get("effectiveGasPrice", 0),
            status=receipt["status"],
            logs=[dict(log) for log in receipt.get("logs", [])],
        )
