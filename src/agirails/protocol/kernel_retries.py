"""Permissionless kernel retries: pending platform-fee debt and the b08c0c6 reputation write."""

from __future__ import annotations

from agirails.protocol.base import ContractBase
from agirails.types.transaction import TransactionReceipt

PLATFORM_FEE_RETRY_GAS_FLOOR = 300_000
REPUTATION_RETRY_GAS_FLOOR = 240_000


class KernelRetries(ContractBase):
    """Retry entry points that anyone may call on the ACTP kernel."""

    async def retry_platform_fee(
        self, transaction_id: str, gas_limit: int | None = None
    ) -> TransactionReceipt:
        """Retry fees permissionlessly; a receipt does not prove funds moved.

        Zero debt is a no-op. A blocked fee recipient can leave debt pending.
        Unknown transactions and revoked vaults propagate errors.
        """
        return await self._send_retry(
            "retryPlatformFee", PLATFORM_FEE_RETRY_GAS_FLOOR, transaction_id, gas_limit
        )

    async def retry_reputation(
        self, transaction_id: str, gas_limit: int | None = None
    ) -> TransactionReceipt:
        """Retry the reputation write permissionlessly (b08c0c6 kernel).

        Only a SETTLED transaction, or a disputed CANCELLED one with no committed
        result, is accepted; others revert "No reputation outcome". A receipt does
        not prove a write: it is skipped when already processed or when no registry
        is set, and a failing registry call is swallowed on-chain. The kernel gives
        the registry a fixed 150k gas inside try/catch, so the limit never drops
        below 240k (the TS SDK minimum).
        """
        return await self._send_retry(
            "retryReputation", REPUTATION_RETRY_GAS_FLOOR, transaction_id, gas_limit
        )

    async def _send_retry(
        self, function_name: str, gas_floor: int, transaction_id: str, gas_limit: int | None
    ) -> TransactionReceipt:
        fn = getattr(self.contract.functions, function_name)(self._to_bytes32(transaction_id))
        effective_gas = (
            gas_limit if gas_limit is not None else await self._estimate_gas_strict(fn, gas_floor)
        )
        tx = await fn.build_transaction(await self._build_tx_params(gas_limit=effective_gas))
        return self._to_receipt(await self._sign_and_send(tx))
