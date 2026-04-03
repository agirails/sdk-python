"""
Background sweep for expired DELIVERED transactions.

When an agent interacts with the SDK (pay), this class checks for
DELIVERED transactions where:
- The agent is the provider
- The dispute window has expired

It then calls release_escrow on each, settling them permissionlessly.
All operations are fire-and-forget — never blocks the primary operation.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from agirails.utils.logging import get_logger

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime

_logger = get_logger(__name__)
_TAG = "[settle-on-interact]"
_DEFAULT_COOLDOWN_S = 5 * 60  # 5 minutes


class SettleOnInteract:
    """Background sweep for expired DELIVERED transactions."""

    def __init__(
        self,
        runtime: IACTPRuntime,
        provider_address: str,
        cooldown_s: float = _DEFAULT_COOLDOWN_S,
    ) -> None:
        self._runtime: Any = runtime
        self._provider_address = provider_address
        self._cooldown_s = cooldown_s
        self._last_sweep_at: float = 0

    def trigger(self) -> None:
        """Fire-and-forget background sweep. Returns immediately, never throws."""
        now = time.monotonic()
        if now - self._last_sweep_at < self._cooldown_s:
            return
        self._last_sweep_at = now  # stamp before async to prevent burst

        async def _safe_sweep() -> None:
            try:
                await self._do_sweep()
            except Exception:
                pass

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_safe_sweep())
        except RuntimeError:
            pass  # no event loop — skip silently

    async def sweep_now(self) -> None:
        """Perform sweep synchronously (awaited). Used in tests."""
        await self._do_sweep()

    async def _do_sweep(self) -> None:
        try:
            # BlockchainRuntime path
            if hasattr(self._runtime, "get_expired_delivered_transactions"):
                txs = await self._runtime.get_expired_delivered_transactions(
                    self._provider_address
                )
                for tx in txs:
                    tx_id = getattr(tx, "tx_id", None) or tx.get("tx_id", "")
                    try:
                        await self._runtime.release_escrow(tx_id)
                        _logger.info(f"{_TAG} Auto-settled expired transaction {tx_id}")
                    except Exception as e:
                        _logger.warning(f"{_TAG} Failed to settle {tx_id}: {e}")
                return

            # MockRuntime path
            if hasattr(self._runtime, "sweep_expired_delivered_for_provider"):
                await self._runtime.sweep_expired_delivered_for_provider(
                    self._provider_address
                )
                return

            # Unknown runtime — no sweep capability
        except Exception as e:
            _logger.warning(f"{_TAG} Sweep failed: {e}")
