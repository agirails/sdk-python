"""
Background sweep for expired DELIVERED transactions.

When an agent interacts with the SDK (pay), this class checks for
DELIVERED transactions where:
- The agent is the provider
- The dispute window has expired

It then calls release_escrow on each, settling them permissionlessly.
All operations are fire-and-forget — never blocks the primary operation.

When the optional ``release_router`` is provided (typically
``client.standard``), settlements route through SmartWalletRouter so
AGIRAILS Smart Wallet providers get Paymaster-sponsored UserOps instead of
raw EOA reverts. Without it, the sweep falls back to the runtime, which only
works for EOA / mock setups. Mirrors TS ``SettleOnInteract`` (the 4th
constructor arg, settle/SettleOnInteract.ts:39-44, 75-79).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, Optional, Protocol

from agirails.utils.logging import get_logger

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime


class ReleaseRouter(Protocol):
    """Minimal surface SettleOnInteract needs to route releaseEscrow.

    Decoupled from the full adapter type so this module stays test-friendly
    and free of import cycles (TS ``ReleaseRouter`` interface,
    settle/SettleOnInteract.ts:13-15).
    """

    async def release_escrow(self, escrow_id: str) -> None: ...

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
        release_router: Optional[ReleaseRouter] = None,
    ) -> None:
        self._runtime: Any = runtime
        self._provider_address = provider_address
        self._cooldown_s = cooldown_s
        self._release_router = release_router
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
                        # Prefer the AA-aware adapter route when available so
                        # Smart Wallet providers (0 ETH on the signer EOA) settle
                        # via Paymaster instead of reverting on intrinsic-gas cost
                        # (TS SettleOnInteract.ts:73-79).
                        if self._release_router is not None:
                            await self._release_router.release_escrow(tx_id)
                        else:
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
