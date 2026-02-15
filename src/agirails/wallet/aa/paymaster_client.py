"""
PaymasterClient -- Gas sponsorship via ERC-7677 paymasters.

Fallback chain: Coinbase CDP (primary) -> Pimlico (backup).
Both implement ERC-7677 pm_getPaymasterStubData / pm_getPaymasterData.

The paymaster fills the ``paymasterAndData`` field of the UserOp,
which the EntryPoint uses to debit gas from the paymaster instead
of the sender's ETH balance.

Uses httpx.AsyncClient for HTTP.

This is a 1:1 port of sdk-js/src/wallet/aa/PaymasterClient.ts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from agirails.wallet.aa.constants import ENTRYPOINT_V06, PaymasterResponse, UserOperationV06
from agirails.wallet.aa.user_op_builder import serialize_user_op

logger = logging.getLogger("agirails.wallet.aa.paymaster")


# ============================================================================
# Types
# ============================================================================


@dataclass
class PaymasterConfig:
    """Configuration for PaymasterClient."""

    primary_url: str
    """Primary paymaster URL (Coinbase CDP)."""

    chain_id: int
    """Chain ID (8453 for Base Mainnet, 84532 for Sepolia)."""

    backup_url: Optional[str] = None
    """Backup paymaster URL (Pimlico)."""

    timeout_s: float = 15.0
    """Request timeout (seconds)."""


# ============================================================================
# PaymasterClient
# ============================================================================


class PaymasterClient:
    """JSON-RPC client for ERC-7677 paymasters.

    Primary + backup (Pimlico failover).
    Methods: get_paymaster_stub_data, get_paymaster_data.
    """

    def __init__(self, config: PaymasterConfig) -> None:
        self._primary_url = config.primary_url
        self._backup_url = config.backup_url
        self._chain_id = config.chain_id
        self._timeout_s = config.timeout_s
        self._request_id = 0

    async def get_paymaster_stub_data(
        self, user_op: UserOperationV06
    ) -> PaymasterResponse:
        """Get stub paymaster data for gas estimation.

        Returns approximate paymasterAndData that the bundler can use
        for gas estimation (exact values come from get_paymaster_data).

        Args:
            user_op: The UserOperation to sponsor.

        Returns:
            PaymasterResponse with paymasterAndData.
        """
        result = await self._call_with_fallback(
            "pm_getPaymasterStubData",
            [
                serialize_user_op(user_op),
                ENTRYPOINT_V06,
                hex(self._chain_id),
                {},  # context
            ],
        )
        return PaymasterResponse(paymaster_and_data=result["paymasterAndData"])

    async def get_paymaster_data(
        self, user_op: UserOperationV06
    ) -> PaymasterResponse:
        """Get final paymaster data for the signed UserOp.

        Called after gas estimation with final gas values.
        Returns the paymaster signature that goes into paymasterAndData.

        Args:
            user_op: The UserOperation with final gas values.

        Returns:
            PaymasterResponse with final paymasterAndData.
        """
        result = await self._call_with_fallback(
            "pm_getPaymasterData",
            [
                serialize_user_op(user_op),
                ENTRYPOINT_V06,
                hex(self._chain_id),
                {},  # context
            ],
        )
        return PaymasterResponse(paymaster_and_data=result["paymasterAndData"])

    # ==========================================================================
    # Internal
    # ==========================================================================

    async def _call_with_fallback(
        self, method: str, params: List[Any]
    ) -> Any:
        """Call primary, fall back to backup."""
        try:
            return await self._json_rpc(self._primary_url, method, params)
        except Exception as primary_error:
            if not self._backup_url:
                raise PaymasterError(
                    f"Gas sponsorship unavailable: {primary_error}. "
                    "No backup paymaster configured."
                ) from primary_error
            logger.warning(
                "Primary paymaster failed, trying backup: method=%s error=%s",
                method,
                str(primary_error),
            )

        try:
            return await self._json_rpc(self._backup_url, method, params)
        except Exception as backup_error:
            raise PaymasterError(
                "Gas sponsorship temporarily unavailable -- both Coinbase and Pimlico "
                "paymasters failed. Please retry later. "
                f"Backup error: {backup_error}"
            ) from backup_error

    async def _json_rpc(self, url: str, method: str, params: List[Any]) -> Any:
        """Execute a JSON-RPC call."""
        self._request_id += 1
        body = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }

        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            response = await client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
            )

        if response.status_code != 200:
            raise PaymasterError(
                f"HTTP {response.status_code}: {response.reason_phrase}"
            )

        data = response.json()

        if "error" in data and data["error"] is not None:
            err = data["error"]
            data_str = f" | data: {err.get('data', '')}" if err.get("data") else ""
            raise PaymasterError(
                f"Paymaster RPC error {err.get('code', -1)}: {err['message']}{data_str}"
            )

        return data.get("result")


# ============================================================================
# Errors
# ============================================================================


class PaymasterError(Exception):
    """Error from paymaster client."""

    pass
