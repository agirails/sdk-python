"""
BundlerClient -- JSON-RPC client for ERC-4337 bundlers.

Supports Coinbase (primary) and Pimlico (backup) bundlers.
Handles gas estimation, UserOp submission, and receipt polling.
Retry with exponential backoff on transient failures.

Uses httpx.AsyncClient for HTTP.

This is a 1:1 port of sdk-js/src/wallet/aa/BundlerClient.ts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from agirails.wallet.aa.constants import ENTRYPOINT_V06, GasEstimate, UserOperationV06
from agirails.wallet.aa.user_op_builder import serialize_user_op

logger = logging.getLogger("agirails.wallet.aa.bundler")


# ============================================================================
# Types
# ============================================================================


@dataclass
class BundlerConfig:
    """Configuration for BundlerClient."""

    primary_url: str
    """Primary bundler URL (Coinbase CDP)."""

    backup_url: Optional[str] = None
    """Backup bundler URL (Pimlico)."""

    max_retries: int = 2
    """Max retry attempts per endpoint."""

    base_delay_s: float = 1.0
    """Base delay for exponential backoff (seconds)."""

    timeout_s: float = 30.0
    """Timeout for individual requests (seconds)."""


@dataclass(frozen=True)
class UserOpReceipt:
    """Receipt for a submitted UserOp."""

    user_op_hash: str
    """UserOp hash."""

    transaction_hash: str
    """Transaction hash on-chain."""

    block_number: int
    """Block number."""

    success: bool
    """Whether the UserOp execution succeeded."""


# ============================================================================
# BundlerClient
# ============================================================================


class BundlerClient:
    """JSON-RPC client for ERC-4337 bundlers.

    Primary URL + backup URL (Pimlico failover).
    Retry with exponential backoff (max 2 retries, 1s base delay).
    Non-transient error detection (AA errors, JSON-RPC errors).
    """

    def __init__(self, config: BundlerConfig) -> None:
        self._primary_url = config.primary_url
        self._backup_url = config.backup_url
        self._max_retries = config.max_retries
        self._base_delay_s = config.base_delay_s
        self._timeout_s = config.timeout_s
        self._request_id = 0

    async def estimate_user_operation_gas(
        self, user_op: UserOperationV06
    ) -> GasEstimate:
        """Estimate gas for a UserOp.

        Args:
            user_op: The UserOperation to estimate.

        Returns:
            GasEstimate with callGasLimit, verificationGasLimit, preVerificationGas.
        """
        result = await self._call_with_fallback(
            "eth_estimateUserOperationGas",
            [serialize_user_op(user_op), ENTRYPOINT_V06],
        )
        return GasEstimate(
            call_gas_limit=int(result["callGasLimit"], 16),
            verification_gas_limit=int(result["verificationGasLimit"], 16),
            pre_verification_gas=int(result["preVerificationGas"], 16),
        )

    async def send_user_operation(self, user_op: UserOperationV06) -> str:
        """Submit a signed UserOp to the bundler.

        Args:
            user_op: The signed UserOperation.

        Returns:
            UserOp hash string.
        """
        return await self._call_with_fallback(
            "eth_sendUserOperation",
            [serialize_user_op(user_op), ENTRYPOINT_V06],
        )

    async def get_user_operation_receipt(
        self, user_op_hash: str
    ) -> Optional[UserOpReceipt]:
        """Get the receipt for a submitted UserOp.

        Args:
            user_op_hash: The UserOp hash.

        Returns:
            UserOpReceipt or None if not yet mined.
        """
        result = await self._call_with_fallback(
            "eth_getUserOperationReceipt",
            [user_op_hash],
        )

        if result is None:
            return None

        return UserOpReceipt(
            user_op_hash=result["userOpHash"],
            transaction_hash=result["receipt"]["transactionHash"],
            block_number=int(result["receipt"]["blockNumber"], 16),
            success=result["success"],
        )

    async def wait_for_receipt(
        self,
        user_op_hash: str,
        timeout_s: float = 60.0,
        poll_interval_s: float = 2.0,
    ) -> UserOpReceipt:
        """Wait for UserOp receipt with polling.

        Args:
            user_op_hash: The UserOp hash to wait for.
            timeout_s: Maximum wait time in seconds.
            poll_interval_s: Polling interval in seconds.

        Returns:
            UserOpReceipt once mined.

        Raises:
            TimeoutError: If receipt not found within timeout.
        """
        elapsed = 0.0
        while elapsed < timeout_s:
            receipt = await self.get_user_operation_receipt(user_op_hash)
            if receipt is not None:
                return receipt
            await asyncio.sleep(poll_interval_s)
            elapsed += poll_interval_s

        raise TimeoutError(
            f"UserOp {user_op_hash} not mined after {timeout_s}s. "
            "The transaction may still be pending -- check the bundler or block explorer."
        )

    # ==========================================================================
    # Internal
    # ==========================================================================

    async def _call_with_fallback(
        self, method: str, params: List[Any]
    ) -> Any:
        """Call primary, fall back to backup, with retries and backoff."""
        try:
            return await self._call_with_retry(self._primary_url, method, params)
        except Exception as primary_error:
            if not self._backup_url:
                raise
            logger.warning(
                "Primary bundler failed, trying backup: method=%s error=%s",
                method,
                str(primary_error),
            )

        return await self._call_with_retry(self._backup_url, method, params)

    async def _call_with_retry(
        self, url: str, method: str, params: List[Any]
    ) -> Any:
        """Call with retry and exponential backoff."""
        last_error: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                return await self._json_rpc(url, method, params)
            except Exception as e:
                last_error = e
                if _is_non_transient(e):
                    raise
                if attempt < self._max_retries:
                    delay = self._base_delay_s * (2 ** attempt)
                    logger.warning(
                        "Bundler request failed, retrying: attempt=%d method=%s delay=%.1fs",
                        attempt + 1,
                        method,
                        delay,
                    )
                    await asyncio.sleep(delay)
        raise last_error  # type: ignore[misc]

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
            raise BundlerHTTPError(
                f"HTTP {response.status_code}: {response.reason_phrase}"
            )

        data = response.json()

        if "error" in data and data["error"] is not None:
            err = data["error"]
            data_str = f" | data: {err.get('data', '')}" if err.get("data") else ""
            raise BundlerRPCError(
                code=err.get("code", -1),
                message=f"Bundler RPC error {err.get('code', -1)}: {err['message']}{data_str}",
                data=err.get("data"),
            )

        return data.get("result")


# ============================================================================
# Errors
# ============================================================================


class BundlerHTTPError(Exception):
    """HTTP-level error from bundler."""

    pass


class BundlerRPCError(Exception):
    """JSON-RPC error from bundler."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


# ============================================================================
# Helpers
# ============================================================================


def _is_non_transient(error: Exception) -> bool:
    """Detect non-transient errors that should not be retried.

    AA errors from bundler (invalid signature, insufficient funds, etc.)
    and JSON-RPC parse/invalid request errors are non-transient.
    """
    if isinstance(error, BundlerRPCError):
        # JSON-RPC parse/invalid request errors
        if -32700 <= error.code <= -32600:
            return True
        # AA validation errors
        msg = str(error).lower()
        if "aa" in msg and ("invalid" in msg or "rejected" in msg):
            return True
    return False
