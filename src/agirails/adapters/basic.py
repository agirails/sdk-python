"""
Basic adapter for AGIRAILS SDK.

Provides the simplest API for ACTP transactions:
- Single `pay()` method that handles everything
- `check_status()` for transaction status with action hints
- Automatic escrow creation and linking
- Sensible defaults for deadline and dispute window

Use this adapter when you want a "just works" experience.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Optional, Union

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
)
from agirails.adapters.types import AdapterMetadata, UnifiedPayParams
from agirails.errors import ValidationError
from agirails.runtime.base import CreateTransactionParams
from agirails.utils.helpers import Address, ServiceHash, ServiceMetadata

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime


class CheckStatusResult(TypedDict):
    """
    Result from check_status() method.

    PARITY: Matches TypeScript SDK's BasicAdapter.checkStatus() return type.

    Attributes:
        state: Current transaction state string.
        can_accept: Whether provider can accept (INITIATED state, before deadline).
        can_complete: Whether provider can mark as delivered (COMMITTED/IN_PROGRESS).
        can_dispute: Whether requester can dispute (DELIVERED state, within window).
    """

    state: str
    can_accept: bool
    can_complete: bool
    can_dispute: bool


@dataclass
class BasicPayParams:
    """
    Parameters for basic pay() method.

    Args:
        to: Provider address to pay
        amount: Amount in USDC (string, int, or float)
        deadline: Optional deadline (default: 24 hours)
        description: Optional service description
    """

    to: str
    amount: Union[str, int, float]
    deadline: Optional[Union[str, int]] = None
    description: Optional[str] = None


@dataclass
class BasicPayResult:
    """
    Result from basic pay() method.

    Args:
        tx_id: Transaction ID (bytes32)
        escrow_id: Escrow ID (bytes32)
        state: Current transaction state
        amount: Amount in wei (string)
        deadline: Deadline timestamp
    """

    tx_id: str
    escrow_id: str
    state: str
    amount: str
    deadline: int


class BasicAdapter(BaseAdapter):
    """
    Basic-level adapter for ACTP transactions.

    Provides a simple `pay()` method that:
    1. Creates a transaction
    2. Links escrow automatically
    3. Returns a simple result

    Example:
        >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
        >>> result = await client.basic.pay(BasicPayParams(
        ...     to="0x...",
        ...     amount="100.50",
        ...     description="Text generation service"
        ... ))
        >>> print(f"Transaction: {result.tx_id}")
    """

    @property
    def metadata(self) -> AdapterMetadata:
        """Adapter metadata — priority 50 (base level)."""
        return AdapterMetadata(
            id="basic",
            priority=50,
            uses_escrow=True,
            supports_disputes=True,
            release_required=True,
        )

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """BasicAdapter handles Ethereum addresses (not URLs)."""
        return Address.is_valid(params.to)

    def validate(self, params: UnifiedPayParams) -> None:
        """Validate unified params for BasicAdapter."""
        if not Address.is_valid(params.to):
            raise ValidationError(
                message="BasicAdapter requires a valid Ethereum address",
                details={"field": "to", "value": params.to},
            )

    async def pay(self, params: Union[BasicPayParams, UnifiedPayParams, dict]) -> BasicPayResult:
        """
        Create and fund a transaction in one call.

        This is the simplest way to start an ACTP transaction:
        1. Validates inputs
        2. Creates transaction
        3. Links escrow (locks funds)
        4. Returns result with all details

        Args:
            params: Payment parameters (BasicPayParams or dict)

        Returns:
            BasicPayResult with transaction details

        Raises:
            ValidationError: If inputs are invalid
            InsufficientBalanceError: If requester has insufficient funds
            InvalidAddressError: If provider address is invalid

        Example:
            >>> result = await client.basic.pay({
            ...     "to": "0x123...",
            ...     "amount": 100,  # $100 USDC
            ...     "deadline": "24h"  # 24 hours from now
            ... })
        """
        # Convert from dict or UnifiedPayParams
        if isinstance(params, dict):
            params = BasicPayParams(**params)
        elif isinstance(params, UnifiedPayParams):
            params = BasicPayParams(
                to=params.to,
                amount=params.amount,
                deadline=params.deadline,
                description=params.description,
            )

        # Validate provider address
        provider = self.validate_address(params.to, "to")

        # Parse amount
        amount_wei = self.parse_amount(params.amount)

        # Parse deadline
        deadline = self.parse_deadline(params.deadline)

        # Parse dispute window (use default)
        dispute_window = self.validate_dispute_window(None)

        # Create service hash from description
        if params.description:
            service_metadata = ServiceMetadata(
                service="basic",
                input={"description": params.description},
            )
            service_hash = ServiceHash.hash(service_metadata)
        else:
            service_hash = ServiceHash.ZERO

        # ====================================================================
        # AIP-12: Batched payment via AA wallet (1 UserOp = approve +
        # createTransaction + linkEscrow). Active when client.create() wired
        # a wallet_provider exposing pay_actp_batched AND contract_addresses
        # — i.e. wallet="auto" or a manually-constructed AutoWalletProvider.
        # On-chain this guarantees msg.sender == Smart Wallet == requester,
        # which the kernel checks via _requesterCheck.
        # ====================================================================
        if (
            self._wallet_provider is not None
            and self._contract_addresses is not None
            and hasattr(self._wallet_provider, "pay_actp_batched")
        ):
            from agirails.wallet.auto_wallet_provider import BatchedPayParams

            batched_result = await self._wallet_provider.pay_actp_batched(
                BatchedPayParams(
                    provider=provider,
                    requester=self._requester_address,
                    amount=amount_wei,
                    deadline=deadline,
                    dispute_window=dispute_window,
                    service_hash=service_hash,
                    agent_id="0",
                    contracts=self._contract_addresses,
                )
            )
            if not batched_result.success:
                raise ValidationError(
                    message=f"Batched payment UserOp failed: {batched_result.hash}",
                    details={"tx_hash": batched_result.hash, "tx_id": batched_result.tx_id},
                )
            return BasicPayResult(
                tx_id=batched_result.tx_id,
                escrow_id=batched_result.tx_id,  # batched path: escrowId == txId
                state="COMMITTED",
                amount=amount_wei,
                deadline=deadline,
            )

        # ====================================================================
        # Legacy flow: sequential on-chain calls (EOA / mock)
        # ====================================================================

        # Create transaction
        tx_params = CreateTransactionParams(
            requester=self._requester_address,
            provider=provider,
            amount=amount_wei,
            deadline=deadline,
            dispute_window=dispute_window,
            service_description=service_hash,
        )
        tx_id = await self._runtime.create_transaction(tx_params)

        # Link escrow (locks funds)
        escrow_id = await self._runtime.link_escrow(
            tx_id=tx_id,
            amount=amount_wei,
        )

        # Get transaction to verify state
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            # This shouldn't happen, but handle it gracefully
            state = "COMMITTED"
        else:
            state = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        return BasicPayResult(
            tx_id=tx_id,
            escrow_id=escrow_id,
            state=state,
            amount=amount_wei,
            deadline=deadline,
        )

    async def get_transaction(self, tx_id: str) -> Optional[Dict]:
        """
        Get transaction details.

        Simple wrapper around runtime.get_transaction with dict output.

        Args:
            tx_id: Transaction ID

        Returns:
            Transaction as dictionary or None if not found
        """
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            return None

        return {
            "tx_id": tx.id,
            "requester": tx.requester,
            "provider": tx.provider,
            "amount": tx.amount,
            "state": tx.state.value if hasattr(tx.state, "value") else str(tx.state),
            "deadline": tx.deadline,
            "created_at": tx.created_at,
        }

    async def get_balance(self) -> str:
        """
        Get requester's USDC balance.

        Returns:
            Balance in USDC (formatted string like "100.00")
        """
        balance_wei = await self._runtime.get_balance(self._requester_address)
        return self.format_amount(balance_wei)

    async def check_status(self, tx_id: str) -> CheckStatusResult:
        """
        Check payment status by transaction ID.

        Returns current state plus action hints (what can be done next).

        PARITY: Matches TypeScript SDK's BasicAdapter.checkStatus() exactly.

        Action hints:
        - can_accept: Provider can accept (INITIATED state, before deadline)
        - can_complete: Provider can mark as delivered (COMMITTED/IN_PROGRESS)
        - can_dispute: Requester can dispute (DELIVERED state, within window)

        Args:
            tx_id: Transaction ID to check.

        Returns:
            CheckStatusResult with state and action hints.

        Raises:
            TransactionNotFoundError: If transaction not found.

        Example:
            >>> status = await adapter.check_status(tx_id)
            >>> print(f"State: {status['state']}")
            >>> if status['can_complete']:
            ...     print("Provider can deliver now")
        """
        tx = await self._runtime.get_transaction(tx_id)

        if tx is None:
            from agirails.errors import TransactionNotFoundError
            raise TransactionNotFoundError(tx_id)

        now = self._runtime.time.now()

        # Get state as string
        state_str = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        # Calculate action hints (matching TS SDK logic exactly)
        can_accept = state_str == "INITIATED" and tx.deadline > now
        can_complete = state_str in ("COMMITTED", "IN_PROGRESS")

        # can_dispute: DELIVERED state + within dispute window
        can_dispute = False
        if state_str == "DELIVERED" and tx.completed_at is not None:
            dispute_window_end = tx.completed_at + tx.dispute_window
            can_dispute = now < dispute_window_end

        return CheckStatusResult(
            state=state_str,
            can_accept=can_accept,
            can_complete=can_complete,
            can_dispute=can_dispute,
        )

    # ==========================================================================
    # IAdapter lifecycle methods
    # ==========================================================================

    async def get_status(self, tx_id: str) -> "TransactionStatus":
        """
        Get transaction status with action hints (IAdapter compliance).

        Mirrors TS ``BasicAdapter.getStatus`` (BasicAdapter.ts:490-522), which
        is byte-for-byte identical to ``StandardAdapter.getStatus``.

        Args:
            tx_id: Transaction ID.

        Returns:
            TransactionStatus with state + action hints.

        Raises:
            RuntimeError: If transaction not found.
        """
        from datetime import datetime, timezone

        from agirails.adapters.standard import TransactionStatus
        from agirails.wallet.smart_wallet_router import compute_dispute_window_ends

        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            raise RuntimeError(f"Transaction {tx_id} not found")

        now = self._runtime.time.now()
        state_str = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        dispute_window_ends: Optional[int] = None
        if tx.completed_at:
            dispute_window_ends = compute_dispute_window_ends(
                tx.completed_at, tx.dispute_window
            )

        def _iso(ts: int) -> str:
            return (
                datetime.fromtimestamp(ts, tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )

        return TransactionStatus(
            state=state_str,
            can_start_work=state_str == "COMMITTED",
            can_deliver=state_str == "IN_PROGRESS",
            can_release=(
                state_str == "DELIVERED"
                and dispute_window_ends is not None
                and now >= dispute_window_ends
            ),
            can_dispute=(
                state_str == "DELIVERED"
                and dispute_window_ends is not None
                and now < dispute_window_ends
            ),
            amount=self.format_amount(tx.amount),
            deadline=_iso(tx.deadline),
            dispute_window_ends=(
                _iso(dispute_window_ends)
                if dispute_window_ends is not None
                else None
            ),
            provider=tx.provider,
            requester=tx.requester,
        )

    async def start_work(self, tx_id: str) -> None:
        """
        Transition to IN_PROGRESS (provider starts work). IAdapter compliance.

        When Smart Wallet is active, routes through the wallet provider so
        msg.sender == Smart Wallet. Mirrors TS ``BasicAdapter.startWork``
        (BasicAdapter.ts:536-542).

        Args:
            tx_id: Transaction ID.
        """
        from agirails.runtime.types import State

        router = self._smart_wallet_router
        if router is not None and router.should_route():
            await router.send_transition(
                tx_id, "IN_PROGRESS", "0x", label="startWork"
            )
            return
        await self._runtime.transition_state(tx_id, State.IN_PROGRESS)

    async def deliver(self, tx_id: str, proof: Optional[str] = None) -> None:
        """
        Transition to DELIVERED (provider completes work). IAdapter compliance.

        When no proof is provided, fetches the transaction's actual
        disputeWindow and encodes it. Mirrors TS ``BasicAdapter.deliver``
        (BasicAdapter.ts:557-573).

        Args:
            tx_id: Transaction ID.
            proof: Optional ABI-encoded dispute-window proof. Defaults to the
                transaction's own disputeWindow.

        Raises:
            RuntimeError: If transaction not found.
        """
        from agirails.runtime.types import State

        delivery_proof = proof
        if not delivery_proof:
            tx = await self._runtime.get_transaction(tx_id)
            if tx is None:
                raise RuntimeError(f"Transaction {tx_id} not found")
            delivery_proof = self.encode_dispute_window_proof(tx.dispute_window)

        router = self._smart_wallet_router
        if router is not None and router.should_route():
            await router.send_transition(
                tx_id, "DELIVERED", delivery_proof, label="deliver"
            )
            return
        await self._runtime.transition_state(tx_id, State.DELIVERED, delivery_proof)

    async def release(
        self, escrow_id: str, attestation_uid: Optional[str] = None
    ) -> None:
        """
        Release escrow funds (EXPLICIT settlement). IAdapter compliance.

        When Smart Wallet is active, validates preconditions + attestation,
        then sends transitionState(SETTLED). Otherwise calls
        ``runtime.release_escrow``. Mirrors TS ``BasicAdapter.release``
        (BasicAdapter.ts:583-592).

        Args:
            escrow_id: Escrow ID (usually same as txId).
            attestation_uid: Optional EAS attestation UID.
        """
        router = self._smart_wallet_router
        if router is not None and router.should_route():
            from agirails.wallet.smart_wallet_router import SmartWalletRouter

            tx_id = SmartWalletRouter.extract_tx_id(escrow_id)
            await router.validate_release_preconditions(tx_id)
            await router.verify_release_attestation(tx_id, attestation_uid)
            await router.send_settle(tx_id)
            return
        await self._runtime.release_escrow(escrow_id, attestation_uid)
