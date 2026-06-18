"""
Standard adapter for AGIRAILS SDK.

Provides granular control over the ACTP transaction lifecycle:
- Separate create_transaction() and link_escrow()
- Manual state transitions
- Escrow management
- Full transaction lifecycle control

Use this adapter when you need more control than BasicAdapter provides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, List, Optional, Union

from web3 import Web3

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
)
from agirails.adapters.types import AdapterMetadata, UnifiedPayParams
from agirails.runtime.base import CreateTransactionParams
from agirails.runtime.types import State
from agirails.utils.helpers import Address, ServiceHash, ServiceMetadata

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime
    from agirails.runtime.types import MockTransaction


@dataclass
class StandardTransactionParams:
    """
    Parameters for standard create_transaction().

    Args:
        provider: Provider address
        amount: Amount in USDC (string, int, or float)
        deadline: Deadline (timestamp, relative, or None for default)
        dispute_window: Dispute window in seconds (None for default)
        description: Service description (optional)
        service_hash: Pre-computed service hash (optional, overrides description)
    """

    provider: str
    amount: Union[str, int, float]
    deadline: Optional[Union[str, int]] = None
    dispute_window: Optional[int] = None
    description: Optional[str] = None
    service_hash: Optional[str] = None


@dataclass
class TransactionDetails:
    """
    Detailed transaction information.

    Returned by get_transaction() for standard users who need full details.
    """

    id: str
    requester: str
    provider: str
    amount: str
    state: str
    deadline: int
    dispute_window: int
    service_description: str
    created_at: int
    updated_at: int
    escrow_id: Optional[str] = None
    delivery_proof: Optional[str] = None
    attestation_uid: Optional[str] = None


@dataclass
class TransactionStatus:
    """
    Adapter-agnostic transaction status with action hints.

    Returned by the IAdapter ``get_status()`` lifecycle method. Mirrors the TS
    ``TransactionStatus`` interface (IAdapter.ts:44-74) field-for-field so the
    same status shape is produced across adapters and SDKs.

    Attributes:
        state: Current transaction state string.
        can_start_work: Provider can start work (COMMITTED -> IN_PROGRESS).
        can_deliver: Provider can mark delivered (IN_PROGRESS -> DELIVERED).
        can_release: Escrow can be released (DELIVERED + dispute window expired).
        can_dispute: Requester can dispute (DELIVERED, within dispute window).
        amount: Transaction amount (formatted USDC string).
        provider: Provider address.
        requester: Requester address.
        deadline: Deadline as ISO 8601 string (optional).
        dispute_window_ends: Dispute window end as ISO 8601 string (optional).
    """

    state: str
    can_start_work: bool
    can_deliver: bool
    can_release: bool
    can_dispute: bool
    amount: str
    provider: str
    requester: str
    deadline: Optional[str] = None
    dispute_window_ends: Optional[str] = None


class StandardAdapter(BaseAdapter):
    """
    Standard adapter for granular ACTP transaction control.

    Provides separate methods for each step of the transaction lifecycle:
    1. create_transaction() - Create transaction (no funds locked yet)
    2. link_escrow() - Lock funds in escrow
    3. transition_state() - Move through states
    4. release_escrow() - Release funds to provider
    5. get_transaction() - Check transaction details

    Example:
        >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
        >>>
        >>> # Step 1: Create transaction
        >>> tx_id = await client.standard.create_transaction(
        ...     StandardTransactionParams(
        ...         provider="0x...",
        ...         amount="100.50",
        ...         deadline="24h",
        ...         description="AI text generation"
        ...     )
        ... )
        >>>
        >>> # Step 2: Link escrow (locks funds)
        >>> escrow_id = await client.standard.link_escrow(tx_id)
        >>>
        >>> # Step 3: Provider delivers work...
        >>> await client.standard.transition_state(tx_id, "DELIVERED")
        >>>
        >>> # Step 4: Release funds
        >>> await client.standard.release_escrow(escrow_id)
    """

    @property
    def metadata(self) -> AdapterMetadata:
        """Adapter metadata — priority 60 (higher than basic)."""
        return AdapterMetadata(
            id="standard",
            priority=60,
            uses_escrow=True,
            supports_disputes=True,
            release_required=True,
        )

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """StandardAdapter handles Ethereum addresses (not URLs)."""
        return Address.is_valid(params.to)

    def validate(self, params: UnifiedPayParams) -> None:
        """Validate unified params for StandardAdapter."""
        from agirails.errors import ValidationError

        if not Address.is_valid(params.to):
            raise ValidationError(
                message="StandardAdapter requires a valid Ethereum address",
                details={"field": "to", "value": params.to},
            )

    async def pay(self, params: Union[UnifiedPayParams, dict]) -> Any:
        """
        Execute payment through StandardAdapter (IAdapter compliance).

        Maps UnifiedPayParams to create_transaction + link_escrow.
        Returns with state=COMMITTED (caller must follow ACTP lifecycle).

        Args:
            params: UnifiedPayParams or dict.

        Returns:
            Dict with txId, escrowId, state, amount, deadline.
        """
        if isinstance(params, dict):
            params = UnifiedPayParams(**params)

        std_params = StandardTransactionParams(
            provider=params.to,
            amount=params.amount,
            deadline=params.deadline,
            description=params.description,
            service_hash=params.service_hash,
        )

        tx_id = await self.create_transaction(std_params)
        escrow_id = await self.link_escrow(tx_id)

        tx = await self._runtime.get_transaction(tx_id)
        return {
            "tx_id": tx_id,
            "escrow_id": escrow_id,
            "state": tx.get("state", "COMMITTED") if isinstance(tx, dict) else getattr(tx, "state", "COMMITTED"),
            "amount": tx.get("amount", str(params.amount)) if isinstance(tx, dict) else getattr(tx, "amount", str(params.amount)),
            "deadline": tx.get("deadline", 0) if isinstance(tx, dict) else getattr(tx, "deadline", 0),
        }

    async def create_transaction(
        self, params: Union[StandardTransactionParams, dict]
    ) -> str:
        """
        Create a new ACTP transaction.

        This creates the transaction record but does NOT lock funds.
        Call link_escrow() to lock funds and move to COMMITTED state.

        Args:
            params: Transaction parameters

        Returns:
            Transaction ID (bytes32)

        Raises:
            ValidationError: If inputs are invalid
            InvalidAddressError: If addresses are invalid
        """
        # Convert dict to dataclass if needed
        if isinstance(params, dict):
            params = StandardTransactionParams(**params)

        # Validate provider address
        provider = self.validate_address(params.provider, "provider")

        # Parse amount
        amount_wei = self.parse_amount(params.amount)

        # Parse deadline
        deadline = self.parse_deadline(params.deadline)

        # Validate dispute window
        dispute_window = self.validate_dispute_window(params.dispute_window)

        # Determine service hash
        if params.service_hash:
            service_hash = params.service_hash
        elif params.description:
            service_metadata = ServiceMetadata(
                service="standard",
                input={"description": params.description},
            )
            service_hash = ServiceHash.hash(service_metadata)
        else:
            service_hash = ServiceHash.ZERO

        # AIP-12: route through Smart Wallet when available (gasless).
        # Submits createTransaction as a UserOp so msg.sender == Smart Wallet ==
        # requester (passes kernel _requesterCheck). The txId is pre-computed from
        # the ACTP nonce inside the DualNonceManager mutex.
        # Mirrors TS StandardAdapter.createTransaction (StandardAdapter.ts:176-194).
        router = self._smart_wallet_router
        wallet_provider = self._wallet_provider
        if (
            router is not None
            and router.should_route()
            and wallet_provider is not None
            and hasattr(wallet_provider, "create_actp_transaction")
            and self._contract_addresses is not None
        ):
            # Service hash must match BlockchainRuntime.validateServiceHash:
            # empty -> ZeroHash, valid bytes32 -> pass-through, raw string ->
            # keccak256(utf8). This differs from the ServiceMetadata wrapper above,
            # which the routed kernel call must NOT use.
            routed_service_hash = _compute_service_hash(
                params.service_hash or params.description
            )

            from agirails.wallet.auto_wallet_provider import (
                CreateACTPTransactionParams,
            )

            result = await wallet_provider.create_actp_transaction(
                CreateACTPTransactionParams(
                    provider=provider,
                    requester=self._requester_address,
                    amount=amount_wei,
                    deadline=deadline,
                    dispute_window=dispute_window,
                    service_hash=routed_service_hash,
                    agent_id=getattr(params, "agent_id", None) or "0",
                    contracts=self._contract_addresses,
                )
            )
            if not result.receipt.success:
                raise RuntimeError(
                    f"createTransaction UserOp failed: {result.receipt.hash}"
                )
            return result.tx_id

        # Fallback: EOA / mock path
        tx_params = CreateTransactionParams(
            requester=self._requester_address,
            provider=provider,
            amount=amount_wei,
            deadline=deadline,
            dispute_window=dispute_window,
            service_description=service_hash,
        )
        tx_id = await self._runtime.create_transaction(tx_params)

        return tx_id

    async def accept_quote(
        self,
        tx_id: str,
        new_amount: Union[str, int, float],
    ) -> None:
        """
        Accept a provider's quote, updating the transaction amount.

        Does NOT change state (stays QUOTED). After accept_quote, call link_escrow.

        Args:
            tx_id: Transaction ID
            new_amount: New amount in user-friendly format ("100", 100.50, "100 USDC")

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If not in QUOTED state.
        """
        amount_wei = self.parse_amount(new_amount)

        # AIP-12: route through Smart Wallet so msg.sender == requester.
        router = self._smart_wallet_router
        if router is not None and router.should_route():
            await router.send_accept_quote(tx_id, amount_wei)
            return

        await self._runtime.accept_quote(tx_id=tx_id, new_amount=amount_wei)

    async def link_escrow(self, tx_id: str, amount: Optional[Union[str, int, float]] = None) -> str:
        """
        Link escrow to transaction (locks funds).

        This locks the funds and transitions the transaction to COMMITTED state.

        Args:
            tx_id: Transaction ID
            amount: Override amount (optional, uses transaction amount if not provided)

        Returns:
            Escrow ID (bytes32)

        Raises:
            TransactionNotFoundError: If transaction doesn't exist
            InvalidStateTransitionError: If transaction is not in INITIATED/QUOTED state
            InsufficientBalanceError: If requester has insufficient funds
        """
        # Get transaction to determine amount if not provided
        if amount is None:
            tx = await self._runtime.get_transaction(tx_id)
            if tx is None:
                from agirails.errors import TransactionNotFoundError
                raise TransactionNotFoundError(tx_id=tx_id)
            amount_wei = tx.amount
        else:
            amount_wei = self.parse_amount(amount)

        # AIP-12: route through Smart Wallet — approve + linkEscrow in a single
        # batched UserOp so msg.sender == Smart Wallet (kernel _requesterCheck).
        router = self._smart_wallet_router
        if router is not None and router.should_route() and self._contract_addresses is not None:
            await router.send_link_escrow(
                tx_id, amount_wei, self._contract_addresses.usdc
            )
            return tx_id  # escrowId == txId (ACTP standard)

        # Link escrow (legacy EOA / mock path)
        escrow_id = await self._runtime.link_escrow(
            tx_id=tx_id,
            amount=amount_wei,
        )

        return escrow_id

    async def transition_state(
        self,
        tx_id: str,
        new_state: Union[str, State],
        proof: Optional[str] = None,
    ) -> None:
        """
        Transition transaction to a new state.

        Valid transitions depend on current state:
        - INITIATED → QUOTED, COMMITTED, CANCELLED
        - QUOTED → COMMITTED, CANCELLED
        - COMMITTED → IN_PROGRESS, CANCELLED (AUDIT FIX: must go through IN_PROGRESS)
        - IN_PROGRESS → DELIVERED, CANCELLED
        - DELIVERED → SETTLED, DISPUTED
        - DISPUTED → SETTLED, CANCELLED (admin only)

        Note: Some transitions (like → COMMITTED) happen automatically via link_escrow().

        Args:
            tx_id: Transaction ID
            new_state: Target state (string or State enum)
            proof: Optional proof for DELIVERED state

        Raises:
            TransactionNotFoundError: If transaction doesn't exist
            InvalidStateTransitionError: If transition is not allowed
        """
        # Convert string to State enum if needed
        if isinstance(new_state, str):
            new_state = State(new_state)

        # AIP-12: route through Smart Wallet so msg.sender matches
        # the party allowed to make this transition (requester for
        # CANCELLED, provider for IN_PROGRESS/DELIVERED, etc).
        router = self._smart_wallet_router
        if router is not None and router.should_route():
            await router.send_transition(
                tx_id, new_state.value, proof or "0x",
                label=f"transitionState({new_state.value})",
            )
            return

        await self._runtime.transition_state(
            tx_id=tx_id,
            new_state=new_state,
            proof=proof,
        )

    async def release_escrow(
        self,
        escrow_id: str,
        attestation_uid: Optional[str] = None,
    ) -> None:
        """
        Release escrow funds to provider.

        This releases the locked funds to the provider, transitioning
        the transaction to SETTLED state.

        SECURITY: MANDATORY attestation verification before release.
        When EAS is required (the runtime mandates it, or an EAS helper is
        available in testnet/mainnet modes), attestation verification is
        REQUIRED — not optional. A missing ``attestation_uid`` raises instead
        of silently releasing funds without delivery proof. Mirrors TS
        ``releaseEscrow`` (StandardAdapter.ts:362-428).

        Verifications performed:
        - Attestation exists and is not revoked (replay-attack protection)
        - Attestation belongs to this transaction (txId cross-check)

        Args:
            escrow_id: Escrow ID to release
            attestation_uid: EAS attestation UID (REQUIRED when EAS available)

        Raises:
            EscrowNotFoundError: If escrow doesn't exist
            DisputeWindowActiveError: If dispute window is still active
            InvalidStateTransitionError: If transaction is not in DELIVERED state
            RuntimeError: If EAS is required but ``attestation_uid`` is omitted
            ValueError: If attestation verification fails
        """
        from agirails.wallet.smart_wallet_router import SmartWalletRouter

        # Determine whether the underlying runtime requires attestation.
        # BlockchainRuntime may expose isAttestationRequired(); otherwise fall
        # back to EAS-helper presence (TS StandardAdapter.ts:366-374).
        runtime_supports_attestation_flag = callable(
            getattr(self._runtime, "is_attestation_required", None)
        )
        if runtime_supports_attestation_flag:
            attestation_required = bool(self._runtime.is_attestation_required())
        else:
            attestation_required = bool(self._eas_helper)

        attestation_verified_locally = False

        # MANDATORY gate: if attestation is required, a uid MUST be supplied.
        if attestation_required and not attestation_uid:
            raise RuntimeError(
                "Attestation verification is REQUIRED for escrow release. "
                "Provide attestation_uid."
            )

        tx_id_from_escrow = SmartWalletRouter.extract_tx_id(escrow_id)

        # If a uid was supplied and the runtime does NOT handle EAS internally but
        # the adapter has a helper, verify (and bind to txId) here. Otherwise the
        # uid is passed down so the runtime/router can enforce/record it.
        if attestation_uid:
            runtime_has_eas = bool(
                getattr(self._runtime, "eas_helper", None)
            )
            if not runtime_supports_attestation_flag and self._eas_helper and not runtime_has_eas:
                from agirails.protocol.eas import EASHelper

                if isinstance(self._eas_helper, EASHelper):
                    await self._eas_helper.verify_and_record_for_release(
                        tx_id_from_escrow,
                        attestation_uid,
                    )
                    attestation_verified_locally = True

        # AIP-12: route through Smart Wallet — validate preconditions +
        # attestation in-process, then send transitionState(SETTLED) so
        # msg.sender == Smart Wallet (kernel _requesterCheck on release).
        router = self._smart_wallet_router
        if router is not None and router.should_route():
            if attestation_required and not self._eas_helper:
                raise RuntimeError(
                    "Attestation verification is required but EAS helper is "
                    "not initialized."
                )
            await router.validate_release_preconditions(tx_id_from_escrow)
            if attestation_uid and self._eas_helper and not attestation_verified_locally:
                await router.verify_release_attestation(
                    tx_id_from_escrow, attestation_uid
                )
            await router.send_settle(tx_id_from_escrow)
            return

        await self._runtime.release_escrow(
            escrow_id=escrow_id,
            attestation_uid=attestation_uid or "",
        )

    async def get_escrow_balance(self, escrow_id: str) -> str:
        """
        Get escrow balance.

        Args:
            escrow_id: Escrow ID

        Returns:
            Balance in wei (string)

        Raises:
            EscrowNotFoundError: If escrow doesn't exist
        """
        return await self._runtime.get_escrow_balance(escrow_id)

    async def get_transaction(self, tx_id: str) -> Optional[TransactionDetails]:
        """
        Get transaction details.

        Args:
            tx_id: Transaction ID

        Returns:
            TransactionDetails or None if not found
        """
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            return None

        # Get escrow info if available
        escrow_id = None
        if hasattr(self._runtime, "_state"):
            # Mock runtime - look up escrow by tx_id
            state = await self._runtime._state_manager.load()
            for eid, escrow in state.escrows.items():
                if escrow.tx_id == tx_id:
                    escrow_id = eid
                    break

        return TransactionDetails(
            id=tx.id,
            requester=tx.requester,
            provider=tx.provider,
            amount=tx.amount,
            state=tx.state.value if hasattr(tx.state, "value") else str(tx.state),
            deadline=tx.deadline,
            dispute_window=tx.dispute_window,
            service_description=tx.service_description or "",
            created_at=tx.created_at,
            updated_at=tx.updated_at,
            escrow_id=escrow_id,
            delivery_proof=tx.delivery_proof,  # PARITY: Renamed from 'proof' to match TS SDK
            attestation_uid=None,  # Not tracked in MockTransaction
        )

    async def get_all_transactions(self) -> List[TransactionDetails]:
        """
        Get all transactions.

        Returns:
            List of TransactionDetails
        """
        transactions = await self._runtime.get_all_transactions()
        result = []
        for tx in transactions:
            details = await self.get_transaction(tx.id)
            if details:
                result.append(details)
        return result

    async def get_transactions_by_provider(
        self,
        provider_address: str,
        state: Optional[Union[str, State]] = None,
        limit: int = 100,
    ) -> List[TransactionDetails]:
        """
        Get transactions by provider address.

        Args:
            provider_address: Provider address to filter by
            state: Optional state filter
            limit: Maximum number of results

        Returns:
            List of TransactionDetails
        """
        # Validate provider address
        provider = self.validate_address(provider_address, "provider")

        # Convert state if needed
        state_filter = None
        if state is not None:
            if isinstance(state, str):
                state_filter = State(state)
            else:
                state_filter = state

        transactions = await self._runtime.get_transactions_by_provider(
            provider=provider,
            state=state_filter,
            limit=limit,
        )

        result = []
        for tx in transactions:
            details = await self.get_transaction(tx.id)
            if details:
                result.append(details)
        return result

    # ==========================================================================
    # IAdapter lifecycle methods
    # ==========================================================================

    async def get_status(self, tx_id: str) -> TransactionStatus:
        """
        Get transaction status with action hints (IAdapter compliance).

        Mirrors TS ``StandardAdapter.getStatus`` (StandardAdapter.ts:590-622).

        Args:
            tx_id: Transaction ID.

        Returns:
            TransactionStatus with state + action hints.

        Raises:
            RuntimeError: If transaction not found.
        """
        from datetime import datetime, timezone

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
        msg.sender == Smart Wallet. Mirrors TS ``StandardAdapter.startWork``
        (StandardAdapter.ts:635-641).

        Args:
            tx_id: Transaction ID.
        """
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
        disputeWindow and encodes it as proof. Mirrors TS
        ``StandardAdapter.deliver`` (StandardAdapter.ts:654-672).

        Args:
            tx_id: Transaction ID.
            proof: Optional ABI-encoded dispute-window proof. Defaults to the
                transaction's own disputeWindow.

        Raises:
            RuntimeError: If transaction not found.
        """
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

        Thin wrapper around ``release_escrow`` for the IAdapter interface.
        Mirrors TS ``StandardAdapter.release`` (StandardAdapter.ts:683-691).

        Args:
            escrow_id: Escrow ID (usually same as txId).
            attestation_uid: Optional EAS attestation UID.
        """
        await self.release_escrow(escrow_id, attestation_uid)


def _compute_service_hash(service_description: Optional[str]) -> str:
    """Compute a bytes32 serviceHash from a service description string.

    Mirrors TS ``computeServiceHash`` (StandardAdapter.ts:702-710), which in turn
    mirrors ``BlockchainRuntime.validateServiceHash``:

    - ``None`` / empty -> ZeroHash
    - already a valid bytes32 hash -> pass through unchanged
    - raw string -> ``keccak256(utf8Bytes(description))``
    """
    if not service_description:
        return ServiceHash.ZERO
    if ServiceHash.is_valid_hash(service_description):
        return service_description
    digest = Web3.keccak(text=service_description).hex()
    return digest if digest.startswith("0x") else "0x" + digest
