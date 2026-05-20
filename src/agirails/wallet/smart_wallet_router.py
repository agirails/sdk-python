"""
SmartWalletRouter — Python port of sdk-js/src/wallet/SmartWalletRouter.ts.

Centralizes the logic for routing ACTPKernel state transitions through a
Smart Wallet (ERC-4337) so on-chain ``msg.sender == Smart Wallet ==
requester/provider``. Without this routing, state-transition calls sent
directly through an EOA fail the kernel ``_requesterCheck`` /
``_providerCheck`` when ``wallet="auto"`` is in use.

Used by :class:`agirails.adapters.StandardAdapter` for ``link_escrow``,
``transition_state``, ``accept_quote``, ``release_escrow``, etc.
``BasicAdapter`` handles ``pay()`` directly via
``AutoWalletProvider.pay_actp_batched``.

@module wallet/smart_wallet_router
@see sdk-js/src/wallet/SmartWalletRouter.ts
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, List, Optional, Union

from eth_abi import encode as abi_encode
from web3 import Web3

from agirails.wallet.auto_wallet_provider import TransactionRequest

# ============================================================================
# Function selectors (matches transaction_batcher.py for consistency)
# ============================================================================

_TRANSITION_STATE_SELECTOR = Web3.keccak(
    text="transitionState(bytes32,uint8,bytes)"
)[:4].hex()

_LINK_ESCROW_SELECTOR = Web3.keccak(
    text="linkEscrow(bytes32,address,bytes32)"
)[:4].hex()

_APPROVE_SELECTOR = Web3.keccak(text="approve(address,uint256)")[:4].hex()

_ACCEPT_QUOTE_SELECTOR = Web3.keccak(
    text="acceptQuote(bytes32,uint256)"
)[:4].hex()


# Threshold to distinguish duration vs absolute-timestamp dispute windows.
# Dispute window durations max at 30 days (~2.6M seconds). Absolute
# timestamps (post-2001) are > 1 billion. No overlap.
_ABSOLUTE_TIMESTAMP_THRESHOLD = 1_000_000_000


# State value integers (matches src/agirails/runtime/types.py _STATE_TO_INT
# and ACTPKernel.sol's State enum ordering).
_STATE_NAME_TO_INT = {
    "INITIATED": 0,
    "QUOTED": 1,
    "COMMITTED": 2,
    "IN_PROGRESS": 3,
    "DELIVERED": 4,
    "SETTLED": 5,
    "DISPUTED": 6,
    "CANCELLED": 7,
}


# ============================================================================
# Helpers
# ============================================================================


def _bytes32_to_bytes(value: str) -> bytes:
    """Convert 0x-prefixed bytes32 hex string to raw 32 bytes."""
    hex_str = value.replace("0x", "")
    if len(hex_str) != 64:
        raise ValueError(
            f"Expected bytes32 (64 hex chars), got {len(hex_str)}: {value}"
        )
    return bytes.fromhex(hex_str)


def _state_to_int(state: Union[int, str]) -> int:
    """Coerce state name or int to the ACTPKernel int representation."""
    if isinstance(state, int):
        return state
    upper = state.upper()
    if upper not in _STATE_NAME_TO_INT:
        raise ValueError(f"Unknown state: {state}")
    return _STATE_NAME_TO_INT[upper]


def compute_dispute_window_ends(
    completed_at: int, dispute_window: int
) -> int:
    """Compute absolute end-time of the dispute window.

    Handles both representations transparently:

    - **Mock mode**: ``dispute_window`` is a duration in seconds →
      ``completed_at + dispute_window``
    - **Blockchain mode**: ``dispute_window`` is an absolute timestamp
      from on-chain → used as-is

    Heuristic: values > 1 billion are absolute timestamps (post-2001
    epoch). Dispute window durations max at 30 days (~2.6M seconds).
    No overlap.
    """
    if dispute_window > _ABSOLUTE_TIMESTAMP_THRESHOLD:
        return dispute_window
    return completed_at + dispute_window


# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class SmartWalletContractAddresses:
    """Subset of contract addresses needed for Smart Wallet call encoding.

    Mirrors :class:`agirails.wallet.aa.transaction_batcher.ContractAddresses`
    but kept separate to avoid coupling the router to the AA batch module.
    """

    usdc: str
    actp_kernel: str
    escrow_vault: str


@dataclass(frozen=True)
class _Receipt:
    hash: str
    success: bool


# ============================================================================
# SmartWalletRouter
# ============================================================================


class SmartWalletRouter:
    """Route ACTPKernel calls through a Smart Wallet wallet provider.

    Construct via :func:`create_smart_wallet_router` so the wallet
    provider / contract / runtime triple is validated up front. When a
    Smart Wallet is wired, all state-transition calls go through the
    wallet provider's ``send_transaction`` / ``send_batch_transaction``
    so ``msg.sender`` on chain equals the Smart Wallet address.
    """

    def __init__(
        self,
        wallet_provider: object,
        contracts: SmartWalletContractAddresses,
        runtime: object,
        eas_helper: Optional[object] = None,
    ) -> None:
        self._wallet_provider = wallet_provider
        self._contracts = contracts
        self._runtime = runtime
        self._eas_helper = eas_helper

    # ------------------------------------------------------------------
    # Routing decision
    # ------------------------------------------------------------------

    def should_route(self) -> bool:
        """``True`` when wallet provider is AA-capable (has ``pay_actp_batched``).

        EOAWalletProvider lacks ``pay_actp_batched`` and falls through to
        the legacy runtime path.
        """
        return hasattr(self._wallet_provider, "pay_actp_batched")

    # ------------------------------------------------------------------
    # Encoders (pure, exposed for testing)
    # ------------------------------------------------------------------

    def encode_transition_state_tx(
        self,
        tx_id: str,
        state_value: Union[int, str],
        proof: str = "0x",
    ) -> TransactionRequest:
        """Encode ``ACTPKernel.transitionState(txId, newState, proof)``."""
        state_int = _state_to_int(state_value)
        proof_bytes = bytes.fromhex(proof.replace("0x", "")) if proof and proof != "0x" else b""
        data = (
            "0x"
            + _TRANSITION_STATE_SELECTOR
            + abi_encode(
                ["bytes32", "uint8", "bytes"],
                [_bytes32_to_bytes(tx_id), state_int, proof_bytes],
            ).hex()
        )
        return TransactionRequest(to=self._contracts.actp_kernel, data=data, value="0")

    def encode_settle_tx(self, tx_id: str) -> TransactionRequest:
        """Encode ``ACTPKernel.transitionState(txId, SETTLED, 0x)``."""
        return self.encode_transition_state_tx(tx_id, "SETTLED", "0x")

    def encode_accept_quote_tx(
        self, tx_id: str, new_amount: str
    ) -> TransactionRequest:
        """Encode ``ACTPKernel.acceptQuote(txId, newAmount)``."""
        data = (
            "0x"
            + _ACCEPT_QUOTE_SELECTOR
            + abi_encode(
                ["bytes32", "uint256"],
                [_bytes32_to_bytes(tx_id), int(new_amount)],
            ).hex()
        )
        return TransactionRequest(to=self._contracts.actp_kernel, data=data, value="0")

    def encode_link_escrow_calls(
        self, tx_id: str, amount: str, usdc_address: str
    ) -> List[TransactionRequest]:
        """Encode the 2-call batch: ``USDC.approve`` + ``linkEscrow``."""
        amount_int = int(amount)

        approve_data = (
            "0x"
            + _APPROVE_SELECTOR
            + abi_encode(
                ["address", "uint256"],
                [
                    Web3.to_checksum_address(self._contracts.escrow_vault),
                    amount_int,
                ],
            ).hex()
        )

        tx_id_bytes = _bytes32_to_bytes(tx_id)
        link_escrow_data = (
            "0x"
            + _LINK_ESCROW_SELECTOR
            + abi_encode(
                ["bytes32", "address", "bytes32"],
                [
                    tx_id_bytes,
                    Web3.to_checksum_address(self._contracts.escrow_vault),
                    tx_id_bytes,  # escrowId == txId (ACTP standard)
                ],
            ).hex()
        )

        return [
            TransactionRequest(to=usdc_address, data=approve_data, value="0"),
            TransactionRequest(
                to=self._contracts.actp_kernel, data=link_escrow_data, value="0"
            ),
        ]

    # ------------------------------------------------------------------
    # Senders
    # ------------------------------------------------------------------

    async def send_transition(
        self,
        tx_id: str,
        state_value: Union[int, str],
        proof: str = "0x",
        label: str = "transitionState",
    ) -> _Receipt:
        """Submit a single ``transitionState`` UserOp."""
        tx = self.encode_transition_state_tx(tx_id, state_value, proof)
        receipt = await self._wallet_provider.send_transaction(tx)  # type: ignore[attr-defined]
        if not receipt.success:
            raise RuntimeError(f"{label} UserOp failed: {receipt.hash}")
        return _Receipt(hash=receipt.hash, success=True)

    async def send_settle(self, tx_id: str) -> _Receipt:
        return await self.send_transition(tx_id, "SETTLED", "0x", label="release")

    async def send_accept_quote(
        self, tx_id: str, new_amount: str
    ) -> _Receipt:
        tx = self.encode_accept_quote_tx(tx_id, new_amount)
        receipt = await self._wallet_provider.send_transaction(tx)  # type: ignore[attr-defined]
        if not receipt.success:
            raise RuntimeError(f"acceptQuote UserOp failed: {receipt.hash}")
        return _Receipt(hash=receipt.hash, success=True)

    async def send_link_escrow(
        self, tx_id: str, amount: str, usdc_address: str
    ) -> _Receipt:
        """Submit the approve + linkEscrow batch as one UserOp."""
        calls = self.encode_link_escrow_calls(tx_id, amount, usdc_address)
        receipt = await self._wallet_provider.send_batch_transaction(calls)  # type: ignore[attr-defined]
        if not receipt.success:
            raise RuntimeError(f"linkEscrow UserOp failed: {receipt.hash}")
        return _Receipt(hash=receipt.hash, success=True)

    # ------------------------------------------------------------------
    # Release preconditions + attestation guard
    # ------------------------------------------------------------------

    async def validate_release_preconditions(
        self, tx_or_id: Union[str, Any]
    ) -> Any:
        """Check state == DELIVERED and dispute window expiry.

        Mock mode: ``dispute_window`` = duration seconds, ``completed_at``
        = delivery timestamp. Blockchain mode: ``dispute_window`` = absolute
        timestamp, ``completed_at`` may be 0 / None — in that case the
        on-chain contract still enforces the window via
        ``_validateSettlementConditions``, so we skip the local check.
        """
        if isinstance(tx_or_id, str):
            tx = await self._runtime.get_transaction(tx_or_id)  # type: ignore[attr-defined]
            tx_id = tx_or_id
        else:
            tx = tx_or_id
            tx_id = getattr(tx, "id", None) or getattr(tx, "tx_id", None)

        if tx is None:
            raise RuntimeError(f"Transaction {tx_id} not found")

        state = getattr(tx, "state", None)
        state_str = state.value if hasattr(state, "value") else str(state)
        if state_str != "DELIVERED":
            raise RuntimeError(
                f"Cannot release escrow: transaction {tx_id} is in state "
                f"{state_str}, expected DELIVERED."
            )

        completed_at = getattr(tx, "completed_at", None)
        dispute_window = getattr(tx, "dispute_window", None)
        if completed_at and dispute_window is not None:
            ends = compute_dispute_window_ends(completed_at, dispute_window)
            now = int(time.time())
            if now < ends:
                # Requester gets to release early; provider doesn't.
                caller = self._wallet_provider.get_address().lower()  # type: ignore[attr-defined]
                requester = (getattr(tx, "requester", "") or "").lower()
                if caller != requester:
                    remaining = ends - now
                    raise RuntimeError(
                        f"Cannot release escrow: dispute window still active "
                        f"for transaction {tx_id}. Window expires in "
                        f"{remaining} seconds."
                    )

        return tx

    async def verify_release_attestation(
        self, tx_id: str, attestation_uid: Optional[str] = None
    ) -> None:
        """Verify (and bind to txId) an EAS attestation if one was supplied.

        When the caller passed an ``attestation_uid`` AND we have an EAS
        helper, run the verify-and-record check (replay protection +
        binding to txId). Without a helper or without a uid, this is a
        no-op — the on-chain contract still applies its own settlement
        gates, and StandardAdapter's release-time attestation requirement
        is enforced upstream by the runtime/caller.
        """
        if attestation_uid and self._eas_helper is not None:
            await self._eas_helper.verify_and_record_for_release(  # type: ignore[attr-defined]
                tx_id, attestation_uid
            )

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_tx_id(escrow_id: str) -> str:
        """Extract txId from a (possibly legacy ``escrow-{txId}-{ts}``) escrowId."""
        if escrow_id.startswith("escrow-"):
            parts = escrow_id.split("-")
            if len(parts) >= 3:
                # legacy mock format: escrow-{txid_hex}-{ts}
                return "-".join(parts[1:-1])
        return escrow_id


# ============================================================================
# Factory
# ============================================================================


def create_smart_wallet_router(
    wallet_provider: Optional[object],
    contracts: Optional[SmartWalletContractAddresses],
    runtime: Optional[object],
    eas_helper: Optional[object] = None,
) -> Optional[SmartWalletRouter]:
    """Build a router when wallet provider supports batched UserOps.

    Returns ``None`` when any of the requirements are unmet — caller
    falls back to the runtime path.
    """
    if (
        wallet_provider is not None
        and contracts is not None
        and runtime is not None
        and hasattr(wallet_provider, "pay_actp_batched")
    ):
        return SmartWalletRouter(wallet_provider, contracts, runtime, eas_helper)
    return None


__all__ = [
    "SmartWalletRouter",
    "SmartWalletContractAddresses",
    "create_smart_wallet_router",
    "compute_dispute_window_ends",
]
