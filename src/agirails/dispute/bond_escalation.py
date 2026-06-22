# PARITY: sdk-js/src/dispute/BondEscalation.ts
# This file and its TypeScript twin MUST stay 1:1 — every public method here has
# a TS twin with the SAME name (camelCase) and arity, and vice-versa. The two
# quote helpers + get_dispute_state decode are anchored to the shared cross-SDK
# fixture `DISPUTE SYSTEM/test-vectors/bond-escalation-vectors.json`, which both
# the pytest and jest suites consume byte-identically. Any change here (rename,
# new method, formula tweak) must be mirrored in the twin.
"""
BondEscalationClient — typed wrapper for the AIP-14 three-tier dispute engine
(``BondEscalation.sol``).

Wraps every method of the normative ``IBondEscalation`` core interface
(AIP-14 §7.1) plus the two bond-quote helpers and the on-chain ``disputes(...)``
reader. This is the dispute counterpart to :class:`ACTPKernel` — it does NOT
touch the kernel's legacy ``raise_dispute``/``resolve_dispute`` (those settle
through the kernel's own SETTLED proof path; the tiered flow here is the AIP-14
successor).

Lifecycle (AIP-14 §3, §7.1)::

    open_dispute(tx_id) -> dispute_id
         |
         v (confident)                 (not confident)
    submit_ai_ruling(ruling, sigs) -- propose_directly(ruling, split)  -- Tier 1
         |                                 |
         v challenge(...) (bond doubles, ceiling $500)
         |
         +--> finalize()          (liveness expired)        -> RESOLVED
         +--> escalate_to_uma(cid) (at ceiling + active)    -> Tier 2 (UMA)
                                                                  |
    sync_external_resolution() / force_resolve_stale() -------> RESOLVED
    claim_escalation_refund()    (split refunds, post-resolve)

Reference: AIP-14 §7 (BondEscalation), §7.1 (IBondEscalation), §7.4 (constants),
§7.13 (bond formulas).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from eth_utils import keccak as _keccak

from agirails.types.dispute import AIRuling, DisputeState, Ruling, Tier

# ---------------------------------------------------------------------------
# Constants (AIP-14 §7.4) — load-bearing, mirror BondEscalation.sol + TS twin
# ---------------------------------------------------------------------------

#: Initial bond rate: 2% of escrow (basis points). AIP-14 §7.4.
ESCALATION_INITIAL_BPS: int = 200
#: Floor for the initial bond: $1 USDC (6 decimals). AIP-14 §7.4.
MIN_ESCALATION_BOND: int = 1_000_000
#: Ceiling for any escalation bond: $500 USDC (6 decimals). AIP-14 §7.4.
MAX_ESCALATION_BOND: int = 500_000_000
#: Each challenge doubles the bond. AIP-14 §7.4.
ESCALATION_MULTIPLIER: int = 2
#: Basis-point denominator.
BPS_DENOMINATOR: int = 10_000


def _load_abi() -> List[Dict[str, Any]]:
    """Load the BondEscalation ABI from the abis directory."""
    abi_path = Path(__file__).parent.parent / "abis" / "bond_escalation.json"
    with open(abi_path) as f:
        return json.load(f)


def _to_bytes32(value: Union[str, bytes]) -> bytes:
    """Normalize a bytes32 input (0x-hex string or raw bytes) to 32 bytes."""
    if isinstance(value, bytes):
        raw = value
    else:
        s = value[2:] if value.startswith(("0x", "0X")) else value
        raw = bytes.fromhex(s)
    if len(raw) != 32:
        raw = raw.rjust(32, b"\x00")
    return raw


def _hex32(value: Union[str, bytes]) -> str:
    """Normalize a bytes32 to a 0x-prefixed lowercase hex string."""
    return "0x" + _to_bytes32(value).hex()


class BondEscalationClient:
    """
    Typed client for the AIP-14 BondEscalation dispute engine.

    Two construction paths (mirrors :class:`ReputationReporter`):

    - Production: pass ``contract`` (a web3 ``AsyncContract``) + ``account`` +
      ``w3`` — write methods build calldata, sign, and broadcast.
    - Testing: pass an injected ``contract`` whose functions record their args;
      the client builds calldata via ``encode_abi`` so tests can assert the
      exact selector + args (the same assertion surface as the TS twin).

    PARITY: BondEscalation.ts ``BondEscalationClient``.
    """

    def __init__(
        self,
        contract: Any,
        *,
        account: Any = None,
        w3: Any = None,
        address: Optional[str] = None,
        confirmations: int = 2,
    ) -> None:
        if confirmations < 1:
            raise ValueError(f"confirmations must be >= 1, got {confirmations}")
        self._contract = contract
        self._account = account
        self._w3 = w3
        self._confirmations = confirmations
        self._address = address or getattr(contract, "address", None)

    @classmethod
    def from_config(
        cls,
        w3: Any,
        account: Any,
        config: Any,
        *,
        confirmations: int = 2,
    ) -> "BondEscalationClient":
        """
        Build a client from a network config (the ``bond_escalation`` address).

        PARITY: ``ACTPKernel.from_config`` (kernel.py). The dispute-contract
        addresses are ``None`` until Phase-6 deployment, in which case this
        raises — callers on undeployed networks must inject a contract directly.
        """
        addr = getattr(config.contracts, "bond_escalation", None)
        if not addr:
            raise ValueError(
                "BondEscalation is not deployed on this network "
                "(config.contracts.bond_escalation is None)"
            )
        contract = w3.eth.contract(
            address=w3.to_checksum_address(addr),
            abi=_load_abi(),
        )
        return cls(
            contract,
            account=account,
            w3=w3,
            address=addr,
            confirmations=confirmations,
        )

    # ------------------------------------------------------------------
    # Accessors (parity with the TS getAddress / getContract)
    # ------------------------------------------------------------------

    def get_address(self) -> Optional[str]:
        """Deployed BondEscalation contract address."""
        return self._address

    def get_contract(self) -> Any:
        """Underlying contract instance."""
        return self._contract

    # ------------------------------------------------------------------
    # Pure quote helpers (AIP-14 §7.13) — no chain access
    # ------------------------------------------------------------------

    @staticmethod
    def quote_initial_bond(escrow_amount: int) -> int:
        """
        Quote the initial Tier-1 bond: ``max(escrow_amount * 2%, $1)``.

        Mirrors ``BondEscalation._calculateInitialBond`` and the TS
        ``quoteInitialBond``. AIP-14 §7.13.

        Args:
            escrow_amount: Disputed escrow remaining (USDC, 6 decimals).

        Returns:
            Initial bond in USDC base units (6 decimals).
        """
        percent_bond = (escrow_amount * ESCALATION_INITIAL_BPS) // BPS_DENOMINATOR
        return percent_bond if percent_bond > MIN_ESCALATION_BOND else MIN_ESCALATION_BOND

    @staticmethod
    def quote_escalation_bond(current_bond: int) -> int:
        """
        Quote the next challenge bond: ``min(current_bond * 2, $500)``.

        Mirrors the challenge bond rule + the TS ``quoteEscalationBond``.
        AIP-14 §7.8 / §7.4.

        Args:
            current_bond: The dispute's current bond (USDC, 6 decimals).

        Returns:
            Next bond in USDC base units, capped at the $500 ceiling.
        """
        nxt = current_bond * ESCALATION_MULTIPLIER
        return MAX_ESCALATION_BOND if nxt > MAX_ESCALATION_BOND else nxt

    # ------------------------------------------------------------------
    # Read helper (decodes the public disputes() tuple)
    # ------------------------------------------------------------------

    async def get_dispute_state(self, dispute_id: str) -> DisputeState:
        """
        Read + decode a dispute's on-chain state from ``disputes(bytes32)``.

        The raw getter returns the 13-field ``DisputeState`` storage struct
        (AIP-14 §7.3); ``tier`` is decoded 0-based onto :class:`Tier`. PARITY:
        TS ``getDisputeState``.

        Args:
            dispute_id: keccak256 dispute identifier (bytes32 hex).

        Returns:
            Decoded :class:`DisputeState`.
        """
        raw = await self._contract.functions.disputes(_to_bytes32(dispute_id)).call()
        return self.decode_dispute_state(dispute_id, raw)

    @staticmethod
    def decode_dispute_state(dispute_id: str, raw: Any) -> DisputeState:
        """
        Decode a raw ``disputes()`` tuple into a :class:`DisputeState`.

        Pure + static so the cross-SDK fixture test can exercise it without a
        contract. Field order is load-bearing (AIP-14 §7.3): ``[transactionId,
        currentRuling, splitBps, currentBond, accumulatedBonds, livenessEnd,
        disputedAt, lastProposer, tier, resolved, winnerPaid, originalPool,
        escrowAmount]``. PARITY: TS ``decodeDisputeState``.
        """
        tx_id_raw = raw[0]
        tx_id = (
            "0x" + tx_id_raw.hex() if isinstance(tx_id_raw, (bytes, bytearray)) else tx_id_raw
        )
        current_ruling = int(raw[1])
        split_bps = int(raw[2])
        tier = int(raw[8])
        resolved = bool(raw[9])

        return DisputeState(
            tx_id=tx_id,
            dispute_id=_hex32(dispute_id),
            tier=tier,
            ruling=current_ruling,
            split_bps=split_bps,
            resolved=resolved,
        )

    # ------------------------------------------------------------------
    # IBondEscalation write methods (AIP-14 §7.1) — identical sigs to TS twin
    # ------------------------------------------------------------------

    async def open_dispute(self, tx_id: str) -> Dict[str, str]:
        """
        Open a dispute for a kernel tx already in the DISPUTED state.

        AIP-14 §7.5. Returns ``{"dispute_id", "eth_tx_hash"}``; ``dispute_id``
        is ``keccak256(abi.encode("ACTP_DISPUTE_V1", tx_id))`` (deterministic),
        also surfaced via the ``DisputeOpened`` event. PARITY: TS ``openDispute``.
        """
        receipt = await self._send("openDispute", [_to_bytes32(tx_id)])
        from eth_abi import encode as _abi_encode

        dispute_id = "0x" + _keccak(
            _abi_encode(["string", "bytes32"], ["ACTP_DISPUTE_V1", _to_bytes32(tx_id)])
        ).hex()
        return {"dispute_id": dispute_id, "eth_tx_hash": receipt}

    async def submit_ai_ruling(self, ruling: AIRuling, signatures: List[Union[str, bytes]]) -> Dict[str, str]:
        """
        Submit an evaluator-signed AIRuling as the Tier-1 proposal.

        AIP-14 §7.7. PARITY: TS ``submitAIRuling``.

        Args:
            ruling: The :class:`AIRuling` (its ``dispute_id`` MUST match).
            signatures: Evaluator EIP-712 signatures (``bytes[]``).
        """
        tuple_arg = self._ai_ruling_to_tuple(ruling)
        sigs = [_normalize_sig(s) for s in signatures]
        receipt = await self._send(
            "submitAIRuling", [_to_bytes32(ruling.dispute_id), tuple_arg, sigs]
        )
        return {"eth_tx_hash": receipt}

    async def propose_directly(
        self, dispute_id: str, ruling: Union[Ruling, int], split_bps: int
    ) -> Dict[str, str]:
        """
        Submit a direct (unsigned) Tier-1 proposal. AIP-14 §7.6.

        PARITY: TS ``proposeDirectly``.
        """
        receipt = await self._send(
            "proposeDirectly", [_to_bytes32(dispute_id), int(ruling), int(split_bps)]
        )
        return {"eth_tx_hash": receipt}

    async def challenge(
        self, dispute_id: str, counter_ruling: Union[Ruling, int], counter_split_bps: int
    ) -> Dict[str, str]:
        """
        Counter an existing proposal with a different outcome + doubled bond.

        AIP-14 §7.8. PARITY: TS ``challenge``.
        """
        receipt = await self._send(
            "challenge",
            [_to_bytes32(dispute_id), int(counter_ruling), int(counter_split_bps)],
        )
        return {"eth_tx_hash": receipt}

    async def finalize(self, dispute_id: str) -> Dict[str, str]:
        """
        Finalize a Tier-1 dispute after liveness expiry. AIP-14 §7.9.

        PARITY: TS ``finalize``.
        """
        receipt = await self._send("finalize", [_to_bytes32(dispute_id)])
        return {"eth_tx_hash": receipt}

    async def escalate_to_uma(self, dispute_id: str, evidence_cid: str) -> Dict[str, str]:
        """
        Escalate a ceiling-bond, liveness-active dispute to UMA OOV3 (Tier 2),
        embedding the IPFS evidence-bundle CID. AIP-14 §7.1, §8.4.

        PARITY: TS ``escalateToUMA``.
        """
        receipt = await self._send(
            "escalateToUMA", [_to_bytes32(dispute_id), evidence_cid]
        )
        return {"eth_tx_hash": receipt}

    async def claim_escalation_refund(self, dispute_id: str) -> Dict[str, str]:
        """
        Claim a proportional split refund after a split (ruling-2) resolution.

        AIP-14 §7.10. Not pausable. PARITY: TS ``claimEscalationRefund``.
        """
        receipt = await self._send("claimEscalationRefund", [_to_bytes32(dispute_id)])
        return {"eth_tx_hash": receipt}

    async def sync_external_resolution(self, dispute_id: str) -> Dict[str, str]:
        """
        Sync a dispute already resolved in the kernel into BondEscalation.

        AIP-14 §7.11. Not pausable. PARITY: TS ``syncExternalResolution``.
        """
        receipt = await self._send("syncExternalResolution", [_to_bytes32(dispute_id)])
        return {"eth_tx_hash": receipt}

    async def force_resolve_stale(self, dispute_id: str) -> Dict[str, str]:
        """
        Force-resolve a dispute past MAX_DISPUTE_DURATION (30 days) to a 50/50
        split. AIP-14 §7.12. Not pausable. PARITY: TS ``forceResolveStale``.
        """
        receipt = await self._send("forceResolveStale", [_to_bytes32(dispute_id)])
        return {"eth_tx_hash": receipt}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _ai_ruling_to_tuple(
        ruling: AIRuling,
    ) -> Tuple[bytes, int, int, int, int, bytes, bytes]:
        """
        Encode :class:`AIRuling` into the positional tuple the contract ABI
        expects (struct field order is load-bearing — mirrors DisputeTypes.sol).
        """
        return (
            _to_bytes32(ruling.dispute_id),
            int(ruling.ruling),
            int(ruling.confidence),
            int(ruling.split_bps),
            int(ruling.timestamp),
            _to_bytes32(ruling.reasoning_hash),
            _to_bytes32(ruling.bundle_hash),
        )

    def encode_calldata(self, method: str, args: List[Any]) -> str:
        """
        Build the 0x-hex calldata for ``method`` via ``encode_abi``. This is the
        assertion surface the tests use (parity with the TS twin's
        ``interface.encodeFunctionData``).
        """
        return self._contract.encode_abi(abi_element_identifier=method, args=args)

    async def _send(self, method: str, args: List[Any]) -> str:
        """
        Build calldata (validating the selector + args), then invoke the
        contract function. Returns the tx-hash string.

        Test mocks supply a contract whose ``functions.<method>(...)`` records
        args and returns an awaitable; production wires through the web3 build /
        sign / send path. Either way, calldata is built first so a malformed
        call raises before broadcast.
        """
        # Build + validate calldata first (assertion surface in tests).
        self.encode_calldata(method, args)

        fn = getattr(self._contract.functions, method)(*args)

        # Production path: build, sign, broadcast via the injected account/w3.
        if self._account is not None and self._w3 is not None:
            nonce = await self._w3.eth.get_transaction_count(
                self._account.address, "pending"
            )
            tx = await fn.build_transaction(
                {"from": self._account.address, "nonce": nonce}
            )
            signed = self._w3.eth.account.sign_transaction(tx, self._account.key)
            tx_hash = await self._w3.eth.send_raw_transaction(signed.raw_transaction)
            await self._w3.eth.wait_for_transaction_receipt(tx_hash)
            return "0x" + tx_hash.hex() if isinstance(tx_hash, (bytes, bytearray)) else str(tx_hash)

        # Test path: the mock fn exposes an awaitable returning a tx hash/receipt.
        result = fn
        send = getattr(result, "transact", None)
        if send is not None:
            tx_hash = await send()
        else:
            tx_hash = await result  # fn itself is awaitable in mocks
        if isinstance(tx_hash, (bytes, bytearray)):
            return "0x" + tx_hash.hex()
        return str(tx_hash)


def _normalize_sig(signature: Union[str, bytes]) -> bytes:
    """Normalize a signature (0x-hex string or raw bytes) to bytes."""
    if isinstance(signature, (bytes, bytearray)):
        return bytes(signature)
    s = signature[2:] if signature.startswith(("0x", "0X")) else signature
    return bytes.fromhex(s)


__all__ = [
    # Constants
    "ESCALATION_INITIAL_BPS",
    "MIN_ESCALATION_BOND",
    "MAX_ESCALATION_BOND",
    "ESCALATION_MULTIPLIER",
    "BPS_DENOMINATOR",
    # Client
    "BondEscalationClient",
]
