# PARITY: sdk-js/src/dispute/CompositeMediator.ts
# Keep the decode shape, split-rate semantics, and the "resolve is not public"
# rule 1:1 across both SDKs.
"""
CompositeMediator — read-only / event client for the AIP-14b split-outcome
mediator (PRD P2-5).

The on-chain CompositeMediator (AIP-14b §6) is a *thin* contract: its ONLY
mutating entrypoint is ``resolve(txId, ruling, splitBps)``, and that function is
``onlyBondEscalation`` — it reverts for every caller except the BondEscalation
contract. There is therefore **no legitimate SDK action** that calls
``resolve()``; an agent or indexer can only *observe* what the mediator did.

Accordingly this client exposes exactly two read surfaces:
    1. ``get_split_recorded_events()`` — pull ``DisputeSplitRecorded`` (every
       ruling-2 resolution the mediator executed: finalize, force_resolve_stale,
       UMA no-winner fallback — AIP-14b §3.4).
    2. ``decode_dispute_split_recorded(log)`` — pure decode of one such event.

``resolve()`` is **deliberately ABSENT** from the public surface. See
:class:`CompositeMediator` docstring and the parity test
``tests/test_dispute/test_composite_mediator.py`` ("resolve is not a public
client method") for the normative assertion + rationale.

ZERO-REMAINING CONSUMER RULE (AIP-14b §6, normative)
----------------------------------------------------
When on-chain escrow ``remaining == 0``, the kernel resolution-proof amounts are
a phantom **1-wei sentinel** (placed only to satisfy the kernel's
``require(requesterAmount > 0 || providerAmount > 0)`` existence check) and are
NOT economic payouts. :func:`decode_resolution_proof` enforces this: with
``remaining == 0`` it surfaces a zero payout for BOTH parties — never a 1-wei
payout. The drained-dispute test pins this.

PARITY: sdk-js/src/dispute/CompositeMediator.ts — every public symbol here has a
TS twin (same name/arity) and vice-versa.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from eth_abi import decode as _abi_decode

# ---------------------------------------------------------------------------
# Decoded event shapes (1:1 with the TS interfaces)
# ---------------------------------------------------------------------------


@dataclass
class DisputeSplitRecorded:
    """
    A decoded ``DisputeSplitRecorded(bytes32 indexed txId, address indexed
    requester, address indexed provider, uint16 splitBps)`` event — the neutral
    reputation trace CompositeMediator emits on every ruling-2 resolution
    (AIP-14b §3.4). Carries NO on-chain penalty.

    PARITY: TS ``DisputeSplitRecorded`` interface.
    """

    tx_id: str
    requester: str
    provider: str
    split_bps: int
    block_number: Optional[int] = None
    log_index: Optional[int] = None
    transaction_hash: Optional[str] = None


@dataclass
class DecodedResolutionProof:
    """
    Decoded kernel resolution proof, AFTER the zero-remaining consumer rule has
    been applied. The amounts are the ECONOMICALLY REAL payouts — never a
    phantom 1-wei sentinel.

    PARITY: TS ``DecodedResolutionProof`` interface.

    PARITY NOTE (representation differs — values match byte-for-byte under the
    zero-remaining rule): this Py twin exposes FLAT ``requester_amount`` /
    ``provider_amount`` ints; the TS twin exposes a NESTED
    ``payouts: {{ requester, provider }}`` object. Field-access code is NOT
    portable across SDKs — ``.requester_amount`` is Py-only; the TS twin reads
    ``.payouts.requester``. This is a locked, documented per-SDK idiom (parity is
    by type NAME, not field shape); there is no ``payouts`` object in Python.

    Attributes:
        is_split:         True when the kernel path was DISPUTED→CANCELLED.
        provider_at_fault: SETTLED-branch flag (96-byte proof); ``None`` for the
                           CANCELLED/split branch (64-byte proof omits it).
        requester_amount: real requester payout (0 when remaining == 0).
        provider_amount:  real provider payout (0 when remaining == 0).
        phantom_sentinel: True when the proof amounts were ignored as a phantom
                          sentinel because remaining == 0 (AIP-14b §6).
    """

    is_split: bool
    requester_amount: int
    provider_amount: int
    phantom_sentinel: bool
    provider_at_fault: Optional[bool] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex_str(value: Union[bytes, str]) -> str:
    """Normalize a bytes/0x-hex value to a 0x-prefixed lowercase hex string."""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return value if value.startswith("0x") else "0x" + value


def _proof_to_bytes(proof: Union[bytes, str]) -> bytes:
    """Normalize a proof (0x-hex string or raw bytes) to bytes."""
    if isinstance(proof, bytes):
        return proof
    s = proof[2:] if proof.startswith(("0x", "0X")) else proof
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# Pure decoders (no chain access — usable on a raw log)
# ---------------------------------------------------------------------------


def decode_dispute_split_recorded(log: Any) -> DisputeSplitRecorded:
    """
    Decode a single ``DisputeSplitRecorded`` event log.

    Accepts a web3 ``LogReceipt`` / ``AttributeDict`` that already carries
    decoded ``args`` (e.g. from ``contract.events.DisputeSplitRecorded()
    .get_all_entries()`` or ``process_log``), mirroring how the TS twin accepts
    an ethers ``EventLog``. PARITY: TS ``decodeDisputeSplitRecorded``.

    Raises:
        ValueError: if the log is not a ``DisputeSplitRecorded`` event.
    """
    event_name = log.get("event") if hasattr(log, "get") else getattr(log, "event", None)
    if event_name is not None and event_name != "DisputeSplitRecorded":
        raise ValueError(
            f"decode_dispute_split_recorded: log is not a DisputeSplitRecorded "
            f"event (got {event_name})"
        )

    args = log.get("args", {}) if hasattr(log, "get") else getattr(log, "args", {})
    if not args:
        raise ValueError(
            "decode_dispute_split_recorded: log carries no decoded args; pass a "
            "processed event log (contract.events.DisputeSplitRecorded()...)."
        )

    def _get(key: str, default: Any = None) -> Any:
        return args.get(key, default) if hasattr(args, "get") else getattr(args, key, default)

    tx_id = _get("txId", b"")
    tx_hash = log.get("transactionHash") if hasattr(log, "get") else getattr(log, "transactionHash", None)
    return DisputeSplitRecorded(
        tx_id=_hex_str(tx_id),
        requester=_get("requester", ""),
        provider=_get("provider", ""),
        split_bps=int(_get("splitBps", 0)),
        block_number=(log.get("blockNumber") if hasattr(log, "get") else getattr(log, "blockNumber", None)),
        log_index=(log.get("logIndex") if hasattr(log, "get") else getattr(log, "logIndex", None)),
        transaction_hash=_hex_str(tx_hash) if isinstance(tx_hash, (bytes, str)) else tx_hash,
    )


def decode_resolution_proof(
    proof: Union[bytes, str],
    remaining: int,
) -> DecodedResolutionProof:
    """
    Decode a kernel resolution proof under the ZERO-REMAINING CONSUMER RULE
    (AIP-14b §6).

    The CompositeMediator encodes two proof shapes (AIP-14b §6):
        - SPLIT  (CANCELLED): ``abi.encode(uint256 requesterAmount,
          uint256 providerAmount)`` — 64 bytes
        - SETTLE (SETTLED):   ``abi.encode(uint256 requesterAmount,
          uint256 providerAmount, bool providerAtFault)`` — 96 bytes

    When ``remaining == 0`` the prevailing party's amount field holds an **inert
    1-wei sentinel** placed solely to pass the kernel's
    ``require(requesterAmount > 0 || providerAmount > 0)`` existence check. It is
    never transferred (the kernel gates every move behind ``if (remaining > 0)``).
    This decoder therefore ZEROS both payouts when ``remaining == 0`` and sets
    ``phantom_sentinel``. No 1-wei payout is ever surfaced.
    PARITY: TS ``decodeResolutionProof``.

    Args:
        proof: the raw proof bytes (0x-hex or bytes) passed to ``transitionState``.
        remaining: the on-chain escrow ``remaining`` at resolution time.
    """
    raw = _proof_to_bytes(proof)
    byte_len = len(raw)

    if byte_len == 96:
        # SETTLED branch: (requesterAmount, providerAmount, providerAtFault)
        req_amt, prov_amt, fault = _abi_decode(["uint256", "uint256", "bool"], raw)
        is_split = False
        provider_at_fault: Optional[bool] = bool(fault)
    else:
        # SPLIT/CANCELLED branch: (requesterAmount, providerAmount) — 64 bytes.
        req_amt, prov_amt = _abi_decode(["uint256", "uint256"], raw)
        is_split = True
        provider_at_fault = None

    # ZERO-REMAINING CONSUMER RULE: proof amounts are a phantom sentinel — ignore.
    if remaining == 0:
        return DecodedResolutionProof(
            is_split=is_split,
            requester_amount=0,
            provider_amount=0,
            phantom_sentinel=True,
            provider_at_fault=provider_at_fault,
        )

    return DecodedResolutionProof(
        is_split=is_split,
        requester_amount=int(req_amt),
        provider_amount=int(prov_amt),
        phantom_sentinel=False,
        provider_at_fault=provider_at_fault,
    )


def compute_split_rate(
    split_recorded: int,
    kernel_disputed_to_cancelled: int,
    total_disputes: int,
) -> float:
    """
    Compute the per-agent / global split rate over a set of resolved disputes
    (AIP-14b §3.4, OQ-11 default).

    OQ-11 (normative default): the numerator counts BOTH
        - ``DisputeSplitRecorded`` events (mediator-executed ruling-2), AND
        - kernel ``DISPUTED → CANCELLED`` transitions (includes admin-CANCELLED),
    at **identical weight**. Both are split outcomes for split-rate purposes.

    Args:
        split_recorded: count of ``DisputeSplitRecorded`` events.
        kernel_disputed_to_cancelled: count of kernel DISPUTED→CANCELLED transitions.
        total_disputes: total disputes observed (denominator).

    Returns:
        Split rate in ``[0, 1]``; ``0.0`` when ``total_disputes == 0``.

    PARITY: TS ``computeSplitRate``.
    """
    if total_disputes <= 0:
        return 0.0
    splits = split_recorded + kernel_disputed_to_cancelled
    return splits / total_disputes


# ---------------------------------------------------------------------------
# Read-only client
# ---------------------------------------------------------------------------


class CompositeMediator:
    """
    Read/event client for the on-chain CompositeMediator (AIP-14b §6).

    ``resolve()`` is intentionally not a method
    ---------------------------------------------
    The on-chain ``resolve(txId, ruling, splitBps)`` is guarded by
    ``onlyBondEscalation`` — it reverts for any caller other than the
    BondEscalation contract (AIP-14b §6: *"modifier onlyBondEscalation"*). There
    is no signer an SDK user could hold that would let ``resolve()`` succeed, so
    exposing it would be a footgun: every call would revert with
    ``"Only tier system"``. Resolution is driven exclusively by the bond game
    (finalize / force_resolve_stale / UMA callbacks inside BondEscalation), which
    then calls the mediator internally. The SDK's job at the mediator boundary is
    purely observational, so this client is **read-only**. The parity test
    "resolve is not a public client method" pins this absence in both SDKs.

    PARITY: TS ``CompositeMediator`` class.
    """

    def __init__(self, contract: Any, address: str) -> None:
        """
        Args:
            contract: a web3 ``AsyncContract`` bound to the CompositeMediator ABI.
            address: the on-chain CompositeMediator address.
        """
        self.contract = contract
        self.address = address

    @staticmethod
    def _load_abi() -> List[Dict[str, Any]]:
        """Load the CompositeMediator ABI from the abis directory."""
        abi_path = Path(__file__).parent.parent / "abis" / "composite_mediator.json"
        with open(abi_path) as f:
            return json.load(f)

    @classmethod
    def from_config(cls, w3: Any, config: Any) -> "CompositeMediator":
        """
        Create a CompositeMediator client from network configuration.

        PARITY: mirrors the ``new CompositeMediator(address, provider)`` ctor in
        the TS twin (read-only; no signer required).
        """
        address = w3.to_checksum_address(config.contracts.composite_mediator)
        contract = w3.eth.contract(address=address, abi=cls._load_abi())
        return cls(contract, address)

    def get_address(self) -> str:
        """Address of the on-chain CompositeMediator. PARITY: TS ``getAddress``."""
        return self.address

    def get_contract(self) -> Any:
        """Underlying web3 contract (read-only surface). PARITY: TS ``getContract``."""
        return self.contract

    async def get_split_recorded_events(
        self,
        tx_id: Optional[str] = None,
        requester: Optional[str] = None,
        provider: Optional[str] = None,
        from_block: Union[int, str] = "earliest",
        to_block: Union[int, str] = "latest",
    ) -> List[DisputeSplitRecorded]:
        """
        Query historical ``DisputeSplitRecorded`` events.

        PARITY: TS ``getSplitRecordedEvents``.
        """
        argument_filters: Dict[str, Any] = {}
        if tx_id is not None:
            argument_filters["txId"] = tx_id
        if requester is not None:
            argument_filters["requester"] = requester
        if provider is not None:
            argument_filters["provider"] = provider

        log_filter = self.contract.events.DisputeSplitRecorded.create_filter(
            fromBlock=from_block,
            toBlock=to_block,
            argument_filters=argument_filters or None,
        )
        logs = await log_filter.get_all_entries()
        return [decode_dispute_split_recorded(log) for log in logs]

    def on_dispute_split_recorded(
        self,
        callback: Callable[[DisputeSplitRecorded], None],
        poll_interval: float = 2.0,
    ) -> Any:
        """
        Subscribe to live ``DisputeSplitRecorded`` events.

        PARITY: TS ``CompositeMediator.onDisputeSplitRecorded``. The TS twin
        returns an unsubscribe ``() => void``; the Py twin returns an
        :class:`asyncio.Task` (the idiomatic async unsubscribe handle) — call
        ``task.cancel()`` to stop watching. The callback receives a decoded
        :class:`DisputeSplitRecorded` for each new event, exactly as the TS twin.

        Args:
            callback: invoked with each decoded :class:`DisputeSplitRecorded`.
            poll_interval: seconds between block-range polls (default 2.0).
        """
        contract = self.contract

        async def _watch() -> None:
            w3 = getattr(contract, "w3", None) or getattr(self, "_w3", None)
            last_block = await w3.eth.block_number
            while True:
                try:
                    current_block = await w3.eth.block_number
                    if current_block > last_block:
                        log_filter = contract.events.DisputeSplitRecorded.create_filter(
                            fromBlock=last_block + 1,
                            toBlock=current_block,
                        )
                        logs = await log_filter.get_all_entries()
                        for log in logs:
                            callback(decode_dispute_split_recorded(log))
                        last_block = current_block
                    await asyncio.sleep(poll_interval)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(poll_interval)

        return asyncio.create_task(_watch())


__all__ = [
    # Types
    "DisputeSplitRecorded",
    "DecodedResolutionProof",
    # Pure decoders / metrics (1:1 with TS standalone functions)
    "decode_dispute_split_recorded",
    "decode_resolution_proof",
    "compute_split_rate",
    # Client
    "CompositeMediator",
]
