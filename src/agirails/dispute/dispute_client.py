"""DisputeClient — the SINGLE facade over the AIP-14b three-tier dispute system
(PRD P2-9).

PARITY: sdk-js/src/dispute/DisputeClient.ts — every public symbol here
(``DisputeClient`` + its methods/properties, ``DisputeSubState``,
``DisputeStatus``, ``decode_dispute_sub_state``) has a TS twin with the SAME name
(camelCase there) and arity, and vice-versa. The §9 sub-state decode is anchored
to the shared cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/dispute-client-status-vectors.json``, which both the
jest and pytest suites consume byte-identically and from which both derive the
SAME sub-state string. Any change here (rename, new method, decode tweak) must be
mirrored in the twin.

It composes the five M1.5 dispute primitives behind one object so an agent
touches one surface instead of five:

==============  ===========================  =====================================
Property        Underlying client            Role (AIP-14b)
==============  ===========================  =====================================
``bond``        :class:`BondEscalationClient` Tier-1 bond game + lifecycle (§7)
``mediator``    :class:`CompositeMediator`    split-trace reads/decoders (§3.4, §6)
``evaluator``   :class:`EvaluatorClient`      Tier-0 off-chain AI handshake (§4)
``uma``         :class:`UMAHelper`            Tier-2 requester self-dispute (§8.6)
``split_indexer`` :class:`DisputeSplitIndexer` per-agent split-rate (§3.4, OQ-11)
==============  ===========================  =====================================

Each sub-client is OPTIONAL: the facade is usable with only the pieces a caller
configured. Properties raise a clear error when the corresponding piece was not
configured, rather than silently no-oping.

The facade adds exactly ONE piece of net-new logic over the primitives:
:meth:`get_dispute_status`, which reads the on-chain dispute and decodes the §9
sub-state (UNINITIALIZED / OPENED / PROPOSED / ESCALATED / RESOLVED) — the single
decode that both SDKs MUST agree on byte-for-byte. Everything else is pure
delegation.

Relationship to the legacy kernel dispute path
----------------------------------------------
``ACTPKernel.raise_dispute`` / ``resolve_dispute`` are the PRE-AIP-14 single-shot
kernel path. The tiered flow reached through THIS client is their AIP-14b
successor: ``raise_dispute`` still opens the kernel DISPUTED state, but resolution
then runs through the bond game here (open → propose/AI → challenge → finalize /
escalate_to_uma) instead of a privileged ``resolve_dispute``. The kernel
docstrings steer callers here (grep ``DisputeClient`` in ``protocol/kernel.py``).

Reference: AIP-14b §3 (architecture), §7 (BondEscalation), §9 (state machine),
PRD P2-9.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from agirails.dispute.bond_escalation import BondEscalationClient
from agirails.dispute.composite_mediator import CompositeMediator
from agirails.dispute.evaluator_client import EvaluatorClient, EvaluatorClientConfig
from agirails.dispute.uma_helper import UMAHelper
from agirails.reputation.dispute_split_indexer import (
    DisputeOutcome,
    DisputeSplitIndexer,
)
from agirails.types.dispute import Ruling, _to_bytes32  # type: ignore[attr-defined]

# PARITY: sdk-js/src/dispute/DisputeClient.ts

# =====================================================================
# §9 sub-state model
# =====================================================================

#: The AIP-14b §9 dispute sub-state, decoded from the on-chain ``disputes(...)``
#: struct. PARITY: TS ``DisputeSubState`` (string-literal values identical):
#: ``"UNINITIALIZED" | "OPENED" | "PROPOSED" | "ESCALATED" | "RESOLVED"``.
DisputeSubState = str

#: The exhaustive set of §9 sub-states (for validation / parity assertions).
DISPUTE_SUBSTATES = (
    "UNINITIALIZED",
    "OPENED",
    "PROPOSED",
    "ESCALATED",
    "RESOLVED",
)


@dataclass
class DisputeStatus:
    """Result of :meth:`DisputeClient.get_dispute_status`: the decoded
    :class:`DisputeState` PLUS the §9 sub-state and the raw ``disputed_at``
    timestamp (0 ⇒ never opened). PARITY: TS ``DisputeStatus``.

    Attributes:
        dispute_id: keccak256 dispute identifier (bytes32 hex).
        substate:   the §9 sub-state (the single cross-SDK decode).
        tier:       current escalation tier (0/1/2).
        resolved:   whether the dispute is finalized on-chain.
        ruling:     current/final ruling (0=provider, 1=requester, 2=split).
        split_bps:  provider share in bps (meaningful for ``ruling == 2``).
        disputed_at: ``disputedAt`` from the struct (0 ⇒ never opened).
        state:      the base decoded :class:`DisputeState`.
    """

    dispute_id: str
    substate: DisputeSubState
    tier: int
    resolved: bool
    ruling: int
    split_bps: int
    disputed_at: int
    state: Any


def _pick(raw: Any, idx: int, name: str) -> Any:
    """Read a field from a raw ``disputes()`` tuple by name (named result) or
    positional index (plain list/tuple). Mirrors the TS ``pick`` closure."""
    # Named-result access (web3 AttributeDict / namedtuple) — best effort.
    try:
        if isinstance(raw, dict):
            if name in raw:
                return raw[name]
        else:
            val = getattr(raw, name, None)
            if val is not None:
                return val
    except Exception:  # pragma: no cover - defensive
        pass
    return raw[idx]


def decode_dispute_sub_state(raw: Any) -> DisputeSubState:
    """Decode the AIP-14b §9 sub-state from a raw ``disputes(bytes32)`` tuple.

    Pure so the cross-SDK fixture test exercises it without a chain. The tuple
    field order is load-bearing (AIP-14b §7.3): ``[transactionId, currentRuling,
    splitBps, currentBond, accumulatedBonds, livenessEnd, disputedAt,
    lastProposer, tier, resolved, winnerPaid, originalPool, escrowAmount]``.

    Decode order is load-bearing (each branch mutually exclusive in priority):
        1. ``disputed_at == 0``  -> ``UNINITIALIZED`` (never opened — FIRST).
        2. ``resolved is True``  -> ``RESOLVED`` (dominates tier).
        3. ``tier == 2``         -> ``ESCALATED``.
        4. ``tier == 1``         -> ``PROPOSED`` (challenge keeps tier==1, so no
           separate CHALLENGED).
        5. else (``tier == 0``)  -> ``OPENED``.

    PARITY: TS ``decodeDisputeSubState`` — identical branch order + outputs
    (anchored to ``dispute-client-status-vectors.json``).
    """
    disputed_at = int(_pick(raw, 6, "disputedAt"))
    tier = int(_pick(raw, 8, "tier"))
    resolved = bool(_pick(raw, 9, "resolved"))

    if disputed_at == 0:
        return "UNINITIALIZED"
    if resolved:
        return "RESOLVED"
    if tier == 2:
        return "ESCALATED"
    if tier == 1:
        return "PROPOSED"
    return "OPENED"


# =====================================================================
# Facade
# =====================================================================


class DisputeClient:
    """The one-object dispute facade (PRD P2-9). See the module docstring for the
    table of sub-clients. Wired onto :class:`ACTPClient` as ``client.dispute`` iff
    the dispute contract addresses are configured for the network.

    Two construction styles:
      - Pass already-built sub-clients (``bond`` / ``mediator`` / ``uma`` /
        ``evaluator`` / ``split_indexer``) — the unit-test / DI path.
      - Use :meth:`from_config` to build the on-chain clients from
        ``(w3, account, config)`` (the ACTPClient wiring path).

    PARITY: TS ``DisputeClient``.
    """

    def __init__(
        self,
        *,
        bond: Optional[BondEscalationClient] = None,
        mediator: Optional[CompositeMediator] = None,
        uma: Optional[UMAHelper] = None,
        evaluator: Optional[EvaluatorClient] = None,
        evaluator_config: Optional[EvaluatorClientConfig] = None,
        split_indexer: Optional[DisputeSplitIndexer] = None,
    ) -> None:
        self._bond = bond
        self._mediator = mediator
        self._uma = uma
        if evaluator is not None:
            self._evaluator: Optional[EvaluatorClient] = evaluator
        elif evaluator_config is not None:
            self._evaluator = EvaluatorClient(evaluator_config)
        else:
            self._evaluator = None
        # The split indexer is ALWAYS present (pure accumulator).
        self._split_indexer = split_indexer or DisputeSplitIndexer()

    # ------------------------------------------------------------------
    # Factory (parity with the per-primitive from_config classmethods)
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        w3: Any,
        account: Any,
        config: Any,
        *,
        confirmations: int = 2,
    ) -> "DisputeClient":
        """Build a facade from a network config, wiring whichever on-chain
        clients have a configured address. Mirrors the TS facade's address-path
        constructor + the per-primitive ``from_config`` classmethods. Pieces with
        a ``None`` address are left unconfigured (their property raises on use).

        PARITY: TS ``new DisputeClient({signer, ...addresses})`` in
        ``ACTPClient.create`` — present iff the dispute addresses are configured.
        """
        contracts = config.contracts
        bond = None
        mediator = None
        uma = None

        if getattr(contracts, "bond_escalation", None):
            bond = BondEscalationClient.from_config(
                w3, account, config, confirmations=confirmations
            )
        if getattr(contracts, "composite_mediator", None):
            mediator = CompositeMediator.from_config(w3, config)
        # UMA helper needs all three addresses; from_config raises otherwise.
        if (
            getattr(contracts, "bond_escalation", None)
            and getattr(contracts, "uma_optimistic_oracle_v3", None)
            and getattr(contracts, "usdc", None)
        ):
            try:
                uma = UMAHelper.from_config(
                    w3, account, config, confirmations=confirmations
                )
            except Exception:
                uma = None

        return cls(bond=bond, mediator=mediator, uma=uma)

    # ------------------------------------------------------------------
    # Sub-client properties (raise a clear error when not configured)
    # ------------------------------------------------------------------

    @property
    def bond(self) -> BondEscalationClient:
        """The Tier-1 :class:`BondEscalationClient`. Raises if not configured."""
        if self._bond is None:
            raise RuntimeError(
                "DisputeClient.bond is not configured (no BondEscalation "
                "address/account/contract). The dispute contracts are not "
                "deployed on this network yet, or you constructed the facade "
                "without a BondEscalation piece."
            )
        return self._bond

    @property
    def mediator(self) -> CompositeMediator:
        """The :class:`CompositeMediator` split-trace read client. Raises if not
        configured."""
        if self._mediator is None:
            raise RuntimeError(
                "DisputeClient.mediator is not configured (no CompositeMediator "
                "address/provider)."
            )
        return self._mediator

    @property
    def uma(self) -> UMAHelper:
        """The Tier-2 :class:`UMAHelper`. Raises if not configured."""
        if self._uma is None:
            raise RuntimeError(
                "DisputeClient.uma is not configured (needs BondEscalation + UMA "
                "OOV3 + USDC addresses + account)."
            )
        return self._uma

    @property
    def evaluator(self) -> EvaluatorClient:
        """The Tier-0 off-chain :class:`EvaluatorClient`. Raises if not
        configured."""
        if self._evaluator is None:
            raise RuntimeError(
                "DisputeClient.evaluator is not configured (pass evaluator or "
                "evaluator_config with a base_url + payment_client)."
            )
        return self._evaluator

    @property
    def split_indexer(self) -> DisputeSplitIndexer:
        """The :class:`DisputeSplitIndexer` — always present (pure accumulator)."""
        return self._split_indexer

    def has_bond(self) -> bool:
        """True when the Tier-1 bond client is configured. PARITY: TS ``hasBond``."""
        return self._bond is not None

    def has_mediator(self) -> bool:
        """True when the mediator read client is configured. PARITY: TS
        ``hasMediator``."""
        return self._mediator is not None

    def has_uma(self) -> bool:
        """True when the UMA helper is configured. PARITY: TS ``hasUMA``."""
        return self._uma is not None

    def has_evaluator(self) -> bool:
        """True when the off-chain evaluator client is configured. PARITY: TS
        ``hasEvaluator``."""
        return self._evaluator is not None

    # ------------------------------------------------------------------
    # The one net-new facade method: §9 sub-state
    # ------------------------------------------------------------------

    async def get_dispute_status(self, dispute_id: str) -> DisputeStatus:
        """Read a dispute's on-chain state and decode its AIP-14b §9 sub-state.

        Reads the public ``disputes(bytes32)`` getter via the configured
        :class:`BondEscalationClient`, then derives the sub-state with the pure
        :func:`decode_dispute_sub_state` (anchored to the cross-SDK golden
        fixture). The returned :class:`DisputeStatus` also carries the base
        :class:`DisputeState` and the raw ``disputed_at``. PARITY: TS
        ``getDisputeStatus``.

        Args:
            dispute_id: keccak256 dispute identifier (bytes32 hex).

        Raises:
            RuntimeError: if the bond client is not configured (dispute stack not
                deployed).
        """
        bond = self.bond  # raises with the clear message if unconfigured
        raw = await bond.get_contract().functions.disputes(
            _to_bytes32(dispute_id)
        ).call()
        state = BondEscalationClient.decode_dispute_state(dispute_id, raw)
        substate = decode_dispute_sub_state(raw)
        disputed_at = int(_pick(raw, 6, "disputedAt"))
        return DisputeStatus(
            dispute_id=dispute_id,
            substate=substate,
            tier=state.tier,
            resolved=state.resolved,
            ruling=state.ruling if state.ruling is not None else int(Ruling.PROVIDER_WINS),
            split_bps=state.split_bps if state.split_bps is not None else 0,
            disputed_at=disputed_at,
            state=state,
        )

    def record_outcomes(self, outcomes: List[DisputeOutcome]) -> None:
        """Feed already-decoded :class:`DisputeOutcome` records to the split
        indexer. Pure delegation to :meth:`DisputeSplitIndexer.add_outcomes`.
        PARITY: TS ``recordOutcomes``.
        """
        self._split_indexer.add_outcomes(outcomes)
