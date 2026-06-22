# PARITY: sdk-js/src/dispute/UMAHelper.ts
# This file and its TypeScript twin MUST stay 1:1 — every public method/constant
# here has a TS twin with the SAME name (camelCase) and arity, and vice-versa.
# ``quote_self_dispute_cost`` and the ``requester_force_dvm`` call sequence are
# anchored to the shared cross-SDK fixture
# ``DISPUTE SYSTEM/test-vectors/uma-self-dispute-vectors.json``, which both the
# pytest and jest suites consume byte-identically. Any change here (rename, new
# method, amount tweak, or reordering the call sequence) must be mirrored in the
# twin.
"""
UMAHelper — the requester-side "self-dispute to DVM" helper (AIP-14b §8.6).

§8.6 ASYMMETRY WARNING (normative)
----------------------------------
Tier-2 escalation is provider-directional by construction: the ONLY assertion
shape ``escalate_to_uma()`` can post is "Provider delivered" (= ruling 0).
``escalate_to_uma()`` is therefore economically rational only for the PROVIDER
side. A requester whose ruling-1 proposal stands unchallenged at the $500
ceiling simply holds position and WINS for free via ``finalize()`` once liveness
expires — they should normally do nothing. This helper exists ONLY for the
residual case: a requester who wants DVM FINALITY now rather than continued
ceiling ping-pong (every ceiling challenge resets liveness). It is deliberately
EXPENSIVE and asymmetric — it does NOT make the requester side cheaper, it bounds
the worst-case dispute DURATION. Do not reach for it as a default; reach for
``finalize()``.

The self-dispute path (§8.6): the requester posts BOTH sides of a UMA assertion
to force the Data Verification Mechanism to vote::

    1. escalate_to_uma(dispute_id, evidence_cid) — posts the $500 ASSERTER bond
       ("Provider delivered"). The requester is the asserter here.
    2. read assertion_id from BondEscalation.disputeToAssertion(dispute_id).
    3. OOV3.disputeAssertion(assertion_id, disputer) — posts a SECOND $500
       DISPUTER bond against their own assertion, forcing DVM review.

If the DVM rules FALSE ("provider did NOT deliver" → ruling 1), the requester as
DISPUTER recovers $750 of the $1,000 posted (§8.2 CASE C / §8.3) and ruling 1
executes locally via the callback. Net cost: $250 (the UMA Store fee = 50% of the
losing asserter bond). See :meth:`UMAHelper.quote_self_dispute_cost`.

SETTLEMENT WARNING (normative, §8.6 + Appendix B.4)
---------------------------------------------------
UMA settlement is EXTERNAL. After the DVM resolves you (or anyone) MUST call
``OOV3.settleAssertion(assertion_id)`` yourself to trigger bond distribution and
the ``assertionResolvedCallback``. If NO ONE calls it, the dispute does not
resolve through UMA at all — and once 30 days elapse from ``disputedAt``,
``BondEscalation.forceResolveStale()`` force-resolves it to a 30-DAY FORCED 50/50
SPLIT, which throws away the favorable DVM outcome you paid $250 for. Call
settleAssertion yourself or risk a 30-day forced 50/50 split.

This helper does NOT itself call ``settle_assertion`` (it cannot know when the
DVM has resolved); it exposes :meth:`UMAHelper.settle_assertion` so the caller
can settle once the DVM result is available, and :meth:`UMAHelper.get_assertion_id`
to look the assertion up.

Reference: AIP-14b §8.2 (UMA lifecycle), §8.3 (bond accounting), §8.4
(escalate_to_uma), §8.6 (escalation directionality / self-dispute path).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# Constants (AIP-14b §7.4 / §8) — load-bearing, mirror BondEscalation.sol + TS
# ---------------------------------------------------------------------------

#: UMA Tier-2 stake: $500 USDC (6 decimals). One bond per side. AIP-14b §7.4.
UMA_BOND: int = 500_000_000

#: Total USDC a requester must post to force the DVM (§8.6): the $500 asserter
#: bond (via ``escalate_to_uma``) PLUS the $500 disputer bond (via
#: ``dispute_assertion``). = $1,000.
SELF_DISPUTE_TOTAL: int = UMA_BOND * 2

#: Amount the requester recovers if the DVM rules FALSE (§8.2 CASE C / §8.3):
#: $500 (own disputer bond returned) + $250 (half the losing asserter bond) =
#: $750.
SELF_DISPUTE_RECOVER: int = UMA_BOND + UMA_BOND // 2

#: Net cost of a successful self-dispute (§8.6): the UMA Store fee, = 50% of the
#: losing asserter bond = $250. ``SELF_DISPUTE_TOTAL - SELF_DISPUTE_RECOVER``.
SELF_DISPUTE_LOSS: int = SELF_DISPUTE_TOTAL - SELF_DISPUTE_RECOVER


def _load_abi(filename: str) -> List[Dict[str, Any]]:
    """Load an ABI from the abis directory."""
    abi_path = Path(__file__).parent.parent / "abis" / filename
    with open(abi_path) as f:
        return json.load(f)


def _to_bytes32(value: Union[str, bytes]) -> bytes:
    """Normalize a bytes32 input (0x-hex string or raw bytes) to 32 bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        s = value[2:] if value.startswith(("0x", "0X")) else value
        raw = bytes.fromhex(s)
    if len(raw) != 32:
        raw = raw.rjust(32, b"\x00")
    return raw


def _hex32(value: Union[str, bytes]) -> str:
    """Normalize a bytes32 to a 0x-prefixed lowercase hex string."""
    return "0x" + _to_bytes32(value).hex()


class SelfDisputeCost(Dict[str, int]):
    """
    Result of a self-dispute cost quote (USDC base units, 6 decimals).

    A ``dict``-shaped value with keys ``total`` / ``recover`` / ``lose`` so it is
    1:1 with the TS ``SelfDisputeCost`` object (``cost["total"]`` ⇄
    ``cost.total``) AND attribute-accessible (``cost.total``) for ergonomics.
    """

    @property
    def total(self) -> int:
        return self["total"]

    @property
    def recover(self) -> int:
        return self["recover"]

    @property
    def lose(self) -> int:
        return self["lose"]


class UMAHelper:
    """
    Typed helper for the requester-side self-dispute-to-DVM path (AIP-14b §8.6).

    Two construction paths (mirrors :class:`BondEscalationClient`):

    - Production: pass the three contracts + ``account`` + ``w3`` — write methods
      build calldata, sign, and broadcast.
    - Testing: pass injected contracts whose functions record their args; the
      helper builds calldata via ``encode_abi`` so tests can assert the exact
      selector + args (the same assertion surface as the TS twin).

    PARITY: UMAHelper.ts ``UMAHelper``.
    """

    def __init__(
        self,
        bond_escalation: Any,
        oov3: Any,
        usdc: Any,
        *,
        account: Any = None,
        w3: Any = None,
        bond_escalation_address: Optional[str] = None,
        oov3_address: Optional[str] = None,
        usdc_address: Optional[str] = None,
        confirmations: int = 2,
    ) -> None:
        if confirmations < 1:
            raise ValueError(f"confirmations must be >= 1, got {confirmations}")
        self._bond_escalation = bond_escalation
        self._oov3 = oov3
        self._usdc = usdc
        self._account = account
        self._w3 = w3
        self._confirmations = confirmations
        self._bond_escalation_address = bond_escalation_address or getattr(
            bond_escalation, "address", None
        )
        self._oov3_address = oov3_address or getattr(oov3, "address", None)
        self._usdc_address = usdc_address or getattr(usdc, "address", None)

    @classmethod
    def from_config(
        cls,
        w3: Any,
        account: Any,
        config: Any,
        *,
        confirmations: int = 2,
    ) -> "UMAHelper":
        """
        Build a helper from a network config (the three dispute-contract
        addresses). PARITY: ``BondEscalationClient.from_config``. The
        dispute-contract addresses are ``None`` until Phase-6 deployment, in
        which case this raises — callers on undeployed networks must inject
        contracts directly.
        """
        be_addr = getattr(config.contracts, "bond_escalation", None)
        oov3_addr = getattr(config.contracts, "uma_oov3", None) or getattr(
            config.contracts, "oov3", None
        )
        usdc_addr = getattr(config.contracts, "usdc", None)
        missing = [
            n
            for n, v in (
                ("bond_escalation", be_addr),
                ("uma_oov3", oov3_addr),
                ("usdc", usdc_addr),
            )
            if not v
        ]
        if missing:
            raise ValueError(
                "UMAHelper is not deployable on this network "
                f"(missing config.contracts: {', '.join(missing)})"
            )
        bond_escalation = w3.eth.contract(
            address=w3.to_checksum_address(be_addr),
            abi=_load_abi("bond_escalation.json"),
        )
        oov3 = w3.eth.contract(
            address=w3.to_checksum_address(oov3_addr),
            abi=_load_abi("i_optimistic_oracle_v3.json"),
        )
        usdc = w3.eth.contract(
            address=w3.to_checksum_address(usdc_addr),
            abi=_load_abi("usdc.json"),
        )
        return cls(
            bond_escalation,
            oov3,
            usdc,
            account=account,
            w3=w3,
            bond_escalation_address=be_addr,
            oov3_address=oov3_addr,
            usdc_address=usdc_addr,
            confirmations=confirmations,
        )

    # ------------------------------------------------------------------
    # Accessors (parity with the TS getBondEscalationAddress / getOOV3Address)
    # ------------------------------------------------------------------

    def get_bond_escalation_address(self) -> Optional[str]:
        """BondEscalation contract address."""
        return self._bond_escalation_address

    def get_oov3_address(self) -> Optional[str]:
        """UMA OOV3 contract address."""
        return self._oov3_address

    # ------------------------------------------------------------------
    # Pure quote (AIP-14b §8.6 / §8.2 CASE C / §8.3) — no chain access
    # ------------------------------------------------------------------

    @staticmethod
    def quote_self_dispute_cost() -> SelfDisputeCost:
        """
        Quote the cost of the requester self-dispute path (§8.6).

        The requester posts $500 (asserter bond via ``escalate_to_uma``) + $500
        (disputer bond via ``dispute_assertion``) = **$1,000 total**. If the DVM
        rules FALSE (provider did NOT deliver), they recover **$750** ($500 own
        disputer bond + $250 = half the losing asserter bond, §8.2 CASE C / §8.3)
        and **lose $250** (the UMA Store fee = 50% of the losing asserter bond).

        PARITY: TS ``quoteSelfDisputeCost``.

        Returns:
            ``{"total": $1000, "recover": $750, "lose": $250}`` in USDC base
            units (also attribute-accessible: ``cost.total``).
        """
        return SelfDisputeCost(
            total=SELF_DISPUTE_TOTAL,  # $1,000
            recover=SELF_DISPUTE_RECOVER,  # $750
            lose=SELF_DISPUTE_LOSS,  # $250
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_assertion_id(self, dispute_id: str) -> str:
        """
        Look up the UMA assertion id for a dispute via
        ``BondEscalation.disputeToAssertion(dispute_id)``. Returns ``bytes32(0)``
        if the dispute has not been escalated to UMA yet. PARITY: TS
        ``getAssertionId``.
        """
        raw = await self._bond_escalation.functions.disputeToAssertion(
            _to_bytes32(dispute_id)
        ).call()
        return _hex32(raw) if isinstance(raw, (bytes, bytearray)) else raw

    # ------------------------------------------------------------------
    # The §8.6 self-dispute flow
    # ------------------------------------------------------------------

    async def requester_force_dvm(
        self, dispute_id: str, evidence_cid: str, disputer: str
    ) -> Dict[str, str]:
        """
        Force the dispute to the UMA DVM by self-disputing (AIP-14b §8.6).

        Issues EXACTLY this call sequence, in order (a call-sequence test pins
        it):

            1. ``USDC.approve(bond_escalation, $500)`` — so ``escalate_to_uma``
               can pull the asserter bond.
            2. ``BondEscalation.escalateToUMA(dispute_id, evidence_cid)`` — posts
               the $500 asserter bond ("Provider delivered").
            3. read ``assertion_id`` ←
               ``BondEscalation.disputeToAssertion(dispute_id)``.
            4. ``USDC.approve(oov3, $500)`` — so ``disputeAssertion`` can pull the
               disputer bond directly to OOV3.
            5. ``OOV3.disputeAssertion(assertion_id, disputer)`` — posts the
               SECOND $500 bond against the requester's own assertion, forcing
               DVM review.

        This does NOT settle the assertion. After the DVM resolves you MUST call
        :meth:`settle_assertion` yourself or risk a 30-day forced 50/50 split
        (see the module docstring). See :meth:`quote_self_dispute_cost` for the
        $1000/$750/$250 economics, and the §8.6 asymmetry warning for why this is
        provider-directional and expensive. PARITY: TS ``requesterForceDVM``.

        Args:
            dispute_id: bytes32 dispute id (already at the Tier-1 $500 ceiling,
                liveness active — ``escalate_to_uma``'s preconditions).
            evidence_cid: IPFS CID of the canonical evidence bundle (§8.4).
            disputer: Address that disputes the assertion (the requester themself;
                receives the $750 if the DVM rules FALSE).

        Returns:
            ``{"assertion_id", "escalate_tx_hash", "dispute_tx_hash"}``.
        """
        # 1. approve BondEscalation for the $500 asserter bond.
        await self._send(self._usdc, "approve", [self._bond_escalation_address, UMA_BOND])

        # 2. escalateToUMA posts the asserter bond ("Provider delivered").
        escalate = await self._send(
            self._bond_escalation,
            "escalateToUMA",
            [_to_bytes32(dispute_id), evidence_cid],
        )

        # 3. read the assertionId the escalation registered.
        raw_assertion = await self._bond_escalation.functions.disputeToAssertion(
            _to_bytes32(dispute_id)
        ).call()
        assertion_id = (
            _hex32(raw_assertion)
            if isinstance(raw_assertion, (bytes, bytearray))
            else raw_assertion
        )

        # 4. approve OOV3 for the $500 disputer bond.
        await self._send(self._usdc, "approve", [self._oov3_address, UMA_BOND])

        # 5. dispute the requester's own assertion, forcing DVM review.
        dispute = await self._send(
            self._oov3, "disputeAssertion", [_to_bytes32(assertion_id), disputer]
        )

        return {
            "assertion_id": assertion_id,
            "escalate_tx_hash": escalate,
            "dispute_tx_hash": dispute,
        }

    async def settle_assertion(self, assertion_id: str) -> Dict[str, str]:
        """
        Settle a resolved UMA assertion, triggering bond distribution and the
        ``assertionResolvedCallback`` (AIP-14b §8.2 STAGE 3, Appendix B.4).

        Callable by anyone once the DVM has resolved (or liveness expired). You
        SHOULD call this yourself after winning the DVM — if no one settles and
        30 days elapse, ``force_resolve_stale()`` overrides the DVM outcome with a
        forced 50/50 split (see the module settlement warning). PARITY: TS
        ``settleAssertion``.

        Args:
            assertion_id: bytes32 UMA assertion id (from :meth:`get_assertion_id`
                or :meth:`requester_force_dvm`).
        """
        receipt = await self._send(
            self._oov3, "settleAssertion", [_to_bytes32(assertion_id)]
        )
        return {"eth_tx_hash": receipt}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def encode_calldata(self, contract: Any, method: str, args: List[Any]) -> str:
        """
        Build the 0x-hex calldata for ``method`` via ``encode_abi``. The assertion
        surface the tests use (parity with the TS twin's
        ``interface.encodeFunctionData``).
        """
        return contract.encode_abi(abi_element_identifier=method, args=args)

    async def _send(self, contract: Any, method: str, args: List[Any]) -> str:
        """
        Build calldata (validating the selector + args), then invoke the contract
        function. Returns the tx-hash string.

        Test mocks supply contracts whose ``functions.<method>(...)`` record args
        and return an awaitable; production wires through the web3 build / sign /
        send path. Either way, calldata is built first so a malformed call raises
        before broadcast. PARITY: ``BondEscalationClient._send``.
        """
        # Build + validate calldata first (assertion surface in tests).
        self.encode_calldata(contract, method, args)

        fn = getattr(contract.functions, method)(*args)

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
            return (
                "0x" + tx_hash.hex()
                if isinstance(tx_hash, (bytes, bytearray))
                else str(tx_hash)
            )

        # Test path: the mock fn exposes an awaitable returning a tx hash/receipt.
        send = getattr(fn, "transact", None)
        if send is not None:
            tx_hash = await send()
        else:
            tx_hash = await fn  # fn itself is awaitable in mocks
        if isinstance(tx_hash, (bytes, bytearray)):
            return "0x" + tx_hash.hex()
        return str(tx_hash)


__all__ = [
    # Constants
    "UMA_BOND",
    "SELF_DISPUTE_TOTAL",
    "SELF_DISPUTE_RECOVER",
    "SELF_DISPUTE_LOSS",
    # Types
    "SelfDisputeCost",
    # Helper
    "UMAHelper",
]
