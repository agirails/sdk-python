"""P2-2 — Dispute-contract ABI + network-config vendoring parity (Python side).

Mirror of the TS suite (sdk-js/tests/dispute-vendor-parity.test.ts). Asserts:

  1. The 3 vendored dispute ABIs (bond_escalation, composite_mediator,
     i_optimistic_oracle_v3) load from the package ``abis/`` dir and expose
     their key on-chain surface.
  2. The network config carries the 3 dispute-contract keys
     (bondEscalation, compositeMediator, umaOptimisticOracleV3) and they
     resolve to None until deployed (testnet Phase 6, mainnet later) — with
     the SAME camelCase keys the TS SDK uses (parity).
  3. The cross-SDK GOLDEN EIP-712 vector reproduces the FROZEN digest — the
     same constant the Solidity EncodingCanonical.t.sol and the TS SDK
     reproduce. The fixture file is byte-identical to the TS copy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agirails.config.networks import get_network, NETWORKS
from agirails.types.dispute import (
    AIRuling,
    DisputeEIP712Domain,
    compute_ruling_digest,
)

# Package abis dir — the SAME path the runtime loads from
# (e.g. kernel.py: Path(__file__).parent.parent / "abis").
_ABIS = Path(__file__).resolve().parents[2] / "src" / "agirails" / "abis"

# Shared cross-SDK golden fixture. Byte-identical to the copy committed under
# sdk-js/tests/fixtures/cross_sdk/dispute_golden_vector.json.
_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "cross_sdk"
    / "dispute_golden_vector.json"
)
GOLDEN = json.loads(_FIXTURE.read_text())

DISPUTE_KEYS = ["bondEscalation", "compositeMediator", "umaOptimisticOracleV3"]


def _load_abi(filename: str) -> list:
    return json.loads((_ABIS / filename).read_text())


def _fn_names(abi: list) -> set:
    return {e.get("name") for e in abi if e.get("type") == "function"}


# ---------------------------------------------------------------------------
# 1. ABIs load + expose surface
# ---------------------------------------------------------------------------


class TestDisputeAbisVendored:
    def test_bond_escalation_abi_loads_with_verifier_surface(self):
        abi = _load_abi("bond_escalation.json")
        names = _fn_names(abi)
        assert {"DOMAIN_SEPARATOR", "submitAIRuling", "openDispute", "finalize"} <= names

    def test_composite_mediator_abi_loads_with_resolve(self):
        abi = _load_abi("composite_mediator.json")
        names = _fn_names(abi)
        assert {"resolve", "kernel", "bondEscalation"} <= names

    def test_optimistic_oracle_v3_abi_loads_with_uma_surface(self):
        abi = _load_abi("i_optimistic_oracle_v3.json")
        names = _fn_names(abi)
        assert {"assertTruth", "settleAndGetAssertionResult", "getMinimumBond"} <= names

    def test_abis_byte_identical_to_ts_copies(self):
        """The 3 Python ABIs must equal the TS-vendored ABIs exactly (parity)."""
        ts_abi = Path(__file__).resolve().parents[3] / "sdk-js" / "src" / "abi"
        if not ts_abi.exists():
            pytest.skip("sdk-js sibling not checked out (CI runs each SDK alone)")
        pairs = [
            ("bond_escalation.json", "BondEscalation.json"),
            ("composite_mediator.json", "CompositeMediator.json"),
            ("i_optimistic_oracle_v3.json", "IOptimisticOracleV3.json"),
        ]
        for py_name, ts_name in pairs:
            py = json.loads((_ABIS / py_name).read_text())
            ts = json.loads((ts_abi / ts_name).read_text())
            assert py == ts, f"{py_name} != {ts_name} (ABI drift between SDKs)"


# ---------------------------------------------------------------------------
# 2. Network-config dispute keys
# ---------------------------------------------------------------------------


class TestNetworkConfigDisputeKeys:
    def test_fixture_lists_canonical_dispute_keys(self):
        assert GOLDEN["contracts"]["keys"] == DISPUTE_KEYS

    @pytest.mark.parametrize("network", ["base-sepolia", "base-mainnet"])
    def test_dispute_keys_present_and_undeployed(self, network):
        cfg = get_network(network)
        wire = cfg.to_dict()["contracts"]
        # snake_case attributes on the dataclass …
        assert cfg.contracts.bond_escalation is None
        assert cfg.contracts.composite_mediator is None
        assert cfg.contracts.uma_optimistic_oracle_v3 is None
        # … and the camelCase wire keys match the TS SDK exactly (parity).
        for key in DISPUTE_KEYS:
            assert key in wire, f"{key} missing from {network} wire config"
            assert wire[key] is None

    def test_both_networks_present(self):
        assert sorted(NETWORKS.keys()) == ["base-mainnet", "base-sepolia"]


# ---------------------------------------------------------------------------
# 3. GOLDEN EIP-712 vector (TS ↔ Py ↔ Solidity anchor)
# ---------------------------------------------------------------------------


class TestGoldenVector:
    def _ruling(self) -> AIRuling:
        r = GOLDEN["ruling"]
        return AIRuling(
            dispute_id=r["disputeId"],
            ruling=r["ruling"],
            confidence=r["confidence"],
            split_bps=r["splitBps"],
            timestamp=r["timestamp"],
            reasoning_hash=r["reasoningHash"],
            bundle_hash=r["bundleHash"],
        )

    def test_domain_separator_matches_frozen(self):
        domain = DisputeEIP712Domain(
            chain_id=GOLDEN["domain"]["chainId"],
            verifying_contract=GOLDEN["domain"]["verifyingContract"],
        )
        assert "0x" + domain.separator().hex() == GOLDEN["expected"]["domainSeparator"]

    def test_struct_hash_matches_frozen(self):
        assert "0x" + self._ruling().struct_hash().hex() == GOLDEN["expected"]["structHash"]

    def test_digest_matches_frozen(self):
        digest = compute_ruling_digest(
            self._ruling(),
            chain_id=GOLDEN["domain"]["chainId"],
            verifying_contract=GOLDEN["domain"]["verifyingContract"],
        )
        assert "0x" + digest.hex() == GOLDEN["expected"]["digest"]
