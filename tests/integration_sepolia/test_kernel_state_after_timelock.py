"""Live-sepolia READ tests — proves the post-timelock kernel state
matches what we believe.

These don't write to chain; they verify:
  - RPC connectivity
  - kernel.agentRegistry() now points to the V4 registry (the
    permissionless executeAgentRegistryUpdate on 2026-05-23 succeeded)
  - kernel parameters (MIN_FEE, platformFeeBps) match the V3+ wire
    contract documented in CHANGELOG

Free to run (no gas, no signer needed); marker-gated only because
they hit live RPC.
"""

from __future__ import annotations

import pytest

from tests.integration_sepolia.conftest import (
    SEPOLIA_REGISTRY_EXPECTED,
)

pytestmark = pytest.mark.integration_sepolia


def test_chain_id_is_base_sepolia(sepolia_w3):
    assert sepolia_w3.eth.chain_id == 84532


def test_agent_registry_post_unlock(kernel_contract):
    """The timelock-gated update on 2026-05-21 → executed 2026-05-23
    flipped agentRegistry from 0x0 to the V4 registry contract. Without
    this, kernel reputation tracking is offline (kernel guards with
    `if (address(agentRegistry) != address(0))`)."""
    current = kernel_contract.functions.agentRegistry().call()
    assert (
        current.lower() == SEPOLIA_REGISTRY_EXPECTED.lower()
    ), (
        f"agentRegistry is {current}; expected {SEPOLIA_REGISTRY_EXPECTED}. "
        f"If this is 0x0, the timelock execute didn't land."
    )


def test_kernel_min_fee_enforced_on_chain(kernel_contract):
    """V3 protocol invariant: MIN_FEE is on-chain ($0.05 USDC =
    50_000 wei). Pre-V3 it was SDK-only."""
    min_fee = kernel_contract.functions.MIN_FEE().call()
    assert min_fee == 50_000, f"MIN_FEE on-chain = {min_fee}, expected 50_000"


def test_platform_fee_bps_within_audit_cap(kernel_contract):
    """Invariant 3 from CLAUDE.md — platformFeeBps ≤ 500 (5% cap)."""
    bps = kernel_contract.functions.platformFeeBps().call()
    assert bps <= 500, f"platformFeeBps = {bps}, exceeds 5% audit cap"
