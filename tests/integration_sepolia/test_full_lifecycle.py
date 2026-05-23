"""Full ACTP lifecycle integration test against live base-sepolia.

Walks the canonical state machine end-to-end on a SINGLE transaction:

    INITIATED → COMMITTED → IN_PROGRESS → DELIVERED → SETTLED

Step D (test_eoa_runtime_lifecycle) covered the create+read leg only.
This file proves the rest of the kernel surface (linkEscrow,
transitionState, releaseEscrow) actually works as documented against
the live V4 sepolia kernel.

Strategy: the same EOA acts as both `requester` and `provider`. Kernel
allows this; transitions IN_PROGRESS / DELIVERED are gated by
provider-only checks, SETTLED by requester-only. With both roles
held by the same address, all guards pass without needing two
coordinated signers.

Cost per full run: 4 sepolia transactions (linkEscrow + IN_PROGRESS
transition + DELIVERED transition + SETTLED release). ~0.0008 ETH.

This is the highest-signal write test in the suite: if any single
on-chain guard regresses (state machine, _requesterCheck,
_providerCheck, dispute-window early-release), the lifecycle stops
mid-flight and we know exactly where.

Marker-gated `-m integration_sepolia`; default skip.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from tests.integration_sepolia.conftest import (
    SEPOLIA_KERNEL,
    SEPOLIA_RPC,
    SEPOLIA_USDC,
)

pytestmark = pytest.mark.integration_sepolia


@pytest.mark.asyncio
async def test_full_lifecycle_eoa(sepolia_signer, sepolia_w3):
    """Run a full INITIATED → SETTLED state walk and assert each
    transition lands on chain with the expected state."""
    from agirails.runtime.base import CreateTransactionParams
    from agirails.runtime.blockchain_runtime import BlockchainRuntime
    from agirails.runtime.types import State
    from eth_hash.auto import keccak
    from web3 import Web3

    # ── Setup ────────────────────────────────────────────────────────────
    rt = await BlockchainRuntime.create(
        private_key=sepolia_signer.key.hex(),
        network="base-sepolia",
        rpc_url=SEPOLIA_RPC,
    )

    # Mint enough USDC to fund both the escrow + provider fee path.
    usdc_abi = [
        {
            "type": "function", "name": "balanceOf",
            "inputs": [{"type": "address"}],
            "outputs": [{"type": "uint256"}], "stateMutability": "view",
        },
        {
            "type": "function", "name": "mint",
            "inputs": [{"type": "address"}, {"type": "uint256"}],
            "outputs": [], "stateMutability": "nonpayable",
        },
    ]
    usdc = sepolia_w3.eth.contract(
        address=Web3.to_checksum_address(SEPOLIA_USDC), abi=usdc_abi
    )
    bal = usdc.functions.balanceOf(sepolia_signer.address).call()
    if bal < 100_000:  # 0.1 USDC headroom
        tx = usdc.functions.mint(
            sepolia_signer.address, 100_000_000
        ).build_transaction({
            "from": sepolia_signer.address,
            "nonce": sepolia_w3.eth.get_transaction_count(sepolia_signer.address),
            "gas": 100_000,
            "maxFeePerGas": sepolia_w3.to_wei("0.01", "gwei"),
            "maxPriorityFeePerGas": sepolia_w3.to_wei("0.001", "gwei"),
        })
        signed = sepolia_signer.sign_transaction(tx)
        tx_hash = sepolia_w3.eth.send_raw_transaction(signed.raw_transaction)
        sepolia_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

    # Distinct service description per run so re-runs are identifiable.
    nonce_hex = format(int(time.time()), "x")
    service_hash = "0x" + keccak(
        f"integration-test-lifecycle-{nonce_hex}".encode("utf-8")
    ).hex()

    # ── 1. INITIATED ──────────────────────────────────────────────────────
    tx_id = await rt.create_transaction(
        CreateTransactionParams(
            requester=sepolia_signer.address,
            provider=sepolia_signer.address,  # self-pay; both guards pass
            amount="50000",  # 0.05 USDC
            deadline=int(time.time()) + 3600,
            dispute_window=3600,  # short window so requester can settle early
            service_description=service_hash,
        )
    )
    tx_after_create = await rt.get_transaction(tx_id)
    assert tx_after_create is not None
    assert tx_after_create.state == State.INITIATED

    # ── 2. INITIATED → COMMITTED (linkEscrow) ─────────────────────────────
    escrow_id = await rt.link_escrow(tx_id, "50000")
    # escrowId equals txId in V3 (ACTP standard); kernel stores it as bytes32.
    tx_after_link = await rt.get_transaction(tx_id)
    assert tx_after_link.state == State.COMMITTED, (
        f"After linkEscrow expected COMMITTED, got {tx_after_link.state}"
    )

    # ── 3. COMMITTED → IN_PROGRESS (provider starts work) ─────────────────
    await rt.transition_state(tx_id, State.IN_PROGRESS)
    tx_after_start = await rt.get_transaction(tx_id)
    assert tx_after_start.state == State.IN_PROGRESS

    # ── 4. IN_PROGRESS → DELIVERED (provider delivers) ────────────────────
    delivery_proof = "0x" + keccak(b"delivery-proof-payload").hex()
    await rt.transition_state(tx_id, State.DELIVERED, proof=delivery_proof)
    tx_after_deliver = await rt.get_transaction(tx_id)
    assert tx_after_deliver.state == State.DELIVERED

    # ── 5. DELIVERED → SETTLED (requester early-release) ──────────────────
    # ACTPKernel allows DELIVERED → SETTLED by the requester without
    # waiting for the dispute window (kernel.sol:700-704). Since signer
    # IS the requester, this should succeed immediately.
    await rt.release_escrow(escrow_id=escrow_id, attestation_uid="")
    tx_after_settle = await rt.get_transaction(tx_id)
    assert tx_after_settle.state == State.SETTLED, (
        f"After release_escrow expected SETTLED, got {tx_after_settle.state}"
    )

    # V3 invariant: locked-bps fields populated at create time and
    # preserved through all transitions.
    assert int(tx_after_settle.platform_fee_bps_locked) > 0
    assert int(tx_after_settle.requester_penalty_bps_locked) > 0
    assert int(tx_after_settle.dispute_bond_bps_locked) > 0
