"""Requester-side ACTP lifecycle integration test against live base-sepolia.

Walks the requester-controllable leg of the state machine:

    INITIATED → COMMITTED

Step D (test_eoa_runtime_lifecycle) covered the create+read leg only.
This file extends coverage to linkEscrow against the live V4 sepolia
kernel — proving the requester-side surface (create + linkEscrow)
works as documented.

Why not the full INITIATED → SETTLED walk: the kernel enforces
``requester != provider`` (``Self-transaction not allowed`` revert)
so we can't use a single-signer trick to drive the provider-only
transitions (IN_PROGRESS, DELIVERED). The full walk needs two
coordinated signers — kept as a follow-up test.

Cost per run: 2 sepolia transactions (createTransaction + linkEscrow).
~0.0004 ETH.

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
async def test_requester_side_lifecycle_eoa(sepolia_signer, sepolia_w3):
    """Walk INITIATED → COMMITTED end-to-end against live sepolia,
    asserting each transition lands on chain with the expected state.

    Provider-only transitions (IN_PROGRESS, DELIVERED) are out of
    scope — kernel rejects ``requester == provider`` so the
    single-signer trick no longer works.
    """
    from agirails.runtime.base import CreateTransactionParams
    from agirails.runtime.blockchain_runtime import BlockchainRuntime
    from agirails.runtime.types import State
    from eth_hash.auto import keccak
    from web3 import Web3

    # ── Sepolia ETH balance gate ─────────────────────────────────────────
    # This test sends 2 on-chain txs (createTransaction + linkEscrow);
    # if the deployer EOA is below the rough cost floor, skip with a
    # refill hint instead of crashing mid-flight on -32003 insufficient
    # funds. Threshold = ~3x a single-tx ceiling at 0.05 gwei × 200k gas.
    MIN_ETH_WEI = 30_000_000_000_000  # 0.00003 ETH (~3 tx headroom)
    eth_bal = sepolia_w3.eth.get_balance(sepolia_signer.address)
    if eth_bal < MIN_ETH_WEI:
        pytest.skip(
            f"Deployer {sepolia_signer.address} has {eth_bal} wei "
            f"(< {MIN_ETH_WEI} wei needed). Refill with sepolia ETH "
            f"from https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet "
            f"or another base-sepolia faucet."
        )

    rt = await BlockchainRuntime.create(
        private_key=sepolia_signer.key.hex(),
        network="base-sepolia",
        rpc_url=SEPOLIA_RPC,
    )

    # Mint enough USDC to fund the escrow leg.
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

    # Dummy provider address — never holds funds and never signs.
    # Kernel only checks `requester != provider`, not that the
    # provider exists on chain.
    dummy_provider = "0x" + "5" * 40

    # ── 1. INITIATED ──────────────────────────────────────────────────────
    tx_id = await rt.create_transaction(
        CreateTransactionParams(
            requester=sepolia_signer.address,
            provider=dummy_provider,
            amount="50000",  # 0.05 USDC
            deadline=int(time.time()) + 3600,
            dispute_window=3600,
            service_description=service_hash,
        )
    )
    tx_after_create = await rt.get_transaction(tx_id)
    assert tx_after_create is not None
    assert tx_after_create.state == State.INITIATED

    # ── 2. INITIATED → COMMITTED (linkEscrow) ─────────────────────────────
    # linkEscrow's _sign_and_send returns once the receipt confirms, so
    # the on-chain tx did land. Public sepolia RPCs are load-balanced
    # across replicas though, and the post-link read may hit a node
    # that hasn't yet seen the new state. Poll with a 30s budget.
    await rt.link_escrow(tx_id, "50000")
    tx_after_link = await rt.get_transaction(tx_id)
    deadline = time.time() + 30
    while tx_after_link.state != State.COMMITTED and time.time() < deadline:
        await asyncio.sleep(2)
        tx_after_link = await rt.get_transaction(tx_id)
    assert tx_after_link.state == State.COMMITTED, (
        f"After linkEscrow expected COMMITTED, got {tx_after_link.state} "
        f"(polled for 30s — replica lag or actual revert)"
    )

    # V3 invariant: locked-bps fields populated at create time and
    # preserved through the escrow link.
    assert int(tx_after_link.platform_fee_bps_locked) > 0
    assert int(tx_after_link.requester_penalty_bps_locked) > 0
    assert int(tx_after_link.dispute_bond_bps_locked) > 0
