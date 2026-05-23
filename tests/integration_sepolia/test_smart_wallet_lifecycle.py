"""Live Base sepolia tests for the Smart Wallet (`wallet="auto"`) path.

This is the biggest test gap left after step D: the entire P1.2.fix2
SmartWalletRouter + StandardAdapter routing (758 LOC, the largest
single change in 3.0.0) had zero live test coverage. EOA path is
covered by ``test_eoa_runtime_lifecycle``; this file proves the AA
gasless path works end-to-end against the live sepolia kernel.

Coverage:
  - AutoWalletProvider construction: derives Smart Wallet
    counterfactual address from the EOA signer + reads
    bundler/paymaster URLs from network config
  - Smart Wallet address differs from EOA signer (proves the
    counterfactual derivation isn't a no-op)
  - pay_actp_batched: full batched UserOp (USDC.approve +
    ACTPKernel.createTransaction + linkEscrow) submitted via
    Coinbase CDP bundler with paymaster sponsorship; on-chain
    state flips to COMMITTED, msg.sender on chain is the Smart
    Wallet (proves kernel _requesterCheck passes via the AA path)

Required env:
  ACTP_KEY_PASSWORD       — same keystore password
  Optional: BASE_SEPOLIA_RPC override

Marker-gated: `-m integration_sepolia` (default skip).
Cost per run: 1-2 sepolia UserOps; gas sponsored by Coinbase
paymaster, so $0 to the signer (just MockUSDC mint to the Smart
Wallet at ~$0 since MockUSDC.mint is permissionless).
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


async def _build_provider(sepolia_signer):
    """Build AutoWalletProvider for the deployer EOA on base-sepolia.

    Async so the provider's asyncio.Lock + nonce manager bind to the
    test's running event loop (not a fixture-scoped loop that gets
    closed before the test calls into it).
    """
    from web3 import Web3
    from agirails.config.networks import get_network
    from agirails.wallet.auto_wallet_provider import (
        AutoWalletConfig,
        AutoWalletProvider,
    )

    network = get_network("base-sepolia")
    if network.aa is None:
        pytest.skip("network.aa not configured — no bundler URLs")
    bundler_primary = network.aa.bundler_urls.get("coinbase")
    paymaster_primary = network.aa.paymaster_urls.get("coinbase")
    if not bundler_primary or not paymaster_primary:
        pytest.skip(
            "Coinbase bundler/paymaster URLs missing — set CDP_API_KEY or "
            "configure network.aa.bundler_urls/paymaster_urls."
        )

    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    chain_id = w3.eth.chain_id

    cfg = AutoWalletConfig(
        private_key=sepolia_signer.key.hex(),
        w3=w3,
        chain_id=chain_id,
        actp_kernel_address=network.contracts.actp_kernel,
        bundler_primary_url=bundler_primary,
        bundler_backup_url=network.aa.bundler_urls.get("pimlico") or None,
        paymaster_primary_url=paymaster_primary,
        paymaster_backup_url=network.aa.paymaster_urls.get("pimlico") or None,
    )
    return await AutoWalletProvider.create(cfg)


# ============================================================================
# Construction + address derivation (no on-chain writes)
# ============================================================================


@pytest.mark.asyncio
async def test_auto_wallet_provider_constructs(sepolia_signer):
    """AutoWalletProvider.create() returns successfully against the
    live CDP bundler — proves all four URLs (bundler/paymaster
    primary+backup) are wired correctly.
    """
    provider = await _build_provider(sepolia_signer)
    info = provider.get_wallet_info()
    assert info is not None
    assert info.chain_id == 84532


@pytest.mark.asyncio
async def test_smart_wallet_address_differs_from_eoa(sepolia_signer):
    """The counterfactual Smart Wallet address must NOT equal the EOA
    signer address — that's the whole point of AA. If they're equal,
    factory derivation is broken or salt is wrong.
    """
    provider = await _build_provider(sepolia_signer)
    smart_wallet = provider.get_address()
    assert smart_wallet.lower() != sepolia_signer.address.lower(), (
        f"Smart Wallet {smart_wallet} = EOA {sepolia_signer.address} — "
        f"factory derivation is degenerate."
    )
    # Smart Wallet address is well-formed.
    assert smart_wallet.startswith("0x") and len(smart_wallet) == 42


# ============================================================================
# Live gasless ACTP payment (the killer test)
# ============================================================================


def _mint_usdc_to(w3, signer, recipient, amount_wei):
    """MockUSDC.mint() is permissionless — fund any address.

    Includes a retry loop on the post-mint ``balanceOf`` read because
    public Base sepolia RPCs are load-balanced across replicas — the
    same provider can serve the mint receipt from one node and a
    ``balanceOf`` call from another that hasn't yet seen the new state.
    Retry until the indexed balance matches the receipt or we time out.
    """
    from web3 import Web3

    usdc_abi = [
        {
            "type": "function",
            "name": "balanceOf",
            "inputs": [{"type": "address"}],
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "mint",
            "inputs": [{"type": "address"}, {"type": "uint256"}],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
    ]
    usdc = w3.eth.contract(
        address=Web3.to_checksum_address(SEPOLIA_USDC), abi=usdc_abi
    )
    bal = usdc.functions.balanceOf(recipient).call()
    if bal >= amount_wei:
        return bal
    tx = usdc.functions.mint(recipient, amount_wei * 5).build_transaction({
        "from": signer.address,
        "nonce": w3.eth.get_transaction_count(signer.address),
        "gas": 100_000,
        "maxFeePerGas": w3.to_wei("0.01", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("0.001", "gwei"),
    })
    signed = signer.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    assert receipt.status == 1, f"MockUSDC.mint reverted (tx={tx_hash.hex()})"

    # Read-after-write retry against load-balanced public RPC.
    deadline = time.time() + 30
    last_bal = 0
    while time.time() < deadline:
        last_bal = usdc.functions.balanceOf(recipient).call()
        if last_bal >= amount_wei:
            return last_bal
        time.sleep(2)
    return last_bal


@pytest.mark.asyncio
async def test_pay_actp_batched_against_live_kernel(sepolia_signer, sepolia_w3):
    """The biggest test in the sprint: a real UserOp from a real Smart
    Wallet, sponsored by the Coinbase paymaster, executing the 3-call
    AIP-12 batch (USDC.approve + ACTPKernel.createTransaction +
    linkEscrow) against the live sepolia kernel.

    If this passes:
      - SmartWalletRouter encoding matches what the AA layer expects
      - Coinbase paymaster sponsors AGIRAILS Smart Wallets
      - kernel ``_requesterCheck`` accepts msg.sender == Smart Wallet
      - state actually flips to COMMITTED on chain

    If this fails, the gasless path advertised in 3.0.0 doesn't work
    end-to-end and we should hold the stable publish.
    """
    from agirails.wallet.aa.transaction_batcher import ContractAddresses
    from agirails.wallet.auto_wallet_provider import BatchedPayParams

    provider = await _build_provider(sepolia_signer)
    sw_addr = provider.get_address()
    # MockUSDC needs to be at the Smart Wallet address (where approve
    # is emitted from in the batched UserOp). EOA-signer is the funder
    # for the mint, but the recipient is the Smart Wallet.
    bal = _mint_usdc_to(sepolia_w3, sepolia_signer, sw_addr, 10_000_000)  # 10 USDC
    assert bal >= 1_000_000, f"Smart Wallet USDC balance {bal} too low"

    from eth_hash.auto import keccak

    service_hash = "0x" + keccak(b"integration-test-smart-wallet").hex()
    deadline = int(time.time()) + 3600

    params = BatchedPayParams(
        provider="0x" + "5" * 40,
        requester=sw_addr,
        amount="50000",  # 0.05 USDC
        deadline=deadline,
        dispute_window=172_800,
        service_hash=service_hash,
        agent_id="0",
        contracts=ContractAddresses(
            usdc=SEPOLIA_USDC,
            actp_kernel=SEPOLIA_KERNEL,
            escrow_vault="0x7dF07327090efcA73DCBa70414aA3131Fc6d2efB",  # V4 sepolia
        ),
    )

    result = await provider.pay_actp_batched(params)
    assert result.success, (
        f"pay_actp_batched UserOp failed: hash={result.hash}. "
        "Check bundler logs + paymaster policy."
    )
    assert result.tx_id.startswith("0x") and len(result.tx_id) == 66

    # Read back via BlockchainRuntime — proves state flipped to
    # COMMITTED AND that the Smart Wallet (not the EOA) is the
    # `requester` field on the on-chain TransactionView.
    from agirails.runtime.blockchain_runtime import BlockchainRuntime

    rt = await BlockchainRuntime.create(
        private_key=sepolia_signer.key.hex(),
        network="base-sepolia",
        rpc_url=SEPOLIA_RPC,
    )
    tx = await rt.get_transaction(result.tx_id)
    assert tx is not None, "Smart Wallet UserOp confirmed but tx not readable"
    assert tx.requester.lower() == sw_addr.lower(), (
        f"on-chain requester {tx.requester} != Smart Wallet {sw_addr} — "
        f"kernel saw a different msg.sender than we expected"
    )
    state_value = tx.state.value if hasattr(tx.state, "value") else str(tx.state)
    assert state_value == "COMMITTED", (
        f"Expected COMMITTED after batched UserOp; got {state_value}"
    )
