"""
E2E Smoke Tests against Base Sepolia.

Tests the Python SDK against live Sepolia contracts:
- 8-param createTransaction
- getTransaction (TransactionView)
- acceptQuote flow (INITIATED → QUOTED → acceptQuote → verify)

Requires:
    PRIVATE_KEY: Deployer private key with Sepolia ETH + MockUSDC
    BASE_SEPOLIA_RPC: RPC URL (optional, defaults to publicnode)

Run:
    PRIVATE_KEY=0x... pytest tests/integration/test_e2e_sepolia.py -v -s
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

from agirails.config.networks import get_network
from agirails.protocol.kernel import ACTPKernel, CreateTransactionParams
from agirails.types.transaction import TransactionState

# Skip all tests if no private key
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
SKIP_REASON = "PRIVATE_KEY not set — need deployer key with Sepolia ETH"

pytestmark = [
    pytest.mark.skipif(not PRIVATE_KEY, reason=SKIP_REASON),
    pytest.mark.integration,
]


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
def w3():
    from web3 import AsyncWeb3

    rpc = os.getenv("BASE_SEPOLIA_RPC", "https://base-sepolia-rpc.publicnode.com")
    return AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc))


@pytest.fixture(scope="module")
def account():
    from eth_account import Account

    return Account.from_key(PRIVATE_KEY)


@pytest.fixture(scope="module")
def config():
    return get_network("base-sepolia")


@pytest.fixture(scope="module")
def kernel(w3, account, config):
    return ACTPKernel.from_config(w3, account, config)


class TestCreateTransaction:
    """E2E: 8-param createTransaction on Sepolia."""

    @pytest.mark.asyncio
    async def test_create_transaction_8_params(self, kernel, w3, account):
        params = CreateTransactionParams(
            provider="0x000000000000000000000000000000000000dEaD",
            requester=account.address,
            amount=100000,  # $0.10
            deadline=int(time.time()) + 7200,
            dispute_window=86400,
            service_hash=w3.keccak(text=f"e2e-create-{int(time.time())}").hex(),
            agent_id=0,
            requester_agent_id=0,
        )
        tx_id = await kernel.create_transaction(params)

        assert tx_id is not None
        assert len(tx_id) == 66  # 0x + 64 hex chars
        assert tx_id.startswith("0x")

    @pytest.mark.asyncio
    async def test_get_transaction_view(self, kernel, w3, account):
        params = CreateTransactionParams(
            provider="0x000000000000000000000000000000000000dEaD",
            requester=account.address,
            amount=100000,
            deadline=int(time.time()) + 7200,
            dispute_window=86400,
            service_hash=w3.keccak(text=f"e2e-view-{int(time.time())}").hex(),
            agent_id=0,
            requester_agent_id=0,
        )
        tx_id = await kernel.create_transaction(params)

        view = await kernel.get_transaction(tx_id)
        assert view.transaction_id.lower() == tx_id.lower()
        assert view.requester.lower() == account.address.lower()
        assert view.provider.lower() == "0x000000000000000000000000000000000000dead"
        assert view.amount == 100000
        state_val = view.state.value if hasattr(view.state, "value") else view.state
        assert state_val == 0  # INITIATED


class TestAcceptQuoteFlow:
    """E2E: INITIATED → QUOTED → acceptQuote → verify amount updated."""

    @pytest.mark.asyncio
    async def test_accept_quote_updates_amount(self, kernel, w3, account, config):
        from eth_account import Account as EthAccount

        # Generate throwaway provider
        provider_acct = EthAccount.create()

        # Fund provider with gas
        nonce = await w3.eth.get_transaction_count(account.address)
        fund_tx = {
            "to": provider_acct.address,
            "value": w3.to_wei(0.00005, "ether"),
            "gas": 21000,
            "maxFeePerGas": 10_000_000,
            "maxPriorityFeePerGas": 5_000_000,
            "nonce": nonce,
            "chainId": 84532,
            "type": 2,
        }
        signed = account.sign_transaction(fund_tx)
        h = await w3.eth.send_raw_transaction(signed.raw_transaction)
        await w3.eth.wait_for_transaction_receipt(h)

        # Step 1: createTransaction
        params = CreateTransactionParams(
            provider=provider_acct.address,
            requester=account.address,
            amount=100000,
            deadline=int(time.time()) + 7200,
            dispute_window=86400,
            service_hash=w3.keccak(text=f"e2e-aq-{int(time.time())}").hex(),
            agent_id=0,
            requester_agent_id=0,
        )
        tx_id = await kernel.create_transaction(params)

        # Step 2: provider transitions to QUOTED
        provider_kernel = ACTPKernel.from_config(w3, provider_acct, config)
        await provider_kernel.transition_state(tx_id, TransactionState.QUOTED, b"")

        view_quoted = await kernel.get_transaction(tx_id)
        state_val = view_quoted.state.value if hasattr(view_quoted.state, "value") else view_quoted.state
        assert state_val == 1, f"Expected QUOTED (1), got {state_val}"

        # Step 3: acceptQuote with new amount
        await kernel.accept_quote(tx_id, 200000)

        # Verify: amount updated, state still QUOTED
        view_after = await kernel.get_transaction(tx_id)
        assert view_after.amount == 200000
        state_val = view_after.state.value if hasattr(view_after.state, "value") else view_after.state
        assert state_val == 1, f"State should stay QUOTED, got {state_val}"
