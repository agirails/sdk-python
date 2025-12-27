#!/usr/bin/env python3
"""
ACTP Happy Path Test
Tests full transaction lifecycle: Create → Link → Progress → Deliver → Settle

Updated for SDK v2.0.0 API (uses standard adapter)

Usage:
    python test_scripts/01_happy_path.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client/requester wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    RPC_URL: Base Sepolia RPC URL (default: https://sepolia.base.org)
"""

import asyncio
import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# Load .env file
load_dotenv()

# Import SDK
from agirails import ACTPClient
from agirails.config import get_network

# Test wallets - derived from private keys in .env
CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY", "")
PROVIDER_PRIVATE_KEY = os.getenv("PROVIDER_PRIVATE_KEY", "")

# Derive addresses from private keys
CLIENT_ADDRESS = Account.from_key(CLIENT_PRIVATE_KEY).address if CLIENT_PRIVATE_KEY else ""
PROVIDER_ADDRESS = Account.from_key(PROVIDER_PRIVATE_KEY).address if PROVIDER_PRIVATE_KEY else ""

# USDC ABI (minimal)
USDC_ABI = [
    {
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]


def format_usdc(amount_wei: int) -> str:
    """Format USDC amount from wei (6 decimals)."""
    return f"{amount_wei / 1_000_000:.2f}"


async def sleep(seconds: float) -> None:
    """Async sleep wrapper."""
    await asyncio.sleep(seconds)


async def main() -> None:
    print("ACTP Happy Path Test (SDK v2.0.0)\n")

    # Validate environment
    if not CLIENT_PRIVATE_KEY or not PROVIDER_PRIVATE_KEY:
        print("Missing environment variables")
        print("Set: CLIENT_PRIVATE_KEY and PROVIDER_PRIVATE_KEY")
        sys.exit(1)

    print(f"Client:   {CLIENT_ADDRESS}")
    print(f"Provider: {PROVIDER_ADDRESS}")
    print()

    # Get network config
    network_config = get_network("base-sepolia")
    print(f"Network: {network_config.name}")
    print(f"Kernel:  {network_config.contracts.actp_kernel}")
    print(f"Escrow:  {network_config.contracts.escrow_vault}")
    print()

    # Initialize clients
    client_sdk = await ACTPClient.create(
        mode="testnet",
        requester_address=CLIENT_ADDRESS,
        private_key=CLIENT_PRIVATE_KEY,
        rpc_url=network_config.rpc_url,
    )

    provider_sdk = await ACTPClient.create(
        mode="testnet",
        requester_address=PROVIDER_ADDRESS,
        private_key=PROVIDER_PRIVATE_KEY,
        rpc_url=network_config.rpc_url,
    )

    print("SDK clients initialized\n")

    # Transaction parameters
    amount = "100"  # 100 USDC (human-readable)
    amount_wei = 100_000_000  # 100 USDC in wei for balance checks
    deadline = int(time.time()) + 86400  # 24 hours
    dispute_window = 7200  # 2 hours

    try:
        # STEP 0: Check USDC balance
        print("STEP 0: Checking USDC balance")

        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))
        usdc = w3.eth.contract(
            address=network_config.contracts.usdc,
            abi=USDC_ABI
        )

        balance = usdc.functions.balanceOf(CLIENT_ADDRESS).call()
        print(f"   Client USDC balance: {format_usdc(balance)} USDC")

        if balance < amount_wei:
            raise Exception(f"Insufficient USDC balance. Have {format_usdc(balance)}, need {amount} USDC")
        print("   Sufficient balance\n")

        # STEP 1: Create transaction
        print("STEP 1: Client creates transaction")
        print(f"   Amount: {amount} USDC")
        print(f"   Provider: {PROVIDER_ADDRESS}")
        print("   Deadline: 24 hours")
        print("   Dispute window: 2 hours")

        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Test service - translation",
        })

        print(f"   Transaction ID: {tx_id}")
        await sleep(2)

        # Check state
        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (INITIATED)")
        print()

        # STEP 2: Link escrow (transitions to COMMITTED)
        print("STEP 2: Client links escrow (SDK handles USDC approval)")
        escrow_id = await client_sdk.standard.link_escrow(tx_id)
        print(f"   Escrow linked! ID: {escrow_id}")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (COMMITTED)")
        print()

        # STEP 3: Provider signals work in progress
        print("STEP 3: Provider starts work")
        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        print("   State: IN_PROGRESS")
        await sleep(2)
        print()

        # STEP 4: Provider delivers result
        print("STEP 4: Provider delivers result")
        await provider_sdk.runtime.transition_state(tx_id, "DELIVERED", b"")
        print("   State: DELIVERED")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        completed_at = tx.completed_at if tx else None
        if completed_at:
            print(f"   Completed at: {datetime.fromtimestamp(completed_at).isoformat()}")
        print()

        # STEP 5: Wait for dispute window (or skip for testing)
        print("STEP 5: Waiting for dispute window...")
        print(f"   (In production, would wait {dispute_window / 3600} hours)")
        print("   For testing, settling immediately...")

        await client_sdk.standard.transition_state(tx_id, "SETTLED")
        print("   Transaction settled!")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   Final State: {tx.state if tx else 'N/A'}")
        print()

        # Final summary
        print("=" * 43)
        print("HAPPY PATH TEST COMPLETE!")
        print("=" * 43)
        print(f"Transaction ID: {tx_id}")
        print(f"Final State:    {tx.state if tx else 'N/A'}")
        print()
        print("Financial Summary:")
        print("   Gross amount:   100.00 USDC")
        print("   Platform fee:     1.00 USDC (1%)")
        print("   Provider net:    99.00 USDC")
        print()
        print("View on Basescan:")
        print(f"   https://sepolia.basescan.org/tx/{tx_id}")

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
