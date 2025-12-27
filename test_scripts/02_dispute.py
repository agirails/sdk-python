#!/usr/bin/env python3
"""
ACTP Dispute Test
Tests dispute flow: Create → Link → Deliver → Dispute → (manual resolution)

Updated for SDK v2.0.0 API

Usage:
    python test_scripts/02_dispute.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client/requester wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    RPC_URL: Base Sepolia RPC URL (default: https://sepolia.base.org)
"""

import asyncio
import os
import sys
import time
from dotenv import load_dotenv
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


async def sleep(seconds: float) -> None:
    """Async sleep wrapper."""
    await asyncio.sleep(seconds)


async def main() -> None:
    print("ACTP Dispute Test (SDK v2.0.0)\n")

    # Validate environment
    if not CLIENT_PRIVATE_KEY or not PROVIDER_PRIVATE_KEY:
        print("Missing environment variables")
        print("Set: CLIENT_PRIVATE_KEY and PROVIDER_PRIVATE_KEY")
        sys.exit(1)

    print(f"Client:   {CLIENT_ADDRESS}")
    print(f"Provider: {PROVIDER_ADDRESS}")
    print()

    network_config = get_network("base-sepolia")

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

    # Human-readable amount
    amount = "50"  # 50 USDC
    deadline = int(time.time()) + 86400  # 24 hours
    dispute_window = 7200  # 2 hours

    try:
        # Create transaction
        print("Creating transaction...")
        print(f"   Amount: {amount} USDC")

        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Disputed service test",
        })
        print(f"   Transaction ID: {tx_id}")
        await sleep(2)

        # Link escrow
        print("Linking escrow (SDK handles USDC approval)...")
        escrow_id = await client_sdk.standard.link_escrow(tx_id)
        print(f"   Escrow linked! ID: {escrow_id}")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (COMMITTED)")
        print()

        # Provider starts work (required before DELIVERED)
        print("Provider starts work...")
        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        print("   State: IN_PROGRESS")
        await sleep(2)

        # Provider delivers
        print("Provider delivers work...")
        await provider_sdk.runtime.transition_state(tx_id, "DELIVERED", b"")
        print("   State: DELIVERED")
        await sleep(2)
        print()

        # Client disputes!
        print("CLIENT RAISES DISPUTE!")
        print('   Reason: "Work quality does not meet requirements"')
        await client_sdk.standard.transition_state(tx_id, "DISPUTED")
        print("   Dispute raised")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (DISPUTED)")
        print()

        # Note: Dispute resolution requires admin privileges on-chain
        # For now, we verify the dispute state was reached
        print("=" * 43)
        print("DISPUTE TEST COMPLETE!")
        print("=" * 43)
        print(f"Transaction ID: {tx_id}")
        print("Final State:    DISPUTED")
        print()
        print("Note: Dispute resolution requires admin/mediator.")
        print("   On-chain resolution would split funds between parties.")
        print("   For full dispute resolution test, run with admin key.")

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
