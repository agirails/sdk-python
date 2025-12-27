#!/usr/bin/env python3
"""
ACTP Cancel Test
Tests cancellation flow: Create → Cancel (before escrow link)

Updated for SDK v2.0.0 API

Usage:
    python test_scripts/03_cancel.py

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
    print("ACTP Cancel Test (SDK v2.0.0)\n")

    # Validate environment
    if not CLIENT_PRIVATE_KEY or not PROVIDER_PRIVATE_KEY:
        print("Missing environment variables")
        print("Set: CLIENT_PRIVATE_KEY and PROVIDER_PRIVATE_KEY")
        sys.exit(1)

    print(f"Client:   {CLIENT_ADDRESS}")
    print(f"Provider: {PROVIDER_ADDRESS}")
    print()

    network_config = get_network("base-sepolia")

    # Initialize SDK client
    client_sdk = await ACTPClient.create(
        mode="testnet",
        requester_address=CLIENT_ADDRESS,
        private_key=CLIENT_PRIVATE_KEY,
        rpc_url=network_config.rpc_url,
    )

    print("SDK client initialized\n")

    # Human-readable amount
    amount = "25"  # 25 USDC
    deadline = int(time.time()) + 86400  # 24 hours
    dispute_window = 3600  # 1 hour

    try:
        # SCENARIO 1: Cancel before escrow link (INITIATED → CANCELLED)
        print("SCENARIO 1: Cancel before escrow link")
        print("   Creating transaction...")
        print(f"   Amount: {amount} USDC")

        tx_id1 = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Service to be cancelled - pre-escrow",
        })
        print(f"   Transaction ID: {tx_id1}")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id1)
        print(f"   State: {tx.state if tx else 'N/A'} (INITIATED)")

        print("\n   Client changes mind...")
        print("   Cancelling transaction...")

        await client_sdk.standard.transition_state(tx_id1, "CANCELLED")
        print("   Transaction cancelled (no funds involved)")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id1)
        print(f"   State: {tx.state if tx else 'N/A'} (CANCELLED)")
        print()

        # SCENARIO 2: Cancel after escrow link (COMMITTED → CANCELLED after deadline)
        # Note: This requires the deadline to pass before cancellation is allowed
        print("SCENARIO 2: Cancel after escrow link")
        print("   Creating transaction with 30-second deadline...")

        short_deadline = int(time.time()) + 30  # 30 seconds

        tx_id2 = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": short_deadline,
            "dispute_window": dispute_window,
            "description": "Service to be cancelled - post-escrow",
        })
        print(f"   Transaction ID: {tx_id2}")
        await sleep(2)

        print("   Linking escrow (SDK handles USDC approval)...")
        escrow_id = await client_sdk.standard.link_escrow(tx_id2)
        print(f"   Escrow linked! ID: {escrow_id}")
        print("   25 USDC locked in escrow")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id2)
        print(f"   State: {tx.state if tx else 'N/A'} (COMMITTED)")

        print("\n   Waiting for deadline to expire (35 seconds)...")
        await sleep(35)  # Wait for deadline to pass

        print("   Client requests cancellation (deadline expired)...")
        print("   Cancelling transaction...")

        await client_sdk.standard.transition_state(tx_id2, "CANCELLED")
        print("   Transaction cancelled")
        print("   25 USDC refunded to client")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id2)
        print(f"   State: {tx.state if tx else 'N/A'} (CANCELLED)")
        print()

        # Summary
        print("=" * 43)
        print("CANCEL TEST COMPLETE!")
        print("=" * 43)
        print()
        print("Scenario 1: Pre-escrow cancel")
        print(f"  Transaction ID: {tx_id1}")
        print("  State: CANCELLED")
        print("  Funds: None involved")
        print()
        print("Scenario 2: Post-escrow cancel (after deadline)")
        print(f"  Transaction ID: {tx_id2}")
        print("  State: CANCELLED")
        print("  Funds: 25 USDC refunded to client")

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
