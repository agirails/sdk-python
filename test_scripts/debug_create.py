#!/usr/bin/env python3
"""
Debug Create Transaction
Helper script for debugging transaction creation issues

Usage:
    python test_scripts/debug_create.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client wallet
"""

import asyncio
import os
import sys
import time
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# Load .env file
load_dotenv()

# Import SDK
from agirails import ACTPClient
from agirails.config import get_network

# Test wallets
CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY", "")
PROVIDER_PRIVATE_KEY = os.getenv("PROVIDER_PRIVATE_KEY", "")

CLIENT_ADDRESS = Account.from_key(CLIENT_PRIVATE_KEY).address if CLIENT_PRIVATE_KEY else ""
PROVIDER_ADDRESS = Account.from_key(PROVIDER_PRIVATE_KEY).address if PROVIDER_PRIVATE_KEY else ""


async def main() -> None:
    print("Debug Create Transaction\n")

    if not CLIENT_PRIVATE_KEY:
        print("Missing CLIENT_PRIVATE_KEY environment variable")
        sys.exit(1)

    network_config = get_network("base-sepolia")

    client = await ACTPClient.create(
        mode="testnet",
        requester_address=CLIENT_ADDRESS,
        private_key=CLIENT_PRIVATE_KEY,
        rpc_url=network_config.rpc_url,
    )

    amount = "100"  # 100 USDC
    deadline = int(time.time()) + 86400
    dispute_window = 7200
    metadata = Web3.keccak(text="Test")

    print("Params:")
    print(f"  Provider: {PROVIDER_ADDRESS}")
    print(f"  Requester: {CLIENT_ADDRESS}")
    print(f"  Amount: {amount} USDC")
    print(f"  Deadline: {deadline}")
    print(f"  DisputeWindow: {dispute_window}")
    print(f"  Metadata: {metadata.hex()}")
    print()

    try:
        print("Calling createTransaction...")
        tx_id = await client.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Debug test transaction",
        })
        print(f"Success! TxID: {tx_id}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
