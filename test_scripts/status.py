#!/usr/bin/env python3
"""
ACTP Status Checker
Check balances and transaction status

Usage:
    python test_scripts/status.py [transaction_id]

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    RPC_URL: Base Sepolia RPC URL (default: https://sepolia.base.org)
"""

import asyncio
import os
import sys
from datetime import datetime
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

# Contract addresses
MOCK_USDC_ADDRESS = os.getenv("MOCK_USDC_ADDRESS", "0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb")

# USDC ABI
USDC_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

STATE_NAMES = [
    "INITIATED",
    "QUOTED",
    "COMMITTED",
    "IN_PROGRESS",
    "DELIVERED",
    "SETTLED",
    "DISPUTED",
    "CANCELLED"
]


def format_usdc(amount_wei: int) -> str:
    """Format USDC amount from wei (6 decimals)."""
    return f"{amount_wei / 1_000_000:.6f}"


def format_eth(amount_wei: int) -> str:
    """Format ETH amount from wei (18 decimals)."""
    return f"{amount_wei / 1e18:.6f}"


async def main() -> None:
    tx_id = sys.argv[1] if len(sys.argv) > 1 else None

    print("ACTP Status Check\n")
    print("=" * 43)
    print("WALLET BALANCES")
    print("=" * 43 + "\n")

    network_config = get_network("base-sepolia")
    w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))
    usdc = w3.eth.contract(address=MOCK_USDC_ADDRESS, abi=USDC_ABI)

    # Check ETH balances
    if CLIENT_ADDRESS:
        client_eth = w3.eth.get_balance(CLIENT_ADDRESS)
        client_usdc = usdc.functions.balanceOf(CLIENT_ADDRESS).call()

        print(f"Client Wallet: {CLIENT_ADDRESS}")
        print(f"  ETH:   {format_eth(client_eth)} ETH")
        print(f"  USDC:  {format_usdc(client_usdc)} USDC")
        print()

    if PROVIDER_ADDRESS:
        provider_eth = w3.eth.get_balance(PROVIDER_ADDRESS)
        provider_usdc = usdc.functions.balanceOf(PROVIDER_ADDRESS).call()

        print(f"Provider Wallet: {PROVIDER_ADDRESS}")
        print(f"  ETH:   {format_eth(provider_eth)} ETH")
        print(f"  USDC:  {format_usdc(provider_usdc)} USDC")
        print()

    # If transaction ID provided, check it
    if tx_id:
        print("=" * 43)
        print("TRANSACTION DETAILS")
        print("=" * 43 + "\n")

        try:
            # Initialize SDK with a key for read operations
            if CLIENT_PRIVATE_KEY:
                sdk = await ACTPClient.create(
                    mode="testnet",
                    requester_address=CLIENT_ADDRESS,
                    private_key=CLIENT_PRIVATE_KEY,
                    rpc_url=network_config.rpc_url,
                )

                tx = await sdk.runtime.get_transaction(tx_id)

                if tx:
                    state_name = STATE_NAMES[tx.state] if 0 <= tx.state < len(STATE_NAMES) else str(tx.state)

                    print(f"Transaction ID: {tx_id}")
                    print(f"State:          {state_name} ({tx.state})")
                    print(f"Amount:         {format_usdc(tx.amount)} USDC")
                    print(f"Requester:      {tx.requester}")
                    print(f"Provider:       {tx.provider}")
                    print(f"Created:        {datetime.fromtimestamp(tx.created_at).isoformat()}")
                    print(f"Deadline:       {datetime.fromtimestamp(tx.deadline).isoformat()}")
                    print(f"Dispute Win:    {tx.dispute_window} seconds")

                    if tx.escrow_contract and tx.escrow_contract != "0x" + "0" * 40:
                        print(f"Escrow:         {tx.escrow_contract}")
                        print(f"Escrow ID:      {tx.escrow_id}")

                    print()
                    print("View on Basescan:")
                    print(f"   https://sepolia.basescan.org/address/{tx.escrow_contract or 'N/A'}")
                else:
                    print(f"Transaction not found: {tx_id}")

        except Exception as e:
            print(f"Error fetching transaction: {e}")
    else:
        print("Tip: Add transaction ID as argument to see details")
        print("   Usage: python test_scripts/status.py <txId>")

    print()


if __name__ == "__main__":
    asyncio.run(main())
