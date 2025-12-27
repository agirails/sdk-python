#!/usr/bin/env python3
"""
ACTP Test Setup - Mint MockUSDC to test wallets
Run this FIRST before any tests

Usage:
    python test_scripts/00_setup.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client/requester wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    RPC_URL: Base Sepolia RPC URL (default: https://sepolia.base.org)
    MOCK_USDC_ADDRESS: MockUSDC contract address
"""

import os
import sys
import time
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# Load .env file
load_dotenv()

# Import SDK config
from agirails.config import get_network

# Base Sepolia configuration
network_config = get_network("base-sepolia")
RPC_URL = network_config.rpc_url
MOCK_USDC_ADDRESS = os.getenv("MOCK_USDC_ADDRESS", "0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb")

# Private keys from environment
CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY", "")
PROVIDER_PRIVATE_KEY = os.getenv("PROVIDER_PRIVATE_KEY", "")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY", CLIENT_PRIVATE_KEY)

# Derive addresses from private keys
CLIENT_ADDRESS = Account.from_key(CLIENT_PRIVATE_KEY).address if CLIENT_PRIVATE_KEY else ""
PROVIDER_ADDRESS = Account.from_key(PROVIDER_PRIVATE_KEY).address if PROVIDER_PRIVATE_KEY else ""

# MockUSDC ABI (minimal for minting)
USDC_ABI = [
    {
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "name": "mint",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
        "type": "function"
    }
]


def format_usdc(amount_wei: int) -> str:
    """Format USDC amount from wei (6 decimals)."""
    return f"{amount_wei / 1_000_000:.2f}"


def main() -> None:
    print("ACTP Test Setup - Minting MockUSDC\n")

    # Validate environment
    if not ADMIN_PRIVATE_KEY:
        print("Missing ADMIN_PRIVATE_KEY environment variable")
        print("TIP: MockUSDC has open minting - use ANY wallet with ETH for gas")
        print("   You can even use: ADMIN_PRIVATE_KEY=<same as CLIENT_PRIVATE_KEY>")
        print("")
        print("Set it with: export ADMIN_PRIVATE_KEY='0x...'")
        sys.exit(1)

    if not CLIENT_PRIVATE_KEY:
        print("Missing CLIENT_PRIVATE_KEY environment variable")
        sys.exit(1)

    if not PROVIDER_PRIVATE_KEY:
        print("Missing PROVIDER_PRIVATE_KEY environment variable")
        sys.exit(1)

    # Connect to Base Sepolia
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    # Test connection by getting chain ID (more reliable than is_connected)
    try:
        chain_id = w3.eth.chain_id
        print(f"Connected to chain ID: {chain_id}")
    except Exception as e:
        print(f"Failed to connect to RPC: {RPC_URL}")
        print(f"Error: {e}")
        sys.exit(1)

    # Create admin account
    admin_account = Account.from_key(ADMIN_PRIVATE_KEY)
    usdc = w3.eth.contract(address=MOCK_USDC_ADDRESS, abi=USDC_ABI)

    print(f"Admin wallet: {admin_account.address}")
    print(f"MockUSDC: {MOCK_USDC_ADDRESS}")
    print(f"RPC: {RPC_URL}")
    print()

    # Mint amount: 10,000 USDC each
    MINT_AMOUNT = 10_000 * 1_000_000  # 6 decimals

    try:
        # Mint to client
        print("Minting 10,000 USDC to CLIENT...")
        print(f"   Address: {CLIENT_ADDRESS}")

        nonce = w3.eth.get_transaction_count(admin_account.address)
        tx = usdc.functions.mint(CLIENT_ADDRESS, MINT_AMOUNT).build_transaction({
            "from": admin_account.address,
            "nonce": nonce,
            "gas": 100_000,
            "maxFeePerGas": w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": w3.eth.gas_price,
        })

        signed = admin_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"   Tx: {tx_hash.hex()}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            print("   Confirmed!")
        else:
            print("   Transaction failed!")
            sys.exit(1)

        # Small delay to ensure nonce propagation
        time.sleep(2)

        # Mint to provider
        print("\nMinting 10,000 USDC to PROVIDER...")
        print(f"   Address: {PROVIDER_ADDRESS}")

        nonce = w3.eth.get_transaction_count(admin_account.address)
        tx = usdc.functions.mint(PROVIDER_ADDRESS, MINT_AMOUNT).build_transaction({
            "from": admin_account.address,
            "nonce": nonce,
            "gas": 100_000,
            "maxFeePerGas": w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": w3.eth.gas_price,
        })

        signed = admin_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"   Tx: {tx_hash.hex()}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            print("   Confirmed!")
        else:
            print("   Transaction failed!")
            sys.exit(1)

        # Check balances
        print("\nFinal Balances:")
        client_balance = usdc.functions.balanceOf(CLIENT_ADDRESS).call()
        provider_balance = usdc.functions.balanceOf(PROVIDER_ADDRESS).call()

        print(f"   Client:   {format_usdc(client_balance)} USDC")
        print(f"   Provider: {format_usdc(provider_balance)} USDC")

        print("\nSetup complete! Ready to run tests.")
        print("\nNext steps:")
        print("1. Ensure CLIENT_PRIVATE_KEY and PROVIDER_PRIVATE_KEY are set")
        print("2. Run: python test_scripts/01_happy_path.py")

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
