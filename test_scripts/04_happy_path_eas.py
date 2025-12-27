#!/usr/bin/env python3
"""
ACTP Happy Path Test with EAS Integration
Tests full transaction lifecycle with delivery attestation:
Create → Link → Progress → Deliver → Attest (EAS) → Settle

Updated for SDK v2.0.0 API

Usage:
    python test_scripts/04_happy_path_eas.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client/requester wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    EAS_DELIVERY_SCHEMA_UID: EAS schema UID for delivery attestations
    RPC_URL: Base Sepolia RPC URL (default: https://sepolia.base.org)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account
from eth_abi import encode

# Load .env file
load_dotenv()

# Import SDK
from agirails import ACTPClient
from agirails.config import get_network

# Test wallets - derived from private keys in .env
CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY", "")
PROVIDER_PRIVATE_KEY = os.getenv("PROVIDER_PRIVATE_KEY", "")
EAS_DELIVERY_SCHEMA_UID = os.getenv("EAS_DELIVERY_SCHEMA_UID", "")

# Derive addresses from private keys (checksummed for EAS compatibility)
CLIENT_ADDRESS = Web3.to_checksum_address(Account.from_key(CLIENT_PRIVATE_KEY).address) if CLIENT_PRIVATE_KEY else ""
PROVIDER_ADDRESS = Web3.to_checksum_address(Account.from_key(PROVIDER_PRIVATE_KEY).address) if PROVIDER_PRIVATE_KEY else ""

# Base Sepolia EAS Contract
EAS_CONTRACT_ADDRESS = "0x4200000000000000000000000000000000000021"

# EAS ABI (minimal for attesting)
EAS_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"name": "schema", "type": "bytes32"},
                    {
                        "components": [
                            {"name": "recipient", "type": "address"},
                            {"name": "expirationTime", "type": "uint64"},
                            {"name": "revocable", "type": "bool"},
                            {"name": "refUID", "type": "bytes32"},
                            {"name": "data", "type": "bytes"},
                            {"name": "value", "type": "uint256"}
                        ],
                        "name": "data",
                        "type": "tuple"
                    }
                ],
                "name": "request",
                "type": "tuple"
            }
        ],
        "name": "attest",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "payable",
        "type": "function"
    }
]


async def sleep(seconds: float) -> None:
    """Async sleep wrapper."""
    await asyncio.sleep(seconds)


async def main() -> None:
    print("ACTP Happy Path Test with EAS Attestation (SDK v2.0.0)\n")

    # Validate environment
    if not CLIENT_PRIVATE_KEY or not PROVIDER_PRIVATE_KEY or not EAS_DELIVERY_SCHEMA_UID:
        print("Missing environment variables")
        print("Set: CLIENT_PRIVATE_KEY, PROVIDER_PRIVATE_KEY, EAS_DELIVERY_SCHEMA_UID")
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

    # Transaction parameters (human-readable)
    amount = "75"  # 75 USDC
    deadline = int(time.time()) + 86400  # 24 hours
    dispute_window = 7200  # 2 hours

    try:
        # STEP 1: Create transaction
        print("STEP 1: Client creates transaction")
        print(f"   Amount: {amount} USDC")
        print("   Deadline: 24 hours")
        print("   Dispute window: 2 hours")

        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Test service - translation with EAS proof",
        })

        print(f"   Transaction ID: {tx_id}")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (INITIATED)")
        print()

        # STEP 2: Link escrow
        print("STEP 2: Client links escrow (SDK handles USDC approval)")
        escrow_id = await client_sdk.standard.link_escrow(tx_id)
        print(f"   Escrow linked! ID: {escrow_id}")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (COMMITTED)")
        print()

        # STEP 3: Provider starts work
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
        print()

        # STEP 5: Provider creates EAS attestation (delivery proof)
        print("STEP 5: Provider creates EAS delivery attestation")
        print(f"   EAS Contract: {EAS_CONTRACT_ADDRESS}")
        print(f"   Schema UID: {EAS_DELIVERY_SCHEMA_UID}")

        # Prepare attestation data (per AIP-6)
        result_cid = "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX"  # Example IPFS CID
        result_data = json.dumps({
            "type": "translation",
            "language": "en-es",
            "wordCount": 1500,
            "quality": "professional"
        })
        result_hash = Web3.keccak(text=result_data)
        delivered_at = int(time.time())

        print("   Delivery proof:")
        print(f"     Result CID: {result_cid}")
        print(f"     Result hash: {result_hash.hex()[:20]}...")
        print(f"     Delivered at: {datetime.fromtimestamp(delivered_at).isoformat()}")

        # Create web3 instance for EAS
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))
        provider_account = Account.from_key(PROVIDER_PRIVATE_KEY)

        print("   Creating on-chain EAS attestation...")

        # Encode attestation data
        # Schema: bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt, uint256 testTimestamp
        tx_id_bytes = bytes.fromhex(tx_id[2:]) if tx_id.startswith("0x") else bytes.fromhex(tx_id)
        encoded_data = encode(
            ["bytes32", "string", "bytes32", "uint256", "uint256"],
            [tx_id_bytes, result_cid, result_hash, delivered_at, int(time.time() * 1000)]
        )

        # Prepare EAS attestation request
        zero_bytes32 = b"\x00" * 32
        schema_uid_bytes = bytes.fromhex(EAS_DELIVERY_SCHEMA_UID[2:]) if EAS_DELIVERY_SCHEMA_UID.startswith("0x") else bytes.fromhex(EAS_DELIVERY_SCHEMA_UID)

        eas = w3.eth.contract(address=EAS_CONTRACT_ADDRESS, abi=EAS_ABI)

        attestation_request = (
            schema_uid_bytes,  # schema
            (
                CLIENT_ADDRESS,  # recipient
                0,  # expirationTime (0 = never)
                False,  # revocable (per AIP-6: delivery attestations are permanent)
                zero_bytes32,  # refUID
                encoded_data,  # data
                0  # value
            )
        )

        # Estimate gas and build transaction
        nonce = w3.eth.get_transaction_count(provider_account.address, "pending")
        estimated_gas = eas.functions.attest(attestation_request).estimate_gas({
            "from": provider_account.address,
            "value": 0
        })
        gas_limit = int(estimated_gas * 1.5)  # 50% buffer for safety
        print(f"   Gas estimated: {estimated_gas}, using: {gas_limit}")

        tx_data = eas.functions.attest(attestation_request).build_transaction({
            "from": provider_account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "maxFeePerGas": w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": w3.eth.gas_price,
        })

        signed_tx = provider_account.sign_transaction(tx_data)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        # Check transaction succeeded
        if receipt.status != 1:
            raise Exception(f"EAS attestation transaction failed: {tx_hash.hex()}")

        # Get attestation UID from logs (Attested event has UID in data field)
        attestation_uid = "unknown"
        if receipt.logs and len(receipt.logs) > 0:
            log = receipt.logs[0]
            # The attestation UID is in the data field of the Attested event
            if hasattr(log, 'data') and log.data:
                uid = log.data
                attestation_uid = uid.hex() if isinstance(uid, bytes) else uid
                if not attestation_uid.startswith("0x"):
                    attestation_uid = "0x" + attestation_uid

        print("   On-chain attestation created!")
        print(f"   Attestation UID: {attestation_uid}")
        print(f"   EAS Explorer: https://base-sepolia.easscan.org/attestation/view/{attestation_uid}")
        await sleep(2)
        print()

        # STEP 6: Client settles transaction
        print("STEP 6: Client settles transaction")
        print("   (In production, this can happen after dispute window expires)")

        await client_sdk.standard.transition_state(tx_id, "SETTLED")
        print("   Transaction settled! Payment released to provider.")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   State: {tx.state if tx else 'N/A'} (SETTLED)")
        print()

        # Final summary
        print("=" * 43)
        print("HAPPY PATH + EAS TEST COMPLETE!")
        print("=" * 43)
        print(f"Transaction ID: {tx_id}")
        print(f"Attestation UID: {attestation_uid}")
        print("Final State:    SETTLED")
        print()
        print("Financial Summary:")
        print("   Gross amount:   75.00 USDC")
        print("   Platform fee:    0.75 USDC (1%)")
        print("   Provider net:   74.25 USDC")
        print()
        print("Links:")
        print(f"   Basescan: https://sepolia.basescan.org/tx/{tx_id}")
        print(f"   EAS Attestation: https://base-sepolia.easscan.org/attestation/view/{attestation_uid}")

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
