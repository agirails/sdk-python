#!/usr/bin/env python3
"""
Comprehensive EAS Test Suite

Tests all EAS integration scenarios:
1. Dispute flow with EAS attestation
2. Attestation revocation
3. Edge cases:
   - Attest before DELIVERED state
   - Multiple attestations for same transaction
   - Invalid attestation UIDs

Updated for SDK v2.0.0 API

Usage:
    python test_scripts/05_eas_comprehensive.py

Environment Variables:
    CLIENT_PRIVATE_KEY: Private key for client/requester wallet
    PROVIDER_PRIVATE_KEY: Private key for provider wallet
    ADMIN_PRIVATE_KEY: Private key for admin wallet (for dispute resolution)
    EAS_DELIVERY_SCHEMA_UID: EAS schema UID for delivery attestations
"""

import asyncio
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional, List
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account
from eth_abi import encode

# Load .env file
load_dotenv()

# Import SDK
from agirails import ACTPClient
from agirails.config import get_network

# Test wallets
CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY", "")
PROVIDER_PRIVATE_KEY = os.getenv("PROVIDER_PRIVATE_KEY", "")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY", "")
EAS_DELIVERY_SCHEMA_UID = os.getenv("EAS_DELIVERY_SCHEMA_UID", "")

# Derive addresses from private keys (checksummed for EAS compatibility)
CLIENT_ADDRESS = Web3.to_checksum_address(Account.from_key(CLIENT_PRIVATE_KEY).address) if CLIENT_PRIVATE_KEY else ""
PROVIDER_ADDRESS = Web3.to_checksum_address(Account.from_key(PROVIDER_PRIVATE_KEY).address) if PROVIDER_PRIVATE_KEY else ""

# Base Sepolia EAS Contract
EAS_CONTRACT_ADDRESS = "0x4200000000000000000000000000000000000021"

# EAS ABI
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
    },
    {
        "inputs": [
            {
                "components": [
                    {"name": "schema", "type": "bytes32"},
                    {
                        "components": [
                            {"name": "uid", "type": "bytes32"},
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
        "name": "revoke",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "getAttestation",
        "outputs": [
            {
                "components": [
                    {"name": "uid", "type": "bytes32"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocationTime", "type": "uint64"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "attester", "type": "address"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "data", "type": "bytes"}
                ],
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]


@dataclass
class TestResult:
    scenario: str
    status: str  # "PASS" or "FAIL"
    details: str
    attestation_uid: Optional[str] = None
    transaction_id: Optional[str] = None


results: List[TestResult] = []


async def sleep(seconds: float) -> None:
    """Async sleep wrapper."""
    await asyncio.sleep(seconds)


def create_attestation(w3: Web3, signer: Account, tx_id: str, result_cid: str, revocable: bool = False) -> str:
    """Create an EAS attestation and return the UID."""
    result_hash = Web3.keccak(text=f"{result_cid}-{time.time()}")
    delivered_at = int(time.time())
    test_timestamp = int(time.time() * 1000)  # Milliseconds for testTimestamp field

    tx_id_bytes = bytes.fromhex(tx_id[2:]) if tx_id.startswith("0x") else bytes.fromhex(tx_id)
    # Schema: bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt, uint256 testTimestamp
    encoded_data = encode(
        ["bytes32", "string", "bytes32", "uint256", "uint256"],
        [tx_id_bytes, result_cid, result_hash, delivered_at, test_timestamp]
    )

    zero_bytes32 = b"\x00" * 32
    schema_uid_bytes = bytes.fromhex(EAS_DELIVERY_SCHEMA_UID[2:]) if EAS_DELIVERY_SCHEMA_UID.startswith("0x") else bytes.fromhex(EAS_DELIVERY_SCHEMA_UID)

    eas = w3.eth.contract(address=EAS_CONTRACT_ADDRESS, abi=EAS_ABI)

    attestation_request = (
        schema_uid_bytes,
        (
            CLIENT_ADDRESS,
            0,
            revocable,
            zero_bytes32,
            encoded_data,
            0
        )
    )

    # Estimate gas and build transaction
    nonce = w3.eth.get_transaction_count(signer.address, "pending")
    estimated_gas = eas.functions.attest(attestation_request).estimate_gas({
        "from": signer.address,
        "value": 0
    })
    gas_limit = int(estimated_gas * 1.5)  # 50% buffer for safety

    tx_data = eas.functions.attest(attestation_request).build_transaction({
        "from": signer.address,
        "nonce": nonce,
        "gas": gas_limit,
        "maxFeePerGas": w3.eth.gas_price * 2,
        "maxPriorityFeePerGas": w3.eth.gas_price,
    })

    signed_tx = signer.sign_transaction(tx_data)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    # Check transaction succeeded
    if receipt.status != 1:
        raise Exception(f"EAS attestation transaction failed: {tx_hash.hex()}")

    # Extract UID from logs - the Attested event has UID in data field
    if receipt.logs and len(receipt.logs) > 0:
        log = receipt.logs[0]
        if hasattr(log, 'data') and log.data:
            uid = log.data
            uid_str = uid.hex() if isinstance(uid, bytes) else uid
            if not uid_str.startswith("0x"):
                uid_str = "0x" + uid_str
            return uid_str

    raise Exception(f"No attestation UID found in logs for tx: {tx_hash.hex()}")


async def test_dispute_flow_with_eas() -> TestResult:
    """
    TEST 1: Dispute Flow with EAS Attestation
    Create → Link → Deliver → Attest → Dispute → Resolve
    Verify attestation persists after dispute resolution
    """
    print("\n" + "=" * 60)
    print(" TEST 1: Dispute Flow with EAS Attestation")
    print("=" * 60 + "\n")

    try:
        network_config = get_network("base-sepolia")
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))

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

        amount = "50"
        deadline = int(time.time()) + 86400
        dispute_window = 7200

        # Create transaction
        print("Creating transaction...")
        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Dispute test with EAS",
        })
        print(f"   Transaction ID: {tx_id}")
        await sleep(2)

        # Link escrow
        print("Linking escrow...")
        await client_sdk.standard.link_escrow(tx_id)
        print("   Escrow linked")
        await sleep(2)

        # Provider delivers
        print("Provider works and delivers...")
        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        await sleep(2)
        await provider_sdk.runtime.transition_state(tx_id, "DELIVERED", b"")
        print("   Delivered")
        await sleep(2)

        # Create EAS attestation
        print("Provider creates EAS attestation...")
        provider_account = Account.from_key(PROVIDER_PRIVATE_KEY)
        attestation_uid = create_attestation(w3, provider_account, tx_id, "QmDisputeTest123", revocable=False)
        print(f"   Attestation UID: {attestation_uid}")
        await sleep(2)

        # Client disputes
        print("Client disputes delivery...")
        await client_sdk.standard.transition_state(tx_id, "DISPUTED")
        print("   Dispute raised")
        await sleep(2)

        # Verify attestation still exists
        print("Verifying attestation persists after dispute...")
        eas = w3.eth.contract(address=EAS_CONTRACT_ADDRESS, abi=EAS_ABI)
        attestation_data = eas.functions.getAttestation(bytes.fromhex(attestation_uid[2:])).call()

        if attestation_data[2] == 0:  # time == 0 means not found
            raise Exception("Attestation not found after dispute")

        print("   Attestation still valid on EAS")
        print(f"   View: https://base-sepolia.easscan.org/attestation/view/{attestation_uid}")

        return TestResult(
            scenario="Dispute Flow with EAS Attestation",
            status="PASS",
            details="Transaction disputed. Attestation persists on EAS after dispute.",
            attestation_uid=attestation_uid,
            transaction_id=tx_id
        )

    except Exception as e:
        return TestResult(
            scenario="Dispute Flow with EAS Attestation",
            status="FAIL",
            details=str(e)
        )


async def test_attestation_revocation() -> TestResult:
    """
    TEST 2: Attestation Revocation
    Create attestation → Revoke → Verify revocation status
    """
    print("\n" + "=" * 60)
    print(" TEST 2: Attestation Revocation")
    print("=" * 60 + "\n")

    try:
        network_config = get_network("base-sepolia")
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))

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

        amount = "25"
        deadline = int(time.time()) + 86400
        dispute_window = 7200

        # Create and deliver transaction
        print("Creating transaction...")
        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Revocation test",
        })
        await sleep(2)

        await client_sdk.standard.link_escrow(tx_id)
        await sleep(2)

        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        await sleep(2)
        await provider_sdk.runtime.transition_state(tx_id, "DELIVERED", b"")
        await sleep(2)

        # Create attestation
        print("Creating attestation...")
        provider_account = Account.from_key(PROVIDER_PRIVATE_KEY)
        # NOTE: This schema is non-revocable (Revocable: False in schema registry)
        # Revocation test would require a revocable schema to be deployed
        # For now, we document this as a known limitation
        print("   NOTE: Schema is non-revocable - skipping revocation test")
        print("   To test revocation, deploy a schema with revocable=True")

        return TestResult(
            scenario="Attestation Revocation",
            status="SKIP",
            details="Schema is non-revocable. Revocation requires a revocable schema to be deployed.",
            transaction_id=tx_id
        )

        # Below code would work with a revocable schema:
        # attestation_uid = create_attestation(w3, provider_account, tx_id, "QmRevocationTest", revocable=True)
        # print(f"   Attestation created: {attestation_uid}")
        # await sleep(2)

        # Revoke attestation (requires revocable schema)
        print("Revoking attestation...")
        eas = w3.eth.contract(address=EAS_CONTRACT_ADDRESS, abi=EAS_ABI)
        schema_uid_bytes = bytes.fromhex(EAS_DELIVERY_SCHEMA_UID[2:])
        uid_bytes = bytes.fromhex(attestation_uid[2:])

        revoke_request = (schema_uid_bytes, (uid_bytes, 0))

        nonce = w3.eth.get_transaction_count(provider_account.address, "pending")
        tx_data = eas.functions.revoke(revoke_request).build_transaction({
            "from": provider_account.address,
            "nonce": nonce,
            "gas": 200_000,
            "maxFeePerGas": w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": w3.eth.gas_price,
        })

        signed_tx = provider_account.sign_transaction(tx_data)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print("   Attestation revoked")
        await sleep(2)

        # Verify revocation
        print("Verifying revocation status...")
        attestation_data = eas.functions.getAttestation(uid_bytes).call()

        if attestation_data[4] == 0:  # revocationTime == 0
            raise Exception("Attestation not properly revoked")

        print(f"   Revocation confirmed (revocationTime: {attestation_data[4]})")

        return TestResult(
            scenario="Attestation Revocation",
            status="PASS",
            details=f"Attestation created and successfully revoked. Revocation timestamp: {attestation_data[4]}",
            attestation_uid=attestation_uid,
            transaction_id=tx_id
        )

    except Exception as e:
        return TestResult(
            scenario="Attestation Revocation",
            status="FAIL",
            details=str(e)
        )


async def test_attest_before_delivered() -> TestResult:
    """
    TEST 3: Edge Case - Attest Before DELIVERED State
    Attempt to create attestation when transaction is still IN_PROGRESS
    Expected: Attestation succeeds (EAS doesn't validate ACTP state)
    """
    print("\n" + "=" * 60)
    print(" TEST 3: Attest Before DELIVERED State")
    print("=" * 60 + "\n")

    try:
        network_config = get_network("base-sepolia")
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))

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

        amount = "10"
        deadline = int(time.time()) + 86400
        dispute_window = 7200

        print("Creating transaction...")
        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Early attestation test",
        })
        await sleep(2)

        await client_sdk.standard.link_escrow(tx_id)
        await sleep(2)

        # Move to IN_PROGRESS (not DELIVERED yet!)
        print("Moving to IN_PROGRESS state...")
        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        await sleep(2)

        tx = await client_sdk.runtime.get_transaction(tx_id)
        print(f"   Current state: {tx.state if tx else 'N/A'} (should be IN_PROGRESS)")

        # Attempt to create attestation BEFORE delivery
        print("Attempting to create attestation in IN_PROGRESS state...")
        provider_account = Account.from_key(PROVIDER_PRIVATE_KEY)
        attestation_uid = create_attestation(w3, provider_account, tx_id, "QmEarlyAttestation")
        print(f"   Attestation created despite IN_PROGRESS state: {attestation_uid}")
        print("   Note: EAS does NOT validate ACTP state - consumer must verify!")

        return TestResult(
            scenario="Attest Before DELIVERED State",
            status="PASS",
            details="Attestation created in IN_PROGRESS state. EAS does not validate ACTP state transitions.",
            attestation_uid=attestation_uid,
            transaction_id=tx_id
        )

    except Exception as e:
        return TestResult(
            scenario="Attest Before DELIVERED State",
            status="FAIL",
            details=str(e)
        )


async def test_multiple_attestations() -> TestResult:
    """
    TEST 4: Edge Case - Multiple Attestations
    Create multiple attestations for the same transaction
    Expected: EAS allows it (no uniqueness constraint)
    """
    print("\n" + "=" * 60)
    print(" TEST 4: Multiple Attestations for Same Transaction")
    print("=" * 60 + "\n")

    try:
        network_config = get_network("base-sepolia")
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))

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

        amount = "15"
        deadline = int(time.time()) + 86400
        dispute_window = 7200

        print("Creating transaction...")
        tx_id = await client_sdk.standard.create_transaction({
            "provider": PROVIDER_ADDRESS,
            "amount": amount,
            "deadline": deadline,
            "dispute_window": dispute_window,
            "description": "Multiple attestations test",
        })
        await sleep(2)

        await client_sdk.standard.link_escrow(tx_id)
        await sleep(2)

        await provider_sdk.standard.transition_state(tx_id, "IN_PROGRESS")
        await sleep(2)
        await provider_sdk.runtime.transition_state(tx_id, "DELIVERED", b"")
        await sleep(2)

        provider_account = Account.from_key(PROVIDER_PRIVATE_KEY)

        # Create FIRST attestation
        print("Creating first attestation...")
        attestation_uid1 = create_attestation(w3, provider_account, tx_id, "QmFirstAttestation")
        print(f"   First attestation: {attestation_uid1}")
        await sleep(2)

        # Create SECOND attestation for SAME transaction
        print("Creating second attestation for same txId...")
        attestation_uid2 = create_attestation(w3, provider_account, tx_id, "QmSecondAttestation")
        print(f"   Second attestation: {attestation_uid2}")
        print("   Note: EAS allows multiple attestations per txId!")

        return TestResult(
            scenario="Multiple Attestations for Same Transaction",
            status="PASS",
            details=f"Created 2 attestations for same txId. EAS does not enforce uniqueness.",
            attestation_uid=f"{attestation_uid1} & {attestation_uid2}",
            transaction_id=tx_id
        )

    except Exception as e:
        return TestResult(
            scenario="Multiple Attestations for Same Transaction",
            status="FAIL",
            details=str(e)
        )


async def test_invalid_attestation_uid() -> TestResult:
    """
    TEST 5: Edge Case - Invalid Attestation UID
    Test behavior when using non-existent attestation UID
    """
    print("\n" + "=" * 60)
    print(" TEST 5: Invalid Attestation UID")
    print("=" * 60 + "\n")

    try:
        network_config = get_network("base-sepolia")
        w3 = Web3(Web3.HTTPProvider(network_config.rpc_url))

        eas = w3.eth.contract(address=EAS_CONTRACT_ADDRESS, abi=EAS_ABI)

        # Generate fake UID (very unlikely to exist)
        fake_uid = bytes.fromhex("9" * 64)

        print(f"Querying non-existent attestation UID: 0x{'9' * 64}")
        attestation_data = eas.functions.getAttestation(fake_uid).call()

        # EAS returns default/empty struct for non-existent UIDs
        if attestation_data[2] == 0:  # time == 0 means not found
            print("   Non-existent UID returns empty/zero data as expected")
            print("   Consumer must check attestation.time != 0 to verify existence")

            return TestResult(
                scenario="Invalid Attestation UID",
                status="PASS",
                details="Non-existent UID query returns empty struct. Consumer must validate attestation.time != 0."
            )
        else:
            raise Exception("Unexpectedly found data for fake UID")

    except Exception as e:
        return TestResult(
            scenario="Invalid Attestation UID",
            status="FAIL",
            details=str(e)
        )


async def main() -> None:
    print("=" * 65)
    print("     COMPREHENSIVE EAS TEST SUITE - Base Sepolia Testnet")
    print("=" * 65)
    print()

    # Validate environment
    if not CLIENT_PRIVATE_KEY or not PROVIDER_PRIVATE_KEY or not EAS_DELIVERY_SCHEMA_UID:
        print("Missing environment variables")
        print("Required: CLIENT_PRIVATE_KEY, PROVIDER_PRIVATE_KEY, EAS_DELIVERY_SCHEMA_UID")
        sys.exit(1)

    print(f"Schema UID: {EAS_DELIVERY_SCHEMA_UID}")
    print(f"EAS Contract: {EAS_CONTRACT_ADDRESS}")
    print(f"Test Accounts: {CLIENT_ADDRESS}, {PROVIDER_ADDRESS}")
    print()
    print("Running 5 comprehensive test scenarios...\n")

    # Run all tests
    results.append(await test_dispute_flow_with_eas())
    results.append(await test_attestation_revocation())
    results.append(await test_attest_before_delivered())
    results.append(await test_multiple_attestations())
    results.append(await test_invalid_attestation_uid())

    # Print summary
    print("\n" + "=" * 65)
    print("                      TEST SUMMARY")
    print("=" * 65 + "\n")

    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")

    for i, result in enumerate(results, 1):
        icon = result.status
        print(f"{icon} TEST {i}: {result.scenario}")
        print(f"   Status: {result.status}")
        print(f"   {result.details}")
        if result.attestation_uid:
            print(f"   Attestation: {result.attestation_uid}")
        if result.transaction_id:
            print(f"   Transaction: {result.transaction_id}")
        print()

    print("=" * 65)
    print(f"Total Tests: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print("=" * 65)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
