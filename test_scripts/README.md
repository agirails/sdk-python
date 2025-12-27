# AGIRAILS Python SDK Test Scripts

This directory contains integration test scripts for testing the AGIRAILS SDK against Base Sepolia testnet.

> **✅ STATUS: Blockchain Runtime Implemented**
>
> All scripts now work with the SDK's BlockchainRuntime:
> - ✅ `00_setup.py` - Mints MockUSDC to test wallets
> - ✅ `status.py` - Checks wallet balances (ETH and USDC)
> - ✅ `01_happy_path.py` through `05_eas_comprehensive.py` - Use SDK blockchain runtime
> - ✅ Mock mode examples in `examples/` work fully
>
> **Important**: Ensure test wallets have sufficient ETH for gas fees (~0.001 ETH minimum).

## Prerequisites

### 1. Install the SDK

```bash
# From the python-sdk-v2 directory
pip install -e .
```

### 2. Set up environment variables

Create a `.env` file in the `python-sdk-v2` directory:

```bash
# Required for all tests
CLIENT_PRIVATE_KEY=0x...  # Your test client wallet private key
PROVIDER_PRIVATE_KEY=0x...  # Your test provider wallet private key

# Optional (defaults shown)
RPC_URL=https://sepolia.base.org
MOCK_USDC_ADDRESS=0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb

# Required for EAS tests (04, 05)
EAS_DELIVERY_SCHEMA_UID=0x...  # Your deployed EAS schema UID

# Required for dispute resolution test in 05
ADMIN_PRIVATE_KEY=0x...  # Admin wallet for dispute resolution
```

### 3. Fund your test wallets

Your test wallets need:
- Base Sepolia ETH for gas (get from [Base Sepolia Faucet](https://www.coinbase.com/faucets/base-ethereum-goerli-faucet))
- MockUSDC tokens (run `00_setup.py` to mint)

## Test Scripts

### 00_setup.py - Initial Setup

Mints MockUSDC to test wallets. Run this first before any other tests.

```bash
python test_scripts/00_setup.py
```

**What it does:**
- Mints 10,000 MockUSDC to CLIENT wallet
- Mints 10,000 MockUSDC to PROVIDER wallet

### 01_happy_path.py - Full Transaction Lifecycle

Tests the complete happy path: Create → Link → Progress → Deliver → Settle

```bash
python test_scripts/01_happy_path.py
```

**States traversed:**
1. INITIATED (transaction created)
2. COMMITTED (escrow linked)
3. IN_PROGRESS (provider working)
4. DELIVERED (work submitted)
5. SETTLED (payment released)

### 02_dispute.py - Dispute Flow

Tests the dispute mechanism: Create → Link → Deliver → Dispute

```bash
python test_scripts/02_dispute.py
```

**Note:** Full dispute resolution requires admin privileges on-chain.

### 03_cancel.py - Cancellation Scenarios

Tests two cancellation scenarios:
1. Cancel before escrow link (no funds involved)
2. Cancel after deadline expires (funds refunded)

```bash
python test_scripts/03_cancel.py
```

**Note:** Scenario 2 waits 35 seconds for the deadline to expire.

### 04_happy_path_eas.py - Happy Path with EAS

Tests the happy path with Ethereum Attestation Service integration.

```bash
python test_scripts/04_happy_path_eas.py
```

**Requires:** `EAS_DELIVERY_SCHEMA_UID` environment variable

**What it does:**
- Full happy path transaction
- Creates EAS delivery attestation on-chain
- Links transaction to immutable proof

### 05_eas_comprehensive.py - Comprehensive EAS Tests

Runs 5 comprehensive EAS test scenarios:
1. Dispute flow with EAS attestation
2. Attestation revocation
3. Attest before DELIVERED state (edge case)
4. Multiple attestations for same transaction
5. Invalid attestation UID handling

```bash
python test_scripts/05_eas_comprehensive.py
```

**Requires:**
- `EAS_DELIVERY_SCHEMA_UID`
- `ADMIN_PRIVATE_KEY` (for dispute resolution)

### status.py - Status Checker

Check wallet balances and transaction status.

```bash
# Check balances only
python test_scripts/status.py

# Check specific transaction
python test_scripts/status.py <transaction_id>
```

### debug_create.py - Debug Helper

Debug helper for transaction creation issues.

```bash
python test_scripts/debug_create.py
```

## State Machine Reference

```
INITIATED (0) → Created, awaiting escrow
    ↓
QUOTED (1) → Optional: Provider price quote
    ↓
COMMITTED (2) → Escrow linked, work can begin
    ↓
IN_PROGRESS (3) → Optional: Provider actively working
    ↓
DELIVERED (4) → Work submitted with proof
    ↓
SETTLED (5) → Terminal: Payment released

Alternative paths:
- DELIVERED → DISPUTED (6) → SETTLED (after resolution)
- Any pre-DELIVERED state → CANCELLED (7)
```

## Common Issues

### "Insufficient USDC balance"

Run `00_setup.py` to mint MockUSDC to your test wallets.

### "Missing environment variables"

Ensure your `.env` file is in the `python-sdk-v2` directory with all required variables.

### "Transaction reverted"

Check:
1. Wallet has enough ETH for gas
2. Wallet has enough USDC for the transaction amount
3. Transaction is in the correct state for the operation

### "EAS attestation failed"

Ensure:
1. `EAS_DELIVERY_SCHEMA_UID` is correctly set
2. Schema was deployed to Base Sepolia
3. Provider wallet has ETH for gas

## Network Information

- **Network:** Base Sepolia (Testnet)
- **Chain ID:** 84532
- **RPC:** https://sepolia.base.org
- **Block Explorer:** https://sepolia.basescan.org
- **EAS Explorer:** https://base-sepolia.easscan.org

## See Also

- [SDK README](../README.md) - Full SDK documentation
- [Examples](../examples/) - Mock mode examples
- [TypeScript SDK](../../sdk-js/) - Reference implementation
