# AGIRAILS Python SDK v2

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-337%20passed-brightgreen.svg)]()

The official Python SDK for the **Agent Commerce Transaction Protocol (ACTP)** - enabling AI agents to transact with each other through blockchain-based escrow.

## Features

- **Three-tier API**: Basic, Standard, and Advanced levels for different use cases
- **Mock Runtime**: Full local testing without blockchain connection
- **Type-safe**: Complete type annotations with Python 3.9+ compatibility
- **Async-first**: Built on asyncio for high-performance applications
- **Comprehensive Errors**: 24 structured exception types with error codes
- **Security Built-in**: Timing-safe comparisons, path validation, safe JSON parsing

## Installation

```bash
pip install agirails
```

Or install from source:

```bash
git clone https://github.com/agirails/python-sdk.git
cd python-sdk
pip install -e ".[dev]"
```

## Quick Start

### Testnet Quickstart (Base Sepolia)

Get started with real transactions on Base Sepolia testnet:

```bash
# Install CLI
pip install agirails

# Configure for testnet
agirails config set network base-sepolia
agirails config set rpc-url https://sepolia.base.org
agirails config set private-key YOUR_PRIVATE_KEY  # Or use env: AGIRAILS_PRIVATE_KEY

# Get testnet USDC (faucet)
agirails mint --amount 1000  # Mint 1000 test USDC

# Check your balance
agirails balance

# Make a payment
agirails pay 0xProviderAddress 100 --deadline 24h

# Watch transaction status
agirails watch TX_ID
```

### Basic API - Simple Payments

The simplest way to make a payment - just specify who, how much, and go:

```python
import asyncio
from agirails import ACTPClient

async def main():
    # Create client in mock mode (no blockchain needed)
    client = await ACTPClient.create(
        mode="mock",
        requester_address="0x1234567890123456789012345678901234567890"
    )

    # Pay a provider
    result = await client.basic.pay({
        "to": "0xabcdefABCDEFabcdefABCDEFabcdefABCDEFabcd",
        "amount": 100,  # $100 USDC
        "deadline": "24h",  # Optional: expires in 24 hours
        "description": "AI text generation service"
    })

    print(f"Transaction ID: {result.tx_id}")
    print(f"Escrow ID: {result.escrow_id}")
    print(f"State: {result.state}")

asyncio.run(main())
```

### Standard API - Full Lifecycle Control

For applications that need explicit control over each transaction step:

```python
import asyncio
from agirails import ACTPClient, StandardTransactionParams

async def main():
    client = await ACTPClient.create(
        mode="mock",
        requester_address="0x1234567890123456789012345678901234567890"
    )

    # Step 1: Create transaction (no funds locked yet)
    tx_id = await client.standard.create_transaction(
        StandardTransactionParams(
            provider="0xabcdefABCDEFabcdefABCDEFabcdefABCDEFabcd",
            amount="100.50",
            deadline="7d",
            dispute_window=172800,  # 2 days in seconds
            description="Complex AI task"
        )
    )
    print(f"Created transaction: {tx_id}")

    # Step 2: Link escrow (locks funds, moves to COMMITTED)
    escrow_id = await client.standard.link_escrow(tx_id)
    print(f"Escrow linked: {escrow_id}")

    # Step 3: Provider delivers work...
    await client.standard.transition_state(tx_id, "DELIVERED", proof="ipfs://...")

    # Step 4: Release funds to provider
    await client.standard.release_escrow(escrow_id)
    print("Payment complete!")

asyncio.run(main())
```

### Advanced API - Direct Runtime Access

For custom workflows and maximum flexibility:

```python
from agirails import ACTPClient, CreateTransactionParams, State

async def main():
    client = await ACTPClient.create(mode="mock", requester_address="0x...")

    # Direct runtime access
    runtime = client.advanced

    # Create transaction with full control
    tx_id = await runtime.create_transaction(CreateTransactionParams(
        requester="0x...",
        provider="0x...",
        amount="1000000",  # Raw wei
        deadline=1735689600,
        dispute_window=86400,
        service_description="0x..."
    ))

    # Get transaction details
    tx = await runtime.get_transaction(tx_id)
    print(f"State: {tx.state}, Amount: {tx.amount}")

asyncio.run(main())
```

## Transaction Lifecycle

ACTP transactions follow an 8-state lifecycle:

```
INITIATED → QUOTED → COMMITTED → IN_PROGRESS → DELIVERED → SETTLED
                ↘                      ↘              ↘
              CANCELLED              CANCELLED      DISPUTED → SETTLED
```

| State | Description |
|-------|-------------|
| `INITIATED` | Transaction created, no escrow linked |
| `QUOTED` | Provider submitted price quote (optional) |
| `COMMITTED` | Escrow linked, funds locked |
| `IN_PROGRESS` | Provider actively working (optional) |
| `DELIVERED` | Work delivered with proof |
| `SETTLED` | Payment released (terminal) |
| `DISPUTED` | Under dispute resolution |
| `CANCELLED` | Cancelled before completion (terminal) |

## Configuration

### Client Modes

```python
# Mock mode - local testing, no blockchain
client = await ACTPClient.create(
    mode="mock",
    requester_address="0x...",
    state_directory=".actp"  # Optional: persist state to disk
)

# Blockchain mode - real transactions (coming soon)
client = await ACTPClient.create(
    mode="blockchain",
    requester_address="0x...",
    private_key="0x...",
    rpc_url="https://sepolia.base.org"
)
```

### Amount Formats

The SDK accepts amounts in multiple formats:

```python
# All equivalent to $100.50 USDC
await client.basic.pay({"to": "0x...", "amount": 100.50})
await client.basic.pay({"to": "0x...", "amount": "100.50"})
await client.basic.pay({"to": "0x...", "amount": "$100.50"})
await client.basic.pay({"to": "0x...", "amount": 100500000})  # Wei
```

### Deadline Formats

```python
# Relative formats
deadline="1h"   # 1 hour from now
deadline="24h"  # 24 hours from now
deadline="7d"   # 7 days from now

# Absolute timestamp
deadline=1735689600  # Unix timestamp

# ISO date string
deadline="2025-01-01T00:00:00Z"
```

## Error Handling

The SDK provides structured exceptions with error codes:

```python
from agirails import (
    ACTPError,
    TransactionNotFoundError,
    InvalidStateTransitionError,
    InsufficientBalanceError,
    ValidationError
)

try:
    await client.basic.pay({"to": "invalid", "amount": 100})
except ValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Error code: {e.code}")
    print(f"Details: {e.details}")
except InsufficientBalanceError as e:
    print(f"Need {e.required}, have {e.available}")
except ACTPError as e:
    print(f"ACTP error [{e.code}]: {e.message}")
```

### Exception Hierarchy

```
ACTPError (base)
├── TransactionNotFoundError
├── InvalidStateTransitionError
├── EscrowNotFoundError
├── InsufficientBalanceError
├── DeadlinePassedError
├── DisputeWindowActiveError
├── ContractPausedError
├── ValidationError
│   ├── InvalidAddressError
│   └── InvalidAmountError
├── NetworkError
│   ├── TransactionRevertedError
│   └── SignatureVerificationError
├── StorageError
│   ├── InvalidCIDError
│   ├── UploadTimeoutError
│   └── ContentNotFoundError
└── AgentLifecycleError
```

## CLI Reference

The SDK includes a full-featured CLI for interacting with ACTP:

### Core Commands

```bash
# Payment operations
agirails pay <to> <amount> [--deadline TIME] [--description TEXT]
agirails balance [ADDRESS]
agirails mint --amount AMOUNT  # Testnet only

# Transaction management
agirails tx list [--state STATE] [--limit N]
agirails tx get <tx_id>
agirails tx cancel <tx_id>

# Time manipulation (mock mode only)
agirails time advance <seconds>
agirails time set <timestamp>
agirails time now
```

### Agent-First Features

```bash
# Watch transaction state changes (streams updates)
agirails watch <tx_id> [--interval SECONDS] [--format json|text]

# Batch operations from file
agirails batch <command_file> [--parallel N] [--continue-on-error]

# Dry-run simulation
agirails simulate pay <to> <amount>
agirails simulate fee <amount>
```

### Configuration

```bash
# Set configuration
agirails config set <key> <value>
agirails config get <key>
agirails config list
agirails config reset

# Available config keys:
#   network: base-sepolia | base-mainnet | mock
#   rpc-url: RPC endpoint URL
#   private-key: Wallet private key (or use AGIRAILS_PRIVATE_KEY env)
#   state-directory: Directory for mock state persistence
```

### Output Formats

```bash
# Human-readable (default)
agirails tx list

# JSON output for scripting
agirails tx list --format json

# NDJSON streaming for watch
agirails watch TX_ID --format ndjson
```

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_client.py

# Run tests matching pattern
pytest -k "test_pay"
```

## API Reference

### ACTPClient

| Method | Description |
|--------|-------------|
| `ACTPClient.create()` | Factory method to create client |
| `client.basic` | Access basic adapter |
| `client.standard` | Access standard adapter |
| `client.advanced` | Access runtime directly |
| `client.get_balance()` | Get USDC balance |
| `client.reset()` | Reset mock state |

### BasicAdapter

| Method | Description |
|--------|-------------|
| `pay(params)` | Create and fund transaction |
| `get_transaction(tx_id)` | Get transaction details |
| `get_balance()` | Get formatted balance |

### StandardAdapter

| Method | Description |
|--------|-------------|
| `create_transaction(params)` | Create transaction |
| `link_escrow(tx_id)` | Link escrow and lock funds |
| `transition_state(tx_id, state)` | Transition to new state |
| `release_escrow(escrow_id)` | Release funds |
| `get_transaction(tx_id)` | Get transaction details |
| `get_all_transactions()` | List all transactions |

## Level 0 & Level 1 APIs

### Level 0 - Low-level Primitives

```python
from agirails import ServiceDirectory, Provider, request, provide

# Register a service
directory = ServiceDirectory()
directory.register("text-gen", provider_address="0x...", capabilities=["gpt-4"])

# Find providers
providers = directory.find(ServiceQuery(capabilities=["gpt-4"]))
```

### Level 1 - Agent Framework

```python
from agirails import Agent, AgentConfig, Job

# Create an agent
agent = Agent(AgentConfig(
    name="my-agent",
    address="0x...",
    services=["text-generation"]
))

# Handle jobs
@agent.on_job
async def handle_job(job: Job) -> str:
    return f"Processed: {job.input}"

await agent.start()
```

## SDK Parity

This Python SDK maintains **full parity** with the TypeScript SDK:

| Feature | Python SDK | TypeScript SDK |
|---------|------------|----------------|
| DeliveryProof Schema | AIP-4 v1.1 (12 fields) | AIP-4 v1.1 (12 fields) |
| Result Hashing | keccak256 | keccak256 |
| JSON Canonicalization | Insertion order | Insertion order |
| EIP-712 Signing | Full support | Full support |
| Level0 API | Full ACTP flow | Full ACTP flow |
| Level1 Agent API | Complete | Complete |
| CLI Commands | watch, batch, simulate | watch, batch, simulate |
| Nonce Tracking | SecureNonce, ReceivedNonceTracker | SecureNonce, ReceivedNonceTracker |
| Attestation Tracking | UsedAttestationTracker | UsedAttestationTracker |

**Shared Test Vectors**: Both SDKs use the same JSON test fixtures in `tests/fixtures/parity/` to ensure identical behavior.

## Security

- **Timing-safe comparisons** for signature verification
- **Path traversal protection** for file operations
- **Safe JSON parsing** removes prototype pollution keys
- **Input validation** for all user inputs
- **Query caps** to prevent DoS attacks

## Platform Notes

### Windows File Locking Limitation

The SDK uses `fcntl.flock()` for atomic file operations in the `MockStateManager`. This is **only available on Unix-like systems** (Linux, macOS).

**Impact on Windows**:
- `MockStateManager` file locking is disabled (graceful degradation)
- State persistence still works, but without locking protection
- **Production environments on Windows should use blockchain mode** instead of mock mode

**Workaround for Windows Development**:
```python
# Windows users should use mock mode without file persistence
client = await ACTPClient.create(mode="mock", persist_state=False)
```

For production deployments on Windows, use the blockchain runtime:
```python
client = await ACTPClient.create(mode="blockchain", rpc_url="https://...")
```

## Requirements

- Python 3.9+
- Dependencies: web3, eth-account, pydantic, aiofiles, httpx

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.

## Links

- [Documentation](https://docs.agirails.io)
- [GitHub](https://github.com/agirails/python-sdk)
- [AGIRAILS Website](https://agirails.io)
