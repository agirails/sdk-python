# AGIRAILS Python SDK

[![PyPI](https://img.shields.io/pypi/v/agirails.svg)](https://pypi.org/project/agirails/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-1738%20passed-brightgreen.svg)]()

The official Python SDK for the **Agent Commerce Transaction Protocol (ACTP)** — enabling AI agents to transact with each other through blockchain-based escrow on Base L2.

**Full 1:1 parity with TypeScript SDK v2.5.0+.**

## Install

```bash
pip install agirails==2.3.1
```

## Features

- **Adapter Routing** — priority-based adapter selection (Standard, Basic, X402)
- **x402 Payments** — HTTP-based instant payments with relay fee splitting
- **ERC-8004 Identity** — on-chain agent identity resolution and reputation
- **Keystore Security (AIP-13)** — fail-closed private key policy, `ACTP_KEYSTORE_BASE64` for CI/CD
- **AGIRAILS.md Source of Truth** — parse, hash, publish, pull, diff agent configs
- **Smart Wallet (ERC-4337)** — batched transactions with paymaster gas sponsorship
- **Lazy Publish** — mainnet activation deferred to first real transaction
- **Three-tier API** — Basic, Standard, and Advanced levels
- **Mock Runtime** — full local testing without blockchain
- **CLI** — `actp pay`, `publish`, `pull`, `diff`, `deploy:env`, `deploy:check`
- **Async-first** — built on asyncio
- **1,738 tests passing**

## Quick Start

```python
import asyncio
from agirails import ACTPClient

async def main():
    client = await ACTPClient.create(mode="mock", requester_address="0x1234...")

    # Adapter router auto-selects the best path
    # EVM address → ACTP (StandardAdapter)
    result = await client.pay({"to": "0xProvider...", "amount": "10.00"})

    # HTTP URL → x402 instant payment
    result = await client.pay({"to": "https://api.example.com/pay", "amount": "5.00"})

    # Agent ID → ERC-8004 resolve → ACTP
    result = await client.pay({"to": "12345", "amount": "10.00"})

    print(f"Transaction: {result.tx_id}, State: {result.state}")

asyncio.run(main())
```

## Adapter Routing

Priority-based adapter selection matching TypeScript `AdapterRouter`:

| Adapter | Priority | Target | Use Case |
|---------|----------|--------|----------|
| **X402Adapter** | 70 | `https://...` URLs | Instant HTTP payments with relay fee splitting |
| **StandardAdapter** | 60 | `0x...` addresses | Full ACTP lifecycle with escrow |
| **BasicAdapter** | 50 | `0x...` addresses | Simple pay-and-forget (Smart Wallet batched) |

## Keystore & Deployment Security (AIP-13)

Fail-closed private key policy with network-aware enforcement:

| Network | `ACTP_PRIVATE_KEY` | Behavior |
|---------|-------------------|----------|
| mock | Allowed | Silent |
| testnet (base-sepolia) | Allowed | Warn once |
| mainnet (base-mainnet) | Blocked | Hard fail |

**Resolution order:** `ACTP_PRIVATE_KEY` → `ACTP_KEYSTORE_BASE64` + `ACTP_KEY_PASSWORD` → `.actp/keystore.json` → `None`

```bash
# Generate base64 keystore for CI/CD
actp deploy:env

# Scan repo for exposed secrets
actp deploy:check
```

## AGIRAILS.md Config Management

```bash
actp publish --network base-sepolia    # Hash + upload to IPFS + register on-chain
actp pull --network base-sepolia       # Fetch config from chain
actp diff --network base-sepolia       # Compare local vs on-chain
```

## Transaction Lifecycle

```
INITIATED → QUOTED → COMMITTED → IN_PROGRESS → DELIVERED → SETTLED
                ↘                      ↘              ↘
              CANCELLED              CANCELLED      DISPUTED → SETTLED
```

## CLI

```bash
# Payments
actp pay <to> <amount> [--deadline TIME]
actp balance [ADDRESS]

# Transaction management
actp tx list [--state STATE]
actp tx status <tx_id>
actp tx deliver <tx_id>
actp tx settle <tx_id>

# Config sync
actp publish [path]
actp pull [path] [--network NETWORK]
actp diff [path] [--network NETWORK]

# Deployment security
actp deploy:env
actp deploy:check [path] [--fix]

# Mock mode
actp mint <address> <amount>
actp time advance <duration>
```

## SDK Parity

Full 1:1 parity with TypeScript SDK v2.5.0+:

| Feature | Python | TypeScript |
|---------|--------|------------|
| Adapter Routing | AdapterRouter + 3 adapters | AdapterRouter + 3 adapters |
| x402 Payments | X402Adapter with relay | X402Adapter with relay |
| ERC-8004 Identity | ERC8004Bridge + ReputationReporter | ERC8004Bridge + ReputationReporter |
| Keystore AIP-13 | Full (30-min TTL cache) | Full (30-min TTL cache) |
| AGIRAILS.md SOT | parse, hash, publish, pull, diff | parse, hash, publish, pull, diff |
| Smart Wallet | ERC-4337 scaffolding | ERC-4337 full |
| Lazy Publish | pending-publish lifecycle | pending-publish lifecycle |
| CLI Commands | pay, publish, pull, diff, deploy:* | pay, publish, pull, diff, deploy:* |
| State Machine | 8 states, all transitions | 8 states, all transitions |
| Cross-SDK Tests | Shared test vectors | Shared test vectors |

## Testing

```bash
pytest                           # Run all 1,738 tests
pytest -v                        # Verbose output
pytest tests/test_adapters/      # Adapter tests only
pytest -k "test_pay"             # Pattern match
```

## Requirements

- Python 3.9+
- Dependencies: web3, eth-account, pydantic, aiofiles, httpx, typer, rich

## Links

- [PyPI](https://pypi.org/project/agirails/)
- [Documentation](https://docs.agirails.io)
- [GitHub](https://github.com/agirails/sdk-python)
- [Discord](https://discord.gg/nuhCt75qe4)

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
