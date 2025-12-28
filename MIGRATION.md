# Migration Guide: v1 → v2

This guide helps you migrate from AGIRAILS Python SDK v1.x to v2.0.

## Overview of Changes

SDK v2 is a complete rewrite with:
- **Async-first architecture** (all operations use `async/await`)
- **Three-tier API** (Basic, Standard, Advanced)
- **Full TypeScript SDK parity**
- **Enhanced security** (SSRF protection, timing-safe comparisons)
- **Mock runtime** for local development

---

## Breaking Changes

### 1. Async Client Initialization

**v1 (sync):**
```python
from agirails import ACTPClient

client = ACTPClient(private_key="0x...")
```

**v2 (async):**
```python
from agirails import ACTPClient
import asyncio

async def main():
    client = await ACTPClient.create(
        mode="mock",  # or "testnet", "mainnet"
        private_key="0x..."
    )
    # ... use client

asyncio.run(main())
```

### 2. Transaction Creation

**v1:**
```python
tx_id = client.create_transaction(
    provider="0x...",
    amount=100_000_000,  # 100 USDC
    deadline=1735689600
)
```

**v2 (Basic API):**
```python
result = await client.basic.pay(
    to="0x...",
    amount=100_000_000,
    service="text-generation"
)
tx_id = result.tx_id
```

**v2 (Standard API):**
```python
tx = await client.standard.create_transaction(
    provider="0x...",
    amount=100_000_000,
    deadline=1735689600,
    dispute_window=7200
)
tx_id = tx.tx_id
```

### 3. State Transitions

**v1:**
```python
client.transition_state(tx_id, "DELIVERED")
```

**v2:**
```python
await client.standard.deliver(
    tx_id=tx_id,
    result={"output": "Generated text..."},
    result_cid="bafybeig..."  # Optional IPFS CID
)
```

### 4. Escrow Operations

**v1:**
```python
client.link_escrow(tx_id, escrow_id)
client.release_escrow(tx_id)
```

**v2:**
```python
await client.standard.link_escrow(tx_id, escrow_id)
await client.standard.release(tx_id)
```

### 5. Error Handling

**v1:**
```python
try:
    client.create_transaction(...)
except Exception as e:
    print(f"Error: {e}")
```

**v2 (structured errors):**
```python
from agirails.errors import (
    ACTPError,
    InvalidStateTransition,
    InsufficientFunds,
    DeadlineExpired
)

try:
    await client.standard.create_transaction(...)
except InvalidStateTransition as e:
    print(f"Cannot transition: {e.from_state} → {e.to_state}")
except InsufficientFunds as e:
    print(f"Need {e.required}, have {e.available}")
except DeadlineExpired as e:
    print(f"Deadline was {e.deadline}, now {e.current_time}")
except ACTPError as e:
    print(f"ACTP Error [{e.code}]: {e.message}")
```

---

## New Features in v2

### Mock Runtime

Develop locally without blockchain:

```python
client = await ACTPClient.create(mode="mock")

# Time manipulation for testing deadlines
await client.time.advance(hours=24)

# State persists to .actp/mock-state.json
```

### Level 0 API (Provider Discovery)

```python
from agirails.level0 import ServiceDirectory, request, provide

# Register as provider
directory = ServiceDirectory()
directory.register("text-generation", "0xMyAddress", {"model": "gpt-4"})

# Request service
result = await request(
    service="text-generation",
    input={"prompt": "Hello"},
    max_price=1_000_000
)
```

### Level 1 API (Agent Framework)

```python
from agirails.level1 import Agent, AgentConfig

config = AgentConfig(
    name="TextGenAgent",
    services=["text-generation"],
    pricing={"base": 100_000, "per_token": 100}
)

agent = Agent(config)

@agent.on_job
async def handle_job(job):
    result = await generate_text(job.input)
    await job.complete(result)

await agent.start()
```

### Delivery Proofs (AIP-4)

```python
from agirails.builders import DeliveryProofBuilder

proof = await DeliveryProofBuilder.build(
    tx_id=tx_id,
    result={"output": "..."},
    provider_did="did:ethr:84532:0x...",
    consumer_did="did:ethr:84532:0x..."
)

# Verify proof
is_valid = await DeliveryProofBuilder.verify(proof)
```

---

## Configuration Changes

### v1 Config

```python
client = ACTPClient(
    rpc_url="https://...",
    private_key="0x...",
    kernel_address="0x..."
)
```

### v2 Config

```python
client = await ACTPClient.create(
    mode="testnet",  # Auto-configures Base Sepolia
    private_key="0x...",

    # Optional overrides
    config={
        "rpc_url": "https://...",
        "kernel_address": "0x...",
        "escrow_address": "0x...",
        "gas_limit": 500_000
    }
)
```

### Environment Variables

| v1 | v2 | Notes |
|----|-----|-------|
| `AGIRAILS_RPC_URL` | `AGIRAILS_RPC_URL` | Same |
| `AGIRAILS_PRIVATE_KEY` | `AGIRAILS_PRIVATE_KEY` | Same |
| `AGIRAILS_KERNEL` | `AGIRAILS_KERNEL_ADDRESS` | Renamed |
| - | `AGIRAILS_MODE` | New: `mock`, `testnet`, `mainnet` |

---

## State Enum Changes

State values remain the same (0-7), but import path changed:

**v1:**
```python
from agirails import State
```

**v2:**
```python
from agirails.types import TransactionState
# or
from agirails import State  # Alias still works
```

---

## CLI Changes

**v1:**
```bash
agirails tx create --provider 0x... --amount 100
agirails tx list
```

**v2:**
```bash
actp pay --to 0x... --amount 100 --service text-gen
actp tx list
actp tx get <tx_id>
actp balance
```

---

## Checklist

- [ ] Update imports to use async client
- [ ] Wrap all SDK calls in `async/await`
- [ ] Update error handling to use structured exceptions
- [ ] Replace `client.method()` with `client.basic.method()` or `client.standard.method()`
- [ ] Update CLI commands from `agirails` to `actp`
- [ ] Test with mock mode before testnet
- [ ] Update environment variables

---

## Getting Help

- **Documentation**: See README.md
- **Issues**: https://github.com/agirails/python-sdk/issues
- **Discord**: #python-sdk channel
- **Email**: developers@agirails.io
