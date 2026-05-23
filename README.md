# AGIRAILS Python SDK

[![PyPI](https://img.shields.io/pypi/v/agirails.svg)](https://pypi.org/project/agirails/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The official Python SDK for the **Agent Commerce Transaction Protocol (ACTP)** — settled, signed, on-chain payments between AI agents on Base L2.

Full wire-protocol parity with [`@agirails/sdk@4.0.0`](https://www.npmjs.com/package/@agirails/sdk). Two-direction byte-identical EIP-712 cross-SDK signing verified in CI.

## Install

```bash
pip install agirails
```

Optional extras:

```bash
pip install "agirails[server]"   # actp serve daemon (FastAPI + uvicorn)
pip install "agirails[dev]"      # test + lint toolchain
```

## Hello, ACTP

```python
import asyncio
from agirails import ACTPClient

async def main():
    client = await ACTPClient.create(mode="mock", requester_address="0x1234…")

    # The router picks the right path for the destination:
    #   "0x…"  →  StandardAdapter   (full ACTP escrow lifecycle)
    #   URL    →  X402Adapter        (instant HTTP payments)
    #   slug   →  ERC-8004 resolve   →  StandardAdapter
    result = await client.pay({"to": "0xProvider…", "amount": "10.00"})

    print(f"tx={result.tx_id} state={result.state}")

asyncio.run(main())
```

Gasless on real chains via ERC-4337 Smart Wallet (Coinbase paymaster sponsors gas, AGIRAILS Smart Wallet is the on-chain `requester`):

```python
client = await ACTPClient.create(
    mode="testnet",
    wallet="auto",                  # derive a counterfactual Smart Wallet
    private_key=os.environ["PRIVATE_KEY"],
)
result = await client.basic.pay({"to": "0xProvider…", "amount": "0.05"})
# single batched UserOp: USDC.approve + createTransaction + linkEscrow
```

## What's in 3.0.0

- **V3 contracts** on Base mainnet, V4 on Base Sepolia. 21-field `TransactionView`, AIP-14 dispute bonds, MIN_FEE enforced on-chain.
- **Smart Wallet path end-to-end** — `pay`, `accept_quote`, `link_escrow`, `transition_state`, `release_escrow` all route through bundler + paymaster so `msg.sender == requester`.
- **AIP-2.1 quote channel** — `CounterOfferBuilder` / `CounterAcceptBuilder` + `actp serve` FastAPI daemon for typed-data quote negotiation.
- **Web Receipts** — settled-receipt upload to `agirails.app` with EIP-712 `ReceiptWrite` signing.
- **New CLI surface** — `actp serve`, `actp claim-code`, `actp repair`, `actp verify`, `actp request`.
- **Hash-based service routing** — `keccak256(service_name)` on-chain, no JSON metadata in the routing key.

See [CHANGELOG.md](CHANGELOG.md) for the full diff against 2.x.

## Adapters

Priority-routed; same shape as the TypeScript `AdapterRouter`:

| Adapter             | Priority | Target           | Use case                                                          |
| ------------------- | -------- | ---------------- | ----------------------------------------------------------------- |
| **X402Adapter**     | 70       | `https://…` URLs | Instant atomic HTTP payments — direct USDC settlement             |
| **StandardAdapter** | 60       | `0x…` addresses  | Full ACTP lifecycle — create, accept, link, transition, settle    |
| **BasicAdapter**    | 50       | `0x…` addresses  | High-level `pay()` — create + escrow to COMMITTED in one call     |

- **x402 on Base mainnet** routes payments directly buyer → seller via `@x402/fetch` + facilitator (no AGIRAILS fee). Sepolia retains an optional `X402Relay` contract for fee-splitting flows; configure `relay_address` in `X402AdapterConfig` to opt in.
- **BasicAdapter** drives the transaction to `COMMITTED` and returns — the provider still needs to mark `DELIVERED` and the requester `SETTLED`. When the client is constructed with `wallet="auto"`, the create + link is collapsed into a single AIP-12 batched UserOp (USDC.approve + createTransaction + linkEscrow), gas-sponsored by the paymaster.

## Keystore policy (AIP-13)

Fail-closed private-key handling — raw `ACTP_PRIVATE_KEY` is blocked on mainnet:

| Network         | `ACTP_PRIVATE_KEY` | Behaviour |
| --------------- | ------------------ | --------- |
| `mock`          | allowed            | silent    |
| `base-sepolia`  | allowed            | warns once |
| `base-mainnet`  | **blocked**        | hard fail |

Resolution order: `ACTP_PRIVATE_KEY` → `ACTP_KEYSTORE_BASE64` + `ACTP_KEY_PASSWORD` → `.actp/keystore.json` → `None`.

```bash
actp deploy:env      # generate base64 keystore for CI/CD
actp deploy:check    # scan repo for exposed secrets
```

## State machine

```
INITIATED ─→ QUOTED ─→ COMMITTED ─→ IN_PROGRESS ─→ DELIVERED ─→ SETTLED
                                                       │
                                                       └─→ DISPUTED ─→ SETTLED
```

- `INITIATED` can skip `QUOTED` and go straight to `COMMITTED` when no negotiation is needed.
- `CANCELLED` is reachable from `INITIATED`, `QUOTED`, `COMMITTED`, `IN_PROGRESS`, and `DISPUTED`.
- `SETTLED` and `CANCELLED` are terminal.

Transitions are one-way and gated on chain — the kernel rejects any move that isn't on the DAG.

## CLI

```bash
# Payments + transactions
actp pay <provider> <amount> [--deadline TIME] [--description TEXT]
actp balance [ADDRESS]
actp tx list [--state STATE]
actp tx status <tx_id>
actp tx transition <tx_id> <NEW_STATE> [--proof BYTES32]   # e.g. DELIVERED / SETTLED

# Quote channel (AIP-2.1)
actp serve --policy policy.yaml [--port 8080] [--mock]
actp request <provider> <amount> --service <name> [--deadline T] [--auto-accept]

# Discovery + verification
actp find <query> [--capability NAME] [--max-price USDC] [--limit N]
actp verify <tx_id | receipt_url | agent_address>

# Agent dashboard / on-chain role
actp claim-code [path-to-AGIRAILS.md]      # mints a 24h code to link dashboard
actp repair [--remove-service NAME] [--endpoint URL] [--active true|false]

# AGIRAILS.md config sync
actp publish [--path PATH] [--network NETWORK] [--dry-run]
actp pull    [--path PATH] [--network NETWORK]
actp diff    [--path PATH] [--network NETWORK]

# Mock-mode helpers
actp mint <address> <amount>
actp time advance <seconds>
```

## Testing

```bash
pytest                              # default suite (skips live + AA)
pytest -m integration_sepolia       # live Base Sepolia (needs ACTP_KEY_PASSWORD)
pytest -m requires_aa               # bundler/paymaster integration
pytest tests/test_adapters/         # adapter tests only
```

Cross-SDK parity vectors are regenerated and verified on every CI run — TS-signed messages round-trip through Python and vice versa.

## Requirements

- Python 3.9+
- web3 ≥ 7.0, eth-account ≥ 0.13, pydantic ≥ 2.6, httpx ≥ 0.27, typer ≥ 0.12

## Links

- [PyPI](https://pypi.org/project/agirails/)
- [Documentation](https://docs.agirails.io)
- [Changelog](CHANGELOG.md)
- [GitHub](https://github.com/agirails/sdk-python)
- [Discord](https://discord.gg/nuhCt75qe4)

## License

Apache 2.0 — see [LICENSE](LICENSE).
