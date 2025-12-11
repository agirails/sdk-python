# AGIRAILS Python SDK (MVP)

Minimal Web3.py client for ACTP on-chain operations (Base Sepolia). Not published to PyPI yet.

[![CI](https://github.com/agirails/AGIRAILS/actions/workflows/sdk-python-ci.yml/badge.svg)](https://github.com/agirails/AGIRAILS/actions/workflows/sdk-python-ci.yml)

## Features
- Connect with private key + RPC (Base Sepolia default)
- `create_transaction` (provider, requester, amount, deadline, dispute_window, service_hash)
- `link_escrow` (USDC approve → Kernel.linkEscrow to approved EscrowVault)
- `transition_state` (admin/bot settlement path)
- `get_transaction` returns full `TransactionView`
- Helpers: `fund_transaction`, `submit_quote`, `deliver`, `dispute`, `cancel`, `release_milestone`, `release_escrow`, `release_escrow_with_verification`, `anchor_attestation`, `get_escrow_status`
- Agent Registry helpers (AIP-7): `register_agent`, `update_endpoint`, `add_service_type`, `remove_service_type`, `set_active_status`, `get_agent`, `get_service_descriptors`

## Install
```bash
pip install -e .
```

## Usage
```python
from agirails_sdk import ACTPClient, Network, State

client = ACTPClient(network=Network.BASE_SEPOLIA, private_key="0x...")

# Create (must be requester)
tx_id = client.create_transaction(
    provider="0xProvider...",
    requester=client.address,  # must match signer
    amount=1_000_000,          # 1 USDC (6 decimals)
    deadline=client.now() + 86400,
    dispute_window=3600,
    service_hash="0x" + "00"*32,
)

# Quote (provider flow)
client.submit_quote(tx_id, "0x" + "ab"*32)

# Fund (approve USDC to EscrowVault + linkEscrow)
escrow_id = client.fund_transaction(tx_id)

# Deliver -> Dispute window (optional)
client.deliver(tx_id, dispute_window_seconds=3600)

# Dispute or cancel if needed
client.dispute(tx_id)
client.cancel(tx_id)

# Settle (admin/bot) or verify delivery attestation then settle (requires EAS config)
client.transition_state(tx_id, State.SETTLED)
client.release_escrow_with_verification(tx_id, "0xAttestationUID...")

# Check escrow status (read-only)
is_active, escrow_amount = client.get_escrow_status(
    None,
    escrow_id,
    expected_requester=client.address,
    expected_provider="0xProvider...",
    expected_amount=1_000_000,
)
print(is_active, escrow_amount)
```

### Notes
- Uses on-chain EscrowVault (kernel signature: `linkEscrow(txId, escrowVault, escrowId)`).
- Dispute window minimum 1h (enforced by contract).
- Gas settings are static defaults (EIP-1559). Tune if needed.
- Alpha: install via source (`pip install -e .` or `pip install .`); PyPI package not yet published.

## Custom RPC / Escrow vault
```python
client = ACTPClient(network=Network.BASE_SEPOLIA, private_key="0x...", rpc_url="https://custom-rpc.example")
# Override vault per call
escrow_id = client.link_escrow(tx_id, escrow_contract="0xYourVault...")
```

## Known limitations
- Alpha, no PyPI release yet.
- EAS verification optional; Base mainnet addresses are placeholders.
- Uses synchronous Web3.py; no async API.

## Release checklist (manual)
```bash
python -m pip install --upgrade pip build twine
python -m build
twine check dist/*
# twine upload dist/*   # only when ready to publish
```

## Tests
```bash
pip install -e . pytest
pytest
```

## Dev tools
- Ruff (`ruff check .`), Black (`black --check .`), Mypy (`mypy src`)
- GitHub Actions workflow: `.github/workflows/sdk-python-ci.yml`
