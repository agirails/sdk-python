#!/usr/bin/env bash
# Audit follow-up #8 — end-to-end smoke against the installed wheel.
#
# Why this matters beyond source-tree pytest:
#   - Packaging issues that source-tree tests can't see:
#     * src/agirails/X.py exists but isn't included in the wheel
#       (manifest miss, hatchling exclude rule, etc.)
#     * __init__.py doesn't re-export something promised in CHANGELOG
#       (we read it from the installed dist, not from src/)
#     * Entry point (`actp` CLI) installed but doesn't actually invoke
#     * Optional extras [server] / [dev] declared but mis-wired
#
# Run from the python-sdk-v2 directory:
#
#   bash scripts/test_installed_wheel.sh
#
# What it does:
#   1. Builds wheel + sdist into ./dist/
#   2. Creates a fresh venv at /tmp/agirails-wheel-smoke
#   3. Installs the wheel (no editable, no source-tree fallback)
#   4. Runs a battery of smoke checks:
#      - Version reads as 3.0.0bN
#      - All top-level re-exports import successfully
#      - Sub-package imports succeed (server, receipts, wallet, builders,
#        cli/lib, adapters)
#      - actp CLI entry point launches and shows help
#      - Optional [server] extra adds FastAPI/uvicorn
#      - Mainnet V3 + Sepolia V4 contract addresses present
#      - Hash routing parity check (Agent.provide reaches keccak-routed tx)
#
# Exit 0 = wheel installs and works as documented.
# Exit non-zero = packaging regression; investigate before publish.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== build =="
rm -rf dist/ build/
python3 -m pip install --quiet --upgrade build
python3 -m build --wheel --sdist 2>&1 | tail -3

WHEEL=$(ls dist/agirails-*-py3-none-any.whl | head -1)
echo "wheel: $WHEEL"

echo "== fresh venv =="
SMOKE_VENV=/tmp/agirails-wheel-smoke-$$
rm -rf "$SMOKE_VENV"
python3 -m venv "$SMOKE_VENV"

# Trap to clean up venv even on failure.
trap 'rm -rf "$SMOKE_VENV"' EXIT

"$SMOKE_VENV/bin/pip" install --quiet --upgrade pip
"$SMOKE_VENV/bin/pip" install --quiet "$WHEEL"

echo "== imports =="
"$SMOKE_VENV/bin/python" - <<'PYEOF'
import re
import sys

import agirails
print(f"version: {agirails.__version__}")
assert re.match(r"^\d+\.\d+\.\d+", agirails.__version__), \
    f"version {agirails.__version__} is not a valid semantic version"

# Top-level re-exports promised in CHANGELOG.
from agirails import (
    ACTPClient, ACTPClientConfig,
    BasicAdapter, StandardAdapter, X402Adapter,
    AutoWalletProvider, EOAWalletProvider, IWalletProvider,
    ERC8004Bridge, ReputationReporter, discover_agents,
    compute_transaction_id,
    QuoteBuilder, DeliveryProofBuilder,
    CounterOfferBuilder, CounterAcceptBuilder, MessageNonceManager,
    upload_receipt, ReceiptUploadPayload, ReceiptUploadOptions,
)
print("top-level imports: OK")

# Sub-package imports (base — no FastAPI yet).
# `create_app` is lazy-loaded via __getattr__ so the package imports
# cleanly without [server] extras; we exercise it AFTER installing
# [server] further down.
from agirails.server import ProviderPolicy, QuoteChannelHandler  # noqa: F401
from agirails.wallet.smart_wallet_router import SmartWalletRouter  # noqa: F401
from agirails.cli.lib.run_request import run_request  # noqa: F401
from agirails.receipts.web_receipt import (
    upload_receipt as _ur, ReceiptUploadFailure,
)  # noqa: F401
print("sub-package imports: OK")

# Network config sanity (the mainnet V3 + Sepolia V4 addresses we
# committed in the sprint).
from agirails.config.networks import get_network
m = get_network("base-mainnet")
assert m.contracts.actp_kernel.lower() == \
    "0x048c811352e8a3fecd5b0ec4aa2c2b94083cc842"
assert m.actp_kernel_deployment_block == 46_212_266
s = get_network("base-sepolia")
assert s.contracts.actp_kernel.lower() == \
    "0x9d25a874f046185d9237cd4954c88d2b74b0021b"
assert s.actp_kernel_deployment_block == 41_725_686
print(f"mainnet kernel: {m.contracts.actp_kernel}")
print(f"sepolia kernel: {s.contracts.actp_kernel}")

# Hash routing parity end-to-end against installed wheel.
import asyncio
from eth_hash.auto import keccak
from agirails.level1.agent import Agent, AgentConfig
from types import SimpleNamespace

async def hash_routing_smoke():
    agent = Agent(AgentConfig(name="smoke"))
    async def _h(job):
        return {"ok": True}
    agent.provide("onboarding", handler=_h)
    tx = SimpleNamespace(
        service_description="0x" + keccak(b"onboarding").hex()
    )
    reg = agent._find_service_handler(tx)
    assert reg is not None, "hash routing broken in installed wheel"
    assert reg.config.name == "onboarding"
asyncio.run(hash_routing_smoke())
print("hash routing: OK (installed wheel finds keccak-routed handler)")

print("\nALL IMPORTS + WIRING CHECKS PASSED")
PYEOF

echo "== CLI entry point =="
"$SMOKE_VENV/bin/actp" --help > /dev/null
echo "actp --help: OK"

echo "== [server] extra opt-in =="
# Without [server] extra: actp serve should fail with install hint.
set +e
SERVE_OUT=$("$SMOKE_VENV/bin/actp" serve --policy /dev/null --mock --port 8889 2>&1 | head -5)
set -e
if echo "$SERVE_OUT" | grep -q "pip install agirails\[server\]"; then
    echo "actp serve gracefully points at [server] extra: OK"
else
    echo "WARNING: actp serve didn't surface the [server] install hint:"
    echo "$SERVE_OUT"
    exit 1
fi

# With [server] extra: server package imports work AND lazy create_app
# now resolves (the __getattr__ trampoline imports the FastAPI factory).
"$SMOKE_VENV/bin/pip" install --quiet "$WHEEL[server]" 2>&1 | tail -2
"$SMOKE_VENV/bin/python" -c "
import fastapi, uvicorn
from agirails.server import create_app  # lazy-load via __getattr__
print(f'fastapi {fastapi.__version__} + uvicorn {uvicorn.__version__} import OK')
print(f'create_app from agirails.server: {create_app!r}')
assert callable(create_app)
"
echo "[server] extra + lazy create_app: OK"

echo
echo "=== ALL CHECKS PASSED ==="
echo "Wheel $(basename "$WHEEL") is ready to publish."
