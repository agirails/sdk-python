"""Shared fixtures for live Base sepolia integration tests.

These tests are gated behind ``-m integration_sepolia`` and need:
  - ``ACTP_KEY_PASSWORD`` env var: keystore decryption password
  - Keystore file at ``~/.actp/mainnet-deployer/deployer``
  - Sepolia ETH on the signer (deployer EOA already has ~0.002 ETH from
    the timelock execution prep on 2026-05-23)

Cost per full run: ~3-5 sepolia transactions = ~0.0005 ETH.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Tuple

import pytest

# Keystore location is machine-specific; override via ACTP_KEYSTORE_PATH.
# Defaults to the per-user ~/.actp location (no hardcoded username).
KEYSTORE_PATH = Path(
    os.environ.get("ACTP_KEYSTORE_PATH", str(Path.home() / ".actp/mainnet-deployer/deployer"))
)
EXPECTED_SIGNER = os.environ.get(
    "ACTP_EXPECTED_SIGNER", "0x1c4e1e01adc3bbbc7b2336e690aae54a6eb4eb1a"
).lower()
SEPOLIA_RPC = "https://sepolia.base.org"
SEPOLIA_KERNEL = "0x9d25A874f046185d9237Cd4954C88D2B74B0021b"
SEPOLIA_REGISTRY_EXPECTED = "0xD91F9aBfBf60b4a2Fd5317ab0cDF3F44faB5D656"
SEPOLIA_USDC = "0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb"


@pytest.fixture(scope="session")
def sepolia_signer():
    """Decrypt the mainnet-deployer keystore once per session.

    The same EOA works on sepolia (different chain, same key). Tests
    re-use the signer to avoid repeated decryption + module-level
    secrets.
    """
    pw = os.environ.get("ACTP_KEY_PASSWORD")
    if not pw:
        pytest.skip(
            "ACTP_KEY_PASSWORD not set — integration tests need keystore "
            "password. Export the env var then re-run with "
            "`pytest -m integration_sepolia`."
        )
    if not KEYSTORE_PATH.exists():
        pytest.skip(f"Keystore not found at {KEYSTORE_PATH}")

    from eth_account import Account

    with open(KEYSTORE_PATH) as f:
        keystore = json.load(f)
    try:
        private_key = Account.decrypt(keystore, pw)
    except ValueError as e:
        pytest.skip(f"Keystore decryption failed: {e}")
    signer = Account.from_key(private_key)
    # Smoke: confirm we got the expected mainnet-deployer EOA so we
    # don't accidentally use a wrong keystore.
    assert signer.address.lower() == EXPECTED_SIGNER
    return signer


@pytest.fixture(scope="session")
def sepolia_w3():
    """AsyncWeb3 (well, sync Web3) connection to Base sepolia."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        # Some public RPCs answer is_connected() with False on first
        # attempt; try a real call before giving up.
        try:
            _ = w3.eth.chain_id
        except Exception:
            pytest.skip("Base sepolia RPC unreachable")
    return w3


@pytest.fixture(scope="session")
def kernel_contract(sepolia_w3):
    from web3 import Web3

    abi = [
        {
            "type": "function",
            "name": "agentRegistry",
            "inputs": [],
            "outputs": [{"type": "address"}],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "platformFeeBps",
            "inputs": [],
            "outputs": [{"type": "uint16"}],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "MIN_FEE",
            "inputs": [],
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
        },
    ]
    return sepolia_w3.eth.contract(
        address=Web3.to_checksum_address(SEPOLIA_KERNEL),
        abi=abi,
    )
