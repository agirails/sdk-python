"""
Account Abstraction constants for CoinbaseSmartWallet on Base.

EntryPoint v0.6 -- CoinbaseSmartWallet hardcodes this version.
Factory address is canonical across all Base networks.

This is a 1:1 port of sdk-js/src/wallet/aa/constants.ts.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ERC-4337 EntryPoint v0.6 (canonical, all EVM chains)
ENTRYPOINT_V06 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

# CoinbaseSmartWallet factory (canonical, all Base networks)
SMART_WALLET_FACTORY = "0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842"

# Default nonce for first Smart Wallet per owner
DEFAULT_WALLET_NONCE = 0


@dataclass(frozen=True)
class SmartWalletCall:
    """CoinbaseSmartWallet Call struct for executeBatch."""

    target: str
    value: int = 0  # wei
    data: str = "0x"  # hex encoded calldata


@dataclass
class UserOperationV06:
    """UserOperation v0.6 struct -- 11 unpacked fields.

    CoinbaseSmartWallet does NOT support v0.7 packed format.
    """

    sender: str = ""
    nonce: int = 0
    init_code: str = "0x"
    call_data: str = "0x"
    call_gas_limit: int = 0
    verification_gas_limit: int = 0
    pre_verification_gas: int = 0
    max_fee_per_gas: int = 0
    max_priority_fee_per_gas: int = 0
    paymaster_and_data: str = "0x"
    signature: str = "0x"


@dataclass(frozen=True)
class GasEstimate:
    """Gas estimation result from bundler."""

    call_gas_limit: int
    verification_gas_limit: int
    pre_verification_gas: int


@dataclass(frozen=True)
class PaymasterResponse:
    """Paymaster sponsorship response."""

    paymaster_and_data: str
