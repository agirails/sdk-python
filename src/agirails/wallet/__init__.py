"""
Wallet utilities for AGIRAILS SDK.

Provides:
- Keystore resolution, caching, and AIP-13 policy enforcement
- AutoWalletProvider (Tier 1): CoinbaseSmartWallet + Paymaster (gasless)
- EOAWalletProvider (Tier 2): Traditional EOA signing
- Account Abstraction (ERC-4337) internals in wallet.aa submodule
"""

from __future__ import annotations

from agirails.wallet.keystore import (
    ResolvePrivateKeyOptions,
    get_cached_address,
    resolve_private_key,
    _clear_cache,
)
from agirails.wallet.auto_wallet_provider import (
    AutoWalletConfig,
    AutoWalletProvider,
    BatchedPayParams,
    BatchedPayResult,
    IWalletProvider,
    TransactionReceipt,
    TransactionRequest,
    WalletInfo,
    WalletTier,
)
from agirails.wallet.eoa_wallet_provider import EOAWalletProvider

__all__ = [
    # Keystore
    "ResolvePrivateKeyOptions",
    "get_cached_address",
    "resolve_private_key",
    "_clear_cache",
    # Wallet providers
    "AutoWalletConfig",
    "AutoWalletProvider",
    "EOAWalletProvider",
    # Types
    "BatchedPayParams",
    "BatchedPayResult",
    "IWalletProvider",
    "TransactionReceipt",
    "TransactionRequest",
    "WalletInfo",
    "WalletTier",
]
