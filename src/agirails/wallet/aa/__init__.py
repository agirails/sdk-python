"""
Account Abstraction (ERC-4337) module for AGIRAILS SDK.

Provides CoinbaseSmartWallet integration with gas-sponsored transactions:
- UserOpBuilder: Constructs ERC-4337 v0.6 UserOperations
- BundlerClient: JSON-RPC client for ERC-4337 bundlers (Coinbase + Pimlico)
- PaymasterClient: ERC-7677 gas sponsorship (Coinbase + Pimlico)
- DualNonceManager: Manages EntryPoint + ACTP nonces with mutex
- TransactionBatcher: Encodes ACTP multi-call batches
- Constants: Canonical addresses and data classes
"""

from __future__ import annotations

from agirails.wallet.aa.constants import (
    ENTRYPOINT_V06,
    SMART_WALLET_FACTORY,
    DEFAULT_WALLET_NONCE,
    GasEstimate,
    PaymasterResponse,
    SmartWalletCall,
    UserOperationV06,
)
from agirails.wallet.aa.user_op_builder import (
    build_init_code,
    build_user_op,
    compute_smart_wallet_address,
    encode_execute_batch,
    get_user_op_hash,
    serialize_user_op,
    sign_user_op,
)
from agirails.wallet.aa.bundler_client import BundlerClient, BundlerConfig, UserOpReceipt
from agirails.wallet.aa.paymaster_client import PaymasterClient, PaymasterConfig
from agirails.wallet.aa.dual_nonce_manager import DualNonceManager
from agirails.wallet.aa.transaction_batcher import (
    ACTPBatchParams,
    ACTPBatchResult,
    ActivationBatchParams,
    ActivationScenario,
    build_actp_pay_batch,
    build_activation_batch,
    build_publish_config_batch,
    build_register_agent_batch,
    build_set_listed_batch,
    build_testnet_init_batch,
    build_testnet_mint_batch,
    compute_transaction_id,
)

__all__ = [
    # Constants
    "ENTRYPOINT_V06",
    "SMART_WALLET_FACTORY",
    "DEFAULT_WALLET_NONCE",
    "GasEstimate",
    "PaymasterResponse",
    "SmartWalletCall",
    "UserOperationV06",
    # UserOpBuilder
    "build_init_code",
    "build_user_op",
    "compute_smart_wallet_address",
    "encode_execute_batch",
    "get_user_op_hash",
    "serialize_user_op",
    "sign_user_op",
    # BundlerClient
    "BundlerClient",
    "BundlerConfig",
    "UserOpReceipt",
    # PaymasterClient
    "PaymasterClient",
    "PaymasterConfig",
    # DualNonceManager
    "DualNonceManager",
    # TransactionBatcher
    "ACTPBatchParams",
    "ACTPBatchResult",
    "ActivationBatchParams",
    "ActivationScenario",
    "build_actp_pay_batch",
    "build_activation_batch",
    "build_publish_config_batch",
    "build_register_agent_batch",
    "build_set_listed_batch",
    "build_testnet_init_batch",
    "build_testnet_mint_batch",
    "compute_transaction_id",
]
