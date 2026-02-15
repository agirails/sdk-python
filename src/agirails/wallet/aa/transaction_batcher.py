"""
TransactionBatcher -- Encodes ACTP multi-call batches.

An ACTP payment requires 3 contract calls:
  1. USDC.approve(escrowVault, amount)
  2. ACTPKernel.createTransaction(provider, requester, amount, deadline, disputeWindow, serviceHash, agentId)
  3. ACTPKernel.linkEscrow(txId, escrowVault, escrowId)

TransactionBatcher encodes all 3 as SmartWalletCall[] for executeBatch.
It pre-computes the txId using the same keccak256 formula as the contract.

This is a 1:1 port of sdk-js/src/wallet/aa/TransactionBatcher.ts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Literal, Optional

from eth_abi import encode as abi_encode
from web3 import Web3

from agirails.wallet.aa.constants import SmartWalletCall


# ============================================================================
# Types
# ============================================================================

ActivationScenario = Literal["A", "B1", "B2", "C", "none"]
"""Lazy publish activation scenario.

- 'A': First activation -- registerAgent + publishConfig + setListed (3 calls)
- 'B1': Re-publish with listing change -- publishConfig + setListed (2 calls)
- 'B2': Re-publish config only -- publishConfig (1 call)
- 'C': Stale pending -- delete pending-publish.json, no calls
- 'none': No pending publish, normal flow
"""


@dataclass
class ServiceDescriptor:
    """Service descriptor for AgentRegistry.registerAgent."""

    service_type_hash: str  # bytes32
    service_type: str
    schema_uri: str
    min_price: int
    max_price: int
    avg_completion_time: int
    metadata_cid: str


@dataclass
class ContractAddresses:
    """Contract addresses for ACTP batch operations."""

    usdc: str
    actp_kernel: str
    escrow_vault: str


@dataclass
class ACTPBatchParams:
    """Parameters for building an ACTP payment batch."""

    provider: str
    requester: str
    amount: str  # USDC wei string (e.g. "1000000" for 1 USDC)
    deadline: int  # Unix timestamp
    dispute_window: int  # Seconds
    service_hash: str  # bytes32
    agent_id: str  # ERC-8004 agent ID ("0" if none)
    actp_nonce: int  # Current ACTP nonce for the requester
    contracts: ContractAddresses


@dataclass
class ACTPBatchResult:
    """Result of building an ACTP payment batch."""

    calls: List[SmartWalletCall]
    tx_id: str  # Pre-computed transaction ID


@dataclass
class ActivationBatchParams:
    """Parameters for building an activation batch."""

    scenario: ActivationScenario
    agent_registry_address: str
    cid: str
    config_hash: str  # bytes32
    endpoint: Optional[str] = None
    service_descriptors: Optional[List[ServiceDescriptor]] = None
    listed: Optional[bool] = None


# ============================================================================
# Function selectors
# ============================================================================

# ERC20.approve(address,uint256)
_APPROVE_SELECTOR = Web3.keccak(text="approve(address,uint256)")[:4].hex()

# ACTPKernel.createTransaction(address,address,uint256,uint256,uint256,bytes32,uint256)
_CREATE_TX_SELECTOR = Web3.keccak(
    text="createTransaction(address,address,uint256,uint256,uint256,bytes32,uint256)"
)[:4].hex()

# ACTPKernel.linkEscrow(bytes32,address,bytes32)
_LINK_ESCROW_SELECTOR = Web3.keccak(
    text="linkEscrow(bytes32,address,bytes32)"
)[:4].hex()

# AgentRegistry.registerAgent(string,(bytes32,string,string,uint256,uint256,uint256,string)[])
_REGISTER_AGENT_SELECTOR = Web3.keccak(
    text="registerAgent(string,(bytes32,string,string,uint256,uint256,uint256,string)[])"
)[:4].hex()

# AgentRegistry.publishConfig(string,bytes32)
_PUBLISH_CONFIG_SELECTOR = Web3.keccak(
    text="publishConfig(string,bytes32)"
)[:4].hex()

# AgentRegistry.setListed(bool)
_SET_LISTED_SELECTOR = Web3.keccak(text="setListed(bool)")[:4].hex()

# MockUSDC.mint(address,uint256)
_MINT_SELECTOR = Web3.keccak(text="mint(address,uint256)")[:4].hex()


# ============================================================================
# Public API
# ============================================================================


def compute_transaction_id(
    requester: str,
    provider: str,
    amount: str,
    service_hash: str,
    nonce: int,
) -> str:
    """Pre-compute ACTP transaction ID.

    Matches ACTPKernel.sol:
        transactionId = keccak256(abi.encodePacked(requester, provider, amount, serviceHash, nonce))

    Args:
        requester: Requester address.
        provider: Provider address.
        amount: Amount in USDC wei (decimal string).
        service_hash: Service hash (bytes32 hex string).
        nonce: ACTP nonce for the requester.

    Returns:
        Hex-encoded transaction ID (0x-prefixed bytes32).
    """
    # abi.encodePacked: address(20) + address(20) + uint256(32) + bytes32(32) + uint256(32)
    packed = (
        bytes.fromhex(requester.lower().replace("0x", "").zfill(40))
        + bytes.fromhex(provider.lower().replace("0x", "").zfill(40))
        + int(amount).to_bytes(32, "big")
        + bytes.fromhex(service_hash.replace("0x", "").zfill(64))
        + nonce.to_bytes(32, "big")
    )
    return "0x" + Web3.keccak(packed).hex()


def build_actp_pay_batch(params: ACTPBatchParams) -> ACTPBatchResult:
    """Build the 3-call ACTP payment batch.

    Returns SmartWalletCall[] for executeBatch and the pre-computed txId.

    Calls:
      1. USDC.approve(escrowVault, amount)
      2. ACTPKernel.createTransaction(provider, requester, amount, deadline, disputeWindow, serviceHash, agentId)
      3. ACTPKernel.linkEscrow(txId, escrowVault, escrowId)

    Args:
        params: ACTP batch parameters.

    Returns:
        ACTPBatchResult with calls and txId.
    """
    amount_int = int(params.amount)

    # Pre-compute txId
    tx_id = compute_transaction_id(
        params.requester,
        params.provider,
        params.amount,
        params.service_hash,
        params.actp_nonce,
    )

    # Call 1: USDC.approve(escrowVault, amount)
    approve_data = "0x" + _APPROVE_SELECTOR + abi_encode(
        ["address", "uint256"],
        [Web3.to_checksum_address(params.contracts.escrow_vault), amount_int],
    ).hex()

    # Call 2: ACTPKernel.createTransaction(...)
    create_tx_data = "0x" + _CREATE_TX_SELECTOR + abi_encode(
        ["address", "address", "uint256", "uint256", "uint256", "bytes32", "uint256"],
        [
            Web3.to_checksum_address(params.provider),
            Web3.to_checksum_address(params.requester),
            amount_int,
            params.deadline,
            params.dispute_window,
            bytes.fromhex(params.service_hash.replace("0x", "")),
            int(params.agent_id or "0"),
        ],
    ).hex()

    # Call 3: ACTPKernel.linkEscrow(txId, escrowVault, escrowId)
    # escrowId = txId (ACTP standard)
    tx_id_bytes = bytes.fromhex(tx_id.replace("0x", ""))
    link_escrow_data = "0x" + _LINK_ESCROW_SELECTOR + abi_encode(
        ["bytes32", "address", "bytes32"],
        [
            tx_id_bytes,
            Web3.to_checksum_address(params.contracts.escrow_vault),
            tx_id_bytes,
        ],
    ).hex()

    calls = [
        SmartWalletCall(
            target=params.contracts.usdc,
            value=0,
            data=approve_data,
        ),
        SmartWalletCall(
            target=params.contracts.actp_kernel,
            value=0,
            data=create_tx_data,
        ),
        SmartWalletCall(
            target=params.contracts.actp_kernel,
            value=0,
            data=link_escrow_data,
        ),
    ]

    return ACTPBatchResult(calls=calls, tx_id=tx_id)


def build_register_agent_batch(
    agent_registry_address: str,
    endpoint: str,
    service_descriptors: List[ServiceDescriptor],
) -> List[SmartWalletCall]:
    """Build a register-agent batch for AgentRegistry.

    Args:
        agent_registry_address: AgentRegistry contract address.
        endpoint: Agent webhook / IPFS gateway URL.
        service_descriptors: At least 1 service descriptor (contract requirement).

    Returns:
        List with one SmartWalletCall for registerAgent.

    Raises:
        ValueError: If no service descriptors provided.
    """
    if len(service_descriptors) == 0:
        raise ValueError("At least one service descriptor is required for registration")

    # Encode ServiceDescriptor[] as tuple array
    tuples = [
        (
            bytes.fromhex(sd.service_type_hash.replace("0x", "")),
            sd.service_type,
            sd.schema_uri,
            sd.min_price,
            sd.max_price,
            sd.avg_completion_time,
            sd.metadata_cid,
        )
        for sd in service_descriptors
    ]

    data = "0x" + _REGISTER_AGENT_SELECTOR + abi_encode(
        ["string", "(bytes32,string,string,uint256,uint256,uint256,string)[]"],
        [endpoint, tuples],
    ).hex()

    return [
        SmartWalletCall(target=agent_registry_address, value=0, data=data),
    ]


def build_publish_config_batch(
    agent_registry_address: str,
    cid: str,
    config_hash: str,
) -> List[SmartWalletCall]:
    """Build a publishConfig batch call for AgentRegistry.

    Args:
        agent_registry_address: AgentRegistry contract address.
        cid: IPFS CID of the uploaded AGIRAILS.md.
        config_hash: Canonical config hash (bytes32).

    Returns:
        List with one SmartWalletCall for publishConfig.
    """
    data = "0x" + _PUBLISH_CONFIG_SELECTOR + abi_encode(
        ["string", "bytes32"],
        [cid, bytes.fromhex(config_hash.replace("0x", ""))],
    ).hex()

    return [
        SmartWalletCall(target=agent_registry_address, value=0, data=data),
    ]


def build_set_listed_batch(
    agent_registry_address: str,
    listed: bool,
) -> List[SmartWalletCall]:
    """Build a setListed batch call for AgentRegistry.

    Args:
        agent_registry_address: AgentRegistry contract address.
        listed: Whether to list the agent.

    Returns:
        List with one SmartWalletCall for setListed.
    """
    data = "0x" + _SET_LISTED_SELECTOR + abi_encode(
        ["bool"],
        [listed],
    ).hex()

    return [
        SmartWalletCall(target=agent_registry_address, value=0, data=data),
    ]


def build_testnet_mint_batch(
    mock_usdc_address: str,
    recipient: str,
    amount: str,
) -> List[SmartWalletCall]:
    """Build a MockUSDC mint call (testnet only).

    Args:
        mock_usdc_address: MockUSDC contract address.
        recipient: Address to mint to.
        amount: Amount to mint (USDC wei string).

    Returns:
        List with one SmartWalletCall for mint.
    """
    data = "0x" + _MINT_SELECTOR + abi_encode(
        ["address", "uint256"],
        [Web3.to_checksum_address(recipient), int(amount)],
    ).hex()

    return [
        SmartWalletCall(target=mock_usdc_address, value=0, data=data),
    ]


def build_testnet_init_batch(
    agent_registry_address: str,
    endpoint: str,
    service_descriptors: List[ServiceDescriptor],
    mock_usdc_address: str,
    recipient: str,
    mint_amount: str,
) -> List[SmartWalletCall]:
    """Build a combined register + mint batch for testnet init.

    Single UserOp: register on AgentRegistry + mint test USDC.
    Both are bootstrap-allowed (gasless without prior registration).

    Args:
        agent_registry_address: AgentRegistry contract address.
        endpoint: Agent webhook / IPFS gateway URL.
        service_descriptors: Service descriptors for registration.
        mock_usdc_address: MockUSDC contract address.
        recipient: Address to mint to.
        mint_amount: Amount to mint (USDC wei string).

    Returns:
        Combined list of SmartWalletCalls (register + mint).
    """
    register_calls = build_register_agent_batch(
        agent_registry_address, endpoint, service_descriptors
    )
    mint_calls = build_testnet_mint_batch(mock_usdc_address, recipient, mint_amount)
    return register_calls + mint_calls


def build_activation_batch(params: ActivationBatchParams) -> List[SmartWalletCall]:
    """Build the full activation batch based on scenario.

    Scenario call counts:
      - A: registerAgent + publishConfig + setListed = 3 calls
      - B1: publishConfig + setListed = 2 calls
      - B2: publishConfig = 1 call
      - C/none: empty (0 calls)

    Args:
        params: Activation batch parameters.

    Returns:
        List of SmartWalletCalls for the activation scenario.

    Raises:
        ValueError: If scenario A is missing endpoint or service_descriptors.
    """
    scenario = params.scenario
    registry = params.agent_registry_address
    cid = params.cid
    config_hash = params.config_hash

    if scenario == "A":
        if not params.endpoint or not params.service_descriptors or len(params.service_descriptors) == 0:
            raise ValueError("Scenario A requires endpoint and service_descriptors")
        register_calls = build_register_agent_batch(
            registry, params.endpoint, params.service_descriptors
        )
        publish_calls = build_publish_config_batch(registry, cid, config_hash)
        list_calls = build_set_listed_batch(
            registry, params.listed if params.listed is not None else True
        )
        return register_calls + publish_calls + list_calls

    elif scenario == "B1":
        publish_calls = build_publish_config_batch(registry, cid, config_hash)
        list_calls = build_set_listed_batch(
            registry, params.listed if params.listed is not None else True
        )
        return publish_calls + list_calls

    elif scenario == "B2":
        return build_publish_config_batch(registry, cid, config_hash)

    else:
        # C or none -- no activation calls
        return []
