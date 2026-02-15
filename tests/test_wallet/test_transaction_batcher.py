"""
Tests for TransactionBatcher -- ACTP multi-call batch encoding.

Covers:
- Transaction ID computation (matches TS/contract)
- ACTP pay batch (3 calls)
- Activation scenarios (A=3, B1=2, B2=1, C=0, none=0)
- Register agent batch
- Testnet init batch
- publish/setListed batches
"""

from __future__ import annotations

import pytest
from web3 import Web3

from agirails.wallet.aa.constants import SmartWalletCall
from agirails.wallet.aa.transaction_batcher import (
    ACTPBatchParams,
    ActivationBatchParams,
    ContractAddresses,
    ServiceDescriptor,
    build_actp_pay_batch,
    build_activation_batch,
    build_publish_config_batch,
    build_register_agent_batch,
    build_set_listed_batch,
    build_testnet_init_batch,
    build_testnet_mint_batch,
    compute_transaction_id,
)


# ============================================================================
# Fixtures
# ============================================================================

REQUESTER = "0x1111111111111111111111111111111111111111"
PROVIDER = "0x2222222222222222222222222222222222222222"
AMOUNT = "1000000"  # 1 USDC
SERVICE_HASH = "0x" + "ab" * 32
AGENT_ID = "0"
NONCE = 0
REGISTRY = "0x6fB222CF3DDdf37Bcb248EE7BBBA42Fb41901de8"
CONFIG_HASH = "0x" + "cd" * 32

CONTRACTS = ContractAddresses(
    usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    actp_kernel="0x132B9eB321dBB57c828B083844287171BDC92d29",
    escrow_vault="0x6aAF45882c4b0dD34130ecC790bb5Ec6be7fFb99",
)

SAMPLE_DESCRIPTOR = ServiceDescriptor(
    service_type_hash="0x" + "ee" * 32,
    service_type="text-generation",
    schema_uri="https://example.com/schema.json",
    min_price=100000,
    max_price=5000000,
    avg_completion_time=30,
    metadata_cid="QmTest123",
)


# ============================================================================
# Tests: compute_transaction_id
# ============================================================================


class TestComputeTransactionId:
    """Tests for transaction ID pre-computation."""

    def test_produces_bytes32_hex(self) -> None:
        """Transaction ID is 0x-prefixed 64-char hex."""
        tx_id = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, NONCE)
        assert tx_id.startswith("0x")
        assert len(tx_id) == 66

    def test_deterministic(self) -> None:
        """Same inputs produce same txId."""
        a = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, NONCE)
        b = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, NONCE)
        assert a == b

    def test_different_nonce_different_id(self) -> None:
        """Different nonces produce different txIds."""
        a = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, 0)
        b = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, 1)
        assert a != b

    def test_different_amount_different_id(self) -> None:
        """Different amounts produce different txIds."""
        a = compute_transaction_id(REQUESTER, PROVIDER, "1000000", SERVICE_HASH, NONCE)
        b = compute_transaction_id(REQUESTER, PROVIDER, "2000000", SERVICE_HASH, NONCE)
        assert a != b

    def test_matches_solidity_packed_encoding(self) -> None:
        """Verify encoding matches abi.encodePacked(address,address,uint256,bytes32,uint256).

        Manual verification: packed = 20 + 20 + 32 + 32 + 32 = 136 bytes.
        """
        tx_id = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, NONCE)
        # Manually build packed encoding
        packed = (
            bytes.fromhex(REQUESTER[2:])
            + bytes.fromhex(PROVIDER[2:])
            + int(AMOUNT).to_bytes(32, "big")
            + bytes.fromhex(SERVICE_HASH[2:])
            + NONCE.to_bytes(32, "big")
        )
        assert len(packed) == 136
        expected = "0x" + Web3.keccak(packed).hex()
        assert tx_id == expected


# ============================================================================
# Tests: build_actp_pay_batch
# ============================================================================


class TestBuildACTPPayBatch:
    """Tests for ACTP payment batch building."""

    def test_produces_three_calls(self) -> None:
        """Payment batch has exactly 3 calls (approve + createTx + linkEscrow)."""
        params = ACTPBatchParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=AMOUNT,
            deadline=1999999999,
            dispute_window=86400,
            service_hash=SERVICE_HASH,
            agent_id=AGENT_ID,
            actp_nonce=NONCE,
            contracts=CONTRACTS,
        )
        result = build_actp_pay_batch(params)
        assert len(result.calls) == 3

    def test_call_targets(self) -> None:
        """Calls target USDC, ACTPKernel, ACTPKernel."""
        params = ACTPBatchParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=AMOUNT,
            deadline=1999999999,
            dispute_window=86400,
            service_hash=SERVICE_HASH,
            agent_id=AGENT_ID,
            actp_nonce=NONCE,
            contracts=CONTRACTS,
        )
        result = build_actp_pay_batch(params)
        assert result.calls[0].target == CONTRACTS.usdc
        assert result.calls[1].target == CONTRACTS.actp_kernel
        assert result.calls[2].target == CONTRACTS.actp_kernel

    def test_all_calls_have_zero_value(self) -> None:
        """All calls have value=0 (USDC is ERC-20, not native ETH)."""
        params = ACTPBatchParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=AMOUNT,
            deadline=1999999999,
            dispute_window=86400,
            service_hash=SERVICE_HASH,
            agent_id=AGENT_ID,
            actp_nonce=NONCE,
            contracts=CONTRACTS,
        )
        result = build_actp_pay_batch(params)
        for call in result.calls:
            assert call.value == 0

    def test_tx_id_matches_standalone(self) -> None:
        """Batch txId matches compute_transaction_id."""
        params = ACTPBatchParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=AMOUNT,
            deadline=1999999999,
            dispute_window=86400,
            service_hash=SERVICE_HASH,
            agent_id=AGENT_ID,
            actp_nonce=NONCE,
            contracts=CONTRACTS,
        )
        result = build_actp_pay_batch(params)
        expected_id = compute_transaction_id(REQUESTER, PROVIDER, AMOUNT, SERVICE_HASH, NONCE)
        assert result.tx_id == expected_id

    def test_approve_has_correct_selector(self) -> None:
        """First call (approve) has correct function selector."""
        params = ACTPBatchParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=AMOUNT,
            deadline=1999999999,
            dispute_window=86400,
            service_hash=SERVICE_HASH,
            agent_id=AGENT_ID,
            actp_nonce=NONCE,
            contracts=CONTRACTS,
        )
        result = build_actp_pay_batch(params)
        approve_selector = Web3.keccak(text="approve(address,uint256)")[:4].hex()
        assert result.calls[0].data[2:10] == approve_selector


# ============================================================================
# Tests: build_activation_batch
# ============================================================================


class TestBuildActivationBatch:
    """Tests for lazy publish activation batches."""

    def test_scenario_a_three_calls(self) -> None:
        """Scenario A produces 3 calls (register + publish + list)."""
        params = ActivationBatchParams(
            scenario="A",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
            endpoint="https://agent.example.com",
            service_descriptors=[SAMPLE_DESCRIPTOR],
            listed=True,
        )
        result = build_activation_batch(params)
        assert len(result) == 3

    def test_scenario_b1_two_calls(self) -> None:
        """Scenario B1 produces 2 calls (publish + list)."""
        params = ActivationBatchParams(
            scenario="B1",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
        )
        result = build_activation_batch(params)
        assert len(result) == 2

    def test_scenario_b2_one_call(self) -> None:
        """Scenario B2 produces 1 call (publish)."""
        params = ActivationBatchParams(
            scenario="B2",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
        )
        result = build_activation_batch(params)
        assert len(result) == 1

    def test_scenario_c_zero_calls(self) -> None:
        """Scenario C produces 0 calls."""
        params = ActivationBatchParams(
            scenario="C",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
        )
        result = build_activation_batch(params)
        assert len(result) == 0

    def test_scenario_none_zero_calls(self) -> None:
        """Scenario 'none' produces 0 calls."""
        params = ActivationBatchParams(
            scenario="none",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
        )
        result = build_activation_batch(params)
        assert len(result) == 0

    def test_scenario_a_missing_endpoint_raises(self) -> None:
        """Scenario A without endpoint raises ValueError."""
        params = ActivationBatchParams(
            scenario="A",
            agent_registry_address=REGISTRY,
            cid="QmTest",
            config_hash=CONFIG_HASH,
            service_descriptors=[SAMPLE_DESCRIPTOR],
        )
        with pytest.raises(ValueError, match="endpoint"):
            build_activation_batch(params)


# ============================================================================
# Tests: build_register_agent_batch
# ============================================================================


class TestBuildRegisterAgentBatch:
    """Tests for agent registration batch."""

    def test_produces_one_call(self) -> None:
        """Registration produces 1 call."""
        result = build_register_agent_batch(
            REGISTRY, "https://agent.example.com", [SAMPLE_DESCRIPTOR]
        )
        assert len(result) == 1

    def test_targets_registry(self) -> None:
        """Call targets the registry address."""
        result = build_register_agent_batch(
            REGISTRY, "https://agent.example.com", [SAMPLE_DESCRIPTOR]
        )
        assert result[0].target == REGISTRY

    def test_empty_descriptors_raises(self) -> None:
        """Empty descriptors raise ValueError."""
        with pytest.raises(ValueError, match="At least one"):
            build_register_agent_batch(REGISTRY, "https://agent.example.com", [])

    def test_has_register_selector(self) -> None:
        """Call data starts with registerAgent selector."""
        result = build_register_agent_batch(
            REGISTRY, "https://agent.example.com", [SAMPLE_DESCRIPTOR]
        )
        selector = Web3.keccak(
            text="registerAgent(string,(bytes32,string,string,uint256,uint256,uint256,string)[])"
        )[:4].hex()
        assert result[0].data[2:10] == selector


# ============================================================================
# Tests: build_testnet_init_batch
# ============================================================================


class TestBuildTestnetInitBatch:
    """Tests for testnet initialization batch."""

    def test_produces_two_calls(self) -> None:
        """Testnet init produces 2 calls (register + mint)."""
        result = build_testnet_init_batch(
            agent_registry_address=REGISTRY,
            endpoint="https://agent.example.com",
            service_descriptors=[SAMPLE_DESCRIPTOR],
            mock_usdc_address="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",
            recipient=REQUESTER,
            mint_amount="10000000000",
        )
        assert len(result) == 2

    def test_first_call_is_register(self) -> None:
        """First call is registerAgent."""
        result = build_testnet_init_batch(
            agent_registry_address=REGISTRY,
            endpoint="https://agent.example.com",
            service_descriptors=[SAMPLE_DESCRIPTOR],
            mock_usdc_address="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",
            recipient=REQUESTER,
            mint_amount="10000000000",
        )
        assert result[0].target == REGISTRY

    def test_second_call_is_mint(self) -> None:
        """Second call is mock USDC mint."""
        mock_usdc = "0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb"
        result = build_testnet_init_batch(
            agent_registry_address=REGISTRY,
            endpoint="https://agent.example.com",
            service_descriptors=[SAMPLE_DESCRIPTOR],
            mock_usdc_address=mock_usdc,
            recipient=REQUESTER,
            mint_amount="10000000000",
        )
        assert result[1].target == mock_usdc
