"""
Tests for UserOpBuilder -- ERC-4337 v0.6 UserOperation construction.

Covers:
- Counterfactual address computation
- UserOp encoding with single/multiple calls
- initCode for first deploy
- Signature encoding (ownerIndex=0)
- Serialization to hex
- UserOp hash computation
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from eth_abi import encode as abi_encode
from eth_account import Account
from web3 import Web3

from agirails.wallet.aa.constants import (
    ENTRYPOINT_V06,
    SMART_WALLET_FACTORY,
    SmartWalletCall,
    UserOperationV06,
)
from agirails.wallet.aa.user_op_builder import (
    build_init_code,
    build_user_op,
    dummy_signature,
    encode_execute_batch,
    get_user_op_hash,
    serialize_user_op,
    sign_user_op,
    _to_hex,
)


# ============================================================================
# Fixtures
# ============================================================================

TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_SIGNER_ADDRESS = Account.from_key(TEST_PRIVATE_KEY).address
TEST_SENDER = "0x1234567890abcdef1234567890abcdef12345678"
TEST_CHAIN_ID = 84532  # Base Sepolia


# ============================================================================
# Tests: encode_execute_batch
# ============================================================================


class TestEncodeExecuteBatch:
    """Tests for encoding executeBatch calldata."""

    def test_single_call(self) -> None:
        """Single call produces valid calldata."""
        calls = [
            SmartWalletCall(
                target="0x1111111111111111111111111111111111111111",
                value=0,
                data="0xabcdef",
            )
        ]
        result = encode_execute_batch(calls)
        assert result.startswith("0x")
        # Should contain the executeBatch selector
        selector = Web3.keccak(
            text="executeBatch((address,uint256,bytes)[])"
        )[:4].hex()
        assert result[2:10] == selector

    def test_multiple_calls(self) -> None:
        """Multiple calls produce valid calldata."""
        calls = [
            SmartWalletCall(
                target="0x1111111111111111111111111111111111111111",
                value=0,
                data="0xaa",
            ),
            SmartWalletCall(
                target="0x2222222222222222222222222222222222222222",
                value=100,
                data="0xbb",
            ),
            SmartWalletCall(
                target="0x3333333333333333333333333333333333333333",
                value=0,
                data="0xccdd",
            ),
        ]
        result = encode_execute_batch(calls)
        assert result.startswith("0x")
        # Result should be longer than single call
        single = encode_execute_batch(calls[:1])
        assert len(result) > len(single)

    def test_empty_data(self) -> None:
        """Call with empty data (0x) encodes correctly."""
        calls = [
            SmartWalletCall(
                target="0x1111111111111111111111111111111111111111",
                value=0,
                data="0x",
            )
        ]
        result = encode_execute_batch(calls)
        assert result.startswith("0x")


# ============================================================================
# Tests: build_init_code
# ============================================================================


class TestBuildInitCode:
    """Tests for building initCode for first deploy."""

    def test_init_code_starts_with_factory(self) -> None:
        """initCode starts with factory address."""
        result = build_init_code(TEST_SIGNER_ADDRESS)
        factory_addr = SMART_WALLET_FACTORY.lower().replace("0x", "")
        assert result.lower().startswith("0x" + factory_addr)

    def test_init_code_contains_create_account_selector(self) -> None:
        """initCode contains createAccount selector after factory address."""
        result = build_init_code(TEST_SIGNER_ADDRESS)
        # Skip 0x + 40 char factory address
        selector_hex = result[42:50]
        expected_selector = Web3.keccak(
            text="createAccount(bytes[],uint256)"
        )[:4].hex()
        assert selector_hex == expected_selector

    def test_init_code_with_custom_nonce(self) -> None:
        """initCode with nonce=1 differs from nonce=0."""
        result_0 = build_init_code(TEST_SIGNER_ADDRESS, nonce=0)
        result_1 = build_init_code(TEST_SIGNER_ADDRESS, nonce=1)
        assert result_0 != result_1

    def test_init_code_deterministic(self) -> None:
        """Same inputs produce same initCode."""
        result_a = build_init_code(TEST_SIGNER_ADDRESS)
        result_b = build_init_code(TEST_SIGNER_ADDRESS)
        assert result_a == result_b


# ============================================================================
# Tests: build_user_op
# ============================================================================


class TestBuildUserOp:
    """Tests for building unsigned UserOperations."""

    def test_first_deploy_has_init_code(self) -> None:
        """First deploy UserOp has non-empty initCode."""
        calls = [SmartWalletCall(target=TEST_SENDER, value=0, data="0x")]
        user_op = build_user_op(
            sender=TEST_SENDER,
            nonce=0,
            calls=calls,
            is_first_deploy=True,
            signer_address=TEST_SIGNER_ADDRESS,
        )
        assert user_op.init_code != "0x"
        assert len(user_op.init_code) > 2

    def test_existing_wallet_has_empty_init_code(self) -> None:
        """Existing wallet UserOp has empty initCode."""
        calls = [SmartWalletCall(target=TEST_SENDER, value=0, data="0x")]
        user_op = build_user_op(
            sender=TEST_SENDER,
            nonce=5,
            calls=calls,
            is_first_deploy=False,
            signer_address=TEST_SIGNER_ADDRESS,
        )
        assert user_op.init_code == "0x"

    def test_placeholder_gas_values(self) -> None:
        """UserOp gas values are placeholder zeros."""
        calls = [SmartWalletCall(target=TEST_SENDER, value=0, data="0x")]
        user_op = build_user_op(
            sender=TEST_SENDER,
            nonce=0,
            calls=calls,
            is_first_deploy=False,
            signer_address=TEST_SIGNER_ADDRESS,
        )
        assert user_op.call_gas_limit == 0
        assert user_op.verification_gas_limit == 0
        assert user_op.pre_verification_gas == 0
        assert user_op.max_fee_per_gas == 0
        assert user_op.max_priority_fee_per_gas == 0

    def test_call_data_is_execute_batch(self) -> None:
        """UserOp callData is executeBatch encoding."""
        calls = [SmartWalletCall(target=TEST_SENDER, value=0, data="0xaa")]
        user_op = build_user_op(
            sender=TEST_SENDER,
            nonce=0,
            calls=calls,
            is_first_deploy=False,
            signer_address=TEST_SIGNER_ADDRESS,
        )
        expected = encode_execute_batch(calls)
        assert user_op.call_data == expected


# ============================================================================
# Tests: get_user_op_hash
# ============================================================================


class TestGetUserOpHash:
    """Tests for UserOp hash computation."""

    def test_hash_is_bytes32(self) -> None:
        """Hash is 0x-prefixed 64-char hex (32 bytes)."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=0,
            init_code="0x",
            call_data="0x",
            call_gas_limit=100000,
            verification_gas_limit=200000,
            pre_verification_gas=50000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=1000000000,
            paymaster_and_data="0x",
            signature="0x",
        )
        result = get_user_op_hash(user_op, TEST_CHAIN_ID)
        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_different_chain_ids_different_hashes(self) -> None:
        """Different chain IDs produce different hashes."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=0,
            init_code="0x",
            call_data="0x",
            paymaster_and_data="0x",
            signature="0x",
        )
        hash_sepolia = get_user_op_hash(user_op, 84532)
        hash_mainnet = get_user_op_hash(user_op, 8453)
        assert hash_sepolia != hash_mainnet

    def test_hash_is_deterministic(self) -> None:
        """Same UserOp produces same hash."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=42,
            init_code="0x",
            call_data="0xdeadbeef",
            paymaster_and_data="0x",
            signature="0x",
        )
        hash_a = get_user_op_hash(user_op, TEST_CHAIN_ID)
        hash_b = get_user_op_hash(user_op, TEST_CHAIN_ID)
        assert hash_a == hash_b


# ============================================================================
# Tests: sign_user_op
# ============================================================================


class TestSignUserOp:
    """Tests for UserOp signing."""

    def test_signature_wrapper_format(self) -> None:
        """Signature is abi.encode(uint256 ownerIndex, bytes sig) format."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=0,
            init_code="0x",
            call_data="0x",
            paymaster_and_data="0x",
            signature="0x",
        )
        sig = sign_user_op(user_op, TEST_PRIVATE_KEY, TEST_CHAIN_ID)
        assert sig.startswith("0x")

        # Decode the wrapper: (uint256, bytes)
        sig_bytes = bytes.fromhex(sig.replace("0x", ""))
        decoded = abi_encode(["uint256"], [0])
        # First 32 bytes should be ownerIndex = 0
        owner_index = int.from_bytes(sig_bytes[:32], "big")
        assert owner_index == 0

    def test_signature_is_deterministic(self) -> None:
        """Same UserOp + key produces same signature."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=0,
            init_code="0x",
            call_data="0xdeadbeef",
            paymaster_and_data="0x",
            signature="0x",
        )
        sig_a = sign_user_op(user_op, TEST_PRIVATE_KEY, TEST_CHAIN_ID)
        sig_b = sign_user_op(user_op, TEST_PRIVATE_KEY, TEST_CHAIN_ID)
        assert sig_a == sig_b


# ============================================================================
# Tests: serialize_user_op
# ============================================================================


class TestSerializeUserOp:
    """Tests for UserOp serialization to JSON-RPC format."""

    def test_fields_are_hex(self) -> None:
        """Numeric fields are hex strings."""
        user_op = UserOperationV06(
            sender=TEST_SENDER,
            nonce=42,
            init_code="0x",
            call_data="0xdeadbeef",
            call_gas_limit=100000,
            verification_gas_limit=200000,
            pre_verification_gas=50000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=1000000000,
            paymaster_and_data="0x",
            signature="0xaabb",
        )
        result = serialize_user_op(user_op)

        assert result["sender"] == TEST_SENDER
        assert result["nonce"] == "0x2a"  # 42
        assert result["callGasLimit"] == hex(100000)
        assert result["verificationGasLimit"] == hex(200000)
        assert result["preVerificationGas"] == hex(50000)
        assert result["maxFeePerGas"] == hex(2000000000)
        assert result["maxPriorityFeePerGas"] == hex(1000000000)
        assert result["initCode"] == "0x"
        assert result["callData"] == "0xdeadbeef"
        assert result["paymasterAndData"] == "0x"
        assert result["signature"] == "0xaabb"

    def test_zero_nonce(self) -> None:
        """Zero nonce serializes to '0x0'."""
        user_op = UserOperationV06(sender=TEST_SENDER)
        result = serialize_user_op(user_op)
        assert result["nonce"] == "0x0"


# ============================================================================
# Tests: dummy_signature
# ============================================================================


class TestDummySignature:
    """Tests for dummy signature generation."""

    def test_dummy_signature_is_valid_hex(self) -> None:
        """Dummy signature is valid hex with correct structure."""
        sig = dummy_signature()
        assert sig.startswith("0x")
        # Should be decodable as (uint256, bytes)
        sig_bytes = bytes.fromhex(sig.replace("0x", ""))
        # First 32 bytes = ownerIndex = 0
        owner_index = int.from_bytes(sig_bytes[:32], "big")
        assert owner_index == 0


# ============================================================================
# Tests: _to_hex helper
# ============================================================================


class TestToHex:
    """Tests for hex conversion helper."""

    def test_zero(self) -> None:
        assert _to_hex(0) == "0x0"

    def test_positive(self) -> None:
        assert _to_hex(255) == "0xff"

    def test_large(self) -> None:
        assert _to_hex(2000000000) == "0x77359400"
