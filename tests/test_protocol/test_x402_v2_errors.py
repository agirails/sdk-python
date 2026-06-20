"""Reachability + hierarchy tests for x402 v2 error subclasses.

The x402 v2 errors live in agirails.types.x402 and mirror
sdk-js/src/errors/X402Errors.ts. In TS they extend ACTPError and carry
machine-readable codes; these tests pin that contract.

NOTE: these errors are NOT yet re-exported from agirails.errors or the
top-level agirails package (see export_changes_needed). They ARE importable
from agirails.types.x402 today, which is what this module verifies.
"""

import pytest

from agirails.errors.base import ACTPError
from agirails.types.x402 import (
    DEFAULT_EVM_NETWORKS,
    DEFAULT_USDC_BY_NETWORK,
    X402AmountExceededError,
    X402ApprovalFailedError,
    X402ConfigError,
    X402NetworkNotAllowedError,
    X402PaymentFailedError,
    X402PublishRequiredError,
    X402SettlementProofMissingError,
    X402SignatureFailedError,
    X402UnsupportedWalletError,
    X402V2Error,
    is_paymaster_gate_error,
)


class TestX402V2ErrorHierarchy:
    def test_base_extends_actp_error(self) -> None:
        assert issubclass(X402V2Error, ACTPError)

    @pytest.mark.parametrize(
        "cls",
        [
            X402ConfigError,
            X402UnsupportedWalletError,
            X402NetworkNotAllowedError,
            X402AmountExceededError,
            X402ApprovalFailedError,
            X402SignatureFailedError,
            X402PaymentFailedError,
        ],
    )
    def test_subclasses_extend_base_and_carry_message(self, cls) -> None:
        err = cls("boom", {"k": "v"})
        assert isinstance(err, X402V2Error)
        assert isinstance(err, ACTPError)
        assert "boom" in str(err)
        assert err.details == {"k": "v"}

    def test_config_error_code(self) -> None:
        assert X402ConfigError("x").code == "X402_CONFIG_ERROR"

    def test_network_not_allowed_code(self) -> None:
        assert X402NetworkNotAllowedError("x").code == "X402_NETWORK_NOT_ALLOWED"

    def test_amount_exceeded_code(self) -> None:
        assert X402AmountExceededError("x").code == "X402_AMOUNT_EXCEEDED"

    def test_publish_required_default_message_and_code(self) -> None:
        err = X402PublishRequiredError()
        assert err.code == "X402_PUBLISH_REQUIRED"
        assert "actp publish" in str(err)

    def test_settlement_proof_missing_default_message(self) -> None:
        err = X402SettlementProofMissingError()
        assert err.code == "X402_SETTLEMENT_PROOF_MISSING"
        assert "payment-response" in str(err)


class TestPaymasterGateDetection:
    @pytest.mark.parametrize(
        "msg",
        [
            "gas sponsorship denied",
            "paymaster policy rejected",
            "unauthorized agent",
            "sponsorship not active",
        ],
    )
    def test_detects_gate_errors(self, msg: str) -> None:
        assert is_paymaster_gate_error(Exception(msg)) is True

    def test_ignores_unrelated_errors(self) -> None:
        assert is_paymaster_gate_error(Exception("network timeout")) is False

    def test_non_exception_input(self) -> None:
        assert is_paymaster_gate_error("just a string") is False


class TestX402V2Constants:
    def test_default_networks_caip2(self) -> None:
        assert "eip155:8453" in DEFAULT_EVM_NETWORKS  # Base mainnet
        assert "eip155:84532" in DEFAULT_EVM_NETWORKS  # Base Sepolia

    def test_usdc_addresses_lowercase(self) -> None:
        for addr in DEFAULT_USDC_BY_NETWORK.values():
            assert addr == addr.lower()
        assert DEFAULT_USDC_BY_NETWORK["eip155:8453"] == (
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        )
