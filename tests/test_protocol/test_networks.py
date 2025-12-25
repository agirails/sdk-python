"""Tests for network configuration."""

import pytest

from agirails.config.networks import (
    BASE_SEPOLIA,
    BASE_MAINNET,
    NETWORKS,
    ContractAddresses,
    EASConfig,
    GasSettings,
    NetworkConfig,
    get_network,
    is_valid_network,
    validate_network_config,
)
from agirails.errors import ValidationError


class TestContractAddresses:
    """Tests for ContractAddresses dataclass."""

    def test_create_with_all_fields(self) -> None:
        """Test creating ContractAddresses with all fields."""
        addresses = ContractAddresses(
            actp_kernel="0x1111111111111111111111111111111111111111",
            escrow_vault="0x2222222222222222222222222222222222222222",
            usdc="0x3333333333333333333333333333333333333333",
            eas="0x4444444444444444444444444444444444444444",
            eas_schema_registry="0x5555555555555555555555555555555555555555",
            agent_registry="0x6666666666666666666666666666666666666666",
        )
        assert addresses.actp_kernel == "0x1111111111111111111111111111111111111111"
        assert addresses.agent_registry == "0x6666666666666666666666666666666666666666"

    def test_create_without_agent_registry(self) -> None:
        """Test creating ContractAddresses without optional agent_registry."""
        addresses = ContractAddresses(
            actp_kernel="0x1111111111111111111111111111111111111111",
            escrow_vault="0x2222222222222222222222222222222222222222",
            usdc="0x3333333333333333333333333333333333333333",
            eas="0x4444444444444444444444444444444444444444",
            eas_schema_registry="0x5555555555555555555555555555555555555555",
        )
        assert addresses.agent_registry is None


class TestEASConfig:
    """Tests for EASConfig dataclass."""

    def test_create_with_schema_uid(self) -> None:
        """Test creating EASConfig with schema UID."""
        config = EASConfig(
            delivery_schema_uid="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        assert config.delivery_schema_uid.startswith("0x")
        assert len(config.delivery_schema_uid) == 66  # 0x + 64 hex chars


class TestGasSettings:
    """Tests for GasSettings dataclass."""

    def test_create_with_gas_values(self) -> None:
        """Test creating GasSettings with gas values."""
        settings = GasSettings(
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
        )
        assert settings.max_fee_per_gas == 2_000_000_000  # 2 gwei
        assert settings.max_priority_fee_per_gas == 1_000_000_000  # 1 gwei


class TestNetworkConfig:
    """Tests for NetworkConfig dataclass."""

    def test_base_sepolia_config(self) -> None:
        """Test Base Sepolia network configuration."""
        assert BASE_SEPOLIA.name == "Base Sepolia"
        assert BASE_SEPOLIA.chain_id == 84532
        assert "sepolia" in BASE_SEPOLIA.rpc_url
        assert "sepolia.basescan.org" in BASE_SEPOLIA.block_explorer
        assert BASE_SEPOLIA.contracts.actp_kernel != "0x0000000000000000000000000000000000000000"
        assert BASE_SEPOLIA.contracts.escrow_vault != "0x0000000000000000000000000000000000000000"

    def test_base_mainnet_config(self) -> None:
        """Test Base Mainnet network configuration."""
        assert BASE_MAINNET.name == "Base Mainnet"
        assert BASE_MAINNET.chain_id == 8453
        assert "basescan.org" in BASE_MAINNET.block_explorer
        # Mainnet contracts are not deployed yet
        assert BASE_MAINNET.contracts.actp_kernel == "0x0000000000000000000000000000000000000000"

    def test_to_dict(self) -> None:
        """Test NetworkConfig.to_dict() method."""
        config_dict = BASE_SEPOLIA.to_dict()

        assert config_dict["name"] == "Base Sepolia"
        assert config_dict["chainId"] == 84532
        assert "contracts" in config_dict
        assert "actpKernel" in config_dict["contracts"]
        assert "eas" in config_dict
        assert "deliverySchemaUID" in config_dict["eas"]
        assert "gasSettings" in config_dict

    def test_immutability(self) -> None:
        """Test that NetworkConfig is immutable (frozen dataclass)."""
        with pytest.raises(AttributeError):
            BASE_SEPOLIA.name = "Modified"  # type: ignore[misc]


class TestNetworksRegistry:
    """Tests for networks registry."""

    def test_networks_registry_contains_expected_networks(self) -> None:
        """Test that NETWORKS contains expected network configurations."""
        assert "base-sepolia" in NETWORKS
        assert "base-mainnet" in NETWORKS
        assert len(NETWORKS) == 2

    def test_networks_registry_values(self) -> None:
        """Test that NETWORKS values are NetworkConfig instances."""
        assert NETWORKS["base-sepolia"] is BASE_SEPOLIA
        assert NETWORKS["base-mainnet"] is BASE_MAINNET


class TestGetNetwork:
    """Tests for get_network() function."""

    def test_get_base_sepolia(self) -> None:
        """Test getting Base Sepolia network configuration."""
        config = get_network("base-sepolia")
        assert config.name == "Base Sepolia"
        assert config.chain_id == 84532

    def test_get_unknown_network_raises_error(self) -> None:
        """Test that getting unknown network raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            get_network("unknown-network")

        assert "Unknown network" in str(exc_info.value)
        assert "unknown-network" in str(exc_info.value)

    def test_get_mainnet_raises_error_not_deployed(self) -> None:
        """Test that getting mainnet raises error because contracts not deployed."""
        with pytest.raises(ValidationError) as exc_info:
            get_network("base-mainnet")

        assert "not yet deployed" in str(exc_info.value).lower() or "zero" in str(exc_info.value).lower()


class TestIsValidNetwork:
    """Tests for is_valid_network() function."""

    def test_valid_networks(self) -> None:
        """Test that valid networks return True."""
        assert is_valid_network("base-sepolia") is True
        assert is_valid_network("base-mainnet") is True

    def test_invalid_networks(self) -> None:
        """Test that invalid networks return False."""
        assert is_valid_network("unknown") is False
        assert is_valid_network("") is False
        assert is_valid_network("ethereum") is False


class TestValidateNetworkConfig:
    """Tests for validate_network_config() function."""

    def test_validate_sepolia_passes(self) -> None:
        """Test that Base Sepolia validation passes."""
        # Should not raise
        validate_network_config(BASE_SEPOLIA)

    def test_validate_mainnet_fails_not_deployed(self) -> None:
        """Test that Base Mainnet validation fails because not deployed."""
        with pytest.raises(ValidationError) as exc_info:
            validate_network_config(BASE_MAINNET)

        error_message = str(exc_info.value)
        assert "zero" in error_message.lower() or "not yet deployed" in error_message.lower()

    def test_validate_custom_config_with_zero_addresses(self) -> None:
        """Test validation with custom config having zero addresses."""
        custom_config = NetworkConfig(
            name="Test Network",
            chain_id=1337,
            rpc_url="http://localhost:8545",
            block_explorer="https://localhost",
            contracts=ContractAddresses(
                actp_kernel="0x0000000000000000000000000000000000000000",
                escrow_vault="0x0000000000000000000000000000000000000000",
                usdc="0x0000000000000000000000000000000000000000",
                eas="0x4200000000000000000000000000000000000021",
                eas_schema_registry="0x4200000000000000000000000000000000000020",
            ),
            eas=EASConfig(delivery_schema_uid="0x" + "0" * 64),
            gas_settings=GasSettings(
                max_fee_per_gas=1_000_000_000,
                max_priority_fee_per_gas=500_000_000,
            ),
        )

        with pytest.raises(ValidationError):
            validate_network_config(custom_config)


class TestContractAddressValues:
    """Tests for actual contract address values."""

    def test_sepolia_kernel_address_format(self) -> None:
        """Test Base Sepolia ACTPKernel address format."""
        address = BASE_SEPOLIA.contracts.actp_kernel
        assert address.startswith("0x")
        assert len(address) == 42  # 0x + 40 hex chars

    def test_sepolia_escrow_address_format(self) -> None:
        """Test Base Sepolia EscrowVault address format."""
        address = BASE_SEPOLIA.contracts.escrow_vault
        assert address.startswith("0x")
        assert len(address) == 42

    def test_sepolia_usdc_address_format(self) -> None:
        """Test Base Sepolia USDC address format."""
        address = BASE_SEPOLIA.contracts.usdc
        assert address.startswith("0x")
        assert len(address) == 42

    def test_sepolia_eas_is_base_native(self) -> None:
        """Test that EAS address is the Base native EAS contract."""
        # Base native EAS is at a predeploy address
        assert BASE_SEPOLIA.contracts.eas == "0x4200000000000000000000000000000000000021"

    def test_sepolia_schema_registry_is_base_native(self) -> None:
        """Test that Schema Registry is the Base native contract."""
        assert BASE_SEPOLIA.contracts.eas_schema_registry == "0x4200000000000000000000000000000000000020"

    def test_mainnet_usdc_is_official(self) -> None:
        """Test that mainnet USDC is the official address."""
        # Official USDC on Base mainnet
        assert BASE_MAINNET.contracts.usdc == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
