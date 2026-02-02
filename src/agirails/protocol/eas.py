"""
Ethereum Attestation Service (EAS) Helper for AGIRAILS SDK.

Provides integration with EAS for creating and verifying attestations:
- Delivery attestations (AIP-4)
- Agent reputation attestations
- Schema registration

EAS is the core on-chain proof system for ACTP protocol.
On Base, EAS is deployed at predeploy address 0x4200000000000000000000000000000000000021.

Example:
    >>> from agirails.protocol import EASHelper
    >>> eas = await EASHelper.create(private_key, network="base-sepolia")
    >>> uid = await eas.create_delivery_attestation(tx_id, output_hash, provider)
    >>> attestation = await eas.get_attestation(uid)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

# Security Note (M-3): Default timeout for transaction receipts (5 minutes)
DEFAULT_TX_WAIT_TIMEOUT = 300.0

try:
    from eth_abi import encode
    from eth_account.signers.local import LocalAccount
    from web3 import AsyncWeb3
    from web3.contract import AsyncContract

    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False
    AsyncWeb3 = None  # type: ignore[misc, assignment]
    AsyncContract = None  # type: ignore[misc, assignment]
    LocalAccount = None  # type: ignore[misc, assignment]

from agirails.config.networks import NetworkConfig, get_network
from agirails.types.transaction import TransactionReceipt
from agirails.utils.used_attestation_tracker import (
    IUsedAttestationTracker,
    InMemoryUsedAttestationTracker,
)


# EAS contract ABI (minimal for attestations)
EAS_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"name": "schema", "type": "bytes32"},
                    {
                        "components": [
                            {"name": "recipient", "type": "address"},
                            {"name": "expirationTime", "type": "uint64"},
                            {"name": "revocable", "type": "bool"},
                            {"name": "refUID", "type": "bytes32"},
                            {"name": "data", "type": "bytes"},
                            {"name": "value", "type": "uint256"},
                        ],
                        "name": "data",
                        "type": "tuple",
                    },
                ],
                "name": "request",
                "type": "tuple",
            }
        ],
        "name": "attest",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "getAttestation",
        "outputs": [
            {
                "components": [
                    {"name": "uid", "type": "bytes32"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocationTime", "type": "uint64"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "attester", "type": "address"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "data", "type": "bytes"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "isAttestationValid",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {
                "components": [
                    {"name": "schema", "type": "bytes32"},
                    {
                        "components": [
                            {"name": "uid", "type": "bytes32"},
                            {"name": "value", "type": "uint256"},
                        ],
                        "name": "data",
                        "type": "tuple",
                    },
                ],
                "name": "request",
                "type": "tuple",
            }
        ],
        "name": "revoke",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    },
]

# Schema Registry ABI (minimal)
SCHEMA_REGISTRY_ABI = [
    {
        "inputs": [
            {"name": "schema", "type": "string"},
            {"name": "resolver", "type": "address"},
            {"name": "revocable", "type": "bool"},
        ],
        "name": "register",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "getSchema",
        "outputs": [
            {
                "components": [
                    {"name": "uid", "type": "bytes32"},
                    {"name": "resolver", "type": "address"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "schema", "type": "string"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

# ACTP Delivery Schema (AIP-6) - Current mainnet standard
# Schema: bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt
DELIVERY_SCHEMA_AIP6 = "bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt"

# Legacy AIP-4 schema (for backwards compatibility)
DELIVERY_SCHEMA_AIP4 = "bytes32 transactionId, bytes32 outputHash, address provider, uint64 timestamp"

# Default to AIP-6 for new registrations
DELIVERY_SCHEMA = DELIVERY_SCHEMA_AIP6

# Zero bytes32 for reference UIDs
ZERO_BYTES32 = "0x" + "0" * 64


@dataclass
class Attestation:
    """
    EAS Attestation data.

    Attributes:
        uid: Unique attestation ID
        schema: Schema UID
        time: Attestation timestamp
        expiration_time: Expiration timestamp (0 = never)
        revocation_time: Revocation timestamp (0 = not revoked)
        ref_uid: Reference attestation UID
        recipient: Attestation recipient
        attester: Who created the attestation
        revocable: Whether attestation can be revoked
        data: Encoded attestation data
    """

    uid: str
    schema: str
    time: int
    expiration_time: int
    revocation_time: int
    ref_uid: str
    recipient: str
    attester: str
    revocable: bool
    data: bytes

    @property
    def is_valid(self) -> bool:
        """Check if attestation is currently valid."""
        now = int(time.time())
        # Not revoked
        if self.revocation_time > 0:
            return False
        # Not expired
        if self.expiration_time > 0 and now > self.expiration_time:
            return False
        return True

    @property
    def is_revoked(self) -> bool:
        """Check if attestation has been revoked."""
        return self.revocation_time > 0

    @property
    def is_expired(self) -> bool:
        """Check if attestation has expired."""
        if self.expiration_time == 0:
            return False
        return int(time.time()) > self.expiration_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "uid": self.uid,
            "schema": self.schema,
            "time": self.time,
            "expirationTime": self.expiration_time,
            "revocationTime": self.revocation_time,
            "refUID": self.ref_uid,
            "recipient": self.recipient,
            "attester": self.attester,
            "revocable": self.revocable,
            "data": "0x" + self.data.hex(),
            "isValid": self.is_valid,
        }


@dataclass
class DeliveryAttestationData:
    """
    Decoded delivery attestation data.

    Supports both AIP-6 (current) and AIP-4 (legacy) schema formats.

    AIP-6 fields: transaction_id, result_cid, result_hash, delivered_at
    AIP-4 fields: transaction_id, output_hash, provider, timestamp

    Attributes:
        transaction_id: ACTP transaction ID (both formats)
        result_cid: IPFS CID of result (AIP-6 only)
        result_hash: Hash of the result (AIP-6) or output (AIP-4)
        delivered_at: Delivery timestamp (AIP-6) or legacy timestamp
        provider: Provider address (AIP-4 only, None for AIP-6)
        schema_version: "aip6" or "aip4"
    """

    transaction_id: str
    result_hash: str  # AIP-6: resultHash, AIP-4: outputHash
    delivered_at: int  # AIP-6: deliveredAt, AIP-4: timestamp
    result_cid: Optional[str] = None  # AIP-6 only
    provider: Optional[str] = None  # AIP-4 only
    schema_version: str = "aip6"

    # Backwards compatibility aliases
    @property
    def output_hash(self) -> str:
        """Alias for result_hash (AIP-4 compatibility)."""
        return self.result_hash

    @property
    def timestamp(self) -> int:
        """Alias for delivered_at (AIP-4 compatibility)."""
        return self.delivered_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = {
            "transactionId": self.transaction_id,
            "resultHash": self.result_hash,
            "deliveredAt": self.delivered_at,
            "schemaVersion": self.schema_version,
        }
        if self.result_cid:
            base["resultCID"] = self.result_cid
        if self.provider:
            base["provider"] = self.provider
        # Legacy aliases
        base["outputHash"] = self.result_hash
        base["timestamp"] = self.delivered_at
        return base


@dataclass
class Schema:
    """
    EAS Schema data.

    Attributes:
        uid: Schema UID
        resolver: Resolver contract address
        revocable: Whether attestations can be revoked
        schema: Schema definition string
    """

    uid: str
    resolver: str
    revocable: bool
    schema: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "uid": self.uid,
            "resolver": self.resolver,
            "revocable": self.revocable,
            "schema": self.schema,
        }


class EASHelper:
    """
    Ethereum Attestation Service helper for ACTP protocol.

    Provides methods to create and verify attestations on EAS.

    Args:
        eas_contract: EAS contract instance
        schema_registry: Schema registry contract instance
        account: Signing account
        w3: Web3 instance
        chain_id: Chain ID
        delivery_schema_uid: Pre-registered delivery schema UID
        attestation_tracker: Optional tracker for replay attack prevention (C-1 fix)

    Example:
        >>> eas = await EASHelper.create(private_key, network="base-sepolia")
        >>> uid = await eas.create_delivery_attestation(
        ...     transaction_id="0x...",
        ...     output_hash="0x...",
        ...     provider="0x..."
        ... )
    """

    def __init__(
        self,
        eas_contract: AsyncContract,
        schema_registry: AsyncContract,
        account: LocalAccount,
        w3: AsyncWeb3,
        chain_id: int,
        delivery_schema_uid: str = "",
        attestation_tracker: Optional[IUsedAttestationTracker] = None,
    ) -> None:
        self._eas = eas_contract
        self._schema_registry = schema_registry
        self._account = account
        self._w3 = w3
        self._chain_id = chain_id
        self._delivery_schema_uid = delivery_schema_uid
        # SECURITY FIX (C-1): Track used attestations to prevent replay attacks
        self._attestation_tracker = attestation_tracker or InMemoryUsedAttestationTracker()

    @property
    def attestation_tracker(self) -> IUsedAttestationTracker:
        """Get the attestation tracker for replay protection."""
        return self._attestation_tracker

    @classmethod
    async def create(
        cls,
        private_key: str,
        network: Union[str, NetworkConfig] = "base-sepolia",
        rpc_url: Optional[str] = None,
        attestation_tracker: Optional[IUsedAttestationTracker] = None,
    ) -> "EASHelper":
        """
        Create EASHelper with connection to blockchain.

        Args:
            private_key: Ethereum private key
            network: Network name or config
            rpc_url: Optional custom RPC URL
            attestation_tracker: Optional tracker for replay attack prevention

        Returns:
            Configured EASHelper instance
        """
        if not HAS_WEB3:
            raise ImportError(
                "web3 and eth_account are required for EASHelper. "
                "Install with: pip install web3 eth-account"
            )

        # Get network config
        if isinstance(network, str):
            config = get_network(network)
        else:
            config = network

        # Use custom RPC or network default
        rpc = rpc_url or config.rpc_url

        # Create web3 instance
        from eth_account import Account

        w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc))
        account = Account.from_key(private_key)

        # Create contract instances
        eas_contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.eas),
            abi=EAS_ABI,
        )
        schema_registry = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.eas_schema_registry),
            abi=SCHEMA_REGISTRY_ABI,
        )

        return cls(
            eas_contract=eas_contract,
            schema_registry=schema_registry,
            account=account,
            w3=w3,
            chain_id=config.chain_id,
            delivery_schema_uid=config.eas.delivery_schema_uid,
            attestation_tracker=attestation_tracker,
        )

    @property
    def address(self) -> str:
        """Get account address."""
        return self._account.address

    @property
    def delivery_schema_uid(self) -> str:
        """Get delivery schema UID."""
        return self._delivery_schema_uid

    def _encode_delivery_data_aip6(
        self,
        transaction_id: str,
        result_cid: str,
        result_hash: str,
        delivered_at: int,
    ) -> bytes:
        """
        Encode delivery attestation data in AIP-6 format (mainnet standard).

        Schema: bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt
        """
        tx_id_bytes = bytes.fromhex(transaction_id.replace("0x", "")).ljust(32, b"\x00")
        result_hash_bytes = bytes.fromhex(result_hash.replace("0x", "")).ljust(32, b"\x00")

        return encode(
            ["bytes32", "string", "bytes32", "uint256"],
            [tx_id_bytes, result_cid, result_hash_bytes, delivered_at],
        )

    def _encode_delivery_data_aip4(
        self,
        transaction_id: str,
        output_hash: str,
        provider: str,
        timestamp: int,
    ) -> bytes:
        """
        Encode delivery attestation data in AIP-4 format (legacy).

        Schema: bytes32 transactionId, bytes32 outputHash, address provider, uint64 timestamp
        """
        tx_id_bytes = bytes.fromhex(transaction_id.replace("0x", "")).ljust(32, b"\x00")
        output_bytes = bytes.fromhex(output_hash.replace("0x", "")).ljust(32, b"\x00")
        provider_addr = self._w3.to_checksum_address(provider)

        return encode(
            ["bytes32", "bytes32", "address", "uint64"],
            [tx_id_bytes, output_bytes, provider_addr, timestamp],
        )

    def _encode_delivery_data(
        self,
        transaction_id: str,
        result_cid: str,
        result_hash: str,
        delivered_at: int,
    ) -> bytes:
        """
        Encode delivery attestation data (defaults to AIP-6 format).

        For legacy AIP-4 format, use _encode_delivery_data_aip4() directly.
        """
        return self._encode_delivery_data_aip6(
            transaction_id, result_cid, result_hash, delivered_at
        )

    def _decode_delivery_data(self, data: bytes) -> DeliveryAttestationData:
        """
        Decode delivery attestation data.

        Tries AIP-6 format first, then falls back to AIP-4 for backwards compatibility.

        AIP-6: bytes32 txId, string resultCID, bytes32 resultHash, uint256 deliveredAt
        AIP-4: bytes32 transactionId, bytes32 outputHash, address provider, uint64 timestamp
        """
        from eth_abi import decode

        # Try AIP-6 format first (current mainnet standard)
        try:
            decoded = decode(
                ["bytes32", "string", "bytes32", "uint256"],
                data,
            )
            tx_id = "0x" + decoded[0].hex()
            result_cid = decoded[1]
            result_hash = "0x" + decoded[2].hex()
            delivered_at = int(decoded[3])

            # Validate decoded values
            if not tx_id or len(tx_id) != 66:
                raise ValueError("Invalid txId")
            if not isinstance(result_cid, str) or len(result_cid) > 2048:
                raise ValueError("Invalid resultCID")
            if not result_hash or len(result_hash) != 66:
                raise ValueError("Invalid resultHash")

            return DeliveryAttestationData(
                transaction_id=tx_id,
                result_cid=result_cid,
                result_hash=result_hash,
                delivered_at=delivered_at,
                schema_version="aip6",
            )
        except Exception:
            pass

        # Fallback to AIP-4 format (legacy)
        try:
            decoded = decode(
                ["bytes32", "bytes32", "address", "uint64"],
                data,
            )
            return DeliveryAttestationData(
                transaction_id="0x" + decoded[0].hex(),
                result_hash="0x" + decoded[1].hex(),  # outputHash -> result_hash
                delivered_at=int(decoded[3]),  # timestamp -> delivered_at
                provider=decoded[2],
                schema_version="aip4",
            )
        except Exception as e:
            raise ValueError(
                f"Failed to decode attestation data. "
                f"Expected AIP-6 (txId, resultCID, resultHash, deliveredAt) or "
                f"AIP-4 (transactionId, outputHash, provider, timestamp) format. "
                f"Error: {e}"
            )

    async def _build_transaction(
        self,
        function: Any,
        value: int = 0,
    ) -> Dict[str, Any]:
        """Build transaction parameters."""
        nonce = await self._w3.eth.get_transaction_count(self._account.address)
        gas_price = await self._w3.eth.gas_price

        tx_params = {
            "from": self._account.address,
            "nonce": nonce,
            "gasPrice": gas_price,
            "chainId": self._chain_id,
            "value": value,
        }

        # Estimate gas
        gas = await function.estimate_gas(tx_params)
        tx_params["gas"] = int(gas * 1.2)  # 20% buffer

        return await function.build_transaction(tx_params)

    async def _send_transaction(
        self,
        tx: Dict[str, Any],
        timeout: float = DEFAULT_TX_WAIT_TIMEOUT,
    ) -> TransactionReceipt:
        """
        Sign and send transaction.

        Security Note (M-3): Uses timeout to prevent indefinite hangs.

        Args:
            tx: Transaction dictionary
            timeout: Max seconds to wait for receipt (default: 300s)

        Returns:
            Transaction receipt

        Raises:
            RuntimeError: If transaction times out
        """
        signed = self._account.sign_transaction(tx)
        tx_hash = await self._w3.eth.send_raw_transaction(signed.raw_transaction)

        try:
            receipt = await asyncio.wait_for(
                self._w3.eth.wait_for_transaction_receipt(tx_hash),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Transaction {tx_hash.hex()} timed out after {timeout}s. "
                "Check network congestion and gas settings."
            )

        return TransactionReceipt(
            transaction_hash=receipt["transactionHash"].hex(),
            block_number=receipt["blockNumber"],
            block_hash=receipt["blockHash"].hex(),
            gas_used=receipt["gasUsed"],
            effective_gas_price=receipt.get("effectiveGasPrice", 0),
            status=receipt["status"],
            logs=[dict(log) for log in receipt.get("logs", [])],
        )

    async def create_delivery_attestation(
        self,
        transaction_id: str,
        result_cid: str,
        result_hash: str,
        recipient: Optional[str] = None,
        expiration_time: int = 0,
        ref_uid: str = ZERO_BYTES32,
        revocable: bool = True,
    ) -> str:
        """
        Create a delivery attestation on EAS (AIP-6 format).

        Args:
            transaction_id: ACTP transaction ID (bytes32)
            result_cid: IPFS CID of the delivered result
            result_hash: Hash of the delivered result (bytes32)
            recipient: Attestation recipient (defaults to attester)
            expiration_time: When attestation expires (0 = never)
            ref_uid: Reference attestation UID
            revocable: Whether attestation can be revoked

        Returns:
            Attestation UID

        Raises:
            ValueError: If delivery schema is not configured
        """
        if not self._delivery_schema_uid:
            raise ValueError(
                "Delivery schema UID not configured. "
                "Register a schema first or provide in network config."
            )

        # Default recipient to attester
        recipient = recipient or self._account.address

        # Encode attestation data (AIP-6 format)
        delivered_at = int(time.time())
        data = self._encode_delivery_data_aip6(
            transaction_id=transaction_id,
            result_cid=result_cid,
            result_hash=result_hash,
            delivered_at=delivered_at,
        )

        # Build attestation request
        request = (
            bytes.fromhex(self._delivery_schema_uid.replace("0x", "")),
            (
                self._w3.to_checksum_address(recipient),
                expiration_time,
                revocable,
                bytes.fromhex(ref_uid.replace("0x", "")),
                data,
                0,  # value
            ),
        )

        # Build and send transaction
        function = self._eas.functions.attest(request)
        tx = await self._build_transaction(function)
        receipt = await self._send_transaction(tx)

        # Extract UID from logs
        # The Attested event contains the UID as the first topic
        if receipt.logs:
            # UID is in the first indexed topic of the Attested event
            attested_event = receipt.logs[0]
            if "topics" in attested_event and len(attested_event["topics"]) > 1:
                return "0x" + attested_event["topics"][1].hex()

        # Fallback: read from return value (if available)
        raise ValueError("Failed to extract attestation UID from transaction")

    async def create_delivery_attestation_aip4(
        self,
        transaction_id: str,
        output_hash: str,
        provider: str,
        recipient: Optional[str] = None,
        expiration_time: int = 0,
        ref_uid: str = ZERO_BYTES32,
        revocable: bool = True,
    ) -> str:
        """
        Create a delivery attestation on EAS (legacy AIP-4 format).

        Use create_delivery_attestation() for new attestations (AIP-6 format).

        Args:
            transaction_id: ACTP transaction ID
            output_hash: Hash of the delivered output
            provider: Provider address
            recipient: Attestation recipient (defaults to provider)
            expiration_time: When attestation expires (0 = never)
            ref_uid: Reference attestation UID
            revocable: Whether attestation can be revoked

        Returns:
            Attestation UID
        """
        if not self._delivery_schema_uid:
            raise ValueError(
                "Delivery schema UID not configured. "
                "Register a schema first or provide in network config."
            )

        recipient = recipient or provider
        timestamp = int(time.time())

        data = self._encode_delivery_data_aip4(
            transaction_id=transaction_id,
            output_hash=output_hash,
            provider=provider,
            timestamp=timestamp,
        )

        request = (
            bytes.fromhex(self._delivery_schema_uid.replace("0x", "")),
            (
                self._w3.to_checksum_address(recipient),
                expiration_time,
                revocable,
                bytes.fromhex(ref_uid.replace("0x", "")),
                data,
                0,
            ),
        )

        function = self._eas.functions.attest(request)
        tx = await self._build_transaction(function)
        receipt = await self._send_transaction(tx)

        if receipt.logs:
            attested_event = receipt.logs[0]
            if "topics" in attested_event and len(attested_event["topics"]) > 1:
                return "0x" + attested_event["topics"][1].hex()

        raise ValueError("Failed to extract attestation UID from transaction")

    async def get_attestation(self, uid: str) -> Attestation:
        """
        Get attestation by UID.

        Args:
            uid: Attestation UID

        Returns:
            Attestation data
        """
        uid_bytes = bytes.fromhex(uid.replace("0x", ""))
        result = await self._eas.functions.getAttestation(uid_bytes).call()

        return Attestation(
            uid="0x" + result[0].hex(),
            schema="0x" + result[1].hex(),
            time=result[2],
            expiration_time=result[3],
            revocation_time=result[4],
            ref_uid="0x" + result[5].hex(),
            recipient=result[6],
            attester=result[7],
            revocable=result[8],
            data=result[9],
        )

    async def is_attestation_valid(self, uid: str) -> bool:
        """
        Check if attestation is valid (not revoked, not expired).

        Args:
            uid: Attestation UID

        Returns:
            True if valid
        """
        uid_bytes = bytes.fromhex(uid.replace("0x", ""))
        return await self._eas.functions.isAttestationValid(uid_bytes).call()

    async def get_delivery_attestation(self, uid: str) -> DeliveryAttestationData:
        """
        Get and decode a delivery attestation.

        Args:
            uid: Attestation UID

        Returns:
            Decoded delivery attestation data
        """
        attestation = await self.get_attestation(uid)
        return self._decode_delivery_data(attestation.data)

    async def revoke_attestation(
        self,
        uid: str,
        value: int = 0,
    ) -> TransactionReceipt:
        """
        Revoke an attestation.

        Args:
            uid: Attestation UID to revoke
            value: Optional ETH value to send

        Returns:
            Transaction receipt
        """
        if not self._delivery_schema_uid:
            raise ValueError("Schema UID required for revocation")

        uid_bytes = bytes.fromhex(uid.replace("0x", ""))
        schema_bytes = bytes.fromhex(self._delivery_schema_uid.replace("0x", ""))

        request = (
            schema_bytes,
            (uid_bytes, value),
        )

        function = self._eas.functions.revoke(request)
        tx = await self._build_transaction(function, value)
        return await self._send_transaction(tx)

    async def register_schema(
        self,
        schema: str,
        resolver: str = "0x0000000000000000000000000000000000000000",
        revocable: bool = True,
    ) -> str:
        """
        Register a new schema.

        Args:
            schema: Schema definition string
            resolver: Optional resolver contract address
            revocable: Whether attestations can be revoked

        Returns:
            Schema UID
        """
        function = self._schema_registry.functions.register(
            schema,
            self._w3.to_checksum_address(resolver),
            revocable,
        )
        tx = await self._build_transaction(function)
        receipt = await self._send_transaction(tx)

        # Extract UID from logs
        if receipt.logs:
            registered_event = receipt.logs[0]
            if "topics" in registered_event and len(registered_event["topics"]) > 1:
                return "0x" + registered_event["topics"][1].hex()

        raise ValueError("Failed to extract schema UID from transaction")

    async def get_schema(self, uid: str) -> Schema:
        """
        Get schema by UID.

        Args:
            uid: Schema UID

        Returns:
            Schema data
        """
        uid_bytes = bytes.fromhex(uid.replace("0x", ""))
        result = await self._schema_registry.functions.getSchema(uid_bytes).call()

        return Schema(
            uid="0x" + result[0].hex(),
            resolver=result[1],
            revocable=result[2],
            schema=result[3],
        )

    async def register_delivery_schema(self) -> str:
        """
        Register the ACTP delivery schema if not already registered.

        Returns:
            Schema UID (new or existing)
        """
        # First check if we have a schema UID and it exists
        if self._delivery_schema_uid:
            try:
                schema = await self.get_schema(self._delivery_schema_uid)
                if schema.schema == DELIVERY_SCHEMA:
                    return self._delivery_schema_uid
            except Exception:
                pass

        # Register new schema
        uid = await self.register_schema(DELIVERY_SCHEMA)
        self._delivery_schema_uid = uid
        return uid

    async def verify_delivery_attestation(
        self,
        tx_id: str,
        attestation_uid: str,
    ) -> bool:
        """
        Verify that an attestation is valid for a given transaction.

        SECURITY: ACTPKernel V1 accepts any bytes32 as attestationUID without validation.
        This means a malicious provider could submit attestation from Transaction A
        for Transaction B. This method provides SDK-side protection by verifying:

        1. Attestation exists and is not revoked
        2. Attestation uses the canonical delivery schema UID
        3. Attestation's txId matches the expected transaction ID
        4. Attestation has not expired
        5. Attestation has not been used for another transaction (replay protection)

        Args:
            tx_id: Expected transaction ID (bytes32)
            attestation_uid: Attestation UID to verify (bytes32)

        Returns:
            True if attestation is valid for this transaction

        Raises:
            ValueError: If attestation is invalid, revoked, expired, schema mismatch, or txId mismatch
        """
        import re

        # 1. Validate input formats
        bytes32_pattern = re.compile(r"^0x[a-fA-F0-9]{64}$")
        if not tx_id or not bytes32_pattern.match(tx_id):
            raise ValueError(f"Invalid tx_id format (expected bytes32): {tx_id}")
        if not attestation_uid or not bytes32_pattern.match(attestation_uid):
            raise ValueError(
                f"Invalid attestation_uid format (expected bytes32): {attestation_uid}"
            )

        # 2. Fetch attestation from EAS contract
        attestation = await self.get_attestation(attestation_uid)

        # 3. Check if attestation exists (uid should match)
        if attestation.uid.lower() != attestation_uid.lower():
            raise ValueError(f"Attestation not found: {attestation_uid}")

        # 4. Check schema UID matches canonical delivery schema (B2 blocker fix)
        if self._delivery_schema_uid:
            if attestation.schema.lower() != self._delivery_schema_uid.lower():
                raise ValueError(
                    f"Schema UID mismatch: expected canonical delivery schema "
                    f"{self._delivery_schema_uid}, got {attestation.schema}. "
                    f"Attestation may be from a different schema!"
                )

        # 5. Check revocation
        if attestation.is_revoked:
            raise ValueError(
                f"Attestation has been revoked: {attestation_uid} "
                f"(revoked at timestamp {attestation.revocation_time})"
            )

        # 6. Check expiration
        if attestation.is_expired:
            raise ValueError(
                f"Attestation has expired: {attestation_uid} "
                f"(expired at {attestation.expiration_time})"
            )

        # 7. Decode attestation data to extract txId
        try:
            delivery_data = self._decode_delivery_data(attestation.data)
            attested_tx_id = delivery_data.transaction_id
        except Exception as e:
            raise ValueError(
                f"Attestation data format mismatch: cannot decode attestation {attestation_uid}. "
                f"Expected delivery proof schema format. Original error: {e}"
            )

        # 8. Verify attestation txId matches expected transaction ID
        if attested_tx_id.lower() != tx_id.lower():
            raise ValueError(
                f"Attestation txId mismatch: expected {tx_id}, got {attested_tx_id}. "
                f"Provider may be attempting to use attestation from different transaction!"
            )

        # 9. SECURITY FIX (C-1): Check if attestation has been used for a different transaction
        if not self._attestation_tracker.is_valid_for_transaction(attestation_uid, tx_id):
            used_for = self._attestation_tracker.get_usage_for_attestation(attestation_uid)
            raise ValueError(
                f"Attestation replay attack detected: attestation {attestation_uid} "
                f"was already used for transaction {used_for}. "
                f"Cannot reuse for transaction {tx_id}."
            )

        # 10. Record this attestation as used for this transaction
        recorded = await self._attestation_tracker.record_usage(attestation_uid, tx_id)
        if not recorded:
            used_for = self._attestation_tracker.get_usage_for_attestation(attestation_uid)
            raise ValueError(
                f"Attestation replay attack detected: attestation {attestation_uid} "
                f"was already used for transaction {used_for}. Cannot reuse for {tx_id}."
            )

        # All checks passed
        return True

    async def verify_and_record_for_release(
        self,
        tx_id: str,
        attestation_uid: str,
    ) -> None:
        """
        Verify attestation for escrow release with mandatory replay protection.

        SECURITY FIX (C-4): This method MUST be called before releaseEscrow()
        to prevent attestation replay attacks.

        Args:
            tx_id: Expected transaction ID (bytes32)
            attestation_uid: Attestation UID to verify (bytes32)

        Raises:
            ValueError: If verification fails or replay attack detected
        """
        await self.verify_delivery_attestation(tx_id, attestation_uid)


__all__ = [
    "EASHelper",
    "Attestation",
    "DeliveryAttestationData",
    "Schema",
    "DELIVERY_SCHEMA",
    "DELIVERY_SCHEMA_AIP6",
    "DELIVERY_SCHEMA_AIP4",
    "ZERO_BYTES32",
    "HAS_WEB3",
]
