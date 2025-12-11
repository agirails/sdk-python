"""ACTP Protocol Client for Python.

This module provides the ACTPClient class for interacting with the
ACTP (Agent Commerce Transaction Protocol) on Base L2 blockchain.

The client supports:
- Transaction creation and state management
- Escrow funding and release
- Milestone-based payments
- Dispute handling
- EAS attestation verification
- Agent registry operations (AIP-7)

Example:
    >>> from agirails_sdk import ACTPClient, Network
    >>> client = ACTPClient(
    ...     network=Network.BASE_SEPOLIA,
    ...     private_key="0x..."
    ... )
    >>> tx_id = client.create_transaction(
    ...     provider="0x...",
    ...     requester=client.address,
    ...     amount=1_000_000,  # 1 USDC (6 decimals)
    ...     deadline=int(time.time()) + 86400,
    ...     dispute_window=7200
    ... )
"""
import json
import secrets
import ipaddress
from pathlib import Path
from typing import Optional, Union

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract
from web3.types import TxParams

import re

from .config import Network, get_network_config
from .constants import (
    ABI_SELECTOR_LENGTH,
    ABI_WORD_LENGTH,
    BYTES32_HEX_LENGTH,
    BYTES32_LENGTH,
    DEFAULT_GAS_LIMIT,
    DID_PATTERN,
    GAS_ESTIMATION_BUFFER,
    MAX_COMPLETION_TIME_SECONDS,
    MAX_FEE_MULTIPLIER,
    MAX_GAS_LIMIT,
    MAX_METADATA_CID_LENGTH,
    MAX_PRICE_USDC,
    MAX_QUERY_LIMIT,
    MAX_SAFE_AMOUNT,
    MAX_SCHEMA_URI_LENGTH,
    MAX_SERVICE_DESCRIPTORS,
    MAX_SERVICE_TYPE_LENGTH,
    MIN_MAX_FEE_GWEI,
    PRIORITY_FEE_GWEI,
    PROVIDER_TIMEOUT_SECONDS,
    QUERY_CAP,
    REPUTATION_MAX,
    REVERT_SELECTOR,
    SERVICE_TYPE_PATTERN,
)
from .errors import (
    DeadlineError,
    InvalidStateTransitionError,
    QueryCapExceededError,
    RpcError,
    TransactionError,
    ValidationError,
)
from .models import AgentProfile, ServiceDescriptor, State, TransactionView

# ABI file directory
ABI_DIR = Path(__file__).parent / "abis"

# ABI loading cache
_ABI_CACHE: dict[str, list] = {}


# ------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------

def _load_abi(name: str) -> list:
    """Load ABI JSON with caching.

    Args:
        name: ABI filename (e.g., "actp_kernel.json")

    Returns:
        Parsed ABI list
    """
    if name not in _ABI_CACHE:
        _ABI_CACHE[name] = json.loads((ABI_DIR / name).read_text())
    return _ABI_CACHE[name]


def _validate_amount(amount: int, field: str = "amount") -> None:
    """Validate amount is non-negative and within safe bounds.

    Args:
        amount: Amount to validate
        field: Field name for error message

    Raises:
        ValidationError: If amount is negative or exceeds maximum safe amount
    """
    if amount < 0:
        raise ValidationError(f"{field} must be non-negative")
    if amount > MAX_SAFE_AMOUNT:
        raise ValidationError(f"{field} exceeds maximum safe amount")


def _validate_address(address: str, field: str = "address") -> None:
    """Validate Ethereum address format.

    Args:
        address: Address to validate (0x-prefixed hex string)
        field: Field name for error message

    Raises:
        ValidationError: If address format is invalid
    """
    if not Web3.is_address(address):
        raise ValidationError(f"{field} must be a valid Ethereum address")


def _validate_endpoint_url(url: str, field: str = "endpoint") -> None:
    """Validate endpoint URL for SSRF protection.

    Prevents Server-Side Request Forgery by blocking:
    - file:// protocol
    - localhost/127.0.0.1 (private IPs)
    - Internal IP ranges (10.x, 172.16-31.x, 192.168.x)
    - IPv6 private ranges (fc00::/7, fe80::/10)
    - Cloud metadata services (169.254.169.254, metadata.google.internal)

    Args:
        url: URL to validate
        field: Field name for error message

    Raises:
        ValidationError: If URL is potentially unsafe

    Reference:
        - TypeScript SDK: validateEndpointURL()
        - OWASP SSRF Prevention Cheat Sheet
    """
    import re
    from urllib.parse import urlparse

    # Must be valid URL
    if not url or not isinstance(url, str):
        raise ValidationError(f"{field} must be a non-empty string")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError(f"{field} must be a valid URL")

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"{field} must use http or https protocol")

    # Block localhost
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"{field} must have a valid hostname")

    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "[::1]"):
        raise ValidationError(f"{field} cannot use localhost")

    # Block cloud metadata services
    if hostname in ("169.254.169.254", "metadata.google.internal"):
        raise ValidationError(f"{field} cannot use cloud metadata services")

    # Block IPv6 mapped IPv4 addresses (::ffff:127.0.0.1)
    if hostname.startswith("::ffff:"):
        raise ValidationError(f"{field} cannot use IPv6-mapped IPv4 addresses")

    # Block private IP ranges (10.x, 172.16-31.x, 192.168.x)
    # Simple regex check for common private IPs
    if re.match(r"^10\.", hostname):
        raise ValidationError(f"{field} cannot use private IP range (10.x.x.x)")
    if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", hostname):
        raise ValidationError(f"{field} cannot use private IP range (172.16-31.x.x)")
    if re.match(r"^192\.168\.", hostname):
        raise ValidationError(f"{field} cannot use private IP range (192.168.x.x)")

    # Block IPv6 private ranges using ipaddress module
    try:
        # Try parsing as IP address
        ip = ipaddress.ip_address(hostname)

        # Block IPv6 private ranges
        if isinstance(ip, ipaddress.IPv6Address):
            # fc00::/7 (Unique Local Addresses)
            if ip in ipaddress.IPv6Network('fc00::/7'):
                raise ValidationError(f"{field} cannot use IPv6 private range (fc00::/7)")
            # fe80::/10 (Link-Local Addresses)
            if ip in ipaddress.IPv6Network('fe80::/10'):
                raise ValidationError(f"{field} cannot use IPv6 link-local range (fe80::/10)")
    except ValueError:
        # Not a raw IP address (likely a domain name), skip IP checks
        pass


def _validate_dispute_window(window: int, field: str = "dispute_window") -> None:
    """Validate dispute window duration.

    Args:
        window: Dispute window in seconds
        field: Field name for error message

    Raises:
        ValidationError: If window is negative or exceeds maximum (30 days)
    """
    MAX_DISPUTE_WINDOW = 30 * 86400  # 30 days in seconds

    if window < 0:
        raise ValidationError(f"{field} must be non-negative")
    if window > MAX_DISPUTE_WINDOW:
        raise ValidationError(f"{field} cannot exceed 30 days (2592000 seconds)")


def _decode_revert_reason(raw: str) -> Optional[str]:
    """Decode Solidity revert reason from error data.

    Args:
        raw: Hex-encoded error data string

    Returns:
        Decoded revert reason string, or None if decoding fails
    """
    # Standard Solidity revertWithReason selector 0x08c379a0 + encoded string
    if raw.startswith(REVERT_SELECTOR) and len(raw) >= 10:
        try:
            data = bytes.fromhex(raw[2:])
            # offset: 4 bytes selector + 32 bytes offset + 32 bytes length
            if len(data) >= ABI_SELECTOR_LENGTH + ABI_WORD_LENGTH + ABI_WORD_LENGTH:
                offset = ABI_SELECTOR_LENGTH + ABI_WORD_LENGTH
                strlen = int.from_bytes(data[offset : offset + ABI_WORD_LENGTH], "big")
                reason_start = offset + ABI_WORD_LENGTH
                reason_bytes = data[reason_start : reason_start + strlen]
                return reason_bytes.decode(errors="ignore")
        except (ValueError, UnicodeDecodeError):
            # ValueError: invalid hex string
            # UnicodeDecodeError: invalid UTF-8 in reason bytes
            return None
    return None


def _encode_uint256(value: int) -> bytes:
    if value < 0 or value >= 1 << 256:
        raise ValidationError("uint256 out of range")
    return value.to_bytes(32, "big")


def _to_bytes32(value: Optional[Union[str, bytes]], field: str) -> bytes:
    if value is None:
        return b"\x00" * BYTES32_LENGTH

    if isinstance(value, str):
        hex_str = value[2:] if value.startswith("0x") else value
        if len(hex_str) != BYTES32_HEX_LENGTH:
            raise ValidationError(f"{field} must be 32 bytes hex string")
        return bytes.fromhex(hex_str)

    if isinstance(value, (bytes, bytearray)):
        if len(value) != BYTES32_LENGTH:
            raise ValidationError(f"{field} must be 32 bytes")
        return bytes(value)

    raise ValidationError(f"{field} must be hex string or bytes32")


class ACTPClient:
    """Minimal ACTP client using Web3.py."""

    ALLOWED_TRANSITIONS = {
        State.INITIATED: {State.QUOTED, State.COMMITTED, State.CANCELLED},
        State.QUOTED: {State.COMMITTED, State.CANCELLED},
        State.COMMITTED: {State.IN_PROGRESS, State.DISPUTED, State.CANCELLED},
        State.IN_PROGRESS: {State.DELIVERED, State.DISPUTED, State.CANCELLED},
        State.DELIVERED: {State.SETTLED, State.DISPUTED},
        State.DISPUTED: {State.SETTLED},
        State.SETTLED: set(),
        State.CANCELLED: set(),
    }

    def __init__(
        self,
        network: Network,
        private_key: str,
        rpc_url: Optional[str] = None,
        web3: Optional[Web3] = None,
        tx_overrides: Optional[dict] = None,
        manual_nonce: bool = False,
        timeout: int = PROVIDER_TIMEOUT_SECONDS,
    ):
        self.config = get_network_config(network, rpc_url)
        # Configure HTTPProvider with timeout to prevent DoS
        self.w3 = web3 or Web3(Web3.HTTPProvider(
            self.config.rpc_url,
            request_kwargs={"timeout": timeout}
        ))
        # Sanitize private key errors to prevent key leakage in stack traces
        try:
            self.account: LocalAccount = Account.from_key(private_key)
        except Exception:
            raise ValidationError("Invalid private key format (key not shown for security)") from None
        self.tx_overrides = tx_overrides or {}
        self.manual_nonce = manual_nonce
        self._next_nonce: Optional[int] = None
        self.kernel: Contract = self.w3.eth.contract(
            address=self.config.actp_kernel,
            abi=_load_abi("actp_kernel.json"),
        )
        self.usdc: Contract = self.w3.eth.contract(
            address=self.config.usdc,
            abi=_load_abi("usdc.json"),
        )
        self.eas: Optional[Contract] = None
        if getattr(self.config, "eas", None) and self.config.eas != "0x0000000000000000000000000000000000000000":
            self.eas = self.w3.eth.contract(address=self.config.eas, abi=_load_abi("eas.json"))
        self.agent_registry: Optional[Contract] = None
        if getattr(self.config, "agent_registry", None) and self.config.agent_registry != "0x0000000000000000000000000000000000000000":
            self.agent_registry = self.w3.eth.contract(address=self.config.agent_registry, abi=_load_abi("agent_registry.json"))

    @property
    def address(self) -> str:
        return self.account.address

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------
    def create_transaction(
        self,
        provider: str,
        requester: str,
        amount: int,
        deadline: int,
        dispute_window: int,
        service_hash: Optional[Union[str, bytes]] = None,
    ) -> str:
        """Create a new ACTP transaction.

        Args:
            provider: Provider address
            requester: Requester address
            amount: Transaction amount in USDC wei (must be non-negative)
            deadline: Unix timestamp deadline (must be in future)
            dispute_window: Dispute window in seconds
            service_hash: Optional service hash

        Returns:
            Transaction ID (bytes32 hex string)

        Raises:
            ValidationError: If amount is negative or deadline is not in future
        """
        # Validate amount is non-negative
        _validate_amount(amount)

        # Validate deadline is in future
        now = self.now()
        if deadline <= now:
            raise DeadlineError("deadline must be in future")

        service_hash_bytes = _to_bytes32(service_hash, "service_hash")
        func = self.kernel.functions.createTransaction(
            provider, requester, amount, deadline, dispute_window, service_hash_bytes
        )

        gas_estimate = self._estimate_gas(func)
        tx = func.build_transaction(self._tx_meta(gas_estimate))
        receipt = self._build_and_send(tx)

        events = self.kernel.events.TransactionCreated().process_receipt(receipt)
        if not events:
            raise TransactionError("TransactionCreated event not found")

        tx_raw = events[0]["args"]["transactionId"]
        if isinstance(tx_raw, str):
            return tx_raw if tx_raw.startswith("0x") else f"0x{tx_raw}"
        return Web3.to_hex(tx_raw)

    def approve_token(self, token_address: str, spender: str, amount: int):
        """Approve token spending (convenience helper).

        Approves a spender (typically EscrowVault) to transfer tokens on behalf of the client.
        This must be called before linking escrow, as the vault needs permission to pull USDC.

        Args:
            token_address: ERC20 token contract address (typically USDC)
            spender: Address to approve (typically EscrowVault address)
            amount: Amount to approve (must be non-negative)

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If addresses are invalid or amount is negative

        Example:
            >>> # Approve EscrowVault to spend USDC
            >>> receipt = client.approve_token(
            ...     token_address=client.config.usdc,
            ...     spender=client.config.escrow_vault,
            ...     amount=1_000_000  # 1 USDC (6 decimals)
            ... )

        Reference:
            - ERC20 approve() standard
            - TypeScript SDK: EscrowVault.approveToken()
        """
        # Validate inputs
        if not Web3.is_address(token_address):
            raise ValidationError("token_address must be a valid address")
        if not Web3.is_address(spender):
            raise ValidationError("spender must be a valid address")
        _validate_amount(amount, "amount")

        # Get ERC20 contract
        token = self.w3.eth.contract(address=token_address, abi=_load_abi("usdc.json"))

        # Approve spending
        func = token.functions.approve(spender, amount)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def link_escrow(
        self,
        tx_id: str,
        amount: Optional[int] = None,
        escrow_contract: Optional[str] = None,
        escrow_id: Optional[Union[str, bytes]] = None,
    ) -> str:
        """Link escrow to a transaction.

        Args:
            tx_id: Transaction ID
            amount: Escrow amount (must be non-negative)
            escrow_contract: Escrow contract address
            escrow_id: Escrow ID

        Returns:
            Escrow ID (bytes32 hex string)

        Raises:
            ValidationError: If amount is negative
        """
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        escrow_contract = escrow_contract or self.config.escrow_vault
        if not Web3.is_address(escrow_contract):
            raise ValidationError("escrow_contract must be a valid address")

        tx_view = self.get_transaction(tx_id)
        amount_to_use = amount if amount is not None else tx_view.amount

        # Validate amount is non-negative
        _validate_amount(amount_to_use)
        escrow_bytes = _to_bytes32(escrow_id or self._random_bytes32(), "escrow_id")

        # 1) Approve vault to pull USDC
        approve_func = self.usdc.functions.approve(escrow_contract, amount_to_use)
        approve_tx = approve_func.build_transaction(self._tx_meta(self._estimate_gas(approve_func)))
        self._build_and_send(approve_tx)

        # 2) Link escrow via kernel (creates escrow + transitions to COMMITTED)
        link_func = self.kernel.functions.linkEscrow(tx_bytes, escrow_contract, escrow_bytes)
        link_tx = link_func.build_transaction(self._tx_meta(self._estimate_gas(link_func, buffer=1.2)))
        self._build_and_send(link_tx)

        return Web3.to_hex(escrow_bytes)

    def get_escrow_status(
        self, escrow_contract: Optional[str], escrow_id: Union[str, bytes], expected_requester: Optional[str] = None, expected_provider: Optional[str] = None, expected_amount: Optional[int] = None
    ):
        """Verify escrow status and parameters.

        Args:
            escrow_contract: Escrow vault contract address (defaults to config)
            escrow_id: Escrow ID (bytes32)
            expected_requester: Expected requester address
            expected_provider: Expected provider address
            expected_amount: Expected escrow amount

        Returns:
            Verification result from escrow vault

        Raises:
            ValidationError: If escrow_contract is invalid
        """
        escrow_contract = escrow_contract or self.config.escrow_vault
        if not Web3.is_address(escrow_contract):
            raise ValidationError("escrow_contract must be a valid address")
        escrow_bytes = _to_bytes32(escrow_id, "escrow_id")
        vault = self.w3.eth.contract(address=escrow_contract, abi=_load_abi("escrow_vault.json"))
        requester = expected_requester or self.address
        provider = expected_provider or "0x0000000000000000000000000000000000000000"
        amount = expected_amount or 0
        return vault.functions.verifyEscrow(escrow_bytes, requester, provider, amount).call()

    def fund_transaction(self, tx_id: str, amount: Optional[int] = None, escrow_id: Optional[Union[str, bytes]] = None) -> str:
        """Convenience: fetch tx → validate state/deadline → approve USDC → link escrow."""
        tx = self.get_transaction(tx_id)
        if tx.requester == "0x0000000000000000000000000000000000000000":
            raise ValidationError("txId not found")
        if tx.state not in (State.INITIATED, State.QUOTED):
            raise InvalidStateTransitionError("state must be INITIATED or QUOTED to fund")
        now_ts = self.now()
        if now_ts > tx.deadline:
            raise DeadlineError("transaction expired (deadline passed)")

        amount_to_use = amount if amount is not None else tx.amount
        return self.link_escrow(tx_id, amount=amount_to_use, escrow_id=escrow_id)

    def submit_quote(self, tx_id: str, quote_hash: Union[str, bytes]):
        """Submit a price quote for a transaction.

        Encodes quote hash as bytes32 proof and transitions INITIATED -> QUOTED.

        Args:
            tx_id: Transaction ID
            quote_hash: Quote content hash (bytes32)

        Returns:
            Transaction receipt

        Raises:
            InvalidStateTransitionError: If not in INITIATED state

        Example:
            >>> client.submit_quote(
            ...     tx_id="0x123...",
            ...     quote_hash="0xabc..."
            ... )
        """
        tx = self.get_transaction(tx_id)
        if tx.state != State.INITIATED:
            raise InvalidStateTransitionError("quote allowed only from INITIATED")
        proof = _to_bytes32(quote_hash, "quote_hash")
        return self.transition_state(tx_id, State.QUOTED, proof)

    def transition_state(self, tx_id: str, new_state: State, proof: Optional[Union[str, bytes]] = None):
        """Transition a transaction to a new state.

        Args:
            tx_id: Transaction ID
            new_state: Target state (must be valid transition)
            proof: Optional proof data (e.g., delivery hash, attestation UID)

        Returns:
            Transaction receipt

        Raises:
            InvalidStateTransitionError: If transition is not allowed
            ValidationError: If proof format is invalid

        Example:
            >>> client.transition_state(
            ...     tx_id="0x123...",
            ...     new_state=State.IN_PROGRESS,
            ...     proof=b""
            ... )
        """
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        if proof is None:
            proof_bytes = b""
        elif isinstance(proof, str):
            hex_str = proof[2:] if proof.startswith("0x") else proof
            proof_bytes = bytes.fromhex(hex_str)
        elif isinstance(proof, (bytes, bytearray)):
            proof_bytes = bytes(proof)
        else:
            raise ValidationError("proof must be hex string or bytes")

        current = self.get_transaction(tx_id)
        if current.state == new_state:
            raise InvalidStateTransitionError("no-op transition")
        allowed = self.ALLOWED_TRANSITIONS.get(current.state, set())
        if new_state not in allowed:
            allowed_names = [s.name for s in allowed]
            raise InvalidStateTransitionError(
                f"invalid transition {current.state.name} -> {new_state.name}; allowed: {allowed_names}"
            )

        func = self.kernel.functions.transitionState(tx_bytes, int(new_state), proof_bytes)
        built = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(built)

    def verify_delivery_attestation(self, tx_id: str, attestation_uid: Union[str, bytes]):
        """Verify an EAS delivery attestation.

        Args:
            tx_id: Transaction ID
            attestation_uid: EAS attestation UID (bytes32)

        Returns:
            Attestation tuple from EAS contract

        Raises:
            ValidationError: If EAS not configured, attestation revoked, expired, or refUID mismatch

        Example:
            >>> attestation = client.verify_delivery_attestation(
            ...     tx_id="0x123...",
            ...     attestation_uid="0xabc..."
            ... )
        """
        if not self.eas:
            raise ValidationError("EAS not configured")
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        att_uid = _to_bytes32(attestation_uid, "attestation_uid")
        att = self.eas.functions.getAttestation(att_uid).call()
        # att tuple: (uid, schema, refUID, time, expirationTime, revocationTime, recipient, attester, data)
        ref_uid = att[2]
        expiration = att[4]
        revocation = att[5]
        if revocation and revocation > 0:
            raise ValidationError("attestation revoked")
        now_ts = self.now()
        if expiration and expiration > 0 and now_ts > expiration:
            raise ValidationError("attestation expired")
        if ref_uid != tx_bytes:
            raise ValidationError("attestation refUID does not match txId")
        return att

    def release_escrow_with_verification(self, tx_id: str, attestation_uid: Union[str, bytes]):
        """Release escrow after verifying EAS attestation.

        Verifies off-chain attestation via EAS, then settles with proof = attestation UID.

        Args:
            tx_id: Transaction ID
            attestation_uid: EAS attestation UID (bytes32)

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If attestation verification fails

        Example:
            >>> receipt = client.release_escrow_with_verification(
            ...     tx_id="0x123...",
            ...     attestation_uid="0xabc..."
            ... )
        """
        # Verify off-chain attestation via EAS, then settle with proof = attestation UID
        self.verify_delivery_attestation(tx_id, attestation_uid)
        return self.transition_state(tx_id, State.SETTLED, proof=_to_bytes32(attestation_uid, "attestation_uid"))

    def release_escrow(self, tx_id: str):
        """Release escrow manually (admin or automated path).

        Args:
            tx_id: Transaction ID

        Returns:
            Transaction receipt

        Example:
            >>> receipt = client.release_escrow(tx_id="0x123...")
        """
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        func = self.kernel.functions.releaseEscrow(tx_bytes)
        built = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(built)

    def release_milestone(self, tx_id: str, amount: int):
        """Milestone release from requester in IN_PROGRESS state.

        Args:
            tx_id: Transaction ID
            amount: Milestone amount (must be non-negative)

        Raises:
            ValidationError: If amount is negative
        """
        # Validate amount is non-negative
        _validate_amount(amount)

        tx_bytes = _to_bytes32(tx_id, "tx_id")
        func = self.kernel.functions.releaseMilestone(tx_bytes, 0, amount)
        built = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(built)

    def anchor_attestation(self, tx_id: str, attestation_uid: Union[str, bytes]):
        """Anchor an EAS attestation UID on-chain.

        Stores attestation UID on-chain (for settled transactions only).

        Args:
            tx_id: Transaction ID
            attestation_uid: EAS attestation UID (bytes32)

        Returns:
            Transaction receipt

        Example:
            >>> receipt = client.anchor_attestation(
            ...     tx_id="0x123...",
            ...     attestation_uid="0xabc..."
            ... )
        """
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        att_uid = _to_bytes32(attestation_uid, "attestation_uid")
        func = self.kernel.functions.anchorAttestation(tx_bytes, att_uid)
        built = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(built)

    def deliver(self, tx_id: str, dispute_window_seconds: Optional[int] = None):
        """Mark transaction as delivered.

        Transitions to DELIVERED state; optional dispute window (seconds) encoded in proof.

        Args:
            tx_id: Transaction ID
            dispute_window_seconds: Custom dispute window duration in seconds

        Returns:
            Transaction receipt

        Example:
            >>> receipt = client.deliver(
            ...     tx_id="0x123...",
            ...     dispute_window_seconds=7200  # 2 hours
            ... )
        """
        proof_bytes = b""
        if dispute_window_seconds is not None:
            proof_bytes = _encode_uint256(dispute_window_seconds)
        return self.transition_state(tx_id, State.DELIVERED, proof=proof_bytes)

    def dispute(self, tx_id: str):
        """Raise a dispute on a transaction.

        Transitions to DISPUTED state (provider or requester path depending on contract auth).

        Args:
            tx_id: Transaction ID

        Returns:
            Transaction receipt

        Example:
            >>> receipt = client.dispute(tx_id="0x123...")
        """
        return self.transition_state(tx_id, State.DISPUTED, proof=b"")

    def resolve_dispute(self, tx_id: str, requester_amount: int, provider_amount: int, mediator_amount: int = 0, mediator: Optional[str] = None):
        """Resolve/settle dispute with payment split.

        Settles disputed transaction by transitioning to SETTLED state with encoded resolution proof.
        The kernel contract decodes the proof and disburses funds to requester, provider, and mediator.

        Args:
            tx_id: Transaction ID
            requester_amount: Amount to refund to requester (must be non-negative)
            provider_amount: Amount to pay to provider (must be non-negative)
            mediator_amount: Amount to pay to mediator (must be non-negative, default 0)
            mediator: Mediator address (required if mediator_amount > 0)

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If amounts are negative, mediator address missing, or transaction not in DISPUTED state

        Example:
            >>> # Provider wins (requester gets nothing)
            >>> receipt = client.resolve_dispute(
            ...     tx_id="0x123...",
            ...     requester_amount=0,
            ...     provider_amount=1_000_000  # Full amount to provider
            ... )
            >>>
            >>> # Split decision (50/50)
            >>> receipt = client.resolve_dispute(
            ...     tx_id="0x123...",
            ...     requester_amount=500_000,
            ...     provider_amount=500_000
            ... )
            >>>
            >>> # Mediator takes fee
            >>> receipt = client.resolve_dispute(
            ...     tx_id="0x123...",
            ...     requester_amount=450_000,
            ...     provider_amount=450_000,
            ...     mediator_amount=100_000,
            ...     mediator="0xMediator..."
            ... )

        Reference:
            - Yellow Paper §3.4 (Dispute Management)
            - TypeScript SDK: ACTPKernel.resolveDispute()
        """
        # Verify transaction is in DISPUTED state
        tx = self.get_transaction(tx_id)
        if tx.state != State.DISPUTED:
            raise InvalidStateTransitionError(f"Cannot resolve dispute: transaction is in {tx.state.name} state, expected DISPUTED")

        # Validate amounts are non-negative
        _validate_amount(requester_amount, "requester_amount")
        _validate_amount(provider_amount, "provider_amount")
        _validate_amount(mediator_amount, "mediator_amount")

        # Validate total amount does not exceed transaction amount
        total_amount = requester_amount + provider_amount + mediator_amount
        if total_amount > tx.amount:
            raise ValidationError(
                f"Total resolution amount ({total_amount}) exceeds transaction amount ({tx.amount})"
            )

        # Validate mediator address if mediator amount > 0
        if mediator_amount > 0:
            if not mediator:
                raise ValidationError("mediator address required when mediator_amount > 0")
            if not Web3.is_address(mediator):
                raise ValidationError("mediator must be a valid address")

        # Use zero address if no mediator
        mediator_address = mediator or "0x0000000000000000000000000000000000000000"

        # Encode resolution proof (128 bytes: 3x uint256 + address)
        # Kernel contract decodes this in _decodeResolutionProof and disburses funds
        from eth_abi import encode

        proof_data = encode(
            ["uint256", "uint256", "uint256", "address"],
            [requester_amount, provider_amount, mediator_amount, mediator_address]
        )

        # Settle dispute via state transition to SETTLED with resolution proof
        return self.transition_state(tx_id, State.SETTLED, proof=proof_data)

    def cancel(self, tx_id: str, proof: Optional[Union[str, bytes]] = None):
        """Cancel a transaction.

        Transitions to CANCELLED state with optional proof data.

        Args:
            tx_id: Transaction ID
            proof: Optional proof data for cancellation reason

        Returns:
            Transaction receipt

        Example:
            >>> receipt = client.cancel(
            ...     tx_id="0x123...",
            ...     proof=b"timeout"
            ... )
        """
        return self.transition_state(tx_id, State.CANCELLED, proof=proof or b"")

    def parse_events(self, receipt) -> dict:
        """Parse and decode contract events from transaction receipt.

        Args:
            receipt: Web3 transaction receipt

        Returns:
            Dictionary with decoded events:
            - transaction_created: List of TransactionCreated events
            - state_transitioned: List of StateTransitioned events
            - escrow_linked: List of EscrowLinked events

        Example:
            >>> receipt = client.create_transaction(...)
            >>> events = client.parse_events(receipt)
            >>> print(events['transaction_created'])
        """
        return {
            "transaction_created": self.kernel.events.TransactionCreated().process_receipt(receipt),
            "state_transitioned": self.kernel.events.StateTransitioned().process_receipt(receipt),
            "escrow_linked": self.kernel.events.EscrowLinked().process_receipt(receipt),
        }

    # ---------------- Agent Registry (AIP-7) ----------------
    def register_agent(self, endpoint: str, service_descriptors: list[dict]):
        """Register an agent profile with service descriptors.

        Args:
            endpoint: Agent's service endpoint URL
            service_descriptors: List of service descriptor dicts

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If agent registry not configured or endpoint URL is unsafe

        Example:
            >>> client.register_agent(
            ...     endpoint="https://agent.example.com",
            ...     service_descriptors=[{"type": "translation", "price": 100}]
            ... )
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")

        # Validate endpoint URL for SSRF protection
        _validate_endpoint_url(endpoint, "endpoint")

        func = self.agent_registry.functions.registerAgent(endpoint, service_descriptors)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def update_endpoint(self, new_endpoint: str):
        """Update agent's service endpoint.

        Args:
            new_endpoint: New endpoint URL

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If agent registry not configured or endpoint URL is unsafe
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")

        # Validate endpoint URL for SSRF protection
        _validate_endpoint_url(new_endpoint, "new_endpoint")

        func = self.agent_registry.functions.updateEndpoint(new_endpoint)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def add_service_type(self, service_type: str):
        """Add a service type to agent's profile.

        Args:
            service_type: Service type identifier string

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If agent registry not configured
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        func = self.agent_registry.functions.addServiceType(service_type)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def remove_service_type(self, service_type_hash: Union[str, bytes]):
        """Remove a service type from agent's profile.

        Args:
            service_type_hash: Hash of the service type to remove (bytes32)

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If agent registry not configured
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        h = _to_bytes32(service_type_hash, "service_type_hash")
        func = self.agent_registry.functions.removeServiceType(h)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def set_active_status(self, is_active: bool):
        """Set agent's active status in the registry.

        Args:
            is_active: True to mark agent as active, False to deactivate

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If agent registry not configured

        Example:
            >>> client.set_active_status(is_active=False)  # Deactivate agent
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        func = self.agent_registry.functions.setActiveStatus(is_active)
        tx = func.build_transaction(self._tx_meta(self._estimate_gas(func)))
        return self._build_and_send(tx)

    def get_agent(self, agent_address: str) -> Optional[AgentProfile]:
        """Get agent profile from the registry.

        Args:
            agent_address: Ethereum address of the agent

        Returns:
            AgentProfile if found, None if not registered

        Raises:
            ValidationError: If agent registry not configured

        Example:
            >>> profile = client.get_agent("0x1234...")
            >>> if profile:
            ...     print(f"Reputation: {profile.reputation_score}")
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        _validate_address(agent_address, "agent_address")
        raw = self.agent_registry.functions.getAgent(agent_address).call()

        # Check if registered (registeredAt > 0)
        if raw[9] == 0:  # registeredAt index
            return None

        return self._map_agent_profile(raw)

    def get_service_descriptors(self, agent_address: str) -> list[ServiceDescriptor]:
        """Get service descriptors for an agent.

        Args:
            agent_address: Ethereum address of the agent

        Returns:
            List of ServiceDescriptor dataclasses

        Raises:
            ValidationError: If agent registry not configured

        Example:
            >>> descriptors = client.get_service_descriptors("0x1234...")
            >>> for desc in descriptors:
            ...     print(desc.service_type, desc.min_price)
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        _validate_address(agent_address, "agent_address")
        raw = self.agent_registry.functions.getServiceDescriptors(agent_address).call()
        return [self._map_service_descriptor(d) for d in raw]

    def get_agent_by_did(self, did: str) -> Optional[AgentProfile]:
        """Get agent profile by DID.

        Args:
            did: Decentralized Identifier (e.g., "did:ethr:84532:0x1234...")

        Returns:
            AgentProfile if found, None if not registered

        Raises:
            ValidationError: If agent registry not configured or DID format invalid

        Example:
            >>> profile = client.get_agent_by_did("did:ethr:84532:0x1234...")
            >>> if profile:
            ...     print(f"Agent: {profile.endpoint}")
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")

        # Validate DID format
        match = re.match(DID_PATTERN, did)
        if not match:
            raise ValidationError(
                "Invalid DID format. Expected did:ethr:<chainId>:<address> "
                "(e.g., did:ethr:84532:0x1234...)"
            )

        # Validate chain ID matches
        did_chain_id = int(match.group(1))
        current_chain_id = self.get_chain_id()
        if did_chain_id != current_chain_id:
            raise ValidationError(
                f"DID chain ID ({did_chain_id}) does not match registry chain ID ({current_chain_id})"
            )

        raw = self.agent_registry.functions.getAgentByDID(did).call()

        # Check if registered (registeredAt > 0)
        if raw[9] == 0:  # registeredAt index
            return None

        return self._map_agent_profile(raw)

    def query_agents_by_service(
        self,
        service_type_hash: str,
        min_reputation: int = 0,
        offset: int = 0,
        limit: int = 100
    ) -> list[str]:
        """Query agents by service type.

        **IMPORTANT - Query Cap Limitation**:

        This method will raise QueryCapExceededError when the registry
        contains more than 1000 agents. This is an intentional DoS prevention.

        When you encounter this error, migrate to an off-chain indexer:
        - The Graph: https://thegraph.com/
        - Goldsky: https://goldsky.com/
        - Alchemy Subgraphs: https://docs.alchemy.com/docs/subgraphs-overview

        Args:
            service_type_hash: Keccak256 hash of service type (bytes32)
            min_reputation: Minimum reputation score (0-10000 scale)
            offset: Pagination offset
            limit: Maximum results to return (capped at 1000)

        Returns:
            List of agent addresses matching criteria

        Raises:
            ValidationError: If agent registry not configured or invalid params
            QueryCapExceededError: When registry exceeds 1000 agents

        Example:
            >>> try:
            ...     agents = client.query_agents_by_service(
            ...         service_type_hash=client.compute_service_type_hash("text-generation"),
            ...         min_reputation=5000,
            ...         limit=50
            ...     )
            ... except QueryCapExceededError:
            ...     print("Use off-chain indexer for large registries")
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")

        # Validate service type hash format
        if not service_type_hash or not re.match(r"^0x[a-fA-F0-9]{64}$", service_type_hash):
            raise ValidationError("service_type_hash must be valid bytes32 hex string")

        # Validate reputation bounds
        if min_reputation < 0 or min_reputation > REPUTATION_MAX:
            raise ValidationError(f"min_reputation must be between 0 and {REPUTATION_MAX}")

        # Validate offset
        if offset < 0:
            raise ValidationError("offset cannot be negative")

        # Validate and cap limit
        if limit <= 0:
            raise ValidationError("limit must be positive")
        if limit > MAX_QUERY_LIMIT:
            limit = MAX_QUERY_LIMIT  # Cap silently

        try:
            agents = self.agent_registry.functions.queryAgentsByService(
                service_type_hash, min_reputation, offset, limit
            ).call()
            return list(agents)
        except Exception as e:
            error_msg = str(e)
            if "Too many agents" in error_msg:
                raise QueryCapExceededError(QUERY_CAP + 1, QUERY_CAP)
            raise

    def supports_service(self, agent_address: str, service_type_hash: str) -> bool:
        """Check if agent supports a service type.

        Args:
            agent_address: Ethereum address of the agent
            service_type_hash: Keccak256 hash of service type (bytes32)

        Returns:
            True if agent supports the service type

        Raises:
            ValidationError: If agent registry not configured

        Example:
            >>> hash = client.compute_service_type_hash("text-generation")
            >>> if client.supports_service("0x1234...", hash):
            ...     print("Agent supports text generation")
        """
        if not self.agent_registry:
            raise ValidationError("agent registry not configured")
        _validate_address(agent_address, "agent_address")
        return self.agent_registry.functions.supportsService(agent_address, service_type_hash).call()

    def compute_service_type_hash(self, service_type: str) -> str:
        """Compute Keccak256 hash of service type string.

        Service types must be lowercase with only a-z, 0-9, and hyphens.

        Args:
            service_type: Human-readable service type (e.g., "text-generation")

        Returns:
            Keccak256 hash as 0x-prefixed hex string (66 chars)

        Raises:
            ValidationError: If service type format is invalid

        Example:
            >>> hash = client.compute_service_type_hash("text-generation")
            >>> print(hash)  # 0x...
        """
        # Validate length
        if len(service_type) > MAX_SERVICE_TYPE_LENGTH:
            raise ValidationError(
                f"Service type exceeds maximum length ({MAX_SERVICE_TYPE_LENGTH} characters)"
            )

        # Validate format
        if not re.match(SERVICE_TYPE_PATTERN, service_type):
            raise ValidationError(
                'Service type must be lowercase alphanumeric with hyphens (e.g., "text-generation")'
            )

        return Web3.keccak(text=service_type).hex()

    def build_did(self, address: str) -> str:
        """Build a DID for an address on the current chain.

        Args:
            address: Ethereum address

        Returns:
            DID string (e.g., "did:ethr:84532:0x1234...")

        Example:
            >>> did = client.build_did(client.address)
            >>> print(did)  # did:ethr:84532:0x...
        """
        _validate_address(address, "address")
        chain_id = self.get_chain_id()
        return f"did:ethr:{chain_id}:{address.lower()}"

    def get_chain_id(self) -> int:
        """Get the chain ID of the connected network.

        Returns:
            Chain ID (e.g., 84532 for Base Sepolia)
        """
        return self.w3.eth.chain_id

    def validate_service_descriptors(self, descriptors: list[dict]) -> None:
        """Validate service descriptors before registration.

        Performs comprehensive validation matching TypeScript SDK:
        - At least one descriptor required
        - Maximum 100 descriptors
        - Service type format validation
        - Hash verification
        - Price range validation
        - Completion time bounds

        Args:
            descriptors: List of service descriptor dicts

        Raises:
            ValidationError: If any validation fails

        Example:
            >>> descriptors = [{
            ...     "serviceType": "text-generation",
            ...     "serviceTypeHash": client.compute_service_type_hash("text-generation"),
            ...     "minPrice": 1_000_000,
            ...     "maxPrice": 100_000_000,
            ...     "avgCompletionTime": 60,
            ...     "schemaURI": "ipfs://Qm...",
            ...     "metadataCID": "Qm..."
            ... }]
            >>> client.validate_service_descriptors(descriptors)
        """
        if not descriptors:
            raise ValidationError("At least one service descriptor required")

        if len(descriptors) > MAX_SERVICE_DESCRIPTORS:
            raise ValidationError(
                f"Too many service descriptors (max: {MAX_SERVICE_DESCRIPTORS})"
            )

        for i, sd in enumerate(descriptors):
            prefix = f"descriptors[{i}]"

            # Validate service type format
            service_type = sd.get("serviceType", "")
            if not service_type:
                raise ValidationError(f"{prefix}.serviceType is required")

            # Compute expected hash and verify
            expected_hash = self.compute_service_type_hash(service_type)
            provided_hash = sd.get("serviceTypeHash", "")
            if provided_hash != expected_hash:
                raise ValidationError(
                    f"{prefix}.serviceTypeHash mismatch for '{service_type}'. "
                    f"Expected {expected_hash}"
                )

            # Validate price range
            min_price = sd.get("minPrice", 0)
            max_price = sd.get("maxPrice", 0)

            if min_price < 0:
                raise ValidationError(f"{prefix}.minPrice cannot be negative")
            if max_price < 0:
                raise ValidationError(f"{prefix}.maxPrice cannot be negative")
            if min_price > max_price:
                raise ValidationError(
                    f"{prefix}.minPrice ({min_price}) cannot exceed maxPrice ({max_price})"
                )
            if max_price > MAX_PRICE_USDC:
                raise ValidationError(
                    f"{prefix}.maxPrice exceeds maximum reasonable value ($1M USDC)"
                )

            # Validate completion time
            avg_time = sd.get("avgCompletionTime", 0)
            if avg_time <= 0:
                raise ValidationError(f"{prefix}.avgCompletionTime must be positive")
            if avg_time > MAX_COMPLETION_TIME_SECONDS:
                raise ValidationError(
                    f"{prefix}.avgCompletionTime exceeds maximum (30 days)"
                )

            # Validate metadata CID length
            metadata_cid = sd.get("metadataCID", "")
            if metadata_cid and len(metadata_cid) > MAX_METADATA_CID_LENGTH:
                raise ValidationError(
                    f"{prefix}.metadataCID exceeds maximum length ({MAX_METADATA_CID_LENGTH} characters)"
                )

            # Validate schema URI length
            schema_uri = sd.get("schemaURI", "")
            if schema_uri and len(schema_uri) > MAX_SCHEMA_URI_LENGTH:
                raise ValidationError(
                    f"{prefix}.schemaURI exceeds maximum length ({MAX_SCHEMA_URI_LENGTH} characters)"
                )

    def _map_agent_profile(self, raw: tuple) -> AgentProfile:
        """Map raw contract tuple to AgentProfile dataclass."""
        return AgentProfile(
            agent_address=raw[0],
            did=raw[1],
            endpoint=raw[2],
            service_types=list(raw[3]),  # Clone array
            staked_amount=raw[4],
            reputation_score=raw[5],
            total_transactions=raw[6],
            disputed_transactions=raw[7],
            total_volume_usdc=raw[8],
            registered_at=raw[9],
            updated_at=raw[10],
            is_active=bool(raw[11]),
        )

    def _map_service_descriptor(self, raw: tuple) -> ServiceDescriptor:
        """Map raw contract tuple to ServiceDescriptor dataclass."""
        return ServiceDescriptor(
            service_type_hash=raw[0].hex() if isinstance(raw[0], bytes) else raw[0],
            service_type=raw[1],
            schema_uri=raw[2],
            min_price=raw[3],
            max_price=raw[4],
            avg_completion_time=raw[5],
            metadata_cid=raw[6],
        )

    def get_transaction(self, tx_id: str) -> TransactionView:
        """Get transaction details from the kernel.

        Args:
            tx_id: Transaction ID (bytes32 hex string)

        Returns:
            TransactionView dataclass with all transaction fields

        Example:
            >>> tx = client.get_transaction("0x123...")
            >>> print(f"State: {tx.state.name}, Amount: {tx.amount}")
        """
        tx_bytes = _to_bytes32(tx_id, "tx_id")
        tx_data = self.kernel.functions.getTransaction(tx_bytes).call()
        return TransactionView(
            transaction_id=tx_data[0],
            requester=tx_data[1],
            provider=tx_data[2],
            state=State(tx_data[3]),
            amount=tx_data[4],
            created_at=tx_data[5],
            updated_at=tx_data[6],
            deadline=tx_data[7],
            service_hash=tx_data[8],
            escrow_contract=tx_data[9],
            escrow_id=tx_data[10],
            attestation_uid=tx_data[11],
            dispute_window=tx_data[12],
            metadata=tx_data[13],
            platform_fee_bps_locked=tx_data[14],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _build_and_send(self, tx: TxParams):
        """Sign and send a transaction, waiting for receipt.

        Args:
            tx: Transaction parameters dict

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If transaction fails (status != 1)
            RpcError: If RPC call fails or reverts
        """
        try:
            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt["status"] != 1:
                raise TransactionError(f"Transaction failed: {tx_hash.hex()}")
            return receipt
        except TransactionError:
            raise
        except ValueError as e:
            reason = None
            if e.args and isinstance(e.args[0], dict):
                reason = e.args[0].get("message") or e.args[0].get("reason")
                data = e.args[0].get("data")
                if isinstance(data, str):
                    decoded = _decode_revert_reason(data)
                    if decoded:
                        reason = decoded
            msg = reason or str(e)
            raise RpcError(msg)
        except Exception as e:
            raise RpcError(str(e))

    def _tx_meta(self, gas: Optional[int] = None, overrides: Optional[dict] = None) -> TxParams:
        """Build transaction metadata with dynamic gas pricing.

        Args:
            gas: Gas limit (estimated if not provided)
            overrides: Additional transaction parameters

        Returns:
            Transaction parameters dict
        """
        if self.manual_nonce:
            if self._next_nonce is None:
                self._next_nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
            nonce = self._next_nonce
            self._next_nonce += 1
        else:
            nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")

        # Use dynamic gas pricing from latest block (suitable for Base L2)
        latest_block = self.w3.eth.get_block("latest")
        base_fee = latest_block.get("baseFeePerGas", 0)

        # For Base L2: base fee is typically ~0.001 gwei, add small buffer
        # maxFeePerGas = base fee * 2 (100% buffer for volatility)
        # maxPriorityFeePerGas = 0.001 gwei (minimal tip for Base L2)
        max_fee_per_gas = max(base_fee * MAX_FEE_MULTIPLIER, self.w3.to_wei(MIN_MAX_FEE_GWEI, "gwei"))
        max_priority_fee = self.w3.to_wei(PRIORITY_FEE_GWEI, "gwei")

        meta: TxParams = {
            "from": self.account.address,
            "nonce": nonce,
            "chainId": self.config.chain_id,
            "gas": gas or DEFAULT_GAS_LIMIT,
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee,
        }
        merged = {**meta, **self.tx_overrides, **(overrides or {})}

        # Validate gas limit doesn't exceed maximum (DoS protection)
        if merged.get("gas", 0) > MAX_GAS_LIMIT:
            raise ValidationError(f"Gas limit ({merged['gas']}) exceeds maximum ({MAX_GAS_LIMIT})")

        return merged

    def _estimate_gas(self, func, buffer: float = GAS_ESTIMATION_BUFFER) -> int:
        """Estimate gas for a contract function call with buffer.

        Args:
            func: Web3 contract function call
            buffer: Multiplier buffer for safety margin (default 1.15 = 15%)

        Returns:
            Estimated gas with buffer applied, capped at MAX_GAS_LIMIT
        """
        base = func.estimate_gas({"from": self.address})
        estimated = int(base * buffer)
        # Cap to prevent excessive gas from malicious RPC
        return min(estimated, MAX_GAS_LIMIT)

    @staticmethod
    def _random_bytes32() -> bytes:
        """Generate cryptographically secure random 32 bytes.

        Returns:
            32 random bytes suitable for transaction IDs
        """
        return secrets.token_bytes(32)

    @staticmethod
    def now() -> int:
        """Get current Unix timestamp.

        Returns:
            Current time as Unix timestamp (seconds since epoch)
        """
        import time

        return int(time.time())
