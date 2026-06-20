"""
AutoWalletProvider -- Tier 1 (Auto) wallet implementation.

Creates a CoinbaseSmartWallet with gas-sponsored transactions:
  1. Load/generate local encrypted key
  2. Derive Smart Wallet address (counterfactual CREATE2)
  3. Check AgentRegistry registration
  4. Build UserOp with executeBatch
  5. Get paymaster sponsorship (Coinbase -> Pimlico fallback)
  6. Submit via bundler

This is a 1:1 port of sdk-js/src/wallet/AutoWalletProvider.ts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from web3 import Web3

from agirails.wallet.aa.constants import SmartWalletCall, UserOperationV06
from agirails.wallet.aa.user_op_builder import (
    build_create_account_factory_data,
    build_replay_safe_typed_data,
    build_user_op,
    compute_smart_wallet_address,
    dummy_signature,
    serialize_erc6492_signature,
    sign_user_op,
    wrap_signature,
)
from agirails.wallet.aa.constants import SMART_WALLET_FACTORY
from agirails.wallet.aa.bundler_client import BundlerClient, BundlerConfig
from agirails.wallet.aa.paymaster_client import PaymasterClient, PaymasterConfig
from agirails.wallet.aa.dual_nonce_manager import DualNonceManager, EnqueueResult
from agirails.wallet.aa.transaction_batcher import (
    build_actp_pay_batch,
    compute_transaction_id,
)

# Max ACTP-nonce bumps when retrying past "Escrow ID already used" collisions.
# Mirrors TS AutoWalletProvider.ts:369 (MAX_NONCE_BUMPS = 12).
MAX_NONCE_BUMPS = 12

logger = logging.getLogger("agirails.wallet.auto")


# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class TransactionRequest:
    """Low-level transaction request.

    Plain strings only -- no web3 types at the interface boundary.
    """

    to: str
    """Target contract address (0x-prefixed)."""

    data: str
    """Calldata (0x-prefixed hex)."""

    value: str = "0"
    """ETH value in wei (decimal string). Defaults to '0'."""


@dataclass(frozen=True)
class TransactionReceipt:
    """Transaction receipt returned after submission."""

    hash: str
    """Transaction hash (EOA) or UserOp tx hash (AA)."""

    success: bool
    """Whether the transaction succeeded."""


WalletTier = str  # Literal["auto", "eoa"] -- keeping str for 3.9 compat


@dataclass(frozen=True)
class WalletInfo:
    """Information about the wallet provider."""

    address: str
    tier: WalletTier
    supports_batching: bool
    gas_sponsored: bool
    chain_id: int


@dataclass(frozen=True)
class BatchedPayResult:
    """Result of a batched ACTP payment via AA wallet."""

    tx_id: str
    """Pre-computed ACTP transaction ID (bytes32)."""

    hash: str
    """Transaction hash from the UserOp."""

    success: bool
    """Whether the UserOp succeeded."""


@dataclass
class BatchedPayParams:
    """Parameters for batched ACTP payment."""

    provider: str
    requester: str
    amount: str
    deadline: int
    dispute_window: int
    service_hash: str
    agent_id: str
    requester_agent_id: str = "0"  # AIP-14: Requester's ERC-8004 agent ID
    contracts: Any = None  # ContractAddresses from transaction_batcher


@dataclass
class CreateACTPTransactionParams:
    """Parameters for creating an ACTP transaction via Smart Wallet (without escrow).

    Mirrors TS ``CreateACTPTransactionParams`` (IWalletProvider.ts:74-86).
    """

    provider: str
    requester: str
    amount: str
    deadline: int
    dispute_window: int
    service_hash: str
    agent_id: str
    requester_agent_id: str = "0"
    contracts: Any = None  # {actp_kernel: str} — ContractAddresses or compatible


@dataclass(frozen=True)
class CreateACTPTransactionResult:
    """Result of creating an ACTP transaction via Smart Wallet.

    Mirrors TS ``CreateACTPTransactionResult`` (IWalletProvider.ts:91-96).
    """

    tx_id: str
    """Pre-computed ACTP transaction ID (bytes32)."""

    receipt: TransactionReceipt
    """Transaction receipt."""


@dataclass
class AutoWalletConfig:
    """Configuration for AutoWalletProvider."""

    private_key: str
    """EOA private key (0x-prefixed hex) that owns the Smart Wallet."""

    w3: Web3
    """Web3 instance connected to the target chain."""

    chain_id: int
    """Chain ID."""

    actp_kernel_address: str
    """ACTPKernel contract address (for ACTP nonce reads)."""

    actp_kernel_deployment_block: Optional[int] = None
    """Known deployment block of ACTPKernel (skips binary search in DualNonceManager)."""

    bundler_primary_url: str = ""
    """Primary bundler URL (Coinbase CDP)."""

    bundler_backup_url: Optional[str] = None
    """Backup bundler URL (Pimlico)."""

    paymaster_primary_url: str = ""
    """Primary paymaster URL (Coinbase CDP)."""

    paymaster_backup_url: Optional[str] = None
    """Backup paymaster URL (Pimlico)."""


# ============================================================================
# IWalletProvider Protocol
# ============================================================================


@runtime_checkable
class IWalletProvider(Protocol):
    """Wallet provider interface.

    All methods use plain strings (no web3 types) to keep the
    interface decoupled from any specific library.
    """

    def get_address(self) -> str:
        """Get the account address used as requester in ACTP transactions."""
        ...

    async def send_transaction(self, tx: TransactionRequest) -> TransactionReceipt:
        """Send a single transaction."""
        ...

    async def send_batch_transaction(
        self, txs: List[TransactionRequest]
    ) -> TransactionReceipt:
        """Send multiple transactions atomically (AA) or sequentially (EOA)."""
        ...

    def get_wallet_info(self) -> WalletInfo:
        """Get wallet metadata."""
        ...

    def sign_typed_data(self, typed_data: dict) -> str:
        """EIP-712 sign a typed-data ``full_message`` dict (native x402 v2).

        Optional: providers that implement it become eligible for x402 v2
        auto-registration (mirrors the TS signTypedData gate).
        """
        ...


# ============================================================================
# AutoWalletProvider
# ============================================================================


class AutoWalletProvider:
    """Tier 1 (Auto) wallet provider with CoinbaseSmartWallet + Paymaster.

    Use the ``create()`` factory method to instantiate.
    """

    def __init__(
        self,
        config: AutoWalletConfig,
        smart_wallet_address: str,
        is_deployed: bool,
    ) -> None:
        self._private_key = config.private_key
        self._w3 = config.w3
        self._chain_id = config.chain_id
        self._smart_wallet_address = smart_wallet_address
        self._is_deployed = is_deployed

        # Derive signer address from private key
        from eth_account import Account

        self._signer_address = Account.from_key(config.private_key).address

        self._bundler = BundlerClient(
            BundlerConfig(
                primary_url=config.bundler_primary_url,
                backup_url=config.bundler_backup_url,
            )
        )
        self._paymaster = PaymasterClient(
            PaymasterConfig(
                primary_url=config.paymaster_primary_url,
                backup_url=config.paymaster_backup_url,
                chain_id=config.chain_id,
            )
        )
        self._nonce_manager = DualNonceManager(
            w3=config.w3,
            sender_address=smart_wallet_address,
            actp_kernel_address=config.actp_kernel_address,
            known_deployment_block=config.actp_kernel_deployment_block,
        )

    @classmethod
    async def create(cls, config: AutoWalletConfig) -> "AutoWalletProvider":
        """Factory method -- computes counterfactual address and checks deployment.

        Args:
            config: AutoWalletConfig with signer key, RPC, bundler/paymaster URLs.

        Returns:
            Initialized AutoWalletProvider.
        """
        from eth_account import Account

        signer_address = Account.from_key(config.private_key).address

        smart_wallet_address = await compute_smart_wallet_address(
            signer_address, config.w3
        )

        # Check if wallet is already deployed (H-3 fix: offload sync RPC to thread)
        code = await asyncio.to_thread(
            config.w3.eth.get_code, Web3.to_checksum_address(smart_wallet_address)
        )
        is_deployed = code != b"" and code != b"\x00"

        logger.info(
            "AutoWalletProvider initialized: signer=%s smartWallet=%s deployed=%s",
            signer_address,
            smart_wallet_address,
            is_deployed,
        )

        return cls(config, smart_wallet_address, is_deployed)

    def get_address(self) -> str:
        """Get the Smart Wallet address (used as requester in ACTP)."""
        return self._smart_wallet_address

    def sign_typed_data(self, typed_data: dict) -> str:
        """EIP-712 sign typed data as a Coinbase Smart Wallet (Tier-1).

        Produces an ERC-1271 / ERC-6492-valid Smart-Wallet signature — NOT a raw
        owner EOA sig — so an x402 facilitator validates it against the Smart
        Wallet contract via ``isValidSignature``. 1:1 with the TS
        ``AutoWalletProvider.signTypedData`` flow (AutoWalletProvider.ts:211-358),
        which delegates to viem's ``toCoinbaseSmartAccount``:

          1. Hash the inner typed data (domain + types + primaryType + message).
          2. Wrap in the Coinbase replay-safe ``CoinbaseSmartWalletMessage``
             struct (verifyingContract = this Smart Wallet).
          3. Owner EOA signs the replay-safe hash.
          4. Encode as ``SignatureWrapper(ownerIndex=0, signature)`` for a
             deployed wallet.
          5. For a counterfactual (undeployed) wallet, wrap in an ERC-6492
             envelope so facilitators can validate via simulation before the
             first UserOp.

        Includes a parity check: the address the factory derives for the owner
        MUST equal ``self._smart_wallet_address`` (the ``verifyingContract`` in
        the replay-safe domain). A mismatch means the signature would validate at
        the wrong contract — we raise ``X402SignatureFailedError`` (fail closed)
        rather than emit a silently-invalid signature.

        The Tier-2 EOA path (``EOAWalletProvider.sign_typed_data``) stays a raw
        owner sig, which is what EIP-3009 ``transferWithAuthorization`` expects.
        """
        from eth_account import Account
        from eth_account.messages import encode_typed_data
        from eth_utils import keccak

        from agirails.types.x402 import X402SignatureFailedError

        try:
            smart_wallet = getattr(self, "_smart_wallet_address", None)
            if not smart_wallet:
                raise X402SignatureFailedError(
                    "AutoWalletProvider.sign_typed_data: Smart Wallet address is "
                    "not set; cannot build a replay-safe ERC-1271 signature."
                )
            chain_id = getattr(self, "_chain_id", None)
            if chain_id is None:
                raise X402SignatureFailedError(
                    "AutoWalletProvider.sign_typed_data: chain_id is not set; "
                    "cannot build the Coinbase replay-safe domain."
                )

            # Parity check: factory-derived address MUST match our stored Smart
            # Wallet address (the verifyingContract we sign against). Mirrors the
            # TS check between computeSmartWalletAddress and viem's getAddress.
            self._assert_smart_wallet_parity(smart_wallet)

            # 1. Hash the inner typed data exactly as EIP-712 (viem hashTypedData).
            inner_signable = encode_typed_data(full_message=typed_data)
            inner_hash = keccak(
                b"\x19\x01" + inner_signable.header + inner_signable.body
            )

            # 2. Replay-safe CoinbaseSmartWalletMessage(bytes32 hash).
            replay_safe = build_replay_safe_typed_data(
                smart_wallet_address=smart_wallet,
                chain_id=int(chain_id),
                inner_hash=inner_hash,
            )

            # 3. Owner EOA signs the replay-safe hash.
            account = Account.from_key(self._private_key)
            replay_safe_signable = encode_typed_data(full_message=replay_safe)
            owner_sig = account.sign_message(replay_safe_signable).signature

            # 4. SignatureWrapper(ownerIndex=0, signature).
            wrapped = wrap_signature(0, bytes(owner_sig))

            # 5. Deployed -> SignatureWrapper; counterfactual -> ERC-6492 envelope.
            if self._is_smart_wallet_deployed():
                return wrapped

            from eth_account import Account as _Account

            owner_address = _Account.from_key(self._private_key).address
            factory_data = build_create_account_factory_data(owner_address)
            return serialize_erc6492_signature(
                factory_address=SMART_WALLET_FACTORY,
                factory_data=factory_data,
                signature=wrapped,
            )
        except X402SignatureFailedError:
            raise
        except Exception as exc:  # noqa: BLE001 — convert to the x402 boundary error
            raise X402SignatureFailedError(
                f"AutoWallet sign_typed_data failed: {exc}"
            )

    def _is_smart_wallet_deployed(self) -> bool:
        """Best-effort live deployment check for the ERC-1271 vs ERC-6492 branch.

        Mirrors viem's ``toSmartAccount`` re-reading on-chain code before
        choosing whether to wrap in the ERC-6492 envelope. Reads code live via
        the Web3 instance (sync — ``sign_typed_data`` is sync); on any failure
        or absent provider, falls back to the cached ``_is_deployed`` flag so we
        never block signing on a transient RPC error.
        """
        w3 = getattr(self, "_w3", None)
        smart_wallet = getattr(self, "_smart_wallet_address", None)
        if w3 is not None and smart_wallet:
            try:
                code = w3.eth.get_code(Web3.to_checksum_address(smart_wallet))
                return code not in (b"", b"\x00", None)
            except Exception:
                pass
        return bool(getattr(self, "_is_deployed", False))

    def _assert_smart_wallet_parity(self, smart_wallet: str) -> None:
        """Assert the factory-derived address matches our Smart Wallet address.

        Re-derives ``factory.getAddress([pad(owner)], nonce)`` synchronously and
        compares (case-insensitively) to ``smart_wallet``. A mismatch means a
        produced signature would validate at the wrong contract, so we fail
        closed with ``X402SignatureFailedError``. When no Web3 instance is
        available (e.g. bare-constructed test doubles), the on-chain derivation
        cannot run, so the check is skipped — the signature itself is still
        built against ``smart_wallet`` as ``verifyingContract``.
        """
        from agirails.types.x402 import X402SignatureFailedError

        w3 = getattr(self, "_w3", None)
        if w3 is None:
            return  # cannot derive on-chain; skip (signature still correct shape)

        from eth_account import Account
        from eth_abi import encode as abi_encode

        try:
            owner_address = Account.from_key(self._private_key).address
            factory_abi = [
                {
                    "inputs": [
                        {"name": "owners", "type": "bytes[]"},
                        {"name": "nonce", "type": "uint256"},
                    ],
                    "name": "getAddress",
                    "outputs": [{"name": "", "type": "address"}],
                    "stateMutability": "view",
                    "type": "function",
                }
            ]
            factory = w3.eth.contract(
                address=Web3.to_checksum_address(SMART_WALLET_FACTORY),
                abi=factory_abi,
            )
            owner_bytes = abi_encode(
                ["address"], [Web3.to_checksum_address(owner_address)]
            )
            derived = factory.functions.getAddress([owner_bytes], 0).call()
        except X402SignatureFailedError:
            raise
        except Exception:
            # Could not derive on-chain (mock/transient); do not block signing.
            return

        if Web3.to_checksum_address(derived) != Web3.to_checksum_address(smart_wallet):
            raise X402SignatureFailedError(
                "Smart Wallet address parity mismatch: "
                f"ours={smart_wallet}, factory={derived}. The factory-derived "
                "address and our stored Smart Wallet address disagree. x402 "
                "payments cannot proceed — signatures would validate at the "
                "wrong contract."
            )

    async def send_transaction(self, tx: TransactionRequest) -> TransactionReceipt:
        """Send a single transaction via Smart Wallet UserOp."""
        return await self.send_batch_transaction([tx])

    async def send_batch_transaction(
        self, txs: List[TransactionRequest]
    ) -> TransactionReceipt:
        """Send multiple transactions atomically via executeBatch UserOp.

        Args:
            txs: List of transaction requests.

        Returns:
            TransactionReceipt with hash and success.

        Raises:
            ValueError: If no transactions provided.
        """
        if len(txs) == 0:
            raise ValueError("send_batch_transaction requires at least one transaction")

        calls = [
            SmartWalletCall(
                target=tx.to,
                value=int(tx.value) if tx.value else 0,
                data=tx.data,
            )
            for tx in txs
        ]

        return await self._nonce_manager.enqueue(
            fn=lambda nonces: self._submit_and_wrap(calls, nonces.entry_point_nonce),
            increments_actp_nonce=False,
        )

    def get_wallet_info(self) -> WalletInfo:
        """Get wallet metadata."""
        return WalletInfo(
            address=self._smart_wallet_address,
            tier="auto",
            supports_batching=True,
            gas_sponsored=True,
            chain_id=self._chain_id,
        )

    def get_nonce_manager(self) -> DualNonceManager:
        """Get the DualNonceManager (for ACTPClient to use for ACTP-aware batching)."""
        return self._nonce_manager

    def get_is_deployed(self) -> bool:
        """Check if the Smart Wallet is deployed on-chain."""
        return self._is_deployed

    def get_read_provider(self) -> Any:
        """Expose the underlying Web3 instance for read-only contract calls.

        Parity with TS ``AutoWalletProvider.getReadProvider`` (AutoWalletProvider
        .ts:202-209). Used by the x402 Permit2 approve path to read
        ``USDC.allowance(smartWallet, PERMIT2)`` BEFORE sponsoring a redundant
        approve across restarts / horizontal scale (see
        ``permit2.read_permit2_allowance_is_set``).
        """
        return self._w3

    async def pay_actp_batched(
        self,
        params: BatchedPayParams,
        prepend_calls: Optional[List[SmartWalletCall]] = None,
    ) -> BatchedPayResult:
        """Execute a batched ACTP payment atomically.

        Builds approve + createTransaction + linkEscrow as a single UserOp.
        Manages ACTP nonce inside the mutex queue for concurrent safety.

        Args:
            params: BatchedPayParams with payment details.
            prepend_calls: Optional calls to prepend (e.g., lazy publish activation).

        Returns:
            BatchedPayResult with txId, hash, and success.
        """

        async def _execute(nonces: Any) -> EnqueueResult[BatchedPayResult]:
            from agirails.wallet.aa.transaction_batcher import ACTPBatchParams

            candidate_nonce = nonces.actp_nonce

            for i in range(MAX_NONCE_BUMPS + 1):
                batch = build_actp_pay_batch(
                    ACTPBatchParams(
                        provider=params.provider,
                        requester=params.requester,
                        amount=params.amount,
                        deadline=params.deadline,
                        dispute_window=params.dispute_window,
                        service_hash=params.service_hash,
                        agent_id=params.agent_id,
                        requester_agent_id=getattr(params, "requester_agent_id", "0") or "0",
                        actp_nonce=candidate_nonce,
                        contracts=params.contracts,
                    )
                )

                # Combine activation calls (if any) with payment calls.
                all_calls = (
                    list(prepend_calls) + batch.calls
                    if prepend_calls
                    else batch.calls
                )

                # On retry, re-read EntryPoint nonce — the previous UserOp consumed
                # it even if the inner ACTP call reverted.
                current_ep_nonce = (
                    nonces.entry_point_nonce
                    if i == 0
                    else await self._nonce_manager.read_entry_point_nonce()
                )

                try:
                    receipt = await self._submit_user_op(all_calls, current_ep_nonce)

                    if not receipt.success:
                        return EnqueueResult(
                            result=BatchedPayResult(
                                tx_id=batch.tx_id,
                                hash=receipt.hash,
                                success=False,
                            ),
                            success=False,
                        )

                    # Keep local nonce cache aligned with the nonce that succeeded.
                    self._nonce_manager.set_cached_actp_nonce(candidate_nonce + 1)

                    return EnqueueResult(
                        result=BatchedPayResult(
                            tx_id=batch.tx_id,
                            hash=receipt.hash,
                            success=receipt.success,
                        ),
                        success=receipt.success,
                    )
                except Exception as error:  # noqa: BLE001 — must inspect revert text
                    message = str(error)
                    # Bundlers may return plain revert text or ABI-encoded revert data.
                    lowered = message.lower()
                    nonce_collision = (
                        "escrow id already used" in lowered
                        or "457363726f7720494420616c72656164792075736564" in lowered
                    )

                    if not nonce_collision or i == MAX_NONCE_BUMPS:
                        raise

                    candidate_nonce += 1
                    logger.warning(
                        "ACTP nonce collision detected during batched pay; "
                        "retrying with incremented nonce: nextActpNonce=%d",
                        candidate_nonce,
                    )

            raise RuntimeError(
                "Unable to submit batched ACTP payment after nonce retries"
            )

        return await self._nonce_manager.enqueue(
            fn=_execute,
            # pay_actp_batched controls the ACTP nonce cache explicitly via
            # set_cached_actp_nonce, so the manager must not auto-increment.
            increments_actp_nonce=False,
        )

    async def create_actp_transaction(
        self, params: CreateACTPTransactionParams
    ) -> CreateACTPTransactionResult:
        """Create an ACTP transaction via Smart Wallet (without escrow linking).

        Encodes just ``ACTPKernel.createTransaction()`` as a single-call UserOp.
        Pre-computes the txId using the same keccak256 formula as the contract.
        Manages the ACTP nonce inside the mutex queue for concurrent safety.

        Mirrors TS ``createACTPTransaction`` (AutoWalletProvider.ts:446-483).

        Args:
            params: CreateACTPTransactionParams with provider/requester/amount/etc.

        Returns:
            CreateACTPTransactionResult with the pre-computed txId and receipt.
        """
        from eth_abi import encode as abi_encode

        kernel_address = (
            params.contracts.actp_kernel
            if hasattr(params.contracts, "actp_kernel")
            else params.contracts["actp_kernel"]
        )

        create_tx_selector = Web3.keccak(
            text=(
                "createTransaction(address,address,uint256,uint256,uint256,"
                "bytes32,uint256,uint256)"
            )
        )[:4].hex()

        async def _execute(nonces: Any) -> EnqueueResult[CreateACTPTransactionResult]:
            tx_id = compute_transaction_id(
                params.requester,
                params.provider,
                params.amount,
                params.service_hash,
                nonces.actp_nonce,
            )

            create_tx_data = "0x" + create_tx_selector + abi_encode(
                [
                    "address",
                    "address",
                    "uint256",
                    "uint256",
                    "uint256",
                    "bytes32",
                    "uint256",
                    "uint256",
                ],
                [
                    Web3.to_checksum_address(params.provider),
                    Web3.to_checksum_address(params.requester),
                    int(params.amount),
                    params.deadline,
                    params.dispute_window,
                    bytes.fromhex(params.service_hash.replace("0x", "")),
                    int(params.agent_id or "0"),
                    int(getattr(params, "requester_agent_id", "0") or "0"),
                ],
            ).hex()

            calls = [
                SmartWalletCall(target=kernel_address, value=0, data=create_tx_data),
            ]

            receipt = await self._submit_user_op(calls, nonces.entry_point_nonce)

            return EnqueueResult(
                result=CreateACTPTransactionResult(tx_id=tx_id, receipt=receipt),
                success=receipt.success,
            )

        return await self._nonce_manager.enqueue(
            fn=_execute,
            increments_actp_nonce=True,  # createTransaction increments ACTP nonce
        )

    # ==========================================================================
    # Internal
    # ==========================================================================

    async def _submit_and_wrap(
        self, calls: List[SmartWalletCall], entry_point_nonce: int
    ) -> EnqueueResult[TransactionReceipt]:
        """Submit a UserOp and wrap result for nonce manager."""
        receipt = await self._submit_user_op(calls, entry_point_nonce)
        return EnqueueResult(result=receipt, success=receipt.success)

    async def _submit_user_op(
        self,
        calls: List[SmartWalletCall],
        entry_point_nonce: int,
    ) -> TransactionReceipt:
        """Build, sponsor, sign, and submit a UserOp.

        Steps:
          1. Build unsigned UserOp
          2. Get fee data from chain
          3. Get stub paymaster data (for gas estimation)
          4. Set dummy signature for gas estimation
          5. Estimate gas via bundler
          6. Get final paymaster data (with real gas values)
          7. Sign UserOp
          8. Submit to bundler
          9. Wait for receipt

        Args:
            calls: SmartWalletCalls to batch.
            entry_point_nonce: Current EntryPoint nonce.

        Returns:
            TransactionReceipt with hash and success.
        """
        # 1. Build unsigned UserOp
        user_op = build_user_op(
            sender=self._smart_wallet_address,
            nonce=entry_point_nonce,
            calls=calls,
            is_first_deploy=not self._is_deployed,
            signer_address=self._signer_address,
        )

        # 2. Get fee data (H-3 fix: offload sync RPC to thread)
        fee_data = await asyncio.to_thread(self._w3.eth.fee_history, 1, "latest", [50])
        base_fee = fee_data["baseFeePerGas"][-1]
        priority_fee = fee_data["reward"][0][0] if fee_data.get("reward") else 1_000_000_000
        user_op.max_fee_per_gas = base_fee * 2 + priority_fee
        user_op.max_priority_fee_per_gas = priority_fee

        # 3. Get stub paymaster data (for gas estimation)
        stub_data = await self._paymaster.get_paymaster_stub_data(user_op)
        user_op.paymaster_and_data = stub_data.paymaster_and_data

        # 4. Dummy signature for gas estimation
        user_op.signature = dummy_signature()

        # 5. Estimate gas
        gas_estimate = await self._bundler.estimate_user_operation_gas(user_op)
        user_op.call_gas_limit = gas_estimate.call_gas_limit
        user_op.verification_gas_limit = gas_estimate.verification_gas_limit
        user_op.pre_verification_gas = gas_estimate.pre_verification_gas

        # 6. Get final paymaster data (with real gas values)
        final_paymaster = await self._paymaster.get_paymaster_data(user_op)
        user_op.paymaster_and_data = final_paymaster.paymaster_and_data

        # 7. Sign
        user_op.signature = sign_user_op(user_op, self._private_key, self._chain_id)

        # 8. Submit
        user_op_hash = await self._bundler.send_user_operation(user_op)
        logger.info("UserOp submitted: hash=%s", user_op_hash)

        # 9. Wait for receipt
        receipt = await self._bundler.wait_for_receipt(user_op_hash)

        # Mark as deployed after first successful UserOp
        if not self._is_deployed and receipt.success:
            self._is_deployed = True

        return TransactionReceipt(
            hash=receipt.transaction_hash,
            success=receipt.success,
        )
