# Changelog

All notable changes to AGIRAILS Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] — 2026-05-XX (in progress)

> Tracks the 2026-05-19 Base mainnet V3 + Sepolia V4 redeploy and brings
> the Python SDK to parity with `@agirails/sdk@4.0.0`. **Breaking** mainnet
> address surface change; ABI shape change (19 → 21 fields).

### Mainnet contracts (Base, chain 8453)

| Contract | Address |
|----------|---------|
| `actp_kernel` | `0x048c811352e8a3fECd5b0Ec4AA2c2b94083CC842` |
| `escrow_vault` | `0x262D5912A9612F0c66dA5d13B4E678D50ebC44b5` |
| `agent_registry` | `0x64Cb18bfb3CC1aCb1370a3B01613391D3561a009` |
| `archive_treasury` | `0x6159A80Ce8362aBB2307FbaB4Ed4D3F4A4231Acc` |
| `usdc` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (Circle, unchanged) |

Deploy block: 46,212,266. Compiler: solc 0.8.34 + via_ir. All 4 contracts
Sourcify EXACT_MATCH verified. Admin / pauser / feeRecipient: Treasury
Safe 2-of-4 `0x61fE58E9…b7f2`.

### Sepolia contracts (Base, chain 84532) — V4 alignment

| Contract | Address |
|----------|---------|
| `actp_kernel` | `0x9d25A874f046185d9237Cd4954C88D2B74B0021b` |
| `escrow_vault` | `0x7dF07327090efcA73DCBa70414aA3131Fc6d2efB` |
| `agent_registry` | `0xD91F9aBfBf60b4a2Fd5317ab0cDF3F44faB5D656` |
| `archive_treasury` | `0x2eE4f7bE289fc9EFC2F9f2D6E53e50abDF23A3eb` |

Deploy block: 41,725,686. Same source as mainnet V3 (identical compiler +
ABI shape).

### Wire-protocol changes

- **`TransactionView` grew from 19 to 21 fields.** Inserted between
  `platform_fee_bps_locked` and `agent_id`:
  - `requester_penalty_bps_locked: int` (AIP-14 / commit d9c6e8e)
  - `dispute_bond_bps_locked: int` (INV-30)
- **`getTransaction()` ABI tuple** updated to match — `from_tuple()` reads
  positions [14]-[20] for the V3+ shape. Pre-V3 (19-field) tuples are
  intentionally rejected with a clear error rather than silently
  mis-positioned.

### Protocol-layer changes (already enforced on-chain)

- **AIP-14 dispute bonds** — disputer posts $1 USDC bond when transitioning
  to DISPUTED; bond returned per fault attribution. `TransactionView`
  surfaces `dispute_initiator` + `dispute_bond` (read-side parity).
- **MIN_FEE on-chain** — $0.05 minimum platform fee now enforced in the
  kernel itself (was SDK-only previously).
- **INV-30** — per-transaction `dispute_bond_bps_locked`. Live admin rate
  updates can't affect in-flight transactions.
- **M-2 mediator timelock hardening** — closes admin-bypass window where
  re-approve of revoked mediator could skip the 2-day cooldown.
- **ERC-8004 `agent_id` + `requester_agent_id`** in `TransactionView` —
  receipts and indexers see agent identity without a second RPC.

### Configuration schema changes

- `ContractAddresses` gains 4 `Optional[str]` fields:
  `archive_treasury`, `identity_registry`, `x402_relay`,
  `erc8004_identity_registry` (all default `None` — backward-compatible).
- `NetworkConfig` gains `actp_kernel_deployment_block: Optional[int]`
  (used by `BlockchainRuntime` to bound initial event-log scan range).
- `NetworkConfig.to_dict()` now surfaces all 4 new contract fields.

### Breaking

- **Mainnet address surface change.** Code that reads addresses via
  `get_network("base-mainnet").contracts.*` migrates automatically.
  Hardcoded V2 addresses must be swapped.
- **`x402_relay` is `None` on mainnet V3.** The legacy X402Relay contract
  is NOT redeployed on mainnet — x402 v2 routes payments directly
  buyer → seller via `@x402/fetch` + facilitator (zero AGIRAILS fee).
  Sepolia retains `0x110b25bb…` for legacy direct-call consumers only.
- **`TransactionView` field ordering changed** between positions 14 and 17.
  Code using field-name access is unaffected; code using positional
  `tuple[index]` decoding will break.

### Migration

For most integrators: `pip install --upgrade agirails` after this release
is sufficient. The SDK reads addresses from `get_network("base-mainnet")`
so callers going through the helper migrate without code changes. Manual
swaps needed only if:
- You hardcoded V2 mainnet addresses anywhere in your code or env.
- You decode `getTransaction()` returns via positional `tuple[index]`
  instead of `TransactionView.from_tuple()` or field-name access.

### Coming in 3.x

- `wallet="auto"` literal auto-detection in `ACTPClient.create()` (mirrors TS)
- Top-level re-exports of `X402Adapter`, `AutoWalletProvider`,
  `EOAWalletProvider`, `ERC8004Bridge`, `ReputationReporter`,
  `discover_agents`, `compute_transaction_id`
- `X402Adapter` auto-registration when wallet provider has `sign_typed_data`
- `CounterOfferBuilder` + `CounterAcceptBuilder` (AIP-2.1 EIP-712 builders)
- `actp serve` daemon (FastAPI quote-channel HTTP for AIP-2.1)
- Web Receipts (EIP-712 ReceiptWrite + agirails.app upload)
- `actp repair`, `actp claim-code`, `actp request`, `actp verify` CLI commands

---

## [2.0.0] - 2024-12-25

### Added

#### Core SDK
- `ACTPClient` - Main client with factory pattern and three-tier API access
- `ACTPClientConfig` - Configuration dataclass for client initialization
- `ACTPClientMode` - Enum for mock/blockchain modes

#### Adapters
- `BasicAdapter` - Simple `pay()` method for quick payments
- `StandardAdapter` - Full lifecycle control with explicit steps
- `BaseAdapter` - Shared utilities for amount/deadline parsing

#### Runtime Layer
- `MockRuntime` - Complete mock implementation for local testing
- `MockStateManager` - File-based state persistence with atomic locking
- `IACTPRuntime` - Abstract interface for runtime implementations
- 8-state transaction lifecycle (INITIATED, QUOTED, COMMITTED, IN_PROGRESS, DELIVERED, SETTLED, DISPUTED, CANCELLED)

#### Error Hierarchy (24 exception types)
- `ACTPError` - Base exception with structured error codes
- Transaction errors: `TransactionNotFoundError`, `InvalidStateTransitionError`, `EscrowNotFoundError`
- Validation errors: `ValidationError`, `InvalidAddressError`, `InvalidAmountError`
- Network errors: `NetworkError`, `TransactionRevertedError`, `SignatureVerificationError`
- Storage errors: `StorageError`, `InvalidCIDError`, `UploadTimeoutError`, `DownloadTimeoutError`
- Agent errors: `NoProviderFoundError`, `ProviderRejectedError`, `DeliveryFailedError`
- Mock errors: `MockStateCorruptedError`, `MockStateVersionError`, `MockStateLockError`

#### Utilities
- `NonceTracker` - Thread-safe nonce management for Ethereum transactions
- `Logger` - Structured logging with JSON output support
- `LRUCache` - Generic LRU cache with size limits
- `Semaphore` / `RateLimiter` - Concurrency control primitives
- Security utilities: `timing_safe_equal()`, `validate_path()`, `safe_json_parse()`
- Helpers: `USDC`, `Deadline`, `Address`, `Bytes32`, `StateHelper`, `DisputeWindow`

#### Level 0 API (Low-level Primitives)
- `ServiceDirectory` - Service registration and discovery
- `ServiceEntry` / `ServiceQuery` - Service metadata and filtering
- `Provider` / `ProviderConfig` - Provider management
- `request()` / `provide()` - Core request/provide functions

#### Level 1 API (Agent Framework)
- `Agent` / `AgentConfig` - Agent abstraction with lifecycle management
- `Job` / `JobContext` / `JobHandler` - Job handling framework
- `PricingStrategy` / `CostModel` - Flexible pricing calculations
- `ServiceConfig` / `ServiceFilter` - Service configuration

#### Types
- `AgentDID` / `DIDDocument` - Decentralized identity types
- `Transaction` / `TransactionState` / `TransactionReceipt` - Transaction types
- `EIP712Domain` / `SignedMessage` / `TypedData` - EIP-712 signing types
- `ServiceRequest` / `ServiceResponse` / `DeliveryProof` - Message types

#### Testing
- 337 unit tests covering all modules
- Async test support with pytest-asyncio
- Mock runtime enables testing without blockchain

### Changed
- Full Python 3.9 compatibility (previously required 3.10+)
- All type annotations now use `Optional[]`, `Union[]`, `List[]`, `Dict[]` from typing module
- Added `from __future__ import annotations` for deferred evaluation

### Security
- Added `timing_safe_equal()` for constant-time signature verification
- Added `safe_json_parse()` to prevent prototype pollution attacks
- Added `validate_path()` to prevent directory traversal attacks
- Added query cap limits (`QueryCapExceededError`) for DoS prevention
- File locking in `MockStateManager` for atomic state operations

### Fixed
- Signature verification now emits warning instead of silently passing on missing crypto

### Developer Experience
- Comprehensive docstrings with usage examples
- Type hints throughout codebase
- Structured error codes for programmatic error handling
- Three-tier API for different experience levels

---

## [Unreleased]

> Note: Changelog entries for v2.1.0 through v2.3.1 were not recorded.
> See git log for detailed changes.

### Planned for 2.1.0
- `BlockchainRuntime` - Real blockchain integration
- CLI tool implementation (`actp` command)
- EAS attestation integration
- Gas estimation and optimization

### Planned for 2.2.0
- WebSocket event streaming
- Transaction batching
- Multi-chain support

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 2.0.0 | 2024-12-25 | Initial v2 release with Python 3.9 support |
