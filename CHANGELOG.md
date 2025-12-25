# Changelog

All notable changes to AGIRAILS Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
