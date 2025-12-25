# Python SDK v2.0 - Implementation Plan

> **Radni dokument** - Ažurira se tijekom implementacije
>
> **Lokacija**: `AGIRAILS/SDK and Runtime/python-sdk-v2/`
> **Referenca**: TypeScript SDK u `AGIRAILS/SDK and Runtime/sdk-js/`
> **Stari SDK**: `AGIRAILS/SDK and Runtime/sdk-python/` (NE DIRATI)
>
> **⚠️ Ultra-Think Review**: 2024-12-25 - Plan proširen nakon detaljne analize TS SDK-a
> **⚠️ Python 3.9 Compatibility**: 2024-12-25 - Syntax fixevi za Python 3.9 kompatibilnost (Union[], Optional[], Dict[], List[])
> **⚠️ Documentation Sprint**: 2024-12-25 - README.md, CHANGELOG.md, error/message tests dodani

---

## Status Overview

| Faza | Status | Progress | Estimated |
|------|--------|----------|-----------|
| Faza 1: Core Infrastructure | 🟢 Completed | 10/10 | 6 dana |
| Faza 2: Client & Adapters | 🟢 Completed | 9/9 | 5 dana |
| Faza 3: Level0/Level1 API | 🟢 Completed | 12/12 | 7 dana |
| Faza 4: BlockchainRuntime | 🟢 Completed | 8/8 | 5 dana |
| Faza 5: Protocol Modules | 🟢 Completed | 7/7 | 4 dana |
| Faza 6: Documentation | 🟡 In Progress | 3/6 | 3 dana |
| Faza 7: CLI Tool | 🔴 Not Started | 0/5 | 3 dana |
| **UKUPNO** | | | **33 dana** |

**Legend**: 🔴 Not Started | 🟡 In Progress | 🟢 Completed | ⏸️ Blocked

**Napredak**:
- Faza 1 kompletirana 2024-12-25 (113 tests passing)
- Faza 2 kompletirana 2024-12-25 (214 tests passing)
- Faza 3 kompletirana 2024-12-25 (303 tests passing)
- Python 3.9 syntax fixes 2024-12-25 (337 tests passing)
- Documentation sprint 2024-12-25 (444 tests passing)
  - README.md (comprehensive)
  - CHANGELOG.md (v2.0.0 release notes)
  - Error module tests (+71 tests)
  - Message/signature tests (+36 tests)
- Faza 4 kompletirana 2024-12-25 (468 tests passing)
  - Network configuration (Base Sepolia + Mainnet)
  - ABIs extracted from Solidity contracts
  - ACTPKernel contract wrapper
  - EscrowVault contract wrapper
  - EventMonitor for blockchain events
  - NonceManager for transaction sequencing
  - BlockchainRuntime (IACTPRuntime implementation)
  - Network tests (+24 tests)
- Faza 5 kompletirana 2024-12-25 (564 tests passing)
  - MessageSigner (EIP-712 typed structured data signing)
  - ProofGenerator (content hashing, Merkle proofs)
  - EASHelper (Ethereum Attestation Service integration)
  - AgentRegistry (AIP-7 agent discovery)
  - DIDManager + DIDResolver (decentralized identity)
  - QuoteBuilder + DeliveryProofBuilder (fluent builders)
  - Protocol/builder tests (+96 tests)

---

## Ključne Odluke (Potvrđene)

| Pitanje | Odluka | Datum |
|---------|--------|-------|
| Parity scope | Functional parity (Pythonic idiomi) | 2024-12-25 |
| MockRuntime | Da, s file-based state (.actp/mock-state.json) | 2024-12-25 |
| Level0/Level1 | Da, puni parity (provide/request/Agent) | 2024-12-25 |
| Async support | Async-first (asyncio) | 2024-12-25 |
| Python version | >=3.9 (široka kompatibilnost, Union/Optional syntax) | 2024-12-25 |
| Web3 library | web3.py >=7.0 (AsyncWeb3) | 2024-12-25 |
| CLI | Da, typer-based (faza 7) | 2024-12-25 |

---

## Security Fixes to Implement

> Ovi security fixes iz TS SDK-a moraju biti implementirani u Python verziji:

| ID | Opis | Lokacija | Status |
|----|------|----------|--------|
| C-1 | Race condition prevention - processingLocks | Agent.py | 🟢 Done |
| C-2 | Memory leak prevention - LRUCache za jobs | security.py | 🟢 Done (LRUCache class) |
| H-1 | DoS prevention - filtered queries | mock_runtime.py | 🟢 Done (get_transactions_by_provider) |
| H-2 | Input validation - service name sanitization | security.py | 🟢 Done (validate_service_name) |
| H-6 | Path traversal prevention | security.py | 🟢 Done (validate_path) |
| H-7 | Timing attack prevention | security.py | 🟢 Done (timing_safe_equal) |
| MEDIUM-4 | Concurrency limiting - Semaphore | semaphore.py | 🟢 Done (Semaphore, RateLimiter) |
| MEDIUM-6 | BigInt precision for USDC | helpers.py | 🟢 Done (integer arithmetic) |
| C-3 | Safe JSON parsing | security.py | 🟢 Done (safe_json_parse) |

---

## Arhitektura

```
python-sdk-v2/
├── IMPLEMENTATION_PLAN.md          # Ovaj dokument
├── pyproject.toml                  # Package config
├── README.md                       # User documentation
├── CHANGELOG.md                    # Version history
│
├── src/
│   └── agirails/                   # Main package (renamed from agirails_sdk)
│       │
│       ├── __init__.py             # Public API exports
│       ├── version.py              # __version__ = "2.0.0"
│       │
│       # ══════════ CORE CLIENT ══════════
│       ├── client.py               # ACTPClient (factory pattern)
│       │
│       # ══════════ RUNTIME LAYER ══════════
│       ├── runtime/
│       │   ├── __init__.py
│       │   ├── base.py             # IACTPRuntime Protocol
│       │   ├── types.py            # MockState, MockTransaction, State enum
│       │   ├── mock_state_manager.py   # File-based persistence
│       │   ├── mock_runtime.py     # MockRuntime implementation
│       │   └── blockchain_runtime.py   # BlockchainRuntime (AsyncWeb3)
│       │
│       # ══════════ ADAPTER LAYER ══════════
│       ├── adapters/
│       │   ├── __init__.py
│       │   ├── base.py             # BaseAdapter (shared utilities)
│       │   ├── basic.py         # BasicAdapter (pay method)
│       │   └── standard.py     # StandardAdapter (lifecycle)
│       │
│       # ══════════ PROTOCOL LAYER ══════════
│       ├── protocol/
│       │   ├── __init__.py
│       │   ├── kernel.py           # ACTPKernel contract wrapper
│       │   ├── escrow.py           # EscrowVault wrapper
│       │   ├── events.py           # EventMonitor (async polling)
│       │   ├── messages.py         # MessageSigner (EIP-712)
│       │   ├── proofs.py           # ProofGenerator
│       │   ├── eas.py              # EASHelper (attestations)
│       │   ├── agent_registry.py   # AIP-7 registry
│       │   └── did.py              # DIDManager + DIDResolver
│       │
│       # ══════════ BUILDERS ══════════
│       ├── builders/
│       │   ├── __init__.py
│       │   ├── quote.py            # QuoteBuilder (AIP-2)
│       │   └── delivery_proof.py   # DeliveryProofBuilder (AIP-4)
│       │
│       # ══════════ LEVEL 0 API ══════════
│       ├── level0/
│       │   ├── __init__.py
│       │   ├── provide.py          # provide() function
│       │   ├── request.py          # request() function
│       │   ├── provider.py         # Provider class
│       │   └── directory.py        # ServiceDirectory
│       │
│       # ══════════ LEVEL 1 API ══════════
│       ├── level1/
│       │   ├── __init__.py
│       │   ├── agent.py            # Agent class
│       │   ├── job.py              # Job, JobHandler, JobContext
│       │   ├── pricing.py          # PricingStrategy
│       │   └── config.py           # AgentConfig, ServiceConfig
│       │
│       # ══════════ CLI ══════════
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py             # Entry point (typer)
│       │   ├── commands/
│       │   │   ├── __init__.py
│       │   │   ├── init.py         # actp init
│       │   │   ├── pay.py          # actp pay
│       │   │   ├── tx.py           # actp tx
│       │   │   ├── balance.py      # actp balance
│       │   │   ├── mint.py         # actp mint
│       │   │   ├── config.py       # actp config
│       │   │   ├── watch.py        # actp watch
│       │   │   ├── simulate.py     # actp simulate
│       │   │   ├── batch.py        # actp batch
│       │   │   └── time.py         # actp time
│       │   └── utils/
│       │       ├── __init__.py
│       │       ├── output.py       # JSON/quiet/pretty formatting
│       │       └── client.py       # Shared client initialization
│       │
│       # ══════════ TYPES ══════════
│       ├── types/
│       │   ├── __init__.py
│       │   ├── transaction.py      # Transaction dataclass
│       │   ├── escrow.py           # Escrow types
│       │   ├── eip712.py           # EIP-712 domain/types
│       │   ├── did.py              # DID types
│       │   ├── message.py          # Message types
│       │   └── agent.py            # AgentProfile, ServiceDescriptor
│       │
│       # ══════════ UTILITIES ══════════
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── helpers.py          # USDC, Address, Deadline, State, Bytes32, ServiceHash
│       │   ├── security.py         # Path validation, timing-safe compare, LRUCache
│       │   ├── validation.py       # Input validation, endpoint URL validation
│       │   ├── nonce.py            # NonceManager
│       │   ├── nonce_tracker.py    # ReceivedNonceTracker
│       │   ├── attestation_tracker.py  # UsedAttestationTracker
│       │   ├── logger.py           # Logger class
│       │   ├── semaphore.py        # Semaphore, RateLimiter
│       │   └── canonical_json.py   # Deterministic JSON serialization
│       │
│       # ══════════ CONFIG ══════════
│       ├── config/
│       │   ├── __init__.py
│       │   └── networks.py         # Network configurations
│       │
│       # ══════════ ERRORS ══════════
│       ├── errors/
│       │   ├── __init__.py
│       │   └── exceptions.py       # Exception hierarchy
│       │
│       # ══════════ ABIs ══════════
│       └── abis/
│           ├── actp_kernel.json
│           ├── escrow_vault.json
│           ├── usdc.json
│           ├── eas.json
│           └── agent_registry.json
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # pytest fixtures
│   ├── test_runtime/
│   │   ├── test_mock_runtime.py
│   │   ├── test_mock_state_manager.py
│   │   └── test_blockchain_runtime.py
│   ├── test_adapters/
│   │   ├── test_basic.py
│   │   └── test_standard.py
│   ├── test_utils/
│   │   ├── test_security.py        # Security utilities tests
│   │   ├── test_helpers.py         # Helper utilities tests
│   │   └── test_validation.py      # Validation tests
│   ├── test_client.py
│   ├── test_level0.py
│   ├── test_level1.py
│   ├── test_cli.py                 # CLI tests
│   └── integration/
│       ├── test_full_lifecycle.py
│       └── test_testnet.py
│
└── examples/
    ├── 01_basic_mock.py
    ├── 02_standard_mock.py
    ├── 03_level0_provide.py
    ├── 04_level1_agent.py
    ├── 05_testnet_example.py
    └── 06_cli_usage.sh             # CLI examples
```

---

## Dependencies

```toml
[project]
name = "agirails"
version = "2.0.0"
description = "AGIRAILS Python SDK - Agent Commerce Transaction Protocol"
requires-python = ">=3.9"
dependencies = [
    "web3>=7.0.0",              # AsyncWeb3 for blockchain
    "eth-account>=0.13.0",      # Account/key management
    "eth-abi>=5.0.0",           # ABI encoding/decoding
    "pydantic>=2.6.0",          # Data validation
    "aiofiles>=24.0.0",         # Async file I/O
    "python-dateutil>=2.8.0",   # Date parsing
    "httpx>=0.27.0",            # Async HTTP client (for ProofGenerator)
    "typer>=0.12.0",            # CLI framework
    "rich>=13.0.0",             # Pretty CLI output
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=5.0.0",
    "black>=24.0.0",
    "ruff>=0.6.0",
    "mypy>=1.11.0",
]

[project.scripts]
actp = "agirails.cli.main:app"
```

---

## FAZA 1: Core Infrastructure

**Cilj**: Funkcionalni MockRuntime s file-based state i 8-state machine

**Estimated**: 6 dana (prošireno za security utilities)

### 1.1 Setup projekta

- [ ] `pyproject.toml` - Package configuration
- [ ] `src/agirails/__init__.py` - Package init
- [ ] `src/agirails/version.py` - Version info
- [ ] `.gitignore` - Python gitignore
- [ ] `tests/conftest.py` - pytest configuration

### 1.2 Error Handling (PROŠIRENO)

- [ ] `src/agirails/errors/__init__.py`
- [ ] `src/agirails/errors/exceptions.py`

  **Core Errors**:
  - [ ] `ACTPError` - Base exception (with code, txHash, details)
  - [ ] `TransactionNotFoundError`
  - [ ] `InvalidStateTransitionError`
  - [ ] `InsufficientBalanceError`
  - [ ] `EscrowNotFoundError`
  - [ ] `DeadlinePassedError` / `DeadlineExpiredError`
  - [ ] `DisputeWindowActiveError`
  - [ ] `ContractPausedError`

  **Validation Errors**:
  - [ ] `ValidationError`
  - [ ] `InvalidAddressError`
  - [ ] `InvalidAmountError`

  **Blockchain Errors**:
  - [ ] `TransactionRevertedError`
  - [ ] `NetworkError`
  - [ ] `SignatureVerificationError`

  **Storage Errors (AIP-7)**:
  - [ ] `StorageError` (base)
  - [ ] `InvalidCIDError`
  - [ ] `UploadTimeoutError`
  - [ ] `DownloadTimeoutError`
  - [ ] `FileSizeLimitExceededError`
  - [ ] `StorageAuthenticationError`
  - [ ] `StorageRateLimitError`
  - [ ] `ContentNotFoundError`

  **Agent/Job Errors**:
  - [ ] `NoProviderFoundError`
  - [ ] `TimeoutError`
  - [ ] `ProviderRejectedError`
  - [ ] `DeliveryFailedError`
  - [ ] `DisputeRaisedError`
  - [ ] `ServiceConfigError`
  - [ ] `AgentLifecycleError`

  **Registry Errors**:
  - [ ] `QueryCapExceededError`

### 1.3 Runtime Types

- [ ] `src/agirails/runtime/__init__.py`
- [ ] `src/agirails/runtime/types.py`
  - [ ] `State` enum (8 states: INITIATED, QUOTED, COMMITTED, IN_PROGRESS, DELIVERED, SETTLED, DISPUTED, CANCELLED)
  - [ ] `TransactionState` type alias
  - [ ] `MockTransaction` dataclass
  - [ ] `MockEscrow` dataclass
  - [ ] `MockAccount` dataclass
  - [ ] `MockBlockchain` dataclass
  - [ ] `MockEvent` dataclass
  - [ ] `MockState` dataclass (root state)
  - [ ] `STATE_TRANSITIONS` dict (valid transitions)
  - [ ] `is_valid_transition()` function
  - [ ] `is_terminal_state()` function

### 1.4 Runtime Interface

- [ ] `src/agirails/runtime/base.py`
  - [ ] `CreateTransactionParams` dataclass
  - [ ] `TimeInterface` Protocol
  - [ ] `IACTPRuntime` Protocol
    - [ ] `create_transaction()`
    - [ ] `link_escrow()`
    - [ ] `transition_state()`
    - [ ] `get_transaction()`
    - [ ] `get_all_transactions()`
    - [ ] `release_escrow()`
    - [ ] `get_escrow_balance()`
    - [ ] `time` property
  - [ ] `IMockRuntime` Protocol (extends IACTPRuntime)
    - [ ] `reset()`
    - [ ] `mint_tokens()`
    - [ ] `get_balance()`
    - [ ] Extended `time` with `advance_time()`, `set_time()`
  - [ ] `is_mock_runtime()` type guard

### 1.5 Mock State Manager

- [ ] `src/agirails/runtime/mock_state_manager.py`
  - [ ] `MockStateManager` class
    - [ ] `__init__(state_directory)` - Initialize with path
    - [ ] `_get_state_file_path()` - Returns `.actp/mock-state.json`
    - [ ] `_ensure_directory()` - Create .actp if not exists
    - [ ] `async load()` - Load state from file
    - [ ] `async save(state)` - Save state to file
    - [ ] `async reset()` - Reset to default state
    - [ ] `async with_lock(updater)` - Atomic update with file lock
  - [ ] File locking with `aiofiles` + `fcntl`
  - [ ] JSON serialization/deserialization
  - [ ] Default state factory

### 1.6 Mock Runtime

- [ ] `src/agirails/runtime/mock_runtime.py`
  - [ ] `MockRuntime` class implementing `IMockRuntime`
    - [ ] `__init__(state_manager)`
    - [ ] `async create_transaction(params)` → `str`
      - [ ] Generate deterministic txId (keccak256)
      - [ ] Validate amount > 0
      - [ ] Validate deadline > now
      - [ ] Create MockTransaction
      - [ ] Emit TransactionCreated event
    - [ ] `async link_escrow(tx_id, amount)` → `str`
      - [ ] Validate tx exists
      - [ ] Validate state is INITIATED or QUOTED
      - [ ] Validate requester balance >= amount
      - [ ] Deduct from requester balance
      - [ ] Create MockEscrow
      - [ ] Auto-transition to COMMITTED
      - [ ] Emit EscrowLinked event
    - [ ] `async transition_state(tx_id, new_state, proof)`
      - [ ] Validate tx exists
      - [ ] Validate transition is allowed
      - [ ] Update state and timestamp
      - [ ] Emit StateTransitioned event
    - [ ] `async get_transaction(tx_id)` → `MockTransaction | None`
    - [ ] `async get_all_transactions()` → `list[MockTransaction]`
    - [ ] `async get_transactions_by_provider(address, state, limit)` → `list[MockTransaction]` (za H-1 security fix)
    - [ ] `async release_escrow(escrow_id, attestation_uid)`
      - [ ] Validate escrow exists
      - [ ] Validate tx in DELIVERED state
      - [ ] Validate dispute window expired
      - [ ] Transfer funds to provider
      - [ ] Delete escrow
      - [ ] Transition to SETTLED
    - [ ] `async get_escrow_balance(escrow_id)` → `str`
    - [ ] `async reset()` - Reset all state
    - [ ] `async mint_tokens(address, amount)`
    - [ ] `async get_balance(address)` → `str`
    - [ ] `time` property
      - [ ] `now()` → `int`
      - [ ] `async advance_time(seconds)`
      - [ ] `async advance_blocks(blocks)`
      - [ ] `async set_time(timestamp)`

### 1.7 Security Utilities (PROŠIRENO)

- [ ] `src/agirails/utils/__init__.py`
- [ ] `src/agirails/utils/security.py`

  **Timing Attack Prevention (H-7)**:
  - [ ] `timing_safe_equal(a: str, b: str)` → `bool` - Constant-time string comparison

  **Path Traversal Prevention (H-6)**:
  - [ ] `validate_path(requested_path, base_directory)` → `str` - Sanitized absolute path

  **Input Validation (H-2)**:
  - [ ] `validate_service_name(service_name)` → `str` - Alphanumeric, dash, dot, underscore only
  - [ ] `is_valid_address(address)` → `bool` - 0x + 40 hex format

  **Safe JSON Parsing (C-3)**:
  - [ ] `safe_json_parse(json_string, schema)` → `T | None` - Prototype pollution prevention
  - [ ] `_sanitize_object(obj)` → `dict` - Remove __proto__, constructor, prototype

  **LRU Cache (C-2)**:
  - [ ] `LRUCache[K, V]` class
    - [ ] `__init__(max_size: int = 1000)`
    - [ ] `get(key: K)` → `V | None`
    - [ ] `set(key: K, value: V)`
    - [ ] `has(key: K)` → `bool`
    - [ ] `delete(key: K)`
    - [ ] `clear()`
    - [ ] `size` property
    - [ ] `values()` → `list[V]`
    - [ ] `keys()` → `list[K]`

### 1.8 Logger Utility (NEW)

- [ ] `src/agirails/utils/logger.py`
  - [ ] `Logger` class
    - [ ] `__init__(source: str, min_level: str = 'info')`
    - [ ] `debug(message, meta)`
    - [ ] `info(message, meta)`
    - [ ] `warn(message, meta)`
    - [ ] `error(message, meta, exception)`

### 1.9 Concurrency Utilities (NEW)

- [ ] `src/agirails/utils/semaphore.py`
  - [ ] `Semaphore` class
    - [ ] `__init__(limit: int)`
    - [ ] `async acquire(timeout_ms: int)`
    - [ ] `release()`
    - [ ] `available_permits` property
    - [ ] `queue_length` property
  - [ ] `RateLimiter` class
    - [ ] `__init__(max_requests: int, window_seconds: int)`
    - [ ] `async acquire()`
    - [ ] `reset()`

### 1.10 Tests for Phase 1

- [ ] `tests/test_runtime/__init__.py`
- [ ] `tests/test_runtime/test_mock_runtime.py`
  - [ ] Test create_transaction happy path
  - [ ] Test create_transaction validation errors
  - [ ] Test link_escrow happy path
  - [ ] Test link_escrow insufficient balance
  - [ ] Test all valid state transitions (8-state matrix)
  - [ ] Test invalid state transitions (should raise)
  - [ ] Test release_escrow happy path
  - [ ] Test release_escrow dispute window active
  - [ ] Test time manipulation
  - [ ] Test reset
  - [ ] Test mint_tokens and get_balance
  - [ ] Test get_transactions_by_provider (filtered query)
- [ ] `tests/test_runtime/test_mock_state_manager.py`
  - [ ] Test load/save persistence
  - [ ] Test reset
  - [ ] Test concurrent access (file locking)
- [ ] `tests/test_utils/test_security.py`
  - [ ] Test timing_safe_equal
  - [ ] Test validate_path (path traversal attempts)
  - [ ] Test validate_service_name
  - [ ] Test safe_json_parse
  - [ ] Test LRUCache eviction

### Faza 1 Checklist

```
[ ] 1.1 Setup projekta (5 files)
[ ] 1.2 Error handling (2 files, 30+ exception classes)
[ ] 1.3 Runtime types (1 file)
[ ] 1.4 Runtime interface (1 file)
[ ] 1.5 Mock state manager (1 file)
[ ] 1.6 Mock runtime (1 file)
[ ] 1.7 Security utilities (1 file)
[ ] 1.8 Logger utility (1 file)
[ ] 1.9 Concurrency utilities (1 file)
[ ] 1.10 Tests (4 files)
```

**Validation Criteria**:
- [ ] All state transitions work correctly
- [ ] File-based state persists across runs
- [ ] LRUCache properly evicts oldest entries
- [ ] timing_safe_equal prevents timing attacks
- [ ] pytest passes with >90% coverage for runtime/

---

## FAZA 2: Client & Adapters

**Cilj**: ACTPClient s Basic/Standard API

**Estimated**: 5 dana (prošireno za helper utilities)

### 2.1 Helper Utilities (PROŠIRENO)

- [ ] `src/agirails/utils/helpers.py`

  **USDC Namespace** (6 decimals):
  - [ ] `USDC.DECIMALS = 6`
  - [ ] `USDC.MIN_AMOUNT_WEI = 50_000` ($0.05)
  - [ ] `USDC.to_wei(amount: str | int | float)` → `int` - Human to wei
  - [ ] `USDC.from_wei(wei: int, decimals: int = 2)` → `str` - Wei to human
  - [ ] `USDC.format(wei: int)` → `str` - "100.50 USDC"
  - [ ] `USDC.meets_minimum(wei: int)` → `bool` - >= $0.05

  **Deadline Namespace**:
  - [ ] `Deadline.hours_from_now(hours)` → `int`
  - [ ] `Deadline.days_from_now(days)` → `int`
  - [ ] `Deadline.at(date: datetime | str)` → `int`
  - [ ] `Deadline.is_past(deadline)` → `bool`
  - [ ] `Deadline.time_remaining(deadline)` → `int`
  - [ ] `Deadline.format(deadline)` → `str` - "in 2 hours"

  **Address Namespace**:
  - [ ] `Address.normalize(address)` → `str` - lowercase
  - [ ] `Address.equals(a, b)` → `bool` - case-insensitive
  - [ ] `Address.truncate(address, chars=4)` → `str` - "0x1234...5678"
  - [ ] `Address.is_valid(address)` → `bool`
  - [ ] `Address.is_zero(address)` → `bool`

  **Bytes32 Namespace**:
  - [ ] `Bytes32.is_valid(value)` → `bool`
  - [ ] `Bytes32.normalize(value)` → `str`
  - [ ] `Bytes32.equals(a, b)` → `bool`
  - [ ] `Bytes32.is_zero(value)` → `bool`
  - [ ] `Bytes32.zero()` → `str`
  - [ ] `Bytes32.truncate(value, chars=6)` → `str`

  **State Namespace**:
  - [ ] `State.STATES` - Tuple of all states
  - [ ] `State.TERMINAL` - ('SETTLED', 'CANCELLED')
  - [ ] `State.is_terminal(state)` → `bool`
  - [ ] `State.is_valid(state)` → `bool`
  - [ ] `State.valid_transitions(current_state)` → `list[str]`
  - [ ] `State.can_transition(from_state, to_state)` → `bool`

  **DisputeWindow Namespace**:
  - [ ] `DisputeWindow.DEFAULT = 172800` (2 days)
  - [ ] `DisputeWindow.MIN = 3600` (1 hour)
  - [ ] `DisputeWindow.MAX = 2592000` (30 days)
  - [ ] `DisputeWindow.hours(h)` → `int`
  - [ ] `DisputeWindow.days(d)` → `int`
  - [ ] `DisputeWindow.is_active(completed_at, window_seconds)` → `bool`
  - [ ] `DisputeWindow.remaining(completed_at, window_seconds)` → `int`

  **ServiceHash Namespace** (CRITICAL for on-chain):
  - [ ] `ServiceHash.to_canonical(metadata: ServiceMetadata)` → `str`
  - [ ] `ServiceHash.hash(metadata: ServiceMetadata | str)` → `str` (bytes32)
  - [ ] `ServiceHash.from_legacy(legacy_format: str)` → `ServiceMetadata | None`
  - [ ] `ServiceHash.get_service_name(metadata)` → `str`
  - [ ] `ServiceHash.is_valid_hash(value)` → `bool`
  - [ ] `ServiceHash.ZERO` constant

  **Convenience Functions**:
  - [ ] `parse_usdc(amount)` → `int` - Wrapper for USDC.to_wei
  - [ ] `format_usdc(wei)` → `str` - Wrapper for USDC.from_wei
  - [ ] `shorten_address(address, chars=4)` → `str` - Wrapper for Address.truncate
  - [ ] `hash_service_metadata(service, input)` → `str` - Wrapper for ServiceHash.hash

### 2.2 Validation Utilities

- [ ] `src/agirails/utils/validation.py`
  - [ ] `validate_address(address, field_name)` - Raise ValidationError
  - [ ] `validate_amount(amount, field_name)` - Positive, not too large
  - [ ] `validate_deadline(deadline, current_time)` - In future
  - [ ] `validate_tx_id(tx_id)` - Valid bytes32 hex
  - [ ] `validate_endpoint_url(url)` - SSRF protection (block private IPs)
  - [ ] `validate_dispute_window(seconds)` - Within MIN/MAX bounds

### 2.3 Canonical JSON

- [ ] `src/agirails/utils/canonical_json.py`
  - [ ] `canonical_json_dumps(obj)` → `str` - Deterministic key ordering
  - [ ] `compute_type_hash(primary_type, types)` → `str` - For EIP-712

### 2.4 Base Adapter

- [ ] `src/agirails/adapters/__init__.py`
- [ ] `src/agirails/adapters/base.py`
  - [ ] `DEFAULT_DEADLINE_SECONDS = 86400` (24h)
  - [ ] `DEFAULT_DISPUTE_WINDOW_SECONDS = 172800` (2 days)
  - [ ] `MIN_AMOUNT_WEI = 50000` ($0.05)
  - [ ] `MAX_DEADLINE_HOURS = 168` (7 days)
  - [ ] `MAX_DEADLINE_DAYS = 30`
  - [ ] `BaseAdapter` class
    - [ ] `__init__(runtime, requester_address, eas_helper)`
    - [ ] `parse_amount(amount)` → `str`
    - [ ] `parse_deadline(deadline)` → `int`
    - [ ] `format_amount(wei)` → `str`
    - [ ] `validate_address(address, field)` → `str`
    - [ ] `validate_dispute_window(seconds)` → `int`

### 2.5 Basic Adapter

- [ ] `src/agirails/adapters/basic.py`
  - [ ] `BasicPayParams` dataclass
    - [ ] `to: str` - Provider address
    - [ ] `amount: str | int | float` - Amount
    - [ ] `deadline: str | int | None` - Optional deadline
    - [ ] `description: str | None` - Optional description
  - [ ] `BasicPayResult` dataclass
    - [ ] `tx_id: str`
    - [ ] `escrow_id: str`
    - [ ] `state: str`
    - [ ] `amount: str`
    - [ ] `deadline: int`
  - [ ] `BasicAdapter` class
    - [ ] `async pay(params: BasicPayParams)` → `BasicPayResult`
      - [ ] Parse amount and deadline
      - [ ] Create transaction
      - [ ] Link escrow
      - [ ] Return result

### 2.6 Standard Adapter

- [ ] `src/agirails/adapters/standard.py`
  - [ ] `StandardTransactionParams` dataclass
    - [ ] `provider: str`
    - [ ] `amount: str | int | float`
    - [ ] `deadline: str | int | None`
    - [ ] `dispute_window: int | None`
    - [ ] `description: str | None`
  - [ ] `StandardAdapter` class
    - [ ] `async create_transaction(params)` → `str`
    - [ ] `async link_escrow(tx_id)` → `str`
    - [ ] `async transition_state(tx_id, new_state)` → `None`
    - [ ] `async release_escrow(escrow_id, attestation_params)` → `None`
    - [ ] `async get_escrow_balance(escrow_id)` → `str`
    - [ ] `async get_transaction(tx_id)` → `MockTransaction | None`

### 2.7 ACTPClient

- [ ] `src/agirails/client.py`
  - [ ] `ACTPClientMode` type = `Literal['mock', 'testnet', 'mainnet']`
  - [ ] `ACTPClientInfo` dataclass
    - [ ] `mode: ACTPClientMode`
    - [ ] `address: str`
    - [ ] `state_directory: Path | None`
  - [ ] `ACTPClientConfig` dataclass
    - [ ] `mode: ACTPClientMode`
    - [ ] `requester_address: str`
    - [ ] `state_directory: Path | None`
    - [ ] `private_key: str | None`
    - [ ] `rpc_url: str | None`
    - [ ] `contracts: dict | None`
    - [ ] `gas_settings: dict | None`
    - [ ] `eas_config: dict | None`
    - [ ] `require_attestation: bool`
    - [ ] `runtime: IACTPRuntime | None`
  - [ ] `ACTPClient` class
    - [ ] `beginner: BasicAdapter` (property)
    - [ ] `intermediate: StandardAdapter` (property)
    - [ ] `advanced: IACTPRuntime` (property, same as runtime)
    - [ ] `runtime: IACTPRuntime`
    - [ ] `info: ACTPClientInfo`
    - [ ] `eas_helper: EASHelper | None`
    - [ ] `__init__(runtime, requester_address, info, eas_helper)`
    - [ ] `@classmethod async create(config)` → `ACTPClient`
      - [ ] Validate requester_address
      - [ ] Mode selection (mock/testnet/mainnet)
      - [ ] Initialize appropriate runtime
      - [ ] Create adapters
    - [ ] `get_address()` → `str`
    - [ ] `get_mode()` → `ACTPClientMode`
    - [ ] `async reset()` - Mock mode only
    - [ ] `async mint_tokens(address, amount)` - Mock mode only
    - [ ] `async get_balance(address)` → `str`
    - [ ] `__repr__()` - Safe string (no private keys)

### 2.8 Package Exports

- [ ] Update `src/agirails/__init__.py`
  - [ ] Export ACTPClient, ACTPClientConfig, ACTPClientMode, ACTPClientInfo
  - [ ] Export BasicAdapter, BasicPayParams, BasicPayResult
  - [ ] Export StandardAdapter, StandardTransactionParams
  - [ ] Export BaseAdapter, DEFAULT_* constants
  - [ ] Export State enum
  - [ ] Export all exceptions
  - [ ] Export IACTPRuntime, IMockRuntime
  - [ ] Export helper namespaces (USDC, Address, Deadline, Bytes32, State, DisputeWindow, ServiceHash)

### 2.9 Tests for Phase 2

- [ ] `tests/test_client.py`
  - [ ] Test ACTPClient.create() mock mode
  - [ ] Test ACTPClient.create() with custom state_directory
  - [ ] Test ACTPClient.create() validation errors
  - [ ] Test get_address(), get_mode()
  - [ ] Test reset() mock mode
  - [ ] Test mint_tokens(), get_balance()
  - [ ] Test __repr__() doesn't leak private key
- [ ] `tests/test_adapters/__init__.py`
- [ ] `tests/test_adapters/test_basic.py`
  - [ ] Test pay() happy path
  - [ ] Test pay() with custom deadline
  - [ ] Test pay() validation errors
- [ ] `tests/test_adapters/test_standard.py`
  - [ ] Test create_transaction()
  - [ ] Test link_escrow()
  - [ ] Test transition_state()
  - [ ] Test release_escrow()
  - [ ] Test get_transaction()
- [ ] `tests/test_utils/test_helpers.py`
  - [ ] Test USDC namespace
  - [ ] Test Deadline namespace
  - [ ] Test Address namespace
  - [ ] Test Bytes32 namespace
  - [ ] Test State namespace
  - [ ] Test DisputeWindow namespace
  - [ ] Test ServiceHash namespace

### Faza 2 Checklist

```
[x] 2.1 Helper utilities (1 file, extensive) - USDC, Deadline, Address, Bytes32, State, DisputeWindow, ServiceHash
[x] 2.2 Validation utilities (1 file) - validate_address, validate_amount, validate_endpoint_url, SSRF protection
[x] 2.3 Canonical JSON (1 file) - deterministic JSON for EIP-712
[x] 2.4 Base adapter (2 files) - BaseAdapter with shared utilities
[x] 2.5 Basic adapter (1 file) - pay() method
[x] 2.6 Standard adapter (1 file) - full lifecycle control
[x] 2.7 ACTPClient (1 file) - factory pattern, mock/testnet/mainnet
[x] 2.8 Package exports (1 file update) - all public APIs exported
[x] 2.9 Tests (5 files) - 214 tests passing
```

**Validation Criteria**:
- [x] `ACTPClient.create(mode='mock')` works
- [x] `client.basic.pay()` creates and funds transaction
- [x] `client.standard.*` all methods work
- [x] All helper namespaces work correctly
- [x] pytest passes with >85% coverage (214 tests passing)

---

## FAZA 3: Level0/Level1 API

**Cilj**: provide(), request(), Agent class za AI agente

**Estimated**: 7 dana (prošireno za Agent complexity)

### 3.1 Job Types

- [ ] `src/agirails/level1/__init__.py`
- [ ] `src/agirails/level1/job.py`
  - [ ] `Job` dataclass
    - [ ] `id: str` - Transaction ID
    - [ ] `service: str` - Service name
    - [ ] `input: Any` - Job input data
    - [ ] `budget: float` - USDC amount
    - [ ] `deadline: datetime` - Deadline
    - [ ] `requester: str` - Address
    - [ ] `metadata: dict` - Additional metadata
  - [ ] `JobContext` class
    - [ ] `agent: Agent`
    - [ ] `progress(percent, message)` - Report progress
    - [ ] `log` - Logger interface (debug/info/warn/error)
    - [ ] `state` - Key-value storage
    - [ ] `cancelled` - Check if cancelled
    - [ ] `on_cancel(handler)` - Register cancel handler
  - [ ] `JobHandler` type alias = `Callable[[Job, JobContext], Awaitable[Any]]`
  - [ ] `JobResult` dataclass
    - [ ] `success: bool`
    - [ ] `output: Any`
    - [ ] `error: str | None`

### 3.2 Configuration Types

- [ ] `src/agirails/level1/config.py`
  - [ ] `NetworkOption` type = `Literal['mock', 'testnet', 'mainnet']`
  - [ ] `WalletOption` type = `str | None` (address or private key)
  - [ ] `RetryConfig` dataclass
    - [ ] `attempts: int = 3`
    - [ ] `delay: int = 1000` (ms)
    - [ ] `backoff: Literal['linear', 'exponential'] = 'exponential'`
  - [ ] `AgentBehavior` dataclass
    - [ ] `auto_accept: bool | Callable[[Job], bool | Awaitable[bool]] = True`
    - [ ] `concurrency: int = 10`
    - [ ] `timeout: int = 300` (seconds)
    - [ ] `retry: RetryConfig | None = None`
  - [ ] `AgentConfig` dataclass
    - [ ] `name: str`
    - [ ] `description: str = ""`
    - [ ] `network: NetworkOption = 'mock'`
    - [ ] `wallet: WalletOption = None`
    - [ ] `state_directory: Path | None = None`
    - [ ] `rpc_url: str | None = None`
    - [ ] `behavior: AgentBehavior | None = None`
    - [ ] `persistence: dict | None = None`
    - [ ] `logging: dict | None = None`
  - [ ] `ServiceFilter` dataclass
    - [ ] `min_budget: float | None = None`
    - [ ] `max_budget: float | None = None`
    - [ ] `custom: Callable[[Job], bool] | None = None`
  - [ ] `ServiceConfig` dataclass
    - [ ] `name: str`
    - [ ] `description: str = ""`
    - [ ] `filter: ServiceFilter | None = None`
    - [ ] `pricing: PricingStrategy | None = None`
    - [ ] `capabilities: list[str] | None = None`
    - [ ] `timeout: int | None = None`

### 3.3 Pricing Strategy

- [ ] `src/agirails/level1/pricing.py`
  - [ ] `CostModel` dataclass
    - [ ] `base: float` - Base cost
    - [ ] `per_unit: dict | None` - {"unit": str, "rate": float}
  - [ ] `PricingStrategy` dataclass
    - [ ] `cost: CostModel`
    - [ ] `margin: float` - e.g., 0.40 for 40%
    - [ ] `min_price: float | None = None`
    - [ ] `max_price: float | None = None`
    - [ ] `below_price: Literal['reject', 'accept', 'counter-offer'] = 'reject'`
    - [ ] `below_cost: Literal['reject', 'accept'] = 'reject'`
  - [ ] `PriceCalculation` dataclass
    - [ ] `cost: float`
    - [ ] `price: float`
    - [ ] `profit: float`
    - [ ] `margin_percent: float`
    - [ ] `decision: Literal['accept', 'reject', 'counter-offer']`
    - [ ] `reason: str | None`
  - [ ] `DEFAULT_PRICING_STRATEGY` constant
  - [ ] `calculate_price(strategy, job)` → `PriceCalculation`

### 3.4 Agent Class (COMPLEX - ~600+ lines)

- [ ] `src/agirails/level1/agent.py`
  - [ ] `AgentStatus` enum
    - [ ] `IDLE`, `STARTING`, `RUNNING`, `PAUSED`, `STOPPING`, `STOPPED`
  - [ ] `AgentStats` dataclass
    - [ ] `jobs_received: int = 0`
    - [ ] `jobs_completed: int = 0`
    - [ ] `jobs_failed: int = 0`
    - [ ] `total_earned: float = 0`
    - [ ] `total_spent: float = 0`
    - [ ] `average_job_time: float = 0`
    - [ ] `success_rate: float = 0`
  - [ ] `AgentBalance` dataclass
    - [ ] `eth: str`
    - [ ] `usdc: str`
    - [ ] `locked: str`
    - [ ] `pending: str`
  - [ ] `Agent` class

    **Properties**:
    - [ ] `name: str`
    - [ ] `description: str | None`
    - [ ] `network: NetworkOption`
    - [ ] `status: AgentStatus`
    - [ ] `address: str`
    - [ ] `service_names: list[str]`
    - [ ] `jobs: list[Job]`
    - [ ] `stats: AgentStats`
    - [ ] `balance: AgentBalance`
    - [ ] `client: ACTPClient | None`

    **Internal State (SECURITY CRITICAL)**:
    - [ ] `_client: ACTPClient | None`
    - [ ] `_services: dict[str, tuple[ServiceConfig, JobHandler]]`
    - [ ] `_active_jobs: LRUCache[str, Job]` (C-2: max 1000)
    - [ ] `_processed_jobs: LRUCache[str, bool]` (C-1: max 10000)
    - [ ] `_processing_locks: set[str]` (C-1: race prevention)
    - [ ] `_concurrency_semaphore: Semaphore` (MEDIUM-4)
    - [ ] `_stats: AgentStats`
    - [ ] `_balance: AgentBalance`
    - [ ] `_config: AgentConfig`
    - [ ] `_polling_task: asyncio.Task | None`
    - [ ] `_logger: Logger`
    - [ ] `_event_emitter: EventEmitter equivalent`

    **Lifecycle Methods**:
    - [ ] `__init__(config: AgentConfig)`
    - [ ] `async start()` - Initialize client, start polling
    - [ ] `async stop()` - Graceful shutdown
    - [ ] `pause()` - Stop accepting new jobs
    - [ ] `resume()` - Resume accepting jobs
    - [ ] `async restart()` - Stop + start

    **Service Registration**:
    - [ ] `provide(service: str | ServiceConfig, handler: JobHandler, options)` → `self`
    - [ ] `async request(service, options: RequestOptions)` → `RequestResult`

    **Balance**:
    - [ ] `async get_balance_async()` → `AgentBalance` (real-time)

    **Events**:
    - [ ] `on(event: str, handler: Callable)`
    - [ ] `_emit(event: str, *args)`

    **Private Methods**:
    - [ ] `_start_polling()` - Start polling loop
    - [ ] `_stop_polling()` - Stop polling loop
    - [ ] `async _poll_for_jobs()` - Poll for new jobs (H-1: filtered)
    - [ ] `_find_service_handler(tx)` → handler (exact match, not substring)
    - [ ] `async _should_auto_accept(tx)` → `bool` (includes pricing eval)
    - [ ] `_create_job_from_transaction(tx)` → `Job`
    - [ ] `_extract_service_name(tx)` → `str`
    - [ ] `_extract_job_input(tx)` → `Any`
    - [ ] `async _process_job(job, handler)` - Process with semaphore
    - [ ] `_create_job_context(job)` → `JobContext`
    - [ ] `async _wait_for_active_jobs(timeout_ms)`
    - [ ] `_generate_address()` → `str`
    - [ ] `_get_private_key()` → `str | None`

### 3.5 Service Directory

- [ ] `src/agirails/level0/__init__.py`
- [ ] `src/agirails/level0/directory.py`
  - [ ] `ServiceEntry` dataclass
    - [ ] `service_name: str`
    - [ ] `provider_address: str`
    - [ ] `endpoint: str | None`
    - [ ] `registered_at: int`
  - [ ] `ServiceDirectory` class
    - [ ] `_services: dict[str, list[ServiceEntry]]`
    - [ ] `register(service_name, provider_address, endpoint)`
    - [ ] `unregister(service_name, provider_address)`
    - [ ] `find(service_name)` → `list[ServiceEntry]`
    - [ ] `find_one(service_name)` → `ServiceEntry | None`
    - [ ] `list_services()` → `list[str]`
  - [ ] `service_directory` - Global singleton instance

### 3.6 Provider Class

- [ ] `src/agirails/level0/provider.py`
  - [ ] `ProviderStatus` type alias = `AgentStatus`
  - [ ] `ProviderStats` type alias = `AgentStats`
  - [ ] `ProviderBalance` type alias = `AgentBalance`
  - [ ] `Provider` class (adapter over Agent)
    - [ ] `_agent: Agent`
    - [ ] `status: ProviderStatus` (property)
    - [ ] `stats: ProviderStats` (property)
    - [ ] `address: str` (property)
    - [ ] `balance: ProviderBalance` (property)
    - [ ] `__init__(agent: Agent)`
    - [ ] `async stop()` - Stop underlying agent
    - [ ] `pause()` - Pause
    - [ ] `resume()` - Resume
    - [ ] `on(event, handler)` - Forward to agent

### 3.7 provide() Function

- [ ] `src/agirails/level0/provide.py`
  - [ ] `ProvideOptions` dataclass
    - [ ] `network: NetworkOption = 'mock'`
    - [ ] `wallet: WalletOption = None`
    - [ ] `state_directory: Path | None = None`
    - [ ] `rpc_url: str | None = None`
    - [ ] `auto_accept: bool = True`
    - [ ] `filter: ServiceFilter | None = None`
  - [ ] `provide(service: str, handler: JobHandler, options: ProvideOptions | None)` → `Provider`
    - [ ] Create Agent with config
    - [ ] Register service with handler
    - [ ] Start agent (async, fire-and-forget)
    - [ ] Register in service_directory
    - [ ] Return Provider adapter

### 3.8 request() Function

- [ ] `src/agirails/level0/request.py`
  - [ ] `RequestOptions` dataclass
    - [ ] `network: NetworkOption = 'mock'`
    - [ ] `wallet: WalletOption = None`
    - [ ] `state_directory: Path | None = None`
    - [ ] `rpc_url: str | None = None`
    - [ ] `provider: str | None = None` - Specific provider
    - [ ] `budget: float` - Amount in USDC
    - [ ] `timeout: int = 300` - Seconds
  - [ ] `RequestStatus` enum
    - [ ] `PENDING`, `ACCEPTED`, `IN_PROGRESS`, `COMPLETED`, `FAILED`, `TIMEOUT`
  - [ ] `RequestResult` dataclass
    - [ ] `tx_id: str`
    - [ ] `status: RequestStatus`
    - [ ] `output: Any | None`
    - [ ] `error: str | None`
    - [ ] `provider: str`
    - [ ] `amount: str`
  - [ ] `async request(service: str, input: Any, options: RequestOptions)` → `RequestResult`
    - [ ] Find provider (from options or service_directory)
    - [ ] Create service metadata JSON
    - [ ] Create ACTPClient
    - [ ] Create transaction with metadata
    - [ ] Link escrow
    - [ ] Wait for completion or timeout
    - [ ] Return result

### 3.9 Nonce Tracker (NEW)

- [ ] `src/agirails/utils/nonce_tracker.py`
  - [ ] `IReceivedNonceTracker` Protocol
  - [ ] `InMemoryReceivedNonceTracker` class
    - [ ] `has_received(nonce)` → `bool`
    - [ ] `mark_received(nonce)`
    - [ ] `cleanup_old(max_age_seconds)`

### 3.10 Type Definitions (NEW)

- [ ] `src/agirails/types/did.py`
  - [ ] `DIDDocument` dataclass
  - [ ] `VerificationMethod` dataclass
- [ ] `src/agirails/types/message.py`
  - [ ] `SignedMessage` dataclass
  - [ ] `QuoteMessage` dataclass
  - [ ] `DeliveryProofMessage` dataclass

### 3.11 Package Exports for Level0/Level1

- [ ] Update `src/agirails/level0/__init__.py`
  - [ ] Export provide, request, service_directory
  - [ ] Export Provider, ProviderStatus, ProviderStats, ProviderBalance
  - [ ] Export ProvideOptions, RequestOptions, RequestResult, RequestStatus
- [ ] Update `src/agirails/level1/__init__.py`
  - [ ] Export Agent, AgentConfig, AgentStatus, AgentStats, AgentBalance
  - [ ] Export Job, JobHandler, JobContext, JobResult
  - [ ] Export ServiceConfig, ServiceFilter
  - [ ] Export PricingStrategy, CostModel, PriceCalculation, calculate_price
- [ ] Update `src/agirails/__init__.py`
  - [ ] Export all Level0/Level1 APIs

### 3.12 Tests for Phase 3

- [ ] `tests/test_level0.py`
  - [ ] Test provide() creates provider
  - [ ] Test provide() registers in directory
  - [ ] Test request() finds provider
  - [ ] Test request() creates transaction with metadata
  - [ ] Test request() with specific provider
  - [ ] Test request() timeout handling
  - [ ] Test service_directory operations
- [ ] `tests/test_level1.py`
  - [ ] Test Agent lifecycle (start/stop/pause/resume)
  - [ ] Test Agent.provide() registers service
  - [ ] Test Agent handles job correctly
  - [ ] Test Agent event system
  - [ ] Test Agent concurrency (semaphore limits)
  - [ ] Test Agent filtering (min/max budget)
  - [ ] Test Agent pricing strategy evaluation
  - [ ] Test LRUCache eviction in Agent
  - [ ] Test race condition prevention (processing_locks)

### Faza 3 Checklist

```
[x] 3.1 Job types (job.py - Job, JobContext, JobResult)
[x] 3.2 Configuration types (config.py - AgentConfig, ServiceConfig, RetryConfig)
[x] 3.3 Pricing strategy (pricing.py - PricingStrategy, CostModel, calculate_price)
[x] 3.4 Agent class (agent.py - ~600+ lines with security measures)
[x] 3.5 Service directory (directory.py - ServiceDirectory, ServiceEntry, ServiceQuery)
[x] 3.6 Provider class (provider.py - Provider, ProviderConfig, ProviderStatus)
[x] 3.7 provide() function (provide.py - functional API)
[x] 3.8 request() function (request.py - RequestHandle, RequestResult)
[x] 3.9 Nonce tracker (nonce_tracker.py - NonceTracker, NonceManager)
[x] 3.10 Type definitions (did.py, message.py, transaction.py)
[x] 3.11 Package exports (level0/__init__.py, level1/__init__.py, main __init__.py)
[x] 3.12 Tests (89 new tests across level0, level1, types)
```

**Validation Criteria**:
- [x] `provide('echo', handler)` starts provider
- [x] `request('echo', input)` gets result
- [x] Agent lifecycle works (start/stop/pause/resume)
- [x] Concurrency limiting works (semaphore)
- [x] LRUCache prevents memory leaks
- [x] pytest passes with 303 tests (89 new)

---

## FAZA 4: BlockchainRuntime

**Cilj**: Real blockchain support (Base Sepolia testnet)

**Estimated**: 5 dana

### 4.1 Network Configuration

- [ ] `src/agirails/config/__init__.py`
- [ ] `src/agirails/config/networks.py`
  - [ ] `NetworkConfig` dataclass
    - [ ] `name: str`
    - [ ] `chain_id: int`
    - [ ] `rpc_url: str`
    - [ ] `block_explorer: str`
    - [ ] `contracts: ContractAddresses`
    - [ ] `eas: EASConfig`
    - [ ] `gas_settings: GasSettings`
  - [ ] `ContractAddresses` dataclass
    - [ ] `actp_kernel: str`
    - [ ] `escrow_vault: str`
    - [ ] `usdc: str`
    - [ ] `eas: str`
    - [ ] `eas_schema_registry: str`
    - [ ] `agent_registry: str | None`
  - [ ] `EASConfig` dataclass
    - [ ] `delivery_schema_uid: str`
  - [ ] `GasSettings` dataclass
    - [ ] `max_fee_per_gas: int`
    - [ ] `max_priority_fee_per_gas: int`
  - [ ] `NETWORKS: dict[str, NetworkConfig]`
    - [ ] `base-sepolia` config
    - [ ] `base-mainnet` config (placeholder)
  - [ ] `get_network(name: str)` → `NetworkConfig`

### 4.2 Copy ABIs from old SDK

- [ ] `src/agirails/abis/actp_kernel.json`
- [ ] `src/agirails/abis/escrow_vault.json`
- [ ] `src/agirails/abis/usdc.json`
- [ ] `src/agirails/abis/eas.json`
- [ ] `src/agirails/abis/agent_registry.json`

### 4.3 Protocol Kernel

- [ ] `src/agirails/protocol/__init__.py`
- [ ] `src/agirails/protocol/kernel.py`
  - [ ] `ACTPKernel` class
    - [ ] `__init__(contract, account)`
    - [ ] `@classmethod from_config(provider, account, config)` → `ACTPKernel`
    - [ ] `async create_transaction(params)` → `str`
    - [ ] `async transition_state(tx_id, new_state, proof)`
    - [ ] `async link_escrow(tx_id, escrow_vault, escrow_id)`
    - [ ] `async release_escrow(escrow_id, tx_id, attestation_uid)`
    - [ ] `async get_transaction(tx_id)` → `Transaction`
    - [ ] `async release_milestone(tx_id, amount)`
    - [ ] `async anchor_attestation(tx_id, attestation_uid)`
    - [ ] `_estimate_gas(func, *args)` → `int`
    - [ ] `_build_tx_options(gas_estimate)` → `dict`

### 4.4 Protocol Escrow

- [ ] `src/agirails/protocol/escrow.py`
  - [ ] `EscrowVault` class
    - [ ] `__init__(contract, usdc_contract, account)`
    - [ ] `@classmethod from_config(provider, account, config)` → `EscrowVault`
    - [ ] `async approve_tokens(amount)`
    - [ ] `async get_allowance(owner)` → `int`
    - [ ] `async get_escrow(escrow_id)` → `Escrow`
    - [ ] `async get_remaining_balance(escrow_id)` → `int`

### 4.5 Event Monitor

- [ ] `src/agirails/protocol/events.py`
  - [ ] `EventMonitor` class
    - [ ] `__init__(kernel_contract, provider)`
    - [ ] `async watch_transaction(tx_id, callback)`
    - [ ] `async wait_for_state(tx_id, target_state, timeout)`
    - [ ] `async get_transaction_history(address, role)` → `list[Transaction]`
    - [ ] `_poll_events(from_block, to_block)`

### 4.6 Nonce Manager

- [ ] `src/agirails/utils/nonce.py`
  - [ ] `NonceManager` class
    - [ ] `__init__(provider, address)`
    - [ ] `async get_nonce()` → `int`
    - [ ] `async increment()`
    - [ ] `async reset()`
    - [ ] Async-safe with asyncio.Lock

### 4.7 BlockchainRuntime

- [ ] `src/agirails/runtime/blockchain_runtime.py`
  - [ ] `BlockchainRuntimeConfig` dataclass
    - [ ] `network: str`
    - [ ] `account: LocalAccount`
    - [ ] `provider: AsyncWeb3`
    - [ ] `contracts: dict | None`
    - [ ] `gas_settings: dict | None`
    - [ ] `eas_config: dict | None`
    - [ ] `require_attestation: bool`
    - [ ] `state_directory: Path | None`
  - [ ] `BlockchainRuntime` class implementing `IACTPRuntime`
    - [ ] `__init__(config: BlockchainRuntimeConfig)`
    - [ ] `async initialize()` - Async setup
      - [ ] Create contract instances
      - [ ] Initialize MessageSigner
      - [ ] Initialize EASHelper (if configured)
      - [ ] Initialize NonceManager
    - [ ] `async create_transaction(params)` → `str`
    - [ ] `async link_escrow(tx_id, amount)` → `str`
      - [ ] Check USDC allowance
      - [ ] Approve if needed
      - [ ] Call kernel.linkEscrow
    - [ ] `async transition_state(tx_id, new_state, proof)`
    - [ ] `async get_transaction(tx_id)` → `Transaction | None`
    - [ ] `async get_all_transactions()` → `list[Transaction]`
    - [ ] `async release_escrow(escrow_id, attestation_uid)`
    - [ ] `async get_escrow_balance(escrow_id)` → `str`
    - [ ] `get_eas_helper()` → `EASHelper | None`
    - [ ] `is_attestation_required()` → `bool`
    - [ ] `time` property (uses blockchain time)

### 4.8 Tests for Phase 4

- [ ] `tests/test_runtime/test_blockchain_runtime.py`
  - [ ] Test initialization with config
  - [ ] Test create_transaction (mocked)
  - [ ] Test link_escrow with approval
  - [ ] Test transition_state
- [ ] `tests/integration/test_testnet.py`
  - [ ] Test full lifecycle on Base Sepolia
  - [ ] Test with real USDC

### Faza 4 Checklist

```
[ ] 4.1 Network configuration (2 files)
[ ] 4.2 Copy ABIs (5 files)
[ ] 4.3 Protocol kernel (2 files)
[ ] 4.4 Protocol escrow (1 file)
[ ] 4.5 Event monitor (1 file)
[ ] 4.6 Nonce manager (1 file)
[ ] 4.7 BlockchainRuntime (1 file)
[ ] 4.8 Tests (2 files)
```

**Validation Criteria**:
- [ ] `ACTPClient.create(mode='testnet')` works
- [ ] Full transaction lifecycle on Base Sepolia
- [ ] Gas estimation works correctly

---

## FAZA 5: Protocol Modules

**Cilj**: Complete protocol layer parity

**Estimated**: 4 dana

### 5.1 Message Signer (EIP-712)

- [ ] `src/agirails/protocol/messages.py`
  - [ ] `EIP712Domain` dataclass
  - [ ] `QuoteRequestData` dataclass
  - [ ] `QuoteResponseData` dataclass
  - [ ] `DeliveryProofData` dataclass
  - [ ] `MessageSigner` class
    - [ ] `@classmethod async create(signer, kernel_address, config)`
    - [ ] `async sign_quote_request(data)` → `str`
    - [ ] `async sign_quote_response(data)` → `str`
    - [ ] `async sign_delivery_proof(data)` → `str`
    - [ ] `async verify_quote_request(data, signature, expected_signer)`
    - [ ] `_build_typed_data(types, message)`

### 5.2 Proof Generator

- [ ] `src/agirails/protocol/proofs.py`
  - [ ] `ProofGenerator` class
    - [ ] `hash_content(content: bytes)` → `str` (keccak256)
    - [ ] `async hash_from_url(url: str)` → `str` (using httpx)
    - [ ] `generate_delivery_proof(tx_id, deliverable, metadata)` → `DeliveryProofData`
    - [ ] `encode_proof(proof)` → `bytes`
    - [ ] `decode_proof(encoded)` → `DeliveryProofData`
    - [ ] `verify_deliverable(expected_hash, actual_content)` → `bool`

### 5.3 EAS Helper

- [ ] `src/agirails/protocol/eas.py`
  - [ ] `AttestationData` dataclass
  - [ ] `EASHelper` class
    - [ ] `__init__(contract, schema_registry, config)`
    - [ ] `@classmethod from_config(provider, config)` → `EASHelper`
    - [ ] `async create_delivery_attestation(tx_id, proof)` → `str`
    - [ ] `async verify_and_record_for_release(tx_id, attestation_uid)`
    - [ ] `async get_attestation(attestation_uid)` → `AttestationData`
    - [ ] `async decode_delivery_proof(attestation)` → `DeliveryProofData`
    - [ ] `async is_attestation_valid(attestation_uid)` → `bool`

### 5.4 Attestation Tracker

- [ ] `src/agirails/utils/attestation_tracker.py`
  - [ ] `IUsedAttestationTracker` Protocol
  - [ ] `InMemoryUsedAttestationTracker` class
  - [ ] `FileBasedUsedAttestationTracker` class
  - [ ] `create_used_attestation_tracker(state_directory)` factory

### 5.5 Agent Registry (AIP-7)

- [ ] `src/agirails/protocol/agent_registry.py`
  - [ ] `AgentRegistry` class
    - [ ] `__init__(contract, account)`
    - [ ] `@classmethod from_config(provider, account, config)` → `AgentRegistry`
    - [ ] `async register_agent(endpoint, service_descriptors)`
    - [ ] `async update_endpoint(new_endpoint)`
    - [ ] `async add_service_type(service_type)`
    - [ ] `async remove_service_type(service_type_hash)`
    - [ ] `async set_active_status(is_active)`
    - [ ] `async get_agent(address)` → `AgentProfile`
    - [ ] `async get_agent_by_did(did)` → `AgentProfile`
    - [ ] `async query_agents_by_service(service_type_hash, min_reputation, offset, limit)` → `list[str]`
    - [ ] `async supports_service(address, service_type_hash)` → `bool`
    - [ ] `compute_service_type_hash(service_type)` → `str`
    - [ ] `build_did(address, chain_id)` → `str`

### 5.6 DID Manager

- [ ] `src/agirails/protocol/did.py`
  - [ ] `DIDDocument` dataclass
  - [ ] `DIDManager` class
    - [ ] `create_did(address, chain_id)` → `str`
    - [ ] `parse_did(did)` → `tuple[str, int]`
    - [ ] `validate_did(did)` → `bool`
  - [ ] `DIDResolver` class
    - [ ] `async resolve(did)` → `DIDDocument`

### 5.7 Builders

- [ ] `src/agirails/builders/__init__.py`
- [ ] `src/agirails/builders/quote.py`
  - [ ] `QuoteBuilder` class
    - [ ] `build(tx_id, quoted_amount, valid_until, signer)` → `Quote`
    - [ ] `verify(quote, expected_signer)` → `bool`
    - [ ] `compute_hash(quote)` → `str`
- [ ] `src/agirails/builders/delivery_proof.py`
  - [ ] `DeliveryProofBuilder` class
    - [ ] `build(tx_id, content_hash, storage_url, signer)` → `DeliveryProof`
    - [ ] `verify(proof, expected_signer)` → `bool`

### Faza 5 Checklist

```
[x] 5.1 Message signer (1 file) - MessageSigner with EIP-712 signing
[x] 5.2 Proof generator (1 file) - ProofGenerator with Merkle tree support
[x] 5.3 EAS helper (1 file) - EASHelper for attestations
[x] 5.4 Agent registry (1 file) - AgentRegistry wrapper
[x] 5.5 DID manager (1 file) - DIDManager + DIDResolver
[x] 5.6 Builders (2 files) - QuoteBuilder, DeliveryProofBuilder
[x] 5.7 Tests (4 files) - 96 new tests for protocol/builders
```

**Validation Criteria**:
- [x] EIP-712 message signing works (MessageSigner)
- [x] Content hashing and Merkle proofs work (ProofGenerator)
- [x] EAS helper initializes correctly
- [x] Agent Registry operations work
- [x] DID creation and resolution works
- [x] Fluent builders work for Quote and DeliveryProof
- [x] pytest passes with 564 tests

---

## FAZA 6: Documentation & Release

**Cilj**: PyPI release ready

**Estimated**: 3 dana

### 6.1 Documentation

- [x] `README.md` - Complete usage documentation ✅ **Completed 2024-12-25**
  - [x] Installation
  - [x] Quick Start (Basic API)
  - [x] Standard API
  - [x] Level0 API (provide/request)
  - [x] Level1 API (Agent)
  - [ ] CLI Usage
  - [x] Configuration
  - [x] Error handling
- [x] `CHANGELOG.md` - Version history ✅ **Completed 2024-12-25**
- [ ] `MIGRATION.md` - v1 to v2 migration guide
- [ ] `docs/` folder (optional, for detailed docs)

### 6.2 Examples

- [ ] `examples/01_basic_mock.py`
- [ ] `examples/02_standard_mock.py`
- [ ] `examples/03_level0_provide.py`
- [ ] `examples/04_level1_agent.py`
- [ ] `examples/05_testnet_example.py`
- [ ] `examples/06_cli_usage.sh`

### 6.3 CI/CD

- [ ] `.github/workflows/ci.yml` - Test on push
- [ ] `.github/workflows/release.yml` - PyPI publish

### 6.4 Package Finalization

- [ ] `pyproject.toml` - Final dependencies
- [ ] `py.typed` marker for type hints
- [ ] License file
- [ ] Final `__init__.py` exports

### 6.5 Release

- [ ] Tag v2.0.0-beta
- [ ] Publish to Test PyPI
- [ ] Test installation
- [ ] Publish to PyPI

### Faza 6 Checklist

```
[x] 6.1 Documentation (README.md, CHANGELOG.md done; MIGRATION.md pending)
[ ] 6.2 Examples (6 files)
[ ] 6.3 CI/CD (2 files)
[~] 6.4 Package finalization (pyproject.toml done; py.typed, LICENSE pending)
[ ] 6.5 Release (publish)
```

---

## FAZA 7: CLI Tool (NEW)

**Cilj**: Developer-friendly command-line interface matching TS SDK

**Estimated**: 3 dana

### 7.1 CLI Framework

- [ ] `src/agirails/cli/__init__.py`
- [ ] `src/agirails/cli/main.py`
  - [ ] Typer app initialization
  - [ ] Version command
  - [ ] Help text with examples
  - [ ] Global options (--json, --quiet)

### 7.2 CLI Commands

- [ ] `src/agirails/cli/commands/__init__.py`
- [ ] `src/agirails/cli/commands/init.py`
  - [ ] `actp init` - Initialize in current directory
  - [ ] Creates `.actp/` folder
  - [ ] Creates default config
- [ ] `src/agirails/cli/commands/pay.py`
  - [ ] `actp pay <provider> <amount>` - Create payment
  - [ ] Options: --deadline, --description
- [ ] `src/agirails/cli/commands/tx.py`
  - [ ] `actp tx status <txId>` - Check status
  - [ ] `actp tx list` - List transactions
  - [ ] `actp tx transition <txId> <state>` - Transition state
- [ ] `src/agirails/cli/commands/balance.py`
  - [ ] `actp balance [address]` - Check balance
- [ ] `src/agirails/cli/commands/mint.py`
  - [ ] `actp mint <address> <amount>` - Mint test tokens (mock only)
- [ ] `src/agirails/cli/commands/config.py`
  - [ ] `actp config show` - Show current config
  - [ ] `actp config set <key> <value>` - Set config value
- [ ] `src/agirails/cli/commands/watch.py`
  - [ ] `actp watch <txId>` - Watch transaction for changes
  - [ ] Real-time updates
- [ ] `src/agirails/cli/commands/simulate.py`
  - [ ] `actp simulate` - Run simulation mode
  - [ ] Interactive transaction simulation
- [ ] `src/agirails/cli/commands/batch.py`
  - [ ] `actp batch <file>` - Execute batch transactions from file
- [ ] `src/agirails/cli/commands/time.py`
  - [ ] `actp time` - Show current mock time
  - [ ] `actp time advance <seconds>` - Advance mock time
  - [ ] `actp time set <timestamp>` - Set mock time

### 7.3 CLI Utilities

- [ ] `src/agirails/cli/utils/__init__.py`
- [ ] `src/agirails/cli/utils/output.py`
  - [ ] `format_json(data)` - JSON output
  - [ ] `format_table(data)` - Table output
  - [ ] `format_quiet(value)` - Minimal output
  - [ ] `print_success(message)`
  - [ ] `print_error(message)`
- [ ] `src/agirails/cli/utils/client.py`
  - [ ] `get_client(ctx)` → `ACTPClient` - Get client from context
  - [ ] `load_config()` → `dict` - Load from .actp/config.json
  - [ ] `save_config(config)` - Save config

### 7.4 Tests

- [ ] `tests/test_cli.py`
  - [ ] Test init command
  - [ ] Test pay command
  - [ ] Test tx status command
  - [ ] Test balance command
  - [ ] Test mint command (mock mode)
  - [ ] Test time commands (mock mode)
  - [ ] Test JSON output mode
  - [ ] Test quiet output mode

### 7.5 Entry Point

- [ ] Update `pyproject.toml` - Add scripts entry
  ```toml
  [project.scripts]
  actp = "agirails.cli.main:app"
  ```

### Faza 7 Checklist

```
[ ] 7.1 CLI framework (2 files)
[ ] 7.2 CLI commands (10 files)
[ ] 7.3 CLI utilities (3 files)
[ ] 7.4 Tests (1 file)
[ ] 7.5 Entry point (1 file update)
```

**Validation Criteria**:
- [ ] `actp --version` shows version
- [ ] `actp init` creates .actp folder
- [ ] `actp pay` works in mock mode
- [ ] `actp tx status` returns JSON
- [ ] All commands support --json and --quiet

---

## Testing Strategy

### Unit Tests
- Location: `tests/test_*.py`
- Framework: pytest + pytest-asyncio
- Coverage target: >85%

### Integration Tests
- Location: `tests/integration/`
- Requires: Base Sepolia testnet access
- Run manually before release

### Security Tests
- Location: `tests/test_utils/test_security.py`
- Test: Path traversal, timing attacks, JSON injection
- Required: 100% coverage for security utilities

### Test Commands

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agirails --cov-report=html

# Run specific test file
pytest tests/test_client.py

# Run only mock tests (fast)
pytest -m "not integration"

# Run integration tests
pytest tests/integration/ --slow

# Run security tests
pytest tests/test_utils/test_security.py -v
```

---

## Development Workflow

### Setup

```bash
cd "AGIRAILS/SDK and Runtime/python-sdk-v2"
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Before Commit

```bash
black src/ tests/
ruff check src/ tests/ --fix
mypy src/
pytest
```

---

## Migration from v1

### Breaking Changes

1. **Async-first**: All methods are now async
   ```python
   # v1 (sync)
   tx_id = client.create_transaction(...)

   # v2 (async)
   tx_id = await client.standard.create_transaction(...)
   ```

2. **Factory pattern**: Use `ACTPClient.create()` instead of constructor
   ```python
   # v1
   client = ACTPClient(network=Network.BASE_SEPOLIA, private_key="...")

   # v2
   client = await ACTPClient.create(ACTPClientConfig(
       mode='testnet',
       requester_address='0x...',
       private_key='...'
   ))
   ```

3. **Three-level API**: Access methods through adapters
   ```python
   # v1
   client.create_transaction(...)

   # v2
   client.standard.create_transaction(...)
   # or
   client.basic.pay(...)
   ```

4. **Package name**: `agirails` instead of `agirails_sdk`

5. **CLI**: New `actp` command available

### Compatibility Shim (Optional)

```python
# src/agirails/compat.py
from .client import ACTPClient as ACTPClientV2
import warnings

class ACTPClient:
    """v1 compatibility wrapper."""

    def __init__(self, network, private_key):
        warnings.warn(
            "ACTPClient v1 API is deprecated. Use ACTPClient.create() instead.",
            DeprecationWarning
        )
        # ... sync wrapper implementation
```

---

## Notes & Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2024-12-25 | Async-first | Better performance for I/O bound blockchain ops |
| 2024-12-25 | Python >=3.9 | Šira kompatibilnost, koristimo Union/Optional syntax umjesto `X \| Y` |
| 2024-12-25 | web3.py >=7.0 | AsyncWeb3 support |
| 2024-12-25 | Package name: agirails | Simpler than agirails_sdk |
| 2024-12-25 | File-based MockState | Matches TS SDK, persistence across runs |
| 2024-12-25 | Added CLI (Faza 7) | Parity with TS SDK actp command |
| 2024-12-25 | LRUCache required | Security fix C-2 for Agent memory leak |
| 2024-12-25 | typer for CLI | Modern, type-safe, better than argparse |
| 2024-12-25 | httpx for HTTP | Async-native, better than aiohttp for this use case |

---

## Kontakti

- **Tech Lead**: Damir
- **TS SDK Reference**: Justin (CTO)

---

## Appendix: TypeScript SDK Reference Files

Key files to reference during implementation:

1. `sdk-js/src/ACTPClient.ts` - Client pattern
2. `sdk-js/src/runtime/IACTPRuntime.ts` - Runtime interface
3. `sdk-js/src/runtime/MockRuntime.ts` - Mock implementation
4. `sdk-js/src/runtime/BlockchainRuntime.ts` - Blockchain implementation
5. `sdk-js/src/adapters/BasicAdapter.ts` - Basic API
6. `sdk-js/src/adapters/StandardAdapter.ts` - Standard API
7. `sdk-js/src/level0/index.ts` - provide/request
8. `sdk-js/src/level1/Agent.ts` - Agent class (**1400+ lines!**)
9. `sdk-js/src/types/state.ts` - State machine
10. `sdk-js/src/protocol/` - Protocol modules
11. `sdk-js/src/utils/security.ts` - Security utilities (**LRUCache!**)
12. `sdk-js/src/utils/Helpers.ts` - Helper utilities (**ServiceHash!**)
13. `sdk-js/src/errors/index.ts` - Error hierarchy
14. `sdk-js/src/cli/index.ts` - CLI entry point

---

*Last Updated: 2024-12-25 (Phase 5 Complete - 564 tests passing)*
