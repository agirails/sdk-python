# Changelog

All notable changes to AGIRAILS Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] — 2026-05-20

### Fixed post-audit (still 3.0.0 — pre-publish)

- **PRD §5.4 hash-based service routing now actually dispatches.**
  Both `Agent.provide()` and `Provider.register_service()` now keep a
  ``keccak256(toUtf8Bytes(name)) → registration`` reverse map and
  consult it first when looking up handlers. Without this, an
  on-chain transaction with `service_description = keccak("foo")`
  (the shape produced by `actp request --service foo`, by
  BuyerOrchestrator, and by the TS SDK) would silently miss the
  matching handler — both code paths previously tried to parse the
  description as JSON / "service:NAME;..." / plain string only.
  Closes the parity gap with TS `Agent.handlersByHash` (Agent.ts:644).
  Legacy JSON / legacy / plain-string formats keep working via the
  string-dispatch fallback.
- `actp request` CLI help no longer claims slug-URL resolution.
  `run_request` rejects anything that isn't a `0x…40` EVM address,
  so the help text now says so explicitly and points users at
  `actp find <slug>` to resolve a slug first. Slug resolution itself
  is a tracked 3.1 item.
- `respx>=0.21.0` added to the `dev` extra. Web Receipts and
  `actp verify` tests need it for httpx mocking; without it the
  full pytest run on a no-extras dev install would fail at
  collection time.
- `NetworkConfig.actp_kernel_deployment_block` docstring corrected
  to reflect that 3.0.0 actually consumes the field in
  `BlockchainRuntime.get_all_transactions()` (the "Not yet wired"
  caveat was stale relative to commit 985fd8b).



> Tracks the 2026-05-19 Base mainnet V3 + Sepolia V4 redeploy and brings
> the Python SDK to parity with `@agirails/sdk@4.0.0`. **Breaking** mainnet
> address surface change; ABI shape change (19 → 21 fields).
>
> Highlights:
>
> - Wire-protocol parity with V3 contracts: 21-field `TransactionView`,
>   AIP-14 dispute bonds, MIN_FEE on-chain.
> - Full `wallet="auto"` Smart Wallet path end-to-end: `pay()` AND every
>   lifecycle call (`accept_quote`, `link_escrow`, `transition_state`,
>   `release_escrow`) now route through the bundler+paymaster so
>   `msg.sender == requester` on chain.
> - AIP-2.1 quote channel: signed `CounterOfferBuilder` /
>   `CounterAcceptBuilder` + an `actp serve` FastAPI daemon that
>   verifies and policy-evaluates incoming counter-offers.
> - Web Receipts upload helper with EIP-712 `ReceiptWrite` signing.
> - Four new CLI commands: `actp serve`, `actp claim-code`, `actp
>   repair`, `actp verify`, `actp request`.

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
  (Sepolia V4: `41_725_686`; Base V3: `46_212_266`). Now actively
  consumed by `BlockchainRuntime.get_all_transactions()` as the
  lower-bound floor for the initial event-log scan — the contract
  didn't exist before that block, so scanning earlier is pure RPC
  waste (and many public RPCs reject ranges that deep on event
  queries). The default `from_block` is now
  `max(deployment_block, latest - 50_000)` so newly-deployed
  contracts scan a small slice and old contracts still get the
  bounded 50k-block heuristic. RPC failure falls back to the deploy
  block alone. Explicit `from_block=…` continues to override both.
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

### Added (parity sprint)

- **Top-level re-exports** of `X402Adapter`, `AutoWalletProvider`,
  `EOAWalletProvider`, `IWalletProvider`, `WalletTier`, `WalletInfo`,
  `ERC8004Bridge`, `ReputationReporter`, `discover_agents`,
  `compute_transaction_id`.
- **`wallet="auto"`** literal in `ACTPClient.create()` — mirrors TS SDK
  `ACTPClient.create({ wallet: 'auto' })`. SDK reads network AA config
  (Coinbase primary, Pimlico backup), constructs `AutoWalletProvider`,
  derives the Smart Wallet counterfactual address, and overrides
  `requester_address` with it. Requires `mode in ("testnet","mainnet")`
  + `private_key`.
- **AIP-12 batched payment routing in `BasicAdapter`** — when an
  `ACTPClient` is created with a wallet provider that implements
  `pay_actp_batched` (`AutoWalletProvider`) and `contract_addresses` is
  resolved (auto-populated by `create()` for testnet/mainnet),
  `client.basic.pay(address)` routes through a single batched UserOp
  (USDC approve + `createTransaction` + `linkEscrow`) instead of three
  sequential EOA-signed calls. This is what makes `wallet="auto"`
  actually gasless end-to-end and ensures on-chain
  `msg.sender == Smart Wallet == requester` (kernel `_requesterCheck`).
  Without a wallet provider exposing `pay_actp_batched`, the legacy
  sequential path through `runtime.create_transaction` is preserved
  unchanged.
- **`SmartWalletRouter`** (`agirails.wallet.smart_wallet_router`) — Python
  port of `sdk-js/src/wallet/SmartWalletRouter.ts`. Encodes ACTPKernel
  state-transition calls (`transitionState`, `acceptQuote`, `linkEscrow`)
  + USDC approve as `TransactionRequest` / batched call lists and
  submits them via `wallet_provider.send_transaction` /
  `send_batch_transaction`. Includes `validate_release_preconditions`
  (state + dispute window check with mock-mode-duration /
  blockchain-mode-absolute-timestamp heuristic) and
  `verify_release_attestation`. Constructed automatically by
  `BaseAdapter` whenever wallet provider + contract addresses are wired.
- **`StandardAdapter` lifecycle routing** — `link_escrow`, `accept_quote`,
  `transition_state`, and `release_escrow` now route through the
  `SmartWalletRouter` when the wallet provider is AA-capable.
  `link_escrow` submits approve + linkEscrow as one batched UserOp;
  `release_escrow` runs preconditions + attestation guard before
  submitting `transitionState(SETTLED)`. This closes the parity gap with
  TS SDK where every lifecycle call on `wallet="auto"` previously
  reverted with kernel `_requesterCheck` / `_providerCheck` mismatch.
  Legacy EOA / mock path is preserved when wallet provider lacks
  `pay_actp_batched`.
- **`actp serve` — AIP-2.1 quote-channel daemon.** New CLI command +
  Python package (`agirails.server`) that runs a FastAPI app exposing:
  - `GET /` — health check (provider address + supported chainIds).
  - `POST /quote-channel/{chainId}/{txId}` — receives AIP-2.1
    `agirails.counteroffer.v1` messages, runs URL-path-binding +
    TTL-with-grace + EIP-712 signature verification (via
    `CounterOfferBuilder`) + in-memory nonce dedup. The response
    carries two independent signals:
    - **Transport** — HTTP status (`201` accepted-for-processing,
      `200` idempotent duplicate, `4xx` rejected) and the
      `accepted` / `duplicate` flags.
    - **Business** — when transport passes, the response also
      includes `verdict: { action, reason, recommended_amount }`
      where `action ∈ {ACCEPT, COUNTER, REJECT}` is the result of
      running the verified message against the loaded
      `ProviderPolicy`. Buyers can distinguish a transport failure
      (`status 4xx`) from a successful negotiation round that ended
      in policy rejection (`status 201` + `verdict.action = "REJECT"`).
  Includes `ProviderPolicy` + `PricingPolicy` dataclasses with JSON
  loader (`load_policy_from_file`), `evaluate_counter` policy engine
  (walk / concede strategies with concede_pct math), and
  `QuoteChannelHandler` framework-agnostic verifier with
  `InMemoryDedupStore`. FastAPI / uvicorn ship as the optional
  `server` extra — install via `pip install agirails[server]`.

  **v1 policy scope:** `evaluate_counter` enforces
  `pricing.{min_acceptable_amount, ideal_amount}`,
  `counter_strategy`, and `concede_pct`. The `services`,
  `min_deadline_seconds`, and `max_requotes` fields are accepted by
  the loader but **not enforced by the counter-evaluation path** —
  `services` belongs to quote-time service filtering;
  `min_deadline_seconds` bounds `tx.deadline` (enforced at quote-time
  and on-chain); `max_requotes` is session state belonging to a
  multi-round orchestrator. These ship in 3.x once the full provider
  orchestrator + on-chain INITIATED watcher (`actp agent`) and
  reverse-channel `CounterAccept` delivery (AIP-2.1 §5.3) land.

- **Web Receipts** (`agirails.receipts.upload_receipt`) — Python port
  of `sdk-js/src/cli/receiptUpload.ts`. Async upload helper that posts
  a settled-transaction receipt to the public agirails.app endpoint:
  - **Mock network** → `POST /api/v1/receipts/mock` with Bearer API key.
  - **On-chain** → `POST /api/v1/receipts` with either Bearer API key
    or the EIP-712 wallet-sig flow (preferred when an agent signer is
    already available). Wallet path runs the
    `/api/v1/receipts/prepare` handshake to fetch a server-issued
    nonce + `issuedAt`, signs `ReceiptWrite(agentAddress, txId,
    network, amountWei, netWei, nonce, issuedAt)` over the
    `AGIRAILS Receipts` domain (chainId = 8453 / 84532), and ships
    the signature in `x-agent-signature` + the address in
    `x-agent-address` headers so the server can recover and bind the
    upload to the agent.
  Best-effort: returns a `ReceiptUploadSuccess | ReceiptUploadFailure`
  union — never raises. Network errors, 4xx/5xx, missing credentials,
  malformed responses all surface as `ReceiptUploadFailure(ok=False,
  reason=...)`. Re-exported at top level as `upload_receipt`,
  `ReceiptUploadPayload`, `ReceiptUploadOptions`, and the two result
  types. Reads `AGIRAILS_BASE_URL` and `AGIRAILS_API_KEY` from env as
  fallback defaults.

- **`X402Adapter` auto-registration** — when an `ACTPClient` is created
  with a `wallet_provider` exposing `send_transaction` (both
  `EOAWalletProvider` and `AutoWalletProvider` qualify) and `mode` is
  testnet or mainnet, the client auto-registers an `X402Adapter` wired
  to a `USDC.transfer(to, amount)` closure that submits via the wallet
  provider. Best-effort: any failure is logged and skipped. Mirrors the
  TS SDK behavior (TS gates on `signTypedData` for x402 v2 EIP-712;
  Python uses the legacy direct-transfer variant pending the v2 port).
- **AIP-2.1 `CounterOfferBuilder` + `CounterAcceptBuilder`** — Python
  ports of the TS counter-offer/accept builders. EIP-712 signed
  off-chain messages for buyer-side counter-offers and provider-side
  acceptance, with canonical-JSON `compute_hash` for on-chain anchoring
  and dedup, monotonic per-message-type nonces (`MessageNonceManager`),
  amount-band validation (≥ $0.05, strictly < quoteAmount, ≤ maxPrice),
  and DID-bound signature recovery. Verify-only construction supported
  by passing `private_key=None` (orchestrator side).

- **`actp request`** — Level 1 negotiated job request (PRD §5.6).
  Distinct from ``actp pay``: pay commits funds directly without a
  handler; request routes through a registered provider's handler.
  Creates an INITIATED transaction whose ``service_description`` is
  the bytes32 routing key ``keccak256(toUtf8Bytes(name.strip()))``;
  a provider listening for that hash quotes, accepts, runs its
  handler, and delivers. CLI prints each state transition with an
  elapsed-time prefix, then issues the requester-immediate settle
  on DELIVERED. Two separate timeouts (``--quote-timeout`` default
  30s, ``--delivery-timeout`` default 5m); quote timeout exits with
  code **2** so scripts can distinguish "provider offline" from
  other failures. ``--quiet`` emits only the tx id, ``--json`` emits
  the full structured result (``txId, finalState, elapsedMs, settled,
  payload``). Backed by a new ``agirails.cli.lib.run_request``
  helper module that the SDK can also call programmatically.
- **`actp verify`** — trustless verification of agent identity files.
  Reads input from file path, URL, or stdin (pipe). Walks the
  verification chain: parses AGIRAILS.md → computes the canonical
  config hash → matches against the on-chain ``getConfigHash`` /
  ``getConfigCID`` for the agent's wallet (or
  ``--address`` override) → optionally fetches the IPFS content at
  the registered CID and confirms it hashes to the same value →
  optionally fetches a reputation snapshot from agirails.app.
  Outputs ``trustTier`` ∈ ``{chain-verified, published, unverified}``
  and exits non-zero on hash mismatch. JSON output uses the same
  camelCase keys as the TS daemon so dashboards and CI can parse
  results from either SDK identically. The marquee invocation::

      curl -s https://agirails.app/a/<slug>/<slug>.md | actp verify
- **`actp repair`** — reshape an on-chain agent without redeploying.
  Drops phantom services, updates endpoint, and toggles
  ``isActive`` / ``listed`` flags via the existing ``AgentRegistry``
  methods. Each repair action sends its own transaction; sequential
  execution means a failure midway leaves the earlier txs landed and
  the user can retry the rest. Requires explicit ``--yes`` in
  non-TTY contexts. ``AgentRegistry`` gains ``set_listed(bool)`` to
  match the TS ``AgentRegistryClient.setListed`` surface.
  Destructive ``deregisterAgent`` deliberately NOT exposed —
  reputation-forfeiting operations live behind a separate command
  with bigger guards.
- **`actp claim-code`** — regenerate a fresh claim code for dashboard
  linking. Reads AGIRAILS.md, resolves the agent's keystore (env or
  encrypted file), signs the
  ``agirails-claim-code:{agent_id}:{chain_name}:{timestamp}`` challenge
  via EIP-191 personal_sign, and exchanges it at
  ``agirails.app/api/v1/agents/claim-code`` for a 24h code. Supports
  Smart Wallet agents where the on-chain owner differs from the EOA
  signer (ships both as ``wallet`` + ``signer``). Output modes:
  default (human), ``--json`` (machine-readable), ``--quiet`` (pipe-
  friendly — emits only the code). Also added
  ``api.request_claim_code`` + ``RequestClaimCodeParams`` to the
  ``agirails_app`` API client for programmatic use.

### Deferred to 3.1+

- **`actp agent`** long-running provider daemon (on-chain INITIATED
  watcher). The TS equivalent already exists; `actp serve` covers the
  AIP-2.1 quote channel surface, so the on-chain watch loop ships
  separately once the hybrid subscription + bounded catch-up sweep
  is ported.
- **Full `ProviderPolicy` enforcement** — `services` /
  `min_deadline_seconds` / `max_requotes` (declared in the policy
  schema but not yet consumed by `evaluate_counter` — see
  `actp serve` section above for the precise scope).
- **Pydantic at HTTP/wire boundaries** — current builders + receipts
  use dataclasses. Pydantic gives nicer parse errors at the
  agirails.app / `actp serve` ingress; tracked as a 3.1 refactor.
- **Workflow-attested PyPI publish (PEP 740)** — Python equivalent of
  the npm OIDC + sigstore + SLSA provenance chain. Current 3.0.0
  ships through the standard `poetry publish` API-token path.

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
| 3.0.0 | 2026-05-20 | V3 mainnet / V4 Sepolia parity, full Smart Wallet path, AIP-2.1 quote channel, Web Receipts, 4 new CLI commands |
| 2.0.0 | 2024-12-25 | Initial v2 release with Python 3.9 support |
