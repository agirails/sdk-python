# Changelog

## 0.1.2
- Added delivery/dispute/cancel helpers, manual release/release_milestone, attestation anchoring, custom Web3 provider injection.
- Added event parsing helper (`parse_events`) and deadline/state errors.
- Added Agent Registry helpers (register/update endpoint/service types/active status + views).
- README expanded with new helpers; version bump to 0.1.2.

## 0.1.1
- Added EAS + EscrowVault ABIs and helpers (`verify_delivery_attestation`, `release_escrow_with_verification`, `get_escrow_status`).
- Added helper methods (`fund_transaction`, `submit_quote`) and validation for no-op transitions.
- Introduced granular errors (`InvalidStateTransitionError`, `RpcError`) and RPC error parsing.
- Added CI workflow with lint/test (ruff/black/mypy/pytest) and dev tooling configs.

## 0.1.0
- Initial MVP (createTransaction, linkEscrow, transitionState, getTransaction) using Web3.py.
