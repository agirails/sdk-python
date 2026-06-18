# Python SDK → TypeScript SDK Parity Gap Report

**Generated:** 2026-06-18 · **TS source of truth:** `@agirails/sdk@4.8.0` · **Python target:** `agirails@3.0.1`

**Totals:** 59 P0 · 162 P1 · 70 P2 · 12 py-extra · **303 gaps**

Severity: **P0** = protocol/correctness/security divergence (wrong hashes, signatures, state, on-chain behavior, security regression) · **P1** = feature/method/event/CLI present in TS but absent in Python · **P2** = polish/messaging/docs · **py-extra** = Python has something TS does not.

---

## Subsystem summary

| Subsystem | Status | P0 | P1 | P2 | py-extra |
|---|---|---|---|---|---|
| delivery-aip16 | missing | 10 | 10 | 0 | 0 |
| config-publish-sync | partial | 6 | 14 | 1 | 1 |
| protocol | partial | 5 | 9 | 4 | 1 |
| level1-agent | partial | 4 | 17 | 13 | 1 |
| adapters | partial | 4 | 11 | 6 | 1 |
| cli | partial | 4 | 10 | 4 | 1 |
| negotiation | partial | 4 | 9 | 1 | 0 |
| wallet | partial | 3 | 9 | 2 | 2 |
| storage | partial | 3 | 8 | 5 | 2 |
| runtime | partial | 3 | 8 | 1 | 0 |
| erc8004 | partial | 3 | 5 | 8 | 0 |
| errors-utils-types-builders-settle | partial | 3 | 4 | 2 | 1 |
| level0 (Simple-tier primitives: provide / request / Provi… | partial | 2 | 13 | 4 | 1 |
| cross-cutting: top-level coverage + index.ts public-expor… | partial | 2 | 8 | 3 | 0 |
| receipts | partial | 2 | 6 | 2 | 0 |
| server (provider server app, policy/policy_engine, QuoteC… | partial | 1 | 3 | 4 | 1 |
| core-client | partial | 0 | 11 | 8 | 0 |
| api-registry | partial | 0 | 7 | 2 | 0 |

---

## P0 — Protocol / Correctness / Security (59)

### delivery-aip16

- **EIP-712 DeliverySetup typed-data schema missing (field order + types must be byte-identical)** _[AIP-16]_ `missing-class`
  - TS DELIVERY_SETUP_TYPES_V1 has exactly these 12 fields in this IMMUTABLE order/type: version(uint8), txId(bytes32), chainId(uint256), kernelAddress(address), requesterAddress(address), signerAddress(address), buyerEphemeralPubkey(bytes32), acceptedChannels(string[]), expectedPrivacy(string), createdAt(uint64), expiresAt(uint64), smartWalletNonce(uint256). Domain = {name:'AGIRAILS Delivery', version:'1', chainId, verifyingContract:kernelAddress}. Any reordering/type drift produces a different typeHash → signatures unverifiable cross-SDK. Python has no equivalent.
  - TS: `sdk-js/src/delivery/eip712.ts:107-125, 70-79` · PY: `ABSENT`
  - Fix: Define the exact same ordered typed-data struct for eth_account.messages.encode_typed_data. Use domain name 'AGIRAILS Delivery', version '1', verifyingContract=kernelAddress. Verify against TS-produced fixtures.
- **EIP-712 DeliveryEnvelope typed-data schema missing** _[AIP-16]_ `missing-class`
  - TS DELIVERY_ENVELOPE_TYPES_V1 has 13 fields in IMMUTABLE order/type: version(uint8), txId(bytes32), chainId(uint256), kernelAddress(address), providerAddress(address), signerAddress(address), scheme(string), providerEphemeralPubkey(bytes32), nonce(bytes12), payloadHash(bytes32), tag(bytes16), createdAt(uint64), smartWalletNonce(uint256). bytes12/bytes16 sizes are unusual and must be encoded as fixed-size byte types, not bytes. Python absent.
  - TS: `sdk-js/src/delivery/eip712.ts:138-157` · PY: `ABSENT`
  - Fix: Mirror the ordered struct exactly; ensure bytes12 nonce and bytes16 tag are encoded as fixed-length byte fields. Test recovery against TS golden signatures.
- **smartWalletNonce (H4 fix) field + undefined→0 recovery normalization missing** _[AIP-16]_ `missing-param`
  - H4 fix appends smartWalletNonce(uint256) to BOTH setup and envelope EIP-712 schemas (default 0 reproduces legacy nonce-0 derivation). recoverSetupSigner/recoverEnvelopeSigner normalize `smartWalletNonce ?? 0` before verifyTypedData so pre-H4 payloads still recover. Builders validate it's a non-negative integer (BUILDER_INVALID_SMART_WALLET_NONCE). Without this field+normalization Python signs/recovers a 11/12-field struct → typeHash mismatch with TS.
  - TS: `sdk-js/src/delivery/eip712.ts:123,155,421-427,459-465; types.ts:301-324,504-520` · PY: `ABSENT`
  - Fix: Include smartWalletNonce in both structs (default 0), validate >=0 integer in builders, and normalize missing→0 before recovery to match TS exactly.
- **X25519 ECDH key primitives missing (generate/derive shared secret + low-order rejection)** _[AIP-16]_ `missing-method`
  - TS keys.ts: generateEphemeralKeyPair (32-byte pub/priv via @noble/curves x25519), deriveSharedSecret (X25519 per RFC7748, MUST reject all-zero/low-order-point shared secret as crypto_shared_secret_failed), pubkeyToHex/pubkeyFromHex (lowercase 0x + 64 hex, case-insensitive decode). Constants X25519_PUBLIC/PRIVATE/SHARED_SECRET_LENGTH=32. Python has no X25519 at all and no x25519 library dependency.
  - TS: `sdk-js/src/delivery/keys.ts:384-512,660-698` · PY: `ABSENT`
  - Fix: Use cryptography.hazmat.primitives.asymmetric.x25519 (X25519PrivateKey/PublicKey). Reproduce all-zero shared-secret rejection. Match @noble clamping/encoding (raw 32-byte little-endian).
- **HKDF-SHA256 session-key derivation missing (salt=txId, info='agirails-delivery-v1', L=32)** _[AIP-16]_ `missing-method`
  - deriveSessionKey runs HKDF-SHA256 with ikm=sharedSecret(32B), salt=txId raw bytes (decoded from 0x+64hex), info=UTF-8 'agirails-delivery-v1' (DELIVERY_HKDF_INFO_V1), digest sha256, keylen 32. The info string and salt-as-txId-bytes are protocol-critical: a Python differing on info/salt yields a different AES key and decryption fails. Python absent.
  - TS: `sdk-js/src/delivery/keys.ts:122,564-632` · PY: `ABSENT`
  - Fix: Use cryptography.hazmat.primitives.kdf.hkdf.HKDF(SHA256, length=32, salt=bytes.fromhex(txId[2:]), info=b'agirails-delivery-v1'). Add known-answer test vs TS.
- **AES-256-GCM encrypt/decrypt with AAD missing (nonce=12, tag=16)** _[AIP-16]_ `missing-method`
  - encryptBody/decryptBody use AES-256-GCM, 12-byte random nonce, 16-byte tag returned SEPARATELY (not appended to ciphertext). Optional AAD fed via setAAD before update; decrypt fails closed on AAD/tag mismatch (crypto_decrypt_failed). bodyHash=keccak256(bytes). Python absent. Tag-separation and nonce/tag byte lengths must match the wire format exactly.
  - TS: `sdk-js/src/delivery/crypto.ts:245-492,532-539` · PY: `ABSENT`
  - Fix: Use cryptography AESGCM(key).encrypt(nonce, data, aad) which appends the 16-byte tag — must split last 16 bytes into separate tag field to match TS wire layout. Use os.urandom(12) nonce. keccak via eth_hash.
- **H5 AAD binding (txId32||signerAddr20 = 52 bytes) missing** _[AIP-16]_ `missing-method`
  - buildEnvelopeAad builds AAD = txId raw 32 bytes || signerAddress raw 20 bytes (ENVELOPE_AAD_LENGTH=52), set into GCM on BOTH encrypt (buildEncrypted) and decrypt (decryptPayload). This binds ciphertext to txId+signer; a misrouted envelope fails the tag check. Byte layout/order is fixed (txId at [0..32), signer at [32..52)). Python absent — any deviation breaks cross-SDK decryption.
  - TS: `sdk-js/src/delivery/envelopeBuilder.ts:189-237,749,1029` · PY: `ABSENT`
  - Fix: Construct identical 52-byte AAD (txId bytes then signer bytes, case-insensitive hex decode) and pass to AESGCM as associated_data on both sides.
- **FIX-1 scheme-aware body encoding missing (public=plaintext JSON, encrypted=0x-hex ciphertext)** _[AIP-16]_ `behavior-diff`
  - public-v1: wire.body = JSON.stringify(payload) plaintext UTF-8 (NOT hex); payloadHash=keccak256(utf8Bytes(body)); verify path JSON.parse(wire.body) directly. encrypted: wire.body = '0x'+hex(ciphertext); payloadHash=keccak256(rawCiphertextBytes); verify hex-decodes first then hashes. payloadHash is computed over CIPHERTEXT (not plaintext) for encrypted. This asymmetry is required to match the Platform verifier byte-for-byte; getting it wrong → every envelope rejected with payload_hash_mismatch. Python absent.
  - TS: `sdk-js/src/delivery/envelopeBuilder.ts:581-600,754-760,888-918,1087-1100; types.ts:533-585` · PY: `ABSENT`
  - Fix: Implement exact scheme branch: public → body=json.dumps(payload) (match TS JSON.stringify whitespace: no spaces? note TS uses default JSON.stringify with NO spaces), hash utf8; encrypted → body='0x'+ciphertext.hex(), hash raw ciphertext bytes. Use the SAME JSON serializer settings as TS JSON.stringify (separators=(',',':')) for buyer round-trip.
- **Canonical-empty constants + scheme-consistency rule missing** _[AIP-16]_ `missing-class`
  - CANONICAL_EMPTY_BYTES32/12/16 ('0x'+'00'*N) used as required values for public-v1 envelopes (providerEphemeralPubkey=empty32, nonce=empty12, tag=empty16) and public setups (buyerEphemeralPubkey=empty32). validateSchemeConsistency rejects public-v1 with non-empty crypto fields AND encrypted with canonical-empty crypto fields. EIP-712 has no absent field so these zero sentinels are signed — must be byte-identical. Python absent.
  - TS: `sdk-js/src/delivery/types.ts:787-823; validate.ts:692-724` · PY: `ABSENT`
  - Fix: Define the three constants and port validate_scheme_consistency with identical error identifiers.
- **public-v1 body serializer must match TS JSON.stringify byte-for-byte** _[AIP-16]_ `behavior-diff`
  - For public-v1 the SIGNED payloadHash = keccak256(utf8Bytes(JSON.stringify(payload))) and wire.body is that exact string; buyer recovers via JSON.parse(wire.body). TS uses plain JSON.stringify (NOT canonicalJson) so key order is insertion order and there are NO spaces between tokens. Python json.dumps defaults to ', ' and ': ' separators (spaces) and would produce different bytes → payload_hash_mismatch and a buyer who reads a different string than was signed.
  - TS: `sdk-js/src/delivery/envelopeBuilder.ts:597-600` · PY: `ABSENT`
  - Fix: Use json.dumps(payload, separators=(',',':'), ensure_ascii=False) preserving insertion order (Python dicts are insertion-ordered) to match Node JSON.stringify exactly; add a cross-SDK fixture test.

### config-publish-sync

- **PUBLISH_METADATA_KEYS missing 'budget' — buyer budget leaks into configHash and on-chain/IPFS artifacts** _[AIP-18]_ `security-diff`
  - TS strips 'budget' from frontmatter before hashing (PUBLISH_METADATA_KEYS line 73, AIP-18 DEC-2: budget is a PRIVATE operational cap that must never appear in any hashed/published artifact). Python's PUBLISH_METADATA_KEYS (agirailsmd.py:66-75) omits 'budget'. Consequence: any AGIRAILS.md carrying a top-level 'budget' field produces a DIFFERENT configHash in Python than TS (canonicalization includes budget), AND the raw budget value is hashed and would be published on-chain/to IPFS — a privacy regression and a cross-SDK hash divergence (same file, different configHash → integrity check failures, diff false-positives).
  - TS: `config/agirailsmd.ts:58-74` · PY: `config/agirailsmd.py:66-75`
  - Fix: Add 'budget' and 'claim_code' to Python PUBLISH_METADATA_KEYS to match TS exactly.
- **PUBLISH_METADATA_KEYS missing 'claim_code' — hash divergence vs TS and web** _[AIP-18]_ `security-diff`
  - TS strips 'claim_code' (draft-adoption code embedded by web owner doc; mirrored in web lib/ipfs/config-hash.ts) before hashing. Python omits it. Any file containing claim_code hashes differently in Python vs TS vs web canonical → cross-SDK and SDK-vs-web configHash mismatch, breaking diff/pull integrity verification and on-chain match.
  - TS: `config/agirailsmd.ts:66-69` · PY: `config/agirailsmd.py:66-75`
  - Fix: Add 'claim_code' to Python PUBLISH_METADATA_KEYS (alongside budget).
- **Missing AGIRAILS.md size bound (MAX_AGIRAILSMD_BYTES=256000) — YAML resource-exhaustion DoS** `security-diff`
  - TS parseAgirailsMd enforces a 256KB hard cap before any YAML/regex work (Apex audit FIND-016) because the parser runs in untrusted contexts (CI jobs, cloned repos, PR workspaces). Python parse_agirails_md (agirailsmd.py:168-206) has no size bound — an attacker-controlled AGIRAILS.md can drive YAML resource exhaustion via deep nesting / anchors.
  - TS: `config/agirailsmd.ts:108,128-136` · PY: `config/agirailsmd.py:168-180`
  - Fix: Add a 256000-byte length check at the top of parse_agirails_md that raises ValueError before yaml.safe_load.
- **Missing YAML alias-count cap (FRONTMATTER_MAX_ALIAS_COUNT=10)** `security-diff`
  - TS pins yaml maxAliasCount to 10 so a malicious file planting aliases trips early instead of walking an expansion graph (billion-laughs class). Python uses yaml.safe_load with PyYAML defaults (no alias-count cap; PyYAML resolves aliases without a low ceiling), leaving the alias-expansion DoS vector open.
  - TS: `config/agirailsmd.ts:118,157` · PY: `config/agirailsmd.py:195`
  - Fix: Use a constrained YAML loader or pre-scan for excessive '*'/'&' anchors; reject files exceeding ~10 aliases before full parse.
- **Pay-only short-circuit missing in extract_registration_params and publish_config (budget can leak to IPFS)** _[AIP-18]_ `security-diff`
  - TS extractRegistrationParams returns empty serviceDescriptors for intent==='pay' (publishPipeline.ts:147-156), and publishAgirailsMd skips the IPFS/Arweave upload entirely when intent!=='pay' guard fails (publishPipeline.ts:345-410) so a buyer's file (which may carry private budget) never leaves the machine. Python extract_registration_params (publish_pipeline.py:93-179) has NO intent check — it raises ValueError if a pay-only file has no services, and Python publish_config ALWAYS uploads content to IPFS/proxy regardless of intent (publish_pipeline.py:294-333). Combined with the missing budget-strip, a pay-only AGIRAILS.md is uploaded to IPFS/proxy WITH the budget in it.
  - TS: `config/publishPipeline.ts:147-156,345-410` · PY: `config/publish_pipeline.py:93-179,294-333`
  - Fix: Add intent=='pay' short-circuit: return ([] descriptors / fallback endpoint) in extract_registration_params and skip upload in publish_config; never send a pay-only file over the network.
- **pull_config: no CID validation before IPFS fetch** `security-diff`
  - TS fetchFromIPFS calls validateCID(cid,'onChainCID') before hitting any gateway (syncOperations.ts:179-180) to reject malformed/injection CIDs (e.g. path traversal into gateway URLs). Python fetch_from_ipfs (sync_operations.py:175-207) interpolates the on-chain CID straight into the gateway URL with no validation, so a malicious/garbage on-chain CID is fetched unchecked (SSRF/URL-injection surface).
  - TS: `config/syncOperations.ts:178-202` · PY: `config/sync_operations.py:175-207`
  - Fix: Add a validate_cid() call (base58/base32 CIDv0/v1 format check) before constructing the gateway URL, mirroring utils/validation.validateCID.

### protocol

- **ProofGenerator uses SHA256, TS uses keccak256 for content hashing** _[AIP-4]_ `behavior-diff`
  - TS ProofGenerator.hashContent (ProofGenerator.ts:86-91) hashes deliverable content with keccak256 per Yellow Paper §11.4.1 (keccak256(toUtf8Bytes(content))). Python ProofGenerator defaults to hash_algorithm='sha256' (proofs.py:110) and _hash() uses hashlib.new(self._algorithm) (proofs.py:121-124). Module-level hash_service_input (proofs.py:426) and hash_service_output (proofs.py:457) are hardcoded hashlib.sha256. Same content therefore produces a DIFFERENT contentHash/serviceHash in Python vs TS — cross-SDK delivery proofs, on-chain serviceHash comparisons, and EAS resultHash all diverge. This breaks any TS<->Python interop on delivery verification.
  - TS: `protocol/ProofGenerator.ts:86-91` · PY: `protocol/proofs.py:110,121-124,426,457`
  - Fix: Change ProofGenerator default to keccak256 (eth_utils.keccak) and make hash_service_input/output use keccak256(utf8) to match TS exactly. Remove the sha256 default.
- **EIP-712 domain name/version mismatch (ACTP/1 vs AGIRAILS)** `security-diff`
  - TS MessageSigner forces EIP-712 domain name='AGIRAILS', version='1.0' (MessageSigner.ts:137-142); the AIP-4 delivery-proof builders use name='AGIRAILS', version='1' (DeliveryProofBuilder.ts:552-555, QuoteBuilder.ts:264,310). Python MessageSigner defaults to domain_name='ACTP', domain_version='1' (messages.py:208-209) and EIP712Domain dataclass defaults name='ACTP', version='1' (types/message.py:47-48). The EIP-712 domainSeparator = hash(name,version,chainId,verifyingContract); a different name/version yields a different domainSeparator, so signatures produced by Python will NOT verify against TS-recovered addresses and vice versa for the same logical message. Wrong-signature/canonicalization divergence.
  - TS: `protocol/MessageSigner.ts:137-142; builders/DeliveryProofBuilder.ts:552-555` · PY: `protocol/messages.py:208-209; types/message.py:47-48`
  - Fix: Set Python MessageSigner default domain to name='AGIRAILS'. For AIP-4 delivery-proof signing use version='1' (match DeliveryProofBuilder); generic ACTPMessage path uses version='1.0' in TS. Add cross-SDK signature golden-vector test.
- **AgentRegistry.set_listed() calls a function absent from bundled Python ABI** `behavior-diff`
  - Python AgentRegistry.set_listed (agent_registry.py:691-709) calls self._contract.functions.setListed(listed), but bundled abis/agent_registry.json does NOT contain setListed (verified function list lacks setListed/publishConfig/MAX_CID_LENGTH). web3.py raises ABIFunctionNotFound/MismatchedABI at call time. Listing toggle is broken in Python. TS does not expose setListed as a wrapper but its abi/AgentRegistry.json DOES include setListed+publishConfig+MAX_CID_LENGTH+ConfigPublished+ListingChanged.
  - TS: `abi/AgentRegistry.json (setListed,publishConfig present)` · PY: `protocol/agent_registry.py:691-709 + abis/agent_registry.json (setListed ABSENT)`
  - Fix: Regenerate abis/agent_registry.json from current AgentRegistry v2 so it includes setListed, publishConfig, MAX_CID_LENGTH, ConfigPublished, ListingChanged, and the full 14-field agents struct (configHash, configCID, listed).
- **Stale Python AgentRegistry ABI: agents() struct truncated, missing config fields/events** `missing-method`
  - TS abi/AgentRegistry.json agents(address) returns a 14-field struct including bytes32 configHash, string configCID, bool listed. Python abis/agent_registry.json agents(address) returns only 11 fields and omits configHash/configCID/listed; it also lacks publishConfig(string,bytes32), setListed(bool), MAX_CID_LENGTH(), and events ConfigPublished(address,string,bytes32) + ListingChanged(address,bool). AgentProfile.from_tuple (agent_registry.py:188-208) decodes 12 fields and would mis-decode/throw against a current getAgent return that includes publish/listing fields. Any AGIRAILS.md SOT publish/listing read path is unsupported in Python.
  - TS: `abi/AgentRegistry.json` · PY: `abis/agent_registry.json; protocol/agent_registry.py:188-208`
  - Fix: Sync the ABI and extend AgentProfile + from_tuple to include config_hash, config_cid, listed. Add publish_config() wrapper and ConfigPublished/ListingChanged event parsing.
- **EAS verifyDeliveryAttestation decodes 2 schemas; TS decodes 3 (incl. divergent legacy AIP-4)** _[AIP-4]_ `behavior-diff`
  - TS verifyDeliveryAttestation (EASHelper.ts:237-337) tries 3 schemas in order: AIP-6 5-field [bytes32,string,bytes32,uint256,uint256] (with testTimestamp), AIP-6 4-field [bytes32,string,bytes32,uint256], then legacy AIP-4 6-field [bytes32,bytes32,uint256,string,uint256,string] (txId,contentHash,timestamp,deliveryUrl,size,mimeType). Python _decode_delivery_data (eas.py:510-569) tries only AIP-6 4-field then AIP-4 [bytes32,bytes32,address,uint64] (txId,outputHash,provider,timestamp) — a DIFFERENT legacy schema than TS. Python cannot decode the TS 5-field test schema nor the TS legacy 6-field schema; the SDKs disagree on what 'AIP-4 legacy' means. Worse, TS attestDeliveryProof (EASHelper.ts:92-103) ENCODES the 6-field legacy schema, which Python's decoder cannot read -> cross-SDK attestation verification fails.
  - TS: `protocol/EASHelper.ts:92-103,237-337` · PY: `protocol/eas.py:453-569`
  - Fix: Align schema set: add AIP-6 5-field variant and the TS legacy 6-field [bytes32,bytes32,uint256,string,uint256,string] schema to Python's decode fallback; pick one canonical legacy AIP-4 layout across both SDKs. Add golden encode/decode cross-test.

### adapters

- **Python X402Adapter is the legacy custom x-payment-* flow, not real x402 v2** `behavior-diff`
  - TS X402Adapter.ts (4.x) is a rewrite around @x402/fetch + @x402/evm: buyer signs EIP-3009 authorization or Permit2 witness off-chain, facilitator submits on-chain and pays gas (buyer gasless), Smart Wallet uses Permit2 (ERC-1271/ERC-6492), settlement proven by decoded payment-response header (proof-missing error, payer-replay check, canonical-USDC asset allowlist, dollar cap, MEV cap, allowedHosts opt-in). Python x402_adapter.py implements the OLD custom HTTP scheme the TS header calls never real x402: parses X-Payment-* response headers, direct transfer_fn or X402Relay payWithFee 1% fee, retries with X-Payment-Tx-Id proof. Wire-incompatible with any real x402 v2 seller.
  - TS: `sdk-js/src/adapters/X402Adapter.ts:1-870` · PY: `python-sdk-v2/src/agirails/adapters/x402_adapter.py:222-499`
  - Fix: Rewrite Python X402Adapter to x402 v2: EIP-3009/Permit2 signing via signTypedData, facilitator submission, payment-response decode + settlement-proof validation, payer-replay check, USDC asset allowlist, maxAmountPerTx, maxAuthorizationValidSec, allowedHosts/paymentMethod opt-in; drop X-Payment-* + X402Relay.
- **X402Adapter has no opt-in safety gate; will auto-pay any HTTPS URL** `security-diff`
  - TS validate() refuses an HTTPS target unless metadata.paymentMethod is x402 or host in allowedHosts, plus enforces maxAmountPerTx, canonical-USDC asset allowlist (rejects mismatched-decimal tokens bypassing the cap), MEV auth cap. Python validate() only checks HTTPS scheme + embedded credentials. No opt-in gate, no amount cap, no asset allowlist, no MEV clamp. A Python caller hitting a malicious 402 endpoint can be charged an arbitrary amount in an arbitrary token.
  - TS: `sdk-js/src/adapters/X402Adapter.ts:322-358,521-588` · PY: `python-sdk-v2/src/agirails/adapters/x402_adapter.py:294-314`
  - Fix: Add opt-in gate, maxAmountPerTx cap, USDC asset allowlist, auth-validity MEV clamp (folds into the v2 rewrite).
- **parse_deadline numeric/relative semantics diverge (wrong on-chain deadlines)** `behavior-diff`
  - TS parseDeadline treats any numeric deadline as a literal Unix timestamp and accepts only +Nh/+Nd strings, 10-year bound (MAX 87600h/3650d). Python parse_deadline re-interprets small ints (<=168 to now+N*3600 hours), accepts bare 1h/7d and ISO dates, MAX 168h/30d. A real near-future Unix timestamp <=168 passed to Python is mis-read as N hours from now; TS +24h rejected by Python and Python 24h by TS; max bound differs.
  - TS: `sdk-js/src/adapters/BaseAdapter.ts:62-68,271-309` · PY: `python-sdk-v2/src/agirails/adapters/base.py:29-30,136-230`
  - Fix: Align Python: numeric to literal Unix timestamp pass-through; accept only +Nh/+Nd; MAX 87600h/3650d.
- **StandardAdapter.release_escrow does not require attestation when EAS available** `security-diff`
  - TS releaseEscrow enforces MANDATORY attestation: if runtime.isAttestationRequired() or an EASHelper present and caller did not pass attestationParams it THROWS; also verifies attestation txId matches escrow txId (anti-replay). Python release_escrow verifies only when attestation_uid explicitly supplied AND eas_helper exists; never throws when attestation required but uid omitted, no isAttestationRequired gate, no txId-match check. A Python caller can release escrow without validating any delivery attestation.
  - TS: `sdk-js/src/adapters/StandardAdapter.ts:362-428` · PY: `python-sdk-v2/src/agirails/adapters/standard.py:354-410`
  - Fix: Add mandatory-attestation gate: detect is_attestation_required()/eas_helper, raise if uid missing, verify attestation txId equals escrow txId before release.

### negotiation

- **verifyQuoteHashOnChain missing (on-chain quote anchoring cross-check)** _[AIP-2.1]_ `missing-method`
  - TS verifyQuoteHashOnChain cross-references an off-chain QuoteMessage against the hash the provider committed on-chain at QUOTED. Two matchers: 'aip2' = QuoteBuilder.computeHash canonical EIP-712 hash; 'legacy' = keccak256(toUtf8Bytes(JSON.stringify({txId, providerIdealPrice, actualEscrow, provider}))). Returns VerifySource tag + canonicalHash/legacyHash. BuyerOrchestrator uses this on counter-round 0 as the anchored MITM defense (substitution detection). Python has no equivalent, so a Python buyer running channel negotiation would have NO on-chain anchor check — a P0 security/correctness divergence if/when the buyer channel path is ported without it.
  - TS: `sdk-js/src/negotiation/verifyQuoteOnChain.ts:61-101` · PY: `ABSENT`
  - Fix: Port verify_quote_hash_on_chain with BOTH matchers byte-for-byte: the legacy hash MUST be keccak256(utf8(json.dumps({txId, providerIdealPrice, actualEscrow, provider}))) with identical key ordering and no whitespace differences, or hashes will mismatch cross-SDK. The canonical matcher must reuse the ported QuoteBuilder.compute_hash.
- **ProviderPolicy lives in server/ with divergent shape and weaker counter enforcement** _[AIP-2.1]_ `behavior-diff`
  - TS negotiation/ProviderPolicy.ts: human-amount fields (min_acceptable.amount/ideal_price.amount as floats), full evaluate(IncomingRequest) checking service_not_offered/currency_mismatch/unit_mismatch/max_price_below_floor/deadline_too_tight, and evaluateCounter enforcing max_requotes + concede math with formatFromBaseUnits messages. Python server/policy.py uses base-unit-int fields (min_acceptable_amount/ideal_amount) and server/policy_engine.evaluate_counter EXPLICITLY does NOT enforce max_requotes (docstring: 'tracked by the orchestrator state machine, out of scope') and does NOT re-check currency/unit/service/deadline on counters. So a Python provider in concede mode has no max_requotes guard — a misbehaving buyer can drive unbounded re-quotes; the defense-in-depth cap TS provides (ProviderPolicy.ts:332-338) is absent. Also the concede tie-break differs: Python accepts when next<=counter (server/policy_engine.py:140-148); TS evaluateCounter has no such accept-instead branch — it always returns requote when in-band — a behavioral divergence in the verdict.
  - TS: `sdk-js/src/negotiation/ProviderPolicy.ts:166-366` · PY: `src/agirails/server/policy.py:60-180 + server/policy_engine.py:57-160`
  - Fix: Port ProviderPolicyEngine into negotiation/ with the full TS field shape (human amounts, services/currency/unit/deadline checks in evaluate, max_requotes enforcement + concede math in evaluate_counter) and reconcile the 'accept-instead-of-requote when concession<=counter' divergence against the TS verdict (TS returns requote; pick one canonical behavior).
- **BuyerOrchestrator on-chain serviceDescription differs: keccak routing key vs JSON blob** _[AIP-2.1]_ `behavior-diff`
  - TS createTransaction passes serviceDescription = keccak256(toUtf8Bytes(policy.task)) — the bytes32 routing key matching what Agent.provide(name) registers in handlersByHash (BuyerOrchestrator.ts:444-449 explicitly fixed this in 4.0.0: pre-4.0.0 it passed JSON.stringify({service,session}) which BlockchainRuntime hashed wholesale so the on-chain serviceHash could NEVER match keccak256(taskName) and provider routing silently missed). Python still passes service_description = json.dumps({service, session}) (buyer_orchestrator.py:372-377) — the EXACT pre-4.0.0 bug. A Python buyer's on-chain serviceHash will not match a provider's registered handler hash, so provider-side routing silently misses.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:444-449` · PY: `src/agirails/negotiation/buyer_orchestrator.py:372-377`
  - Fix: Change Python createTransaction to pass keccak256(utf8(policy.task)) as service_description (use the SDK's keccak helper). Drop the JSON blob; session correlation now uses tx_id only. This is a protocol-correctness fix independent of the channel port.
- **Re-quote MITM guards (provider/maxPrice anchoring) missing in Python buyer path** _[AIP-2.1]_ `security-diff`
  - TS _runNegotiationRound on subsequent re-quotes guards two attacker mutations the channel EIP-712 verify cannot catch: (a) provider DID switched mid-negotiation -> CANCELLED; (b) maxPrice inflated mid-negotiation -> CANCELLED (P0 audit finding: without it the accept-if-affordable last-round branch would compare against the attacker's inflated max and commit above policy ceiling). Both anchor to the FIRST quote which cross-checked the on-chain hash on round 0. Python has no buyer re-quote path at all, so when ported these guards MUST be included or the buyer is exploitable.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:802-844` · PY: `ABSENT`
  - Fix: When porting the buyer counter loop, replicate the round-0 on-chain hash verify AND the round>0 provider-equality + maxPrice-equality anchoring to the first quote; on mismatch transition CANCELLED and record an error round.

### level1-agent

- **Pricing margin formula diverges (markup vs markdown) — different on-chain prices** `behavior-diff`
  - TS calculatePrice computes price = cost / (1 - margin) (margin = share of FINAL price); Python calculate_target_price computes price = cost * (1 + margin) (margin = markup over cost). For cost=$10, margin=0.40: TS = $16.67, Python = $14.00. These are not the same number, so a Python provider and a TS provider with identical config quote/accept at different thresholds. Counter-offer and accept/reject decisions therefore diverge across SDKs for the same job, and the documented invariant comments in both files describe the TS formula.
  - TS: `sdk-js/src/level1/pricing/PriceCalculator.ts:78-79` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:103`
  - Fix: Change Python to price = cost / (1 - clamp(margin,0,1)); clamp margin to [0,1] like TS Math.max(0,Math.min(1,margin)).
- **DEFAULT_PRICING_STRATEGY defaults differ (margin 0.20 vs 0.40, below_price reject vs counter-offer, maxNegotiationRounds missing)** `behavior-diff`
  - TS DEFAULT_PRICING_STRATEGY: margin 0.4, behavior.belowPrice 'counter-offer', belowCost 'reject', maxNegotiationRounds 10. Python DEFAULT_PRICING_STRATEGY: margin 0.20, below_price 'reject', below_cost 'reject'. Combined with the formula gap, a service with no explicit pricing prices and decides completely differently in Python: it rejects below-target jobs that TS would counter-offer, and uses a lower margin. This is a protocol-economic divergence for the zero-config default path that both Agents fall back to.
  - TS: `sdk-js/src/level1/pricing/PriceCalculator.ts:233-245` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:141-147`
  - Fix: Set Python default margin=0.40, below_price='counter-offer', below_cost='reject', add max_negotiation_rounds=10 (and a behavior structure to match).
- **PricingStrategy decision boundaries diverge (max-price reject, margin reported as markup, no minimum/maximum on PriceCalculation.price clamp)** `behavior-diff`
  - TS clamps price between strategy.minimum (default 0.05) and strategy.maximum (default 10000) BEFORE the decision, and decides accept when budget>=price, below-price-behavior when cost<=budget<price, below-cost-behavior when budget<cost. Python instead: rejects when offered_price > max_price (TS never rejects for being TOO generous), computes margin_percent as actual_profit/cost*100 (markup) vs TS profit/price (share of price), has no default minimum/maximum and never clamps the target price by a default minimum 0.05. The decision band and reported margin_percent therefore differ in sign and magnitude, and a high-budget job is wrongly rejected by Python.
  - TS: `sdk-js/src/level1/pricing/PriceCalculator.ts:82-110` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:191-220`
  - Fix: Mirror TS: clamp price to [minimum 0.05, maximum 10000]; never reject for budget above max; decision = accept if budget>=price else belowPrice if budget>=cost else belowCost; marginPercent = profit/price.
- **calculate_price never estimates per-unit cost (units defaults to 0; no estimateUnits)** `missing-method`
  - TS calculatePrice internally calls estimateUnits(job, perUnit.unit) to count words/tokens/chars/images/minutes from job.input, so per-unit pricing actually applies. Python calculate_price takes units=0 by default and the Agent calls it with no units (agent.py:796 calculate_price(pricing, job)), so per_unit cost is ALWAYS zero — a service priced per word/token charges only its base. Cost and therefore accept/reject decisions are wrong for any per-unit strategy.
  - TS: `sdk-js/src/level1/pricing/PriceCalculator.ts:61-64,140-198` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:150-154,177-178`
  - Fix: Port estimateUnits (word/token/character/image/minute/request branches) and call it inside calculate_price when cost.per_unit is set; have Agent pass the result.

### cli

- **`actp test` runs a mock simulation instead of live Sentinel onboarding** _[AIP-16]_ `behavior-diff`
  - TS test.ts (4.0.0) hits the deployed Sentinel on Base Sepolia via runRequest, walks the real state machine, settles real escrow, wires the AIP-16 RelayDeliveryChannel (expectedKernelAddress/expectedChainId/deliveryPrivacy:'public'), prints the channel reflection (with local-fallback), renders the V3 framed receipt, prints receiptUrl, and offers an X share. Python test.py is the pre-4.0.0 MOCK earning loop: parses AGIRAILS.md, runs MockRuntime create->link->IN_PROGRESS->DELIVERED->advance_time->release, renders a V2 receipt. No live network, no AIP-16, no settlement on-chain, no receiptUrl, no share. The flagged 'AIP-16 delivery wired into actp test' is absent.
  - TS: `sdk-js/src/cli/commands/test.ts:136-315` · PY: `python-sdk-v2/src/agirails/cli/commands/test.py:78-226`
  - Fix: Rewrite test.py to call run_request against resolveAgent('sentinel','base-sepolia') with a RelayDeliveryChannel, render V3 receipt, print receipt_url. Depends on AIP-16 delivery port + run_request delivery surface + renderReceiptV3 + resolveAgent + sentinelReflections.
- **run_request missing entire AIP-16 delivery surface** _[AIP-16]_ `missing-param`
  - TS runRequest accepts deliveryChannel, expectedKernelAddress, expectedChainId, deliveryPrivacy, envelopeWaitMs, smartWalletNonce and implements signed DeliverySetupBuilder POST (EIP-712), envelope subscription, encrypted (x25519-aes256gcm) + public-v1 decode, grace-period polling, and sets deliveryError. Python run_request has none of these params and no delivery logic (header explicitly states 'Scope (3.0.0): poll-only'). A buyer using Python never posts a setup envelope nor receives the cryptographically-bound delivery payload — it only reads legacy tx.delivery_proof.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:116-200,371-535,601-689` · PY: `python-sdk-v2/src/agirails/cli/lib/run_request.py:105-247`
  - Fix: Port the delivery module + DeliverySetupBuilder/DeliveryEnvelopeBuilder/generateEphemeralKeyPair to Python, then add the 6 kwargs + setup-POST + subscribe + decode blocks to run_request.
- **`actp init` does not generate wallet/keystore or ACTP_KEY_PASSWORD** _[AIP-18]_ `behavior-diff`
  - TS init.ts mints an encrypted EOA keystore, computes the Smart Wallet address (wallet:auto), and runs ensureKeyPassword (generateStrongPassword 24-byte base64 -> ACTP_KEY_PASSWORD persisted to .env chmod 0600 + .gitignore, fingerprint logged). Python init.py only writes a config.json with a default/random address — no keystore, no password gen, no Smart Wallet. A Python-initialized agent on testnet/mainnet has no signer and cannot transact gaslessly; the security model (encrypted keystore, never logging the raw password) is not implemented in the CLI init path.
  - TS: `sdk-js/src/cli/commands/init.ts:62-240,442-472` · PY: `python-sdk-v2/src/agirails/cli/commands/init.py:34-104`
  - Fix: Port generateWallet/computeSmartWalletInit + ensureKeyPassword into init.py with --wallet auto|eoa support.
- **publish.py has no AIP-18 buyer-link / pay-only path** _[AIP-18]_ `missing-method`
  - TS publish.ts uses the V4 parser and branches on intent: pay-only buyers LINK (saveBuyerLink writes buyer-link.json — the DEC-8 gas-sponsorship gate marker so the auto-wallet grants gasless tx), skip IPFS upload + on-chain registration, auto-mint test USDC to the buyer Smart Wallet (idempotent), and sync intent+services_needed to web (so pay-only agents are hidden from public discovery). It also validates intent vs services/servicesNeeded. Python publish.py uses the v3 agirailsmd parser, has no buyer-link.json write, no pay-only short-circuit, no buyer-mint, no intent validation, no intent web-sync. A Python pay-only buyer cannot be gas-sponsored and `actp publish` would try to register them as a provider.
  - TS: `sdk-js/src/cli/commands/publish.ts:255-290,459-661,755-911,1141-1160` · PY: `python-sdk-v2/src/agirails/cli/commands/publish.py:1-600`
  - Fix: Port config/buyerLink.saveBuyerLink + V4 parser usage + pay-only branch (skip upload/registration, mint buyer USDC, sync intent/services_needed) into publish.py.

### runtime

- **BlockchainRuntime.getTransactionsByProvider missing in Python** `missing-method`
  - TS PRD-5.2 bounded sweep; Python lacks it; level1/agent.py:643 calls it unconditionally so AttributeError swallowed and provider gets ZERO jobs on testnet/mainnet.
  - TS: `BlockchainRuntime.ts:721-770` · PY: `blockchain_runtime.py ABSENT`
- **submitQuote AIP-2.1 canonical quote-hash missing in Python runtimes+kernel** _[AIP-2]_ `missing-method`
  - TS canonical keccak256 via QuoteBuilder.computeHash, only path to QUOTED; Python has no submit_quote/quoteHash so QUOTED hash unreconstructable by buyers.
  - TS: `MockRuntime.ts:862-890; BlockchainRuntime.ts:600-610` · PY: `ABSENT`
- **MockRuntime CANCELLED no escrow refund / no EscrowRefunded in Python** `behavior-diff`
  - TS refunds requester, zeroes escrow, emits EscrowRefunded; Python only updates state, stranding requester balance.
  - TS: `MockRuntime.ts:734-773` · PY: `mock_runtime.py:425-463`

### wallet

- **StandardAdapter.create_transaction is NOT routed through Smart Wallet in Python (wrong msg.sender for Tier-1)** _[AIP-12]_ `missing-method`
  - TS StandardAdapter.createTransaction routes through walletProvider.createACTPTransaction when a Smart Wallet is wired, submitting createTransaction as a UserOp where msg.sender == Smart Wallet == requester (passes kernel _requesterCheck) and pre-computing txId from the ACTP nonce inside the DualNonceManager mutex. Python standard.py.create_transaction unconditionally calls self._runtime.create_transaction via the EOA signer. For a Tier-1 user the Smart Wallet is the requester but the EOA is msg.sender, so the kernel _requesterCheck reverts or records the wrong requester. AutoWalletProvider.create_actp_transaction does not exist in Python and standard.py has no routing branch.
  - TS: `sdk-js/src/adapters/StandardAdapter.ts:177-194; sdk-js/src/wallet/AutoWalletProvider.ts:446-483` · PY: `python-sdk-v2/src/agirails/adapters/standard.py:219-230; create_actp_transaction ABSENT in auto_wallet_provider.py`
  - Fix: Port AutoWalletProvider.createACTPTransaction (single-call createTransaction UserOp inside nonce_manager.enqueue(increments_actp_nonce=True), pre-compute txId via compute_transaction_id), add CreateACTPTransactionParams/Result, add Smart-Wallet routing branch to standard.py.create_transaction.
- **AutoWalletProvider.pay_actp_batched missing ACTP nonce-collision retry loop** _[AIP-12]_ `behavior-diff`
  - TS payACTPBatched loops up to MAX_NONCE_BUMPS=12: on a bundler revert matching Escrow ID already used (plain text or ABI-hex 457363726f7720494420616c72656164792075736564) it increments candidateNonce, re-reads the EntryPoint nonce, rebuilds the batch, retries; on success pins setCachedActpNonce(candidate+1). Python pay_actp_batched builds and submits once with no collision detection, no nonce bump, no EntryPoint re-read, so it permanently fails under duplicate-nonce conditions and never re-aligns the cached ACTP nonce.
  - TS: `sdk-js/src/wallet/AutoWalletProvider.ts:366-437` · PY: `python-sdk-v2/src/agirails/wallet/auto_wallet_provider.py:313-369`
  - Fix: Implement the 12-bump retry loop: catch BundlerRPCError, match revert string/hex, bump candidate nonce, call public read_entry_point_nonce(), set_cached_actp_nonce(candidate+1) on success. Requires the DualNonceManager additions below.
- **DualNonceManager missing event-derivation nonce fallback + adaptive getLogs chunking (falls back to 0)** `behavior-diff`
  - When ACTPKernel.requesterNonces is unavailable, TS _readActpNonce derives the ACTP nonce from on-chain TransactionCreated logs: binary-search the deployment block (with hint validation), count requester-filtered logs in adaptive chunks (10000 to 1000, halving on range errors), nonce = log count, 0n only as last resort. Python _read_actp_nonce on any exception silently sets nonce = 0. A wrong nonce changes the deterministic txId keccak256(requester,provider,amount,serviceHash,nonce) and the linkEscrow escrowId, so on a deployment lacking requesterNonces Python computes the wrong txId. This is the changelog adaptive getLogs chunking robustness item.
  - TS: `sdk-js/src/wallet/aa/DualNonceManager.ts:164-341` · PY: `python-sdk-v2/src/agirails/wallet/aa/dual_nonce_manager.py:186-205`
  - Fix: Port findContractDeploymentBlock (binary search + hint validation) and countRequesterTransactionCreatedEvents (chunked w3.eth.get_logs 10k to 1k adaptive halving, TransactionCreated topic + zero-padded requester topic); derive nonce = log count; keep 0 only as last resort.

### erc8004

- **giveFeedback ABI/selector divergence — Python writes to wrong/non-existent function on canonical ERC-8004 registry** `security-diff`
  - TS canonical giveFeedback signature is `giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)` (8 params; value=int128; tag1=actp_settled, tag2=capability). Python ABI declares `giveFeedback(uint256 agentId, int8 value, bytes32 feedbackHash, string tag1)` (4 params, reordered, value=int8). These produce completely different 4-byte function selectors, so on the SAME deployed Reputation Registry the Python call either reverts (no such selector) or could collide with an unintended function. Even the encoded args differ (int8 vs int128, missing valueDecimals/tag2/endpoint/feedbackURI). Python also drops capability/endpoint/feedbackURI/reason entirely. This is a protocol-level write divergence that corrupts on-chain reputation reporting.
  - TS: `sdk-js/src/types/erc8004.ts:254 ; sdk-js/src/erc8004/ReputationReporter.ts:275-285 ; test sdk-js/src/erc8004/ReputationReporter.test.ts:85-95` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:91-103 ; python-sdk-v2/src/agirails/erc8004/reputation_reporter.py:216-221`
  - Fix: Replace Python ERC8004_REPUTATION_ABI giveFeedback with the 8-param canonical form (int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash) and thread capability/endpoint/feedbackURI/reason through report_settlement/report_dispute matching TS.
- **getSummary ABI/selector + return-shape divergence** `security-diff`
  - TS getSummary is `getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) view returns (uint256 count, int256 summaryValue, uint8 summaryValueDecimals)` and getAgentReputation calls it with ([], tag1, '') returning {count, score}. Python declares `getSummary(uint256 agentId, string tag1) view returns (uint256 positive, uint256 negative, uint256 total)` and returns {positive, negative, total}. Different selector (missing address[] and second string), different argument encoding, and different decoded semantics (TS score=int256 summaryValue vs PY positive/negative/total uints). Reads against the real registry will fail to decode or return wrong values.
  - TS: `sdk-js/src/types/erc8004.ts:257 ; sdk-js/src/erc8004/ReputationReporter.ts:383-393` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:104-117 ; python-sdk-v2/src/agirails/erc8004/reputation_reporter.py:170-178`
  - Fix: Align Python getSummary ABI to (uint256,address[],string,string)->(uint256,int256,uint8); call with ([], tag1 or '', '') and return {count, score} matching TS getAgentReputation.
- **Bridge network not threaded from client mode — testnet client resolves agents against MAINNET registry** `behavior-diff`
  - TS ACTPClient derives erc8004Network from config.mode (testnet->'base-sepolia', else->'base') and constructs both ERC8004Bridge and ReputationReporter with that network and rpcUrl (ACTPClient.ts:1047-1058). Python client.py auto-registers `ERC8004Bridge()` with NO config, so ERC8004BridgeConfig defaults to network='base-mainnet' and the public mainnet RPC — unconditionally. A Python testnet/mock client therefore queries the MAINNET Identity Registry (0x8004A169...) and a mainnet RPC when resolving agent IDs for payment routing, producing wrong owner/wallet (or not-found) for testnet agents. ReputationReporter is also never auto-wired in the Python client at all.
  - TS: `sdk-js/src/ACTPClient.ts:1046-1058` · PY: `python-sdk-v2/src/agirails/client.py:201-208`
  - Fix: In client._try_register_optional_adapters / create(), map client mode->ERC8004Network (testnet->base-sepolia, mainnet->base-mainnet) and pass ERC8004BridgeConfig(network=..., rpc_url=...) into ERC8004Bridge(); also instantiate a ReputationReporter with mode-derived network where TS does.

### storage

- **ArweaveClient uses custom non-ANS104 Irys signing that will not produce valid Irys/Arweave transactions** _[AIP-7]_ `behavior-diff`
  - TS ArweaveClient wraps the official @irys/sdk: new Irys({network,token,key,config}); irys.ready(); irys.upload(buffer,{tags}); irys.fund(); irys.getPrice(); irys.getLoadedBalance(). The Irys SDK signs a proper ANS-104 data-item (deep-hash of headers+tags+data) and submits to the node. Python hand-rolls the HTTP call: POSTs raw content to {node}/tx/{currency} with headers x-address, x-signature where signature = personal_sign(sha256_hex(content)) via eth_account encode_defunct, and passes tags as x-tag-{i}-name/value headers. Irys does NOT accept this — it requires a signed ANS-104 data item, not an EIP-191 personal_sign over the sha256 hex string. So the Python upload path produces transactions the real Irys node will reject. Balance/price endpoints (/account/balance/{currency}, /price/{currency}/{size}) are also not the SDK contract. Functional/protocol divergence: archives written via Python will not land on Arweave the same way (or at all).
  - TS: `sdk-js/src/storage/ArweaveClient.ts:197-218,365-379` · PY: `python-sdk-v2/src/agirails/storage/arweave_client.py:255-300`
  - Fix: Port the @irys/sdk equivalent (irys-py / bundlr client) or implement true ANS-104 data-item signing (deep-hash over tags+data per Irys spec) so uploaded items validate on node1.irys.xyz; match estimateCost/getPrice and getLoadedBalance semantics.
- **FilebaseClient uses HTTP basic auth PUT instead of AWS Signature V4 (uploads will be rejected by Filebase S3)** _[AIP-7]_ `behavior-diff`
  - TS FilebaseClient uses @aws-sdk/client-s3 S3Client with credentials + forcePathStyle, sending PutObjectCommand/HeadObjectCommand which AWS-SigV4-sign the request — the protocol Filebase S3 requires. Python instead does httpx.put(url, content=..., auth=(access_key, secret_key)) i.e. HTTP Basic auth, and the code comment explicitly admits 'In production, use proper AWS Signature V4' / 'use aioboto3'. Filebase's S3-compatible API does not accept HTTP Basic auth; SigV4 is mandatory, so Python uploads will 403. CID read from x-amz-meta-cid header matches, but the request never authenticates correctly.
  - TS: `sdk-js/src/storage/FilebaseClient.ts:114-123,196-208,633-646` · PY: `python-sdk-v2/src/agirails/storage/filebase_client.py:138-187`
  - Fix: Use aioboto3/botocore SigV4 signing (or aws-sigv4 over httpx) to sign PutObject/HeadObject against s3.filebase.com with region us-east-1 and path-style addressing, mirroring the TS @aws-sdk client.
- **ArweaveClient.download skips TX-ID validation, gateway allowlist, and download size limit (SSRF + DoS regression)** _[AIP-7]_ `security-diff`
  - TS downloadBundle/downloadJSON call validateArweaveTxId(txId) (43-char base64url regex), only fetch from ARWEAVE_GATEWAY validated against ALLOWED_ARWEAVE_GATEWAYS, and stream-enforce maxDownloadSize=10MB (Content-Length pre-check + during-stream cancel). Python ArweaveClient.download accepts an arbitrary gateway_url with NO is_gateway_allowed() check (unlike its own FilebaseClient.download which does check), performs NO tx_id validation, and does NO size-limit enforcement (reads response.content unbounded). SSRF hole (caller-supplied gateway) + DoS hole (unbounded download) + missing input validation present in TS.
  - TS: `sdk-js/src/storage/ArweaveClient.ts:483-499,522-554,617-633` · PY: `python-sdk-v2/src/agirails/storage/arweave_client.py:366-411`
  - Fix: In Python ArweaveClient.download add validate_arweave_tx_id(tx_id), reject gateways not in ALLOWED_ARWEAVE_GATEWAYS via is_gateway_allowed(), and stream with aiter_bytes enforcing a max_download_size (add 10MB default like TS).

### errors-utils-types-builders-settle

- **canonical_json byte-divergence on float-valued numbers breaks cross-SDK keccak hashes** _[AIP-4]_ `behavior-diff`
  - Python canonical_json_dumps uses json.dumps which renders integer-valued floats with a trailing '.0' (e.g. 1.0 -> "1.0", 60.0 -> "60.0", -0.0 -> "-0.0") whereas TS fast-json-stable-stringify (JSON.stringify number coercion) renders them WITHOUT (1.0 -> "1", -0.0 -> "0"). Empirically verified end-to-end: compute_result_hash({"amount":1.0}) = 0x46a9... in Python vs TS computeResultHash = 0xe16c...; {"estimatedTime":60.0} 0x53a0 vs 0x2473; {"x":-0.0} 0x6cbc vs 0x8fa0; all differ. Any hashed object containing a float-valued number diverges. On the protocol hot path: DeliveryProof resultHash (computeResultHash over resultData), Quote/CounterOffer justificationHash (canonical hash of justification with float estimatedTime/computeCost/marketRate/breakdown values), and quote computeHash. Provider signing with one SDK and consumer verifying with the other get mismatched hashes -> broken signature/attestation verification and on-chain anchor mismatch.
  - TS: `sdk-js/src/utils/canonicalJson.ts:17-29 (stringify = fast-json-stable-stringify)` · PY: `python-sdk-v2/src/agirails/utils/canonical_json.py:18-61 (json.dumps + _deep_sort)`
  - Fix: Make canonical_json_dumps emit numbers like JS JSON.stringify: integer-valued floats as bare integers, -0.0 as 0, match JS exponential formatting (1e21), reject/normalize non-finite. Best: pre-walk converting float x where x==int(x) to int before json.dumps and normalize -0.0->0. Add cross-SDK golden-vector test (Python hash == TS hash) over floats, -0, big ints, unicode, nested.
- **Python delivery builder compute_output_hash hashes raw bytes/str without JSON-quoting (not equal TS computeResultHash)** _[AIP-4]_ `behavior-diff`
  - builders/delivery_proof.py::compute_output_hash hashes str/bytes inputs DIRECTLY as utf-8 (data = output.encode('utf-8')) and only canonical-JSONs non-str/bytes. TS computeResultHash ALWAYS runs the value through fast-json-stable-stringify, so a string deliverable is JSON-quoted before hashing. Verified: TS computeResultHash("hello") = 0xf6fb31...; Python compute_output_hash("hello") = 0x1c8aff...; while Python types/message.py::compute_result_hash("hello") = 0xf6fb31... (correct). The builder with_output() path produces a resultHash that disagrees with TS (and with Python's own compute_result_hash) for any string or bytes deliverable.
  - TS: `sdk-js/src/utils/canonicalJson.ts:36-38 + builders/DeliveryProofBuilder.ts:212 (computeResultHash(resultData))` · PY: `python-sdk-v2/src/agirails/builders/delivery_proof.py:184-200 (compute_output_hash str/bytes shortcut)`
  - Fix: Route compute_output_hash through canonical_json_dumps for all input types (including str/bytes -> JSON.stringify-equivalent quoting) to match TS, OR delegate to types/message.compute_result_hash. Keep size-cap. Add golden vector for str/bytes/dict.
- **Python builders/quote.py QuoteBuilder is a divergent SHA-256 fluent builder, not the AIP-2 EIP-712 signed quote** _[AIP-2]_ `behavior-diff`
  - TS builders/QuoteBuilder.ts is the canonical AIP-2 quote: produces agirails.quote.v1 message, EIP-712 signs (AIP2QuoteTypes/AGIRAILS domain), verify(), and computeHash() = keccak256(toUtf8Bytes(canonicalJson(quoteWithoutSig))) with justificationHash. Python builders/quote.py exports a DIFFERENT Quote/QuoteBuilder: a fluent local object with fields transaction_id/price/estimated_time/valid_until, NO EIP-712 signing, NO agirails.quote.v1 type, and Quote.compute_hash() uses hashlib.sha256 over a 5-field canonical-JSON subset (provider lowercased) returning a 0x sha256 -- NOT keccak256 and NOT the TS field set. The builders are non-interoperable; a Python-built quote cannot be verified by TS QuoteBuilder.verify and the hashes differ in both algorithm (sha256 vs keccak) and content.
  - TS: `sdk-js/src/builders/QuoteBuilder.ts:97-361 (computeHash keccak256, signQuote EIP-712)` · PY: `python-sdk-v2/src/agirails/builders/quote.py:100-111 (compute_hash hashlib.sha256), 114-319 (fluent builder, no signing)`
  - Fix: Port the AIP-2 QuoteBuilder (agirails.quote.v1 EIP-712 sign/verify/computeHash with keccak256 canonical hash + justificationHash) into builders/quote.py mirroring CounterOfferBuilder. Legacy fluent Quote can remain but must NOT be the canonical hashing path. Confirm whether server/quote_channel.py already implements the signed quote and reconcile.

### level0 (Simple-tier primitives: provide / request / Provider / Serv…

- **request() encodes on-chain serviceDescription as JSON blob, not bytes32 keccak routing key** `behavior-diff`
  - TS request() sets serviceDescription = ethers.keccak256(ethers.toUtf8Bytes(validatedService)) — a bytes32 routing key — and explicitly documents (request.ts:127-145) that pre-4.0.0 passing JSON.stringify({service,input,timestamp}) caused BlockchainRuntime.validateServiceHash to hash the whole JSON so on-chain serviceHash = keccak256(JSON) never matched agent.provide(name) and routing failed silently on real chains. Python request() reintroduces exactly that bug: service_metadata = json.dumps({service, input, timestamp}) is passed as service_description (request.py:757-777). On testnet/mainnet this produces the wrong on-chain serviceHash and routing to a real provider fails. It also will not interoperate with a TS provider, which sends/expects the bytes32 routing key.
  - TS: `level0/request.ts:127-161` · PY: `level0/request.py:753-778`
  - Fix: Compute service_hash = '0x'+keccak(name.encode()).hex() (eth_hash) and pass it as service_description, exactly like TS. Move input out of the on-chain field (it is intentionally dropped in 4.0.0; emit the same warning).
- **request↔provider routing path mismatch: Python request never emits the bytes32 key its own provider treats as PRIMARY** `behavior-diff`
  - Python Provider._extract_service_name (provider.py:561-603) treats a 0x+64-hex bytes32 service_description as the PRIMARY routing path (reverse-map _service_name_by_hash), and returns 'unknown' for a bytes32 it does not recognize. But Python request() never sends bytes32 — it sends a JSON blob — so request→provider only works via the JSON FALLBACK branch. Net effect: (a) Python request cannot route to a TS provider (which keys off keccak(name)); (b) the two Python halves silently rely on the legacy JSON fallback that TS removed; (c) on-chain BlockchainRuntime that stores serviceDescription as bytes32 will deliver a hash the provider maps, but request never created that hash. The canonicalization between the two SDKs is inconsistent.
  - TS: `level0/request.ts:145` · PY: `level0/provider.py:569-603`
  - Fix: Make request() emit the keccak bytes32 key so the provider's PRIMARY path fires; keep JSON only as a transitional fallback or remove it to match TS.

### receipts

- **V2 EIP-712 ReceiptWriteV2 type + domain version 2 missing (signature divergence)** _[AIP-7]_ `missing-method`
  - TS push.ts signs EIP-712 'AGIRAILS Receipts' version '2' over ReceiptWriteV2 with 13 fields (signerAddress, participantRole, providerAddress, requesterAddress, kernelAddress, txId, network, amountWei, feeWei, netWei, serviceHash, nonce, issuedAt) and algorithm tag 'EIP712-ReceiptV2'. Python only knows the V1 ReceiptWrite (version '1', 7 fields: agentAddress, txId, network, amountWei, netWei, nonce, issuedAt) in web_receipt.py _build_receipt_write_typed_data. A Python agent therefore cannot produce a signature the Platform's V2 POST handler will accept on the new push path — wrong domain version and wrong typed-data struct.
  - TS: `sdk-js/src/receipts/push.ts:34-55,150-184` · PY: `python-sdk-v2/src/agirails/receipts/web_receipt.py:36-37,301-351 (V1 only)`
  - Fix: Implement RECEIPT_WRITE_DOMAIN_V2 (version '2') and the 13-field ReceiptWriteV2 typed data; include chainId in domain; send agentSignatureAlgorithm='EIP712-ReceiptV2', participantRole, and the prepare-issued nonce/issuedAt. Keep the V1 web_receipt path for backward compat.
- **smart-wallet vs EOA requesterAddress handling in receipt push** _[AIP-12]_ `security-diff`
  - TS runRequest.ts:747-756 deliberately passes requesterAddress=client.info.address (the smart wallet when AutoWallet is active, the EOA in Tier 2/3) rather than the local EOA-derived requesterAddress, because the Platform independently runs assertOnChainMatches and would silently null the receiptUrl on a mismatch. Because Python has no push path at all, this correctness nuance is unimplemented; a naive Python port that signs/sends with the EOA address while the on-chain requester is the smart wallet would always fail server-side on-chain verification (422) under AutoWallet.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:747-767` · PY: `ABSENT`
  - Fix: When porting the push, source requester_address from client.info.address (resolved smart-wallet/EOA), NOT the raw EOA from the private key, to match on-chain state.

### cross-cutting: top-level coverage + index.ts public-export parity +…

- **AIP-16 encrypted delivery channel subsystem entirely missing in Python** _[AIP-16]_ `missing-module`
  - TS has a full delivery/ directory implementing the AIP-16 encrypted result delivery channel: crypto.ts (AES-256-GCM via node:crypto), keys.ts (X25519 ECDH + HKDF-SHA256 session-key derivation via @noble/curves), eip712.ts, envelopeBuilder.ts, nonce-keys.ts, channel.ts, channelLog.ts, setupBuilder.ts, validate.ts, MockDeliveryChannel.ts, RelayDeliveryChannel.ts. Python has ONLY builders/delivery_proof.py which is the AIP-1 signed DeliveryProof (plaintext proof-of-delivery), NOT the AIP-16 encrypted envelope channel. No DeliveryChannel, MockDeliveryChannel, RelayDeliveryChannel, no envelope encryption/decryption, no X25519 key exchange, no session-key derivation. A Python provider cannot receive or a requester cannot send encrypted delivery payloads, so any agent relying on AIP-16 confidential delivery is non-interoperable. This is a protocol-level cross-SDK interop divergence.
  - TS: `sdk-js/src/delivery/ (entire dir: crypto.ts, keys.ts, eip712.ts, envelopeBuilder.ts, channel.ts, MockDeliveryChannel.ts, RelayDeliveryChannel.ts, setupBuilder.ts, validate.ts, nonce-keys.ts, index.ts)` · PY: `ABSENT (only python-sdk-v2/src/agirails/builders/delivery_proof.py exists, which is AIP-1 not AIP-16)`
  - Fix: Port delivery/ to Python: implement X25519 (via cryptography's x25519 or coincurve), HKDF-SHA256 + AES-256-GCM (via the `cryptography` package), envelope builder/validator, and Mock/Relay delivery channels. Add a `cryptography` dependency to pyproject.toml. Mirror crypto.ts/keys.ts constants (DELIVERY_SESSION_KEY_LENGTH, HKDF salt/info) exactly for cross-SDK interop, and reuse the aip16-cross-repo-eip712 vectors as golden tests.
- **No encryption dependency in pyproject for AIP-16 (cryptography/X25519/AES-GCM)** _[AIP-16]_ `missing-module`
  - TS delivery uses @noble/curves (X25519) + node:crypto (AES-256-GCM, HKDF-SHA256, randomBytes). Python pyproject.toml declares no crypto primitive library at all (no `cryptography`, `coincurve`, `pynacl`, or equivalent). Even if delivery code were ported, the capability is absent. eth-account/eth-hash do not provide X25519 ECDH, AES-GCM AEAD, or HKDF.
  - TS: `sdk-js/package.json dep @noble/curves ^1.9.0; sdk-js/src/delivery/keys.ts (x25519 from @noble/curves/ed25519), crypto.ts (createCipheriv/createDecipheriv node:crypto)` · PY: `python-sdk-v2/pyproject.toml dependencies (no crypto AEAD/ECDH lib)`
  - Fix: Add `cryptography>=42` (provides X25519PrivateKey, AESGCM, HKDF) to dependencies, or `coincurve` + `cryptography`. Verify GCM tag handling and HKDF salt/info match the TS implementation byte-for-byte.

### server (provider server app, policy/policy_engine, QuoteChannel tra…

- **Python QuoteChannelClient SSRF guard (assert_safe_peer_url) absent** _[AIP-2.1]_ `missing-method`
  - TS assertSafePeerUrl(url, allowInsecureTargets) is called before every client POST to block SSRF into localhost/loopback/link-local(169.254.169.254 cloud metadata)/RFC1918/IPv6 ULA, including IPv4-mapped IPv6 (::ffff:127.0.0.1 dotted AND ::ffff:7f00:1 hex forms) and *.localhost. Peer endpoints come from on-chain AgentRegistry / agirails.app DB (adversary-writable), so a malicious endpoint could exfiltrate signed payloads into internal infra. Python has no quote-channel client at all, so this protection is entirely missing on the send path. Note: validation.py has a separate SSRF helper for endpoint validation but it is NOT wired into any quote-channel send path.
  - TS: `sdk-js/src/transport/QuoteChannel.ts:385-469 (assertSafePeerUrl), 200 (call-site)` · PY: `ABSENT (no quote-channel client; validation.py SSRF helper not wired to channel send)`
  - Fix: When porting QuoteChannelClient, port assertSafePeerUrl semantics exactly (https-only by default, allow_insecure_targets flag, IPv4-mapped-IPv6 re-extraction, all the loopback/link-local/RFC1918/ULA literals) or reuse validation.py's SSRF check with equivalent coverage. Keep the same error messages so test fixtures match.


---

## P1 — Missing Features (162)

### level1-agent

- **AIP-16 secure delivery channel entirely absent from Python** _[AIP-16]_ `missing-module`
  - TS Agent has the full AIP-16 Phase 2e/3 delivery surface: AgentConfig.deliveryChannel/deliverySigner/kernelAddress/chainId/smartWalletNonce, maybePublishDeliveryEnvelope (build + publish DeliveryEnvelopeWireV1 public or encrypted x25519-aes256gcm between handler result and DELIVERED), ensureAip16AutoWire (zero-config RelayDeliveryChannel + kernel/chainId from networkConfig + deliverySigner from keystore), ACTP_DELIVERY_CHANNEL=v1 gate, AGIRAILS_RELAY_URL, per-service delivery.mode/privacy via DeliveryServiceConfig + DEFAULT_DELIVERY_CONFIG. Python has no delivery module at all (grep confirms NONE in python-sdk-v2), no delivery field on ServiceConfig, no envelope publishing. A Python provider can never emit signed/encrypted delivery envelopes, so buyers fall back to on-chain proof only.
  - TS: `sdk-js/src/level1/Agent.ts:2128-2412 (and Options.ts:34-82)` · PY: `ABSENT`
  - Fix: Port the delivery subsystem (envelopeBuilder, channel, Mock/Relay channels, EIP-712 envelope signing) then wire AgentConfig fields + maybe_publish_delivery_envelope + ensure_aip16_auto_wire into _process_job with the ACTP_DELIVERY_CHANNEL gate.
- **smartWalletNonce config + server-side providerAddress derivation absent** _[AIP-16]_ `missing-param`
  - TS AgentConfig.smartWalletNonce (default 0) is threaded into DeliveryEnvelopeBuilder.buildPublic/buildEncrypted so providers whose Smart Wallet deployed at a non-zero factory nonce derive the correct on-chain providerAddress for the AIP-16 envelope signature. Python has no smartWalletNonce field and no envelope build, so this protocol-correctness knob does not exist.
  - TS: `sdk-js/src/level1/Agent.ts:232-250,480-488,2371,2392` · PY: `ABSENT`
  - Fix: Add smart_wallet_nonce to AgentConfig and thread it into the ported envelope builder (default 0).
- **job:declined and job:filtered events never emitted** `missing-event`
  - TS emitJobDecision fires job:declined (economic: budget below/above filter band, pricing rejected, pricing error) and job:filtered (policy: custom/legacy filter declined, auto_accept disabled, auto_accept callback declined) with a machine-readable {jobId, requester, amount, reason, ...} payload, dispatched over rawListeners and swallowing sync+async listener throws. Python's _should_auto_accept silently returns False for every rejection path — no decline/filter events, no reason payload. Consumers (e.g. Sentinel decline counters) cannot observe why a Python agent passed on a job.
  - TS: `sdk-js/src/level1/Agent.ts:1402-1604,1651-1691` · PY: `python-sdk-v2/src/agirails/level1/agent.py:784-808`
  - Fix: Add _emit_job_decision and fire job:declined/job:filtered at each rejection branch in _should_auto_accept with the same reason taxonomy; guard listener exceptions.
- **payment:received event never emitted** `missing-event`
  - TS emits payment:received with job.budget after a successful job (Agent.ts:2019) — the earn-side signal consumers listen for. Python _complete_job emits only job:completed; there is no payment:received event. The Python event docstring (agent.py:562-576) does not list it.
  - TS: `sdk-js/src/level1/Agent.ts:2019` · PY: `python-sdk-v2/src/agirails/level1/agent.py:933`
  - Fix: Emit 'payment:received' with job.budget in _complete_job after job:completed.
- **job:rejected (concurrency-limit) event never emitted** `missing-event`
  - TS processJob, when the concurrency semaphore times out, removes the job from active/processed sets, emits job:rejected with reason 'concurrency_limit', and throws an explanatory error. Python _process_job on semaphore-acquire failure emits job:failed with a string message instead of job:rejected and does not clean processed_jobs for retry. Different event name + different recovery semantics.
  - TS: `sdk-js/src/level1/Agent.ts:1815-1833` · PY: `python-sdk-v2/src/agirails/level1/agent.py:817-820`
  - Fix: Emit 'job:rejected' with 'concurrency_limit' and restore retryability (clear processed/active) to match TS.
- **Bounded-retry-for-repeatedly-failing-jobs absent (jobAttempts / MAX_JOB_ATTEMPTS)** `missing-method`
  - TS tracks per-job failure counts in an LRUCache jobAttempts and, after MAX_JOB_ATTEMPTS (3), marks a transiently-failing job processed so polling stops retrying it forever (handler throwing on bad input). Python _fail_job has no attempt counter; worse, _execute_job ALWAYS marks the job processed in its finally block (agent.py:884), so Python actually never retries a failed job at all — the opposite extreme. TS distinguishes transient (retry up to 3x) vs permanent; Python does neither (single attempt, no bounded retry, no transient retry).
  - TS: `sdk-js/src/level1/Agent.ts:375-383,2063-2081` · PY: `python-sdk-v2/src/agirails/level1/agent.py:878-885,935-950`
  - Fix: Add a job_attempts LRU and only mark processed on success, permanent revert, or after MAX_JOB_ATTEMPTS=3 transient failures; otherwise clear processed for retry on next poll.
- **Permanent-kernel-revert detection (no-retry skip-set) absent** `missing-method`
  - TS inspects the failure error for permanent revert reasons (Transaction expired, Invalid transition, Only requester, Only provider, Not authorized, Not participant) in BOTH plaintext and hex-encoded (UserOp simulation) form, and marks such jobs processed so polling never burns bundler quota retrying an unrecoverable tx. Python has no such classification — combined with its always-mark-processed behavior it never retries anything, so transient RPC blips are also dropped permanently. Both retry policies (transient and permanent) diverge from TS.
  - TS: `sdk-js/src/level1/Agent.ts:2032-2050` · PY: `ABSENT`
  - Fix: Port the permanentRevertReasons list + plaintext/hex matching into _fail_job and only then mark processed; otherwise apply bounded transient retry.
- **ZeroHash sole-handler raw-pay routing fix absent** `missing-method`
  - TS findServiceHandler: when serviceHash is ZeroHash or absent AND exactly one handler is registered, it routes the raw-pay tx to that sole handler (Level 0 client.pay(provider,amount) creates serviceHash=ZeroHash, no serviceDescription). Without this the job never runs and stays COMMITTED forever. Python _find_service_handler skips the zero_hash branch (returns nothing for normalized==zero_hash) and falls to from_legacy string parse, which fails for raw-pay txs — so a single-service Python provider silently drops every raw client.pay job.
  - TS: `sdk-js/src/level1/Agent.ts:1269-1299` · PY: `python-sdk-v2/src/agirails/level1/agent.py:704-730`
  - Fix: Add: if (no routable hash) and len(_handlers_by_hash)==1, route to the sole handler with a warn log; mirror the 0/2+ handler guards.
- **Counter-offer QUOTED transition + AIP-2.1 ProviderOrchestrator path absent** _[AIP-2.1]_ `missing-method`
  - TS shouldAutoAccept, on a 'counter-offer' pricing decision, either submits a canonical AIP-2.1 signed QuoteMessage via ProviderOrchestrator.quote (when setProviderOrchestrator was called) or falls back to a legacy keccak256(JSON{txId,providerIdealPrice,actualEscrow,provider}) hash and transitionState(tx,'QUOTED',proof) routed through StandardAdapter (AA paymaster). Python has no setProviderOrchestrator, no QUOTED transition, and treats counter-offer pricing only as a reject inside _should_auto_accept (it checks decision=='reject' only; counter-offer falls through to accept logic). A Python provider can never make an on-chain counter-offer.
  - TS: `sdk-js/src/level1/Agent.ts:972-974,1483-1565` · PY: `python-sdk-v2/src/agirails/level1/agent.py:794-797`
  - Fix: Add set_provider_orchestrator + counter-offer handling that emits a QUOTED transition (legacy hash and/or orchestrator quote); currently counter-offer decisions are silently mis-handled.
- **Live on-chain subscription path (subscribeProviderJobs) absent** `missing-method`
  - TS subscribeIfBlockchain wires BlockchainRuntime.subscribeProviderJobs(provider, onJob) so jobs arrive via live TransactionCreated events (idempotent, torn down on pause/stop, re-established on resume) in addition to polling. Python has only the 2s poll loop; runtime has no subscribe_provider_jobs (grep NONE). Python providers have higher job-pickup latency and the pause/resume subscription lifecycle is a no-op.
  - TS: `sdk-js/src/level1/Agent.ts:696-733,710-715` · PY: `ABSENT`
  - Fix: Add subscribe_provider_jobs to the blockchain runtime and a subscribe/unsubscribe lifecycle in Agent that converges on the same handle_incoming_transaction pipeline.
- **Mode-dependent poll state filter missing (mock INITIATED, blockchain COMMITTED+IN_PROGRESS orphan recovery)** `behavior-diff`
  - TS pollForJobs polls INITIATED in mock mode (provider drives linkEscrow) and COMMITTED+IN_PROGRESS on testnet/mainnet (IN_PROGRESS = orphan-recovery for a tx that advanced past COMMITTED then crashed before DELIVERED). Python _poll_for_jobs polls only State.COMMITTED regardless of mode, so (a) mock-mode provider-driven INITIATED→COMMITTED flows differ, and (b) a Python provider that crashes after IN_PROGRESS but before DELIVERED leaves the tx stuck forever — no orphan recovery.
  - TS: `sdk-js/src/level1/Agent.ts:1078-1086` · PY: `python-sdk-v2/src/agirails/level1/agent.py:642-647`
  - Fix: Make the polled state set mode-dependent and add IN_PROGRESS orphan recovery; thread provider-side linkEscrow only in mock.
- **Settlement step lacks state re-read / idempotency guard; unconditional IN_PROGRESS transition** `behavior-diff`
  - TS processJob re-reads current tx state before transitioning, only does COMMITTED→IN_PROGRESS when state is COMMITTED, skips when already IN_PROGRESS, and bails for CANCELLED/DISPUTED — making re-delivery (orphan recovery / poll re-pickup) idempotent. Python _execute_job calls transition_state(IN_PROGRESS) unconditionally (catching errors as 'might already be IN_PROGRESS') then _complete_job transitions DELIVERED. On re-delivery or a non-workable state Python will attempt invalid transitions and rely on swallowed exceptions, with no guard against acting on a CANCELLED/DISPUTED tx.
  - TS: `sdk-js/src/level1/Agent.ts:1890-1949` · PY: `python-sdk-v2/src/agirails/level1/agent.py:832-846,903-926`
  - Fix: Re-read tx state before the IN_PROGRESS hop; skip when past COMMITTED, bail on terminal/disputed states; mirror TS idempotency.
- **ProofGenerator delivery proof not attached on completion** `behavior-diff`
  - TS processJob builds an authenticated delivery proof via ProofGenerator.generateDeliveryProof({txId, deliverable, metadata}) and (in mock) attaches deliveryProofJson to the tx state for buyer-side verification; the real result is also embedded. Python _complete_job only abi-encodes the disputeWindow uint256 as the DELIVERED proof and never generates/attaches a content-hash delivery proof — buyers verifying off-chain content against Python providers have no structured proof.
  - TS: `sdk-js/src/level1/Agent.ts:1842-1906` · PY: `python-sdk-v2/src/agirails/level1/agent.py:903-926`
  - Fix: Port ProofGenerator usage and attach the delivery proof (mock state poke + on-chain proof) the way TS does.
- **safeEmitError no-crash-on-unhandled-error pattern not implemented as designed** `behavior-diff`
  - TS safeEmitError emits 'error' only when a listener is attached, else logs at error level 'no error listener attached; not crashing' — explicit guard so a long-running daemon does not die on Node's unhandled-'error' throw. Python _emit simply no-ops when no handler is registered (so no crash either) but provides NO error logging when unobserved — failures vanish silently with no operator signal, and there is no single safe-error seam. The intent (visible-but-non-fatal) is only half met.
  - TS: `sdk-js/src/level1/Agent.ts:1029-1035` · PY: `python-sdk-v2/src/agirails/level1/agent.py:590-598,300,619`
  - Fix: Add a _safe_emit_error that emits 'error' if a handler exists else logs at error level; route start()/poll/process failures through it.
- **Provider authorization check on incoming tx missing** `security-diff`
  - TS handleIncomingTransaction verifies tx.provider.toLowerCase() === this.address.toLowerCase() and drops/logs unauthorized txs before processing. Python _process_transaction performs no provider-match check — it trusts whatever get_transactions_by_provider returns. While the query is scoped by provider, the TS defense-in-depth authz guard (and case-insensitive normalization) is absent, so a runtime that returns a mismatched provider tx would be processed.
  - TS: `sdk-js/src/level1/Agent.ts:1156-1163` · PY: `python-sdk-v2/src/agirails/level1/agent.py:664-702`
  - Fix: Add a case-insensitive provider==self.address guard in _process_transaction before routing.
- **Agent address derivation is fake (sha256) instead of eth_account key derivation** _[AIP-13]_ `behavior-diff`
  - TS generateAddress/getPrivateKey use ethers.Wallet to derive the real checksummed address from the private key, resolve ACTP_PRIVATE_KEY/keystore for testnet/mainnet, and throw ValidationError for invalid keys or missing keys on blockchain modes. Python _resolve_address, when given a 64-hex private key, returns '0x'+sha256(key)[:40] — a fabricated address that is NOT the real Ethereum address for that key. On-chain identity/provider matching would be wrong if a private key is supplied this way. (For mock this only affects routing; for real keys it is incorrect.)
  - TS: `sdk-js/src/level1/Agent.ts:2489-2545` · PY: `python-sdk-v2/src/agirails/level1/agent.py:976-991`
  - Fix: Use eth_account to derive the real address from the key; reject invalid keys; resolve keystore/ACTP_PRIVATE_KEY for testnet/mainnet.
- **ServiceConfig.delivery field and DeliveryServiceConfig/DEFAULT_DELIVERY_CONFIG absent** _[AIP-16]_ `missing-class`
  - TS Options.ts defines DeliveryServiceConfig {mode, privacy} and DEFAULT_DELIVERY_CONFIG (channel+public) and declaration-merges a delivery? field onto ServiceConfig, which Agent reads to decide envelope mode. Python ServiceConfig (config.py) has no delivery field and there is no DeliveryServiceConfig/DEFAULT_DELIVERY_CONFIG type. Services cannot declare delivery mode/privacy.
  - TS: `sdk-js/src/level1/types/Options.ts:34-82` · PY: `python-sdk-v2/src/agirails/level1/config.py:168-211`
  - Fix: Add DeliveryServiceConfig + DEFAULT_DELIVERY_CONFIG and a delivery field on ServiceConfig.

### config-publish-sync

- **No V4 typed parser module (agirailsmdV4)** _[AIP-18]_ `missing-module`
  - TS agirailsmdV4.ts provides parseAgirailsMdV4 + validateAgirailsMdV4 with typed AgirailsMdV4Config (intent earn/pay/both, services normalization legacy-string->object, servicesNeeded with services_needed alias, budget, pricing band w/ min_price<=max_price validation, network coercion, SLA/covenant/payment defaults, description/howToRequest body split, x402-requires-endpoint validation, MIN_PRICE>=0.05). Python has NO equivalent — there is no typed V4 parse/validate. This is the type the CLI buyer-aware diff/pull and publish pay-only branch depend on (v4.intent==='pay').
  - TS: `config/agirailsmdV4.ts:138-408` · PY: `ABSENT`
  - Fix: Port agirailsmdV4.ts to a Python module (parse_agirails_md_v4, validate_agirails_md_v4) with the same intent/services/servicesNeeded/pricing rules.
- **No defaults module (V4_DEFAULTS, V4_CONSTRAINTS, computeDisplayFee)** `missing-module`
  - TS defaults.ts holds V4_DEFAULTS (intent='earn', pricing/sla/payment defaults), V4_CONSTRAINTS (MIN_PRICE=0.05, MAX_SLUG_LENGTH=64, SLUG_PATTERN, VALID_INTENTS/NETWORKS/PAYMENT_MODES, HOW_TO_REQUEST_HEADING) and computeDisplayFee (max(amount*1%,$0.05) display fee that must stay parity-locked with web). Python has none of these constants in config/.
  - TS: `config/defaults.ts:14-95` · PY: `ABSENT`
  - Fix: Port defaults.ts; computeDisplayFee must match max(amountWei*100/10000, 50000).
- **No slugUtils module (generateSlug, validateSlug)** `missing-module`
  - TS slugUtils.ts provides generateSlug (lowercase, non-alnum->hyphen, collapse, trim, slice 64) and validateSlug (empty/length/pattern). Python config/ has no slug utilities; the Python publish CLI relies on agirails.app check_slug only and cannot locally generate/validate slugs identically to TS.
  - TS: `config/slugUtils.ts:24-47` · PY: `ABSENT`
  - Fix: Port slugUtils.ts as generate_slug/validate_slug using the same regex/length rules.
- **No buyerLink module — AIP-18 gasless-buyer gate marker entirely absent** _[AIP-18]_ `missing-module`
  - TS buyerLink.ts (BuyerLink type, saveBuyerLink, loadBuyerLink, hasBuyerLink, deleteBuyerLink, getBuyerLinkPath) writes .actp/buyer-link.json so the SDK auto-wallet gate grants gas-sponsored transactions to a linked pure buyer (DEC-8: buyers are gasless, need only USDC). Without it, a pay-only buyer with no on-chain configHash and no pending-publish would fall back to the EOA wallet and require ETH. Python has NO buyer-link module anywhere (grep confirms none). Writes are atomic (tmp+rename, mode 0600) and symlink-safe.
  - TS: `config/buyerLink.ts:36-132` · PY: `ABSENT`
  - Fix: Port buyerLink.ts to Python (save/load/has/delete_buyer_link, get_buyer_link_path) reusing pending_publish's get_actp_dir and the same atomic+symlink-safe write, and wire the auto-wallet gate to honor it.
- **Buyer-link write path missing in publish CLI (pay-only buyer never linked)** _[AIP-18]_ `missing-method`
  - TS CLI publish.ts detects isPayOnly (v4Config.intent==='pay'), skips IPFS upload, and writes the buyer-link marker into the published agent's project root (publish.ts:604-627). Python CLI publish.py has NO pay-only detection and NO buyer-link write — it always extracts registration params and runs the provider path. A Python-published pay-only buyer never gets the gasless gate marker.
  - TS: `cli/commands/publish.ts:459-627` · PY: `cli/commands/publish.py:300-601`
  - Fix: Add isPayOnly branch in Python publish that writes buyer-link.json into project root .actp (ACTP_DIR override honored) for intent=='pay' agents.
- **Idempotent test-USDC mint not implemented — Python re-mints on every (re)publish** _[AIP-18]_ `behavior-diff`
  - TS mintTestnetUsdcForBuyer checks USDC balanceOf(smartWallet)>0 and skips minting if already funded ('Test USDC already present — skipping mint', publish.ts:1191-1201) so re-publishing doesn't keep topping up. Python _activate_on_testnet ALWAYS appends build_testnet_mint_batch(...'1000000000') unconditionally (publish.py:268-273) — every testnet publish/re-publish mints another 1000 USDC. No balance-gate idempotence.
  - TS: `cli/commands/publish.ts:1191-1201` · PY: `cli/commands/publish.py:268-273`
  - Fix: Read USDC balanceOf(smartWallet) before adding the mint batch; skip mint when balance>0 (matches TS).
- **defaultDiscoveryEndpoint missing — Python uses pending.agirails.io (404) instead of agent profile URL** `missing-method`
  - TS extractRegistrationParams defaults a missing endpoint to https://agirails.app/a/{slug} via defaultDiscoveryEndpoint(slug) (publishPipeline.ts:89-92,144-167) — a real navigable profile. Python falls back to PENDING_ENDPOINT='https://pending.agirails.io' (publish_pipeline.py:111-113), the legacy 404 sentinel the TS code explicitly deprecated. On-chain endpoint differs between SDKs for the same file.
  - TS: `config/publishPipeline.ts:76-92,144-167` · PY: `config/publish_pipeline.py:111-113`
  - Fix: Add default_discovery_endpoint(slug)->'https://agirails.app/a/{slug}' and use it as the fallback in extract_registration_params.
- **serviceType format validation missing in extract_registration_params** `missing-param`
  - TS validateServiceType enforces /^[a-z0-9]+(-[a-z0-9]+)*$/ on every service type (publishPipeline.ts:107-117) and throws on invalid/empty before computing serviceTypeHash. Python silently lowercases and skips empty (publish_pipeline.py:122-124,164) but never validates the hyphenated-alphanumeric format, so a malformed service type is hashed and sent to AgentRegistry instead of being rejected. Note: the keccak256 of the (validated, lowercased) serviceType itself matches between SDKs; the gap is the missing reject path.
  - TS: `config/publishPipeline.ts:107-117,173,204` · PY: `config/publish_pipeline.py:122-124,164-166`
  - Fix: Port validate_service_type with the same regex and raise on invalid types in both services and capabilities paths.
- **USDC overflow / negative-value guard missing (usdcToBaseUnits)** `missing-param`
  - TS usdcToBaseUnits rejects negative values and values > MAX_SAFE_USDC (floor(MAX_SAFE_INTEGER/1e6)) before BigInt conversion (publishPipeline.ts:104,119-124). Python computes int(float(price)*1_000_000) with no negative or overflow checks (publish_pipeline.py:132-138), so a huge or negative price band is silently passed to the registry. Python int() has no precision loss, but the negative/upper-bound rejection semantics differ from TS.
  - TS: `config/publishPipeline.ts:103-124` · PY: `config/publish_pipeline.py:129-138`
  - Fix: Add usdc_to_base_units(value, field) with negative + MAX_SAFE_USDC checks; reuse it in price parsing.
- **Bidirectional reconcile subsystem absent (decideReconcile, fetchWebState, reconcile, WebState/ReconcileAction/ReconcileDecision/ReconcileResult)** `missing-method`
  - TS syncOperations.ts implements Faza B three-way reconcile: decideReconcile (pure local<->web<->chain anchor diff producing pull-web/push-local/conflict-web-wins/conflict-local-wins), fetchWebState (reads {slug}.md + X-Config-Hash/X-Updated-At headers from agirails.app), and reconcile (writes conflict snapshots .conflict-<ts>.md / .web-conflict-<ts>.md, atomic pull-web write, returns needsPublish). Python sync_operations.py has only diff_config/pull_config — no reconcile, no web-state fetch, no conflict snapshotting, none of the related types.
  - TS: `config/syncOperations.ts:301-478` · PY: `ABSENT`
  - Fix: Port decideReconcile (pure, unit-testable), fetchWebState, reconcile and the WebState/ReconcileAction/ReconcileDecision/ReconcileResult types.
- **pull_config: non-atomic local write (no tmp+rename)** `behavior-diff`
  - TS pull writes the stamped file via tmp+renameSync (syncOperations.ts:274-276) for atomicity. Python pull_config writes directly with Path.write_text (sync_operations.py:287), so a crash mid-write can leave a truncated/corrupt AGIRAILS.md. (Python pending_publish already uses atomic writes, so the helper exists — it just isn't used here.)
  - TS: `config/syncOperations.ts:273-276` · PY: `config/sync_operations.py:287`
  - Fix: Write to local_path+'.tmp' then os.replace() onto local_path.
- **Buyer-aware diff: no 'buyer-local' short-circuit / honest budget-private messaging** _[AIP-18]_ `behavior-diff`
  - TS CLI diff.ts short-circuits when the local file parses as v4 intent=='pay': emits status 'buyer-local', inSync:true, and the honest message 'Buyer config is local-authored; not anchored on-chain (budget stays private) — nothing to diff on-chain' (diff.ts:76-108). Python CLI diff.py has no buyer detection — a pay-only file falls through to the on-chain diff and reports the misleading 'no-remote / run publish'.
  - TS: `cli/commands/diff.ts:76-108` · PY: `cli/commands/diff.py (no buyer branch)`
  - Fix: In Python diff command, parse v4 intent first; if 'pay' return buyer-local status with the same local-sovereign messaging.
- **Buyer-aware pull: no 'buyer-local' short-circuit** _[AIP-18]_ `behavior-diff`
  - TS CLI pull.ts short-circuits intent=='pay' files with status 'buyer-local' and 'config is local-authored and budget is private — nothing to pull' (pull.ts:77-111). Python CLI pull.py has no such branch, so pulling a buyer file performs a misleading on-chain lookup.
  - TS: `cli/commands/pull.ts:77-111` · PY: `cli/commands/pull.py (no buyer branch)`
  - Fix: Mirror the diff buyer-local short-circuit in the Python pull command.
- **Smart Wallet (config.address/smartWallet) read before EOA fallback missing in publish CLI buyer path** _[AIP-18]_ `behavior-diff`
  - TS publish.ts, for a wallet:auto pay-only buyer, reads cfg.smartWallet from .actp/config.json and uses it (falling back to EOA only if unknown) so the DB link and buyer-link marker record the Smart Wallet address the buyer actually transacts from, matching on-chain payment attribution (publish.ts:589-602,620). Python publish.py has no pay-only branch and never resolves a Smart Wallet address for the buyer-link/DB link — buyer attribution would use the bare EOA.
  - TS: `cli/commands/publish.ts:589-602` · PY: `cli/commands/publish.py (absent)`
  - Fix: In the Python buyer branch, read smart_wallet from .actp/config.json (wallet=='auto') and prefer it over the EOA for buyer-link wallet and DB upsert.

### level0 (Simple-tier primitives: provide / request / Provider / Serv…

- **request() does not route through StandardAdapter (no AA / SmartWalletRouter / Paymaster)** `behavior-diff`
  - TS request() deliberately calls client.standard.createTransaction / linkEscrow / transitionState / releaseEscrow so AA-enabled requesters use the Paymaster-sponsored UserOp path (request.ts:147-161, 171, 233, 292); going through runtime directly force-signs with a raw EOA that holds no ETH under the gasless model. Python calls effective_client.runtime.create_transaction directly (request.py:778) and runtime.transition_state for cancel — bypassing the adapter entirely. On testnet/mainnet with a gasless (Tier-1) requester this cannot pay for gas.
  - TS: `level0/request.ts:147-161` · PY: `level0/request.py:769-778`
  - Fix: Route through client.standard.* like TS so AA requesters get sponsored UserOps; fall through to runtime for mock/EOA.
- **request() omits testnet/mainnet linkEscrow → tx stuck in INITIATED** `behavior-diff`
  - TS request() calls client.standard.linkEscrow(txId) for testnet/mainnet to reach COMMITTED, noting ACTPKernel.linkEscrow requires msg.sender==requester and that omitting it left the tx INITIATED indefinitely (request.ts:163-172). Python request() never links escrow on the requester side at all (only the provider poll loop links escrow). On a real chain the requester-driven linkEscrow is missing.
  - TS: `level0/request.ts:163-172` · PY: `level0/request.py:778-805`
  - Fix: After createTransaction, if network in (testnet, mainnet) call client.standard.linkEscrow(tx_id).
- **request() does not mint mock tokens to fund the requester** `behavior-diff`
  - TS request() in mock mode checks requester balance and mints (amount - balance + 10 USDC buffer) via runtime.mintTokens so the escrow can be funded (request.ts:113-125). Python request() has no such logic; a mock requester with zero balance will fail to fund escrow.
  - TS: `level0/request.ts:113-125` · PY: `level0/request.py:737-778`
  - Fix: In mock mode, if runtime exposes mint/get_balance, top up the requester with the same +10 USDC buffer before createTransaction.
- **request() never auto-releases escrow after dispute window** `behavior-diff`
  - TS request() on DELIVERED+escrowId computes computeDisputeWindowEnds(completedAt, disputeWindow) vs runtime.time.now(); if elapsed, in mock it calls client.standard.releaseEscrow(escrowId) to settle, and on testnet/mainnet warns that auto-release is disabled (request.ts:281-307). Python request()/RequestHandle.wait has no dispute-window evaluation and never releases escrow, so funds remain locked until external action.
  - TS: `level0/request.ts:281-307` · PY: `level0/request.py:403-465`
  - Fix: Port computeDisputeWindowEnds + runtime.time.now() check and call releaseEscrow in mock; emit the manual-verify warning on testnet/mainnet.
- **request() default RPC resolution for testnet/mainnet missing** `behavior-diff`
  - TS request() resolves a default rpcUrl from config/networks (base-sepolia / base-mainnet) when none is supplied (request.ts:79-86). Python request() passes rpc_url straight through (request.py:730-735) with no default lookup, so a testnet/mainnet request with no rpc_url has no endpoint.
  - TS: `level0/request.ts:79-86` · PY: `level0/request.py:730-735`
  - Fix: When network in (testnet, mainnet) and rpc_url is None, look up the network config default RPC.
- **request() auto wallet does not resolve keystore private key** _[AIP-13]_ `behavior-diff`
  - TS request() runs resolveKeyIfNeeded → resolvePrivateKey(stateDirectory,{network}) so an 'auto' wallet on testnet/mainnet loads the AIP-13 keystore and derives the requester address from it (request.ts:88-99, 358-366). Python only derives a private key when the wallet arg is literally a 0x-64-hex string or {privateKey} (request.py:859-885); 'auto' yields no key and a fabricated mock requester address even on testnet/mainnet.
  - TS: `level0/request.ts:88-99` · PY: `level0/request.py:826-885`
  - Fix: Port resolveKeyIfNeeded using the Python keystore resolve_private_key for auto/undefined wallet on testnet/mainnet.
- **request() fabricates a fake provider address instead of throwing NoProviderFoundError** `behavior-diff`
  - TS findProvider returns undefined when nothing is registered and request() throws NoProviderFoundError with availableProviders (request.ts:73-77, 388-397). Python _find_provider returns a synthetic '0x'+'provider'.hex padded address when provider is None/'any' (request.py:609-611), so request proceeds against a bogus provider instead of failing fast.
  - TS: `level0/request.ts:73-77` · PY: `level0/request.py:609-613`
  - Fix: Return None and raise a NoProviderFoundError equivalent when no real provider is registered.
- **request() drops provider address validation/checksum and ValidationError typing** `behavior-diff`
  - TS findProvider validates an explicit provider with isValidAddress and normalizes via ethers.getAddress (checksum), throwing ValidationError on bad input (request.ts:380-385). Python _find_provider returns provider_option verbatim with no validation or checksum (request.py:595-597). It also lowercases addresses elsewhere rather than EIP-55 checksumming.
  - TS: `level0/request.ts:380-385` · PY: `level0/request.py:595-597`
  - Fix: Validate with is_valid_address and checksum via eth_utils.to_checksum_address; raise a ValidationError equivalent.
- **provide() does not create/start a level1 Agent and returns ServiceEntry, not a Provider lifecycle object** `behavior-diff`
  - TS provide(service, handler, options): creates new Agent({network, wallet, stateDirectory, rpcUrl, behavior.autoAccept}), registers {name, filter}, calls agent.start(), registers in serviceDirectory, and returns a Provider object exposing ready (Promise), status/address/balance, pause()/resume()/stop(), on(event), stats (provide.ts:55-137). Python provide(name, handler?, *, description, capabilities, schema, metadata) only registers a handler on a module-global Provider registry and returns a ServiceEntry (or a decorator) — it never instantiates an Agent, never starts on-chain polling, and exposes no ready/status/address/balance/pause/resume/stop/on/stats lifecycle (provide.py:105-164). The two provide() functions have incompatible signatures and semantics.
  - TS: `level0/provide.ts:55-137` · PY: `level0/provide.py:105-164`
  - Fix: Provide a TS-parity provide() that wires the level1 Agent (which already exists at level1/agent.py), starts it, registers in the directory, and returns a Provider-shaped lifecycle handle; keep the registry-style provide() under a distinct name if still needed.
- **ProvideOptions shape diverges (no wallet/filter/autoAccept/network/rpcUrl/stateDirectory)** `signature-diff`
  - TS ProvideOptions = {wallet, filter:{minBudget,maxBudget}, autoAccept:boolean|fn, network, rpcUrl, stateDirectory} (Options.ts:101-188). Python ProvideOptions = {description, capabilities, schema, metadata, auto_start} (provide.py:32-49) — a completely different field set with none of the TS wallet/filter/autoAccept/network/rpcUrl options. Budget filtering (minBudget/maxBudget) and custom autoAccept are absent in Python level0.
  - TS: `level1/types/Options.ts:101-188` · PY: `level0/provide.py:32-49`
  - Fix: Add a TS-parity ProvideOptions (wallet, filter min/maxBudget, autoAccept boolean|callable, network, rpcUrl, stateDirectory) for the Agent-backed provide().
- **Provider lifecycle surface diverges (no ready/pause/resume/balance; states differ)** `missing-method`
  - TS Provider exposes ready:Promise<void>, status('starting'|'running'|'paused'|'stopped'), address, balance:{eth,usdc}, pause(), resume(), stop():Promise, on('job:received'|'job:completed'|'job:failed'|'payment:received'), stats{jobsCompleted,jobsFailed,totalEarned,averageJobTime} (Provider.ts:62-123). Python Provider has no ready promise, no pause()/resume(), no balance, no on()/event emitter (events are absent entirely), status enum differs (IDLE/STARTING/RUNNING/STOPPING/STOPPED/ERROR vs starting/running/paused/stopped), and stats keys differ (jobs_received/jobs_completed/jobs_failed/total_earnings vs jobsCompleted/jobsFailed/totalEarned/averageJobTime — no averageJobTime, extra jobs_received).
  - TS: `level0/Provider.ts:62-123` · PY: `level0/provider.py:103-177`
  - Fix: Expose a TS-parity Provider lifecycle (ready, pause/resume, balance, on(events), matching status strings and stats keys including averageJobTime).
- **Provider has no event emitter (job:received/completed/failed, payment:received)** `missing-event`
  - TS Provider.on supports 'job:received'(job), 'job:completed'(job,result), 'job:failed'(job,error), 'payment:received'(amount) (Provider.ts:114-117). Python Provider emits no events at all — _process_job only logs and updates stats (provider.py:644-746). Consumers relying on payment:received / job:* callbacks have no Python equivalent at level0.
  - TS: `level0/Provider.ts:108-118` · PY: `level0/provider.py:644-746`
  - Fix: Add an event-emitter (or callback registry) and emit job:received/completed/failed and payment:received from the poll/process loop.
- **ServiceDirectory data model and validation diverge (Set<address> + checksum + name/address validation vs single-entry name registry)** `behavior-diff`
  - TS serviceDirectory maps service→Set<checksummed address>, validates the service name (validateServiceName), validates the provider with isValidAddress and normalizes via ethers.getAddress, supports multiple providers per service, findProviders returns [] (graceful) on invalid name, and exposes register/unregister/findProviders/getServices/clear/size as a SINGLETON (ServiceDirectory.ts:23-132). Python ServiceDirectory maps name→single ServiceEntry, performs NO address validation and NO checksum, raises ValueError on duplicate name (TS silently dedups via Set), and is instance-based (the singleton is via get_global_directory). API names differ (findProviders vs find/find_by_capability, getServices vs list_names). Security notes H-2/H-5 (name/address poisoning prevention) are not enforced in the Python directory.
  - TS: `level0/ServiceDirectory.ts:39-132` · PY: `level0/directory.py:140-376`
  - Fix: Provide a TS-parity service directory keyed service→set of validated/checksummed addresses with validateServiceName + isValidAddress, exported as a singleton named serviceDirectory; keep the richer ServiceQuery registry as a separate component.

### core-client

- **ACTPClient lacks client-level state-transition methods startWork/deliver/release/getStatus** `missing-method`
  - TS ACTPClient exposes startWork(txId), deliver(txId, disputeWindowSeconds?), release(escrowId, attestationUID?), getStatus(txId) as first-class client methods that fire settle-on-interact, route through SmartWalletRouter when AA is active (batching startWork+deliver, settling via Paymaster, reporting ERC-8004 reputation on release), and fall back to runtime.transitionState on EOA/mock. Python ACTPClient has NONE — callers reach into client.standard.transition_state / client.runtime.transition_state directly (level1/agent.py, level0/request.py/provider.py). Result: no client-level Smart-Wallet routing, no automatic ERC-8004 reputation on release, no deliver() two-step recovery, no x402-stateless status hint.
  - TS: `ACTPClient.ts:1419-1441 (getStatus), 1475 (startWork), 1507 (deliver), 1577 (release)` · PY: `client.py:121-855 (ABSENT)`
  - Fix: Port start_work/deliver/release/get_status onto Python ACTPClient with SmartWalletRouter routing, settle-on-interact triggers, deliver-batch, and release-time ReputationReporter.report_settlement.
- **release() does not report ERC-8004 reputation; ACTPClient holds no ReputationReporter** `missing-method`
  - TS create() builds a ReputationReporter (testnet/mainnet) and release() fires reputationReporter.reportSettlement({agentId, txId}) non-blocking when the tx carried an agentId; TS also exposes getReputationReporter(). Python ACTPClient never constructs/stores a ReputationReporter and has no release(), so client-path on-chain ERC-8004 reputation is never written. (ReputationReporter exists in agirails.erc8004 but is not wired into the client.)
  - TS: `ACTPClient.ts:1054-1058, 1594-1613, 1670-1672` · PY: `client.py:599-653 (_create_blockchain_runtime builds no reporter); getReputationReporter ABSENT`
  - Fix: Construct ReputationReporter in _create_blockchain_runtime, store on client, add get_reputation_reporter() and fire report_settlement from a new release().
- **create() lacks AgentRegistry / lazy-publish / buyer-link gate for gas sponsorship** _[AIP-18]_ `behavior-diff`
  - TS create() (testnet/mainnet, wallet auto) reads on-chain AgentRegistry state, loads pending-publish and buyer-link markers, and only grants the gas-sponsored AutoWalletProvider when configHash != ZERO OR pending publish exists OR a linked buyer marker exists (AIP-18 DEC-8), else falls back to EOAWalletProvider with a warning. On registry-check failure it fails open only if pending/buyer-link, else fails closed to EOA. Python create() builds AutoWalletProvider UNCONDITIONALLY whenever wallet=='auto' (never falls back to EOA), would request Paymaster sponsorship for unregistered/unpublished agents, never loads buyer-link/pending-publish, never detects lazy scenario, never deletes stale pending (scenario C).
  - TS: `ACTPClient.ts:918-1006` · PY: `client.py:288-296, 382-479`
  - Fix: Port getOnChainAgentState + detectLazyPublishScenario + loadBuyerLink + loadPendingPublish gate into Python create(); fall back to EOAWalletProvider when gate fails; delete stale pending.
- **create() has no lazy-publish activation pipeline; getActivationCalls() missing** `missing-method`
  - TS create() computes lazyScenario/pendingPublish/agentRegistryAddress/erc8004IdentityRegistryAddress + a staleness flag (recomputing AGIRAILS.md config hash), stores them, and exposes getActivationCalls() returning SmartWalletCall[] (buildActivationBatch) prepended to the first payment UserOp plus an onSuccess that deletes pending-publish. Python ACTPClient stores none of this and has no getActivationCalls(); first-payment on-chain activation (register/setConfig/list/mint-identity) is never threaded through the client. (Python lazy logic lives only in cli/commands/publish.py.)
  - TS: `ACTPClient.ts:1088-1117, 1696-1736` · PY: `client.py (ABSENT); lazy logic only in cli/commands/publish.py:57,211-217`
  - Fix: Thread lazyScenario/pendingPublish/registry+identity addresses through Python create() and add get_activation_calls() returning AA calls + onSuccess delete.
- **No non-blocking config drift detection / auto-sync on startup** `missing-method`
  - TS create() fires client.checkConfigDrift(config) (non-mock, non-blocking): resolves identity {slug}.md via .actp/config.json, skips buyers (intent: pay), and when ACTP_AUTO_SYNC != 0/false with a slug present runs reconcile() to pull newer web edits into the local file (snapshot-safe) or warn 'Local config ahead'; with auto-sync off does warning-only drift detection (computeConfigHash vs on-chain configHash, template-mode messaging, 'Run: actp diff'). Python ACTPClient has no checkConfigDrift, no ACTP_AUTO_SYNC handling, no startup reconcile/drift messaging.
  - TS: `ACTPClient.ts:1119-1124, 1753-1869` · PY: `client.py:218-380 (no drift call); checkConfigDrift ABSENT`
  - Fix: Port checkConfigDrift with ACTP_AUTO_SYNC handling, identity-pointer resolution, buyer skip, reconcile/diff messaging; call fire-and-forget from create() for non-mock.
- **getBalance() returns formatted USDC string in Python vs wei string in TS** `signature-diff`
  - TS ACTPClient.getBalance(address) returns raw balance in USDC wei as a string ('1000000000'), delegating to runtime.getBalance. Python get_balance(address=None) formats via USDC.from_wei and returns a human string like '100.00'. Different units/semantics for the same method name — TS-ported code expecting wei will misbehave. Python also makes address optional (defaults to requester); TS requires it.
  - TS: `ACTPClient.ts:1308-1315` · PY: `client.py:822-840`
  - Fix: Return wei string for parity (or add a separate get_formatted_balance); align the address-required signature or document divergence.
- **reset() re-mints $1M USDC and mock create() auto-mints; TS does neither** `behavior-diff`
  - Python _create_mock_runtime auto-mints '1000000000000' ($1M USDC) to the requester on every mock client creation, and reset() re-mints the same after clearing state. TS create() in mock mode mints nothing and reset() only calls runtime.reset() with no re-mint — tests must mint explicitly. Silently changes starting balances for any balance-sensitive flow ported from TS, and is an undocumented extra fund injection.
  - TS: `ACTPClient.ts:789-813, 1214-1226` · PY: `client.py:580-597, 779-793`
  - Fix: Remove auto-mint from mock create() and re-mint from reset() for parity, or gate behind an explicit opt-in flag.
- **SettleOnInteract wired without releaseRouter (no Paymaster settlement for AA providers)** `behavior-diff`
  - TS constructs SettleOnInteract(runtime, requesterAddress, undefined, this.standard) — passing StandardAdapter as releaseRouter so AA-enabled providers settle expired DELIVERED txs through SmartWalletRouter/Paymaster instead of reverting on raw-EOA gas. Python SettleOnInteract has no release_router parameter (def __init__(self, runtime, provider_address, cooldown_s)) and the client constructs it with only 2 args, so the background sweep can only call runtime.release_escrow directly — which reverts for gasless AA providers.
  - TS: `ACTPClient.ts:711-716; settle/SettleOnInteract.ts:39-44` · PY: `client.py:188; settle/settle_on_interact.py:32-40`
  - Fix: Add release_router param to Python SettleOnInteract and pass self._standard from the client; route sweep releases through it when AA is active.
- **AIP-16 secure delivery channel module entirely absent in Python** _[AIP-16]_ `missing-module`
  - TS ships src/delivery/ (channel.ts, crypto.ts, eip712.ts, envelopeBuilder.ts, keys.ts, nonce-keys.ts, setupBuilder.ts, validate.ts, MockDeliveryChannel.ts, RelayDeliveryChannel.ts, types.ts, channelLog.ts, index.ts) implementing AIP-16 encrypted delivery envelopes, EIP-712 signing, key derivation, nonce-keys, AAD binding, Mock+Relay channels. Python src/agirails/ has NO delivery/ directory. While its own subsystem, it is consumed via the client/run flow, so total absence is a parity gap for the client-driven secure-delivery path. (TS index.ts does not re-export the channel either, but runtime code uses it.)
  - TS: `src/delivery/ (full module)` · PY: `src/agirails/delivery/ (ABSENT)`
  - Fix: Port the AIP-16 delivery module (crypto, eip712, envelopeBuilder, keys, nonce-keys, setupBuilder, validate, Mock+Relay channels) to Python.
- **AIP-18 buyer-link config marker absent in Python (only pending_publish present)** _[AIP-18]_ `missing-module`
  - TS config/buyerLink.ts (loadBuyerLink/BuyerLink) provides the buyer-link gate marker letting a pure buyer (intent: pay) get gasless AA sponsorship without registering on-chain (AIP-18 DEC-8), consumed in create(). Python config/ has pending_publish.py but no buyer_link.py, so the buyer-link signal cannot be loaded and the gasless-buyer path in create() cannot be honored.
  - TS: `ACTPClient.ts:66,937-942,969-971; config/buyerLink.ts` · PY: `config/pending_publish.py present; config/buyer_link.py ABSENT`
  - Fix: Port buyerLink.ts (load_buyer_link + BuyerLink) and wire it into the create() gate and drift skip.
- **X402Adapter auto-registration uses legacy direct-transfer instead of x402 v2 EIP-712** `behavior-diff`
  - TS auto-registers a real x402 v2 X402Adapter gated on walletProvider.signTypedData (EIP-712 / Permit2; defaults maxAmountPerTx $1, autoApprovePermit2, maxAuthorizationValidSec 300). Python _maybe_register_x402 gates on send_transaction and wires the LEGACY direct-transfer variant (USDC.transfer calldata via send_transaction) — a different on-chain payment mechanism and security posture (no EIP-712 authorization, no Permit2, no per-tx amount cap defaults). Python comments acknowledge this divergence.
  - TS: `ACTPClient.ts:679-699` · PY: `client.py:371-577`
  - Fix: Implement an x402 v2 EIP-712/Permit2 adapter in Python and auto-register it when wallet provider exposes sign_typed_data, matching TS gating and defaults.

### adapters

- **AdapterMetadata missing name, requires_identity, settlement_mode, supported_identity_types** `missing-param`
  - TS AdapterMetadata has id,name,usesEscrow,supportsDisputes,requiresIdentity,supportedIdentityTypes?,settlementMode(explicit|timed|atomic),priority. Python has only id,priority,uses_escrow,supports_disputes,release_required. Missing name, requires_identity, settlement_mode, supported_identity_types; Python adds release_required (TS derives from settlementMode not atomic). Python cannot express explicit/timed/atomic settlement in metadata.
  - TS: `sdk-js/src/types/adapter.ts:28-71` · PY: `python-sdk-v2/src/agirails/adapters/types.py:31-53`
  - Fix: Add name, requires_identity, settlement_mode Literal, supported_identity_types; set per adapter (basic/standard explicit, x402 atomic).
- **Python IAdapter Protocol omits the ACTP lifecycle contract** `missing-method`
  - TS IAdapter mandates metadata,pay,canHandle,validate,getStatus,startWork,deliver,release plus isAdapter() guard, TransactionStatus type, AdapterTransactionState union. Python IAdapter Protocol declares only metadata,can_handle,validate,pay; no is_adapter guard, no TransactionStatus, no AdapterTransactionState. Router/registry cannot rely on lifecycle methods.
  - TS: `sdk-js/src/adapters/IAdapter.ts:29-292` · PY: `python-sdk-v2/src/agirails/adapters/i_adapter.py:23-106`
  - Fix: Extend Protocol with get_status/start_work/deliver/release; add TransactionStatus dataclass, AdapterTransactionState Literal, is_adapter() guard.
- **BasicAdapter missing IAdapter lifecycle methods** `missing-method`
  - TS BasicAdapter implements getStatus() (TransactionStatus + dispute-window-ends), startWork(), deliver() (auto-encodes tx.disputeWindow when proof omitted), release() SmartWalletRouter-aware. Python BasicAdapter implements none (only pay, check_status, get_transaction, get_balance). A Python basic-adapter caller cannot drive IN_PROGRESS/DELIVERED/SETTLED via the adapter.
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:490-592` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:94-365`
  - Fix: Add get_status/start_work/deliver(auto-encode proof)/release routing through SmartWalletRouter.
- **StandardAdapter missing IAdapter lifecycle wrappers** `missing-method`
  - TS StandardAdapter implements getStatus(),startWork(),deliver(),release() (release extracts txId then releaseEscrow w/ attestation), SmartWalletRouter-aware. Python StandardAdapter exposes granular create_transaction/link_escrow/transition_state/release_escrow but NOT the IAdapter-shaped get_status/start_work/deliver/release. Polymorphic IAdapter callers cannot use it.
  - TS: `sdk-js/src/adapters/StandardAdapter.ts:590-691` · PY: `python-sdk-v2/src/agirails/adapters/standard.py:111-521`
  - Fix: Add get_status/start_work/deliver/release wrappers delegating to transition_state/release_escrow, matching TS proof-encoding + SmartWalletRouter.
- **BasicAdapter.pay and StandardAdapter.pay return non-UnifiedPayResult shapes** `signature-diff`
  - TS both return UnifiedPayResult (txId,escrowId,adapter,state,success,amount formatted,releaseRequired true,provider,requester,deadline ISO,erc8004AgentId). Python BasicAdapter.pay->BasicPayResult (tx_id,escrow_id,state,amount raw wei,deadline int); Python StandardAdapter.pay->plain dict. Both omit adapter,success,release_required,provider,requester,formatted amount,ISO deadline,erc8004_agent_id (needed for reputation reporting).
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:370-413; StandardAdapter.ts:481-532` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:136-272; standard.py:136-170`
  - Fix: Introduce a UnifiedPayResult dataclass and return it from both pay() methods (formatted amount, ISO deadline, adapter id, success, release_required, provider, requester, erc8004_agent_id).
- **BasicAdapter does not route URL recipients (no routeUrlPayment / activation provider)** _[AIP-12]_ `behavior-diff`
  - TS BasicAdapter.pay() detects HTTPS targets and forwards to activationProvider.routeUrlPayment(); it also threads lazy-publish activation calls (getActivationCalls/onSuccess) into payACTPBatched on first payment and deletes pending-publish on success. Python BasicAdapter.pay() has no URL detection (validate_address raises on a URL) and no activation/lazy-publish wiring in the batched path (agent_id hardcoded 0). Direct client.basic.pay with a URL fails; first-payment lazy-publish is not batched through basic.
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:35-38,220-270,370-432` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:136-235`
  - Fix: Add activation-call provider hook: route HTTPS recipients to the client router, prepend lazy-publish activation calls into pay_actp_batched on first payment with onSuccess cleanup.
- **BasicAdapter/StandardAdapter do not enforce maxTransactionAmount cap** `missing-method`
  - TS BasicAdapter.payBasic and StandardAdapter.createTransaction enforce runtime.maxTransactionAmount and throw a message about unaudited contracts. Python BasicAdapter.pay and StandardAdapter.create_transaction never reference maxTransactionAmount, so the mainnet safety cap is absent.
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:205-214; StandardAdapter.ts:165-174` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:136-235; standard.py:172-230`
  - Fix: Expose runtime.max_transaction_amount and enforce it in both Python create paths with the same message.
- **StandardAdapter.create_transaction lacks the SmartWallet gasless createACTPTransaction route** _[AIP-12]_ `behavior-diff`
  - TS StandardAdapter.createTransaction routes through walletProvider.createACTPTransaction (gasless UserOp, computeServiceHash from serviceDescription) when SmartWalletRouter active, else EOA/mock. Python create_transaction always uses the runtime path (no SmartWallet branch), so standard-adapter creation is not gasless even with a wallet provider. Python link_escrow/accept_quote/transition_state/release_escrow DO have SmartWallet routes; only create_transaction is missing it.
  - TS: `sdk-js/src/adapters/StandardAdapter.ts:176-205,702-710` · PY: `python-sdk-v2/src/agirails/adapters/standard.py:172-230`
  - Fix: Add the SmartWalletRouter createACTPTransaction gasless route, computing serviceHash identically (empty to ZERO, valid hash passthrough, raw to keccak256 utf8).
- **StandardAdapter.link_escrow lacks RPC-propagation retry-backoff** `behavior-diff`
  - TS linkEscrow retries getTransaction with 0/500/1000/2000ms backoff to tolerate load-balanced public-RPC propagation lag before throwing not-found. Python link_escrow does a single get_transaction and immediately raises TransactionNotFoundError if null, causing spurious failures against load-balanced RPCs right after create_transaction.
  - TS: `sdk-js/src/adapters/StandardAdapter.ts:249-283` · PY: `python-sdk-v2/src/agirails/adapters/standard.py:260-303`
  - Fix: Add the same bounded retry-with-backoff (0/500/1000/2000ms) around get_transaction in link_escrow.
- **UnifiedPayParams missing dispute_window, http_method, http_body, http_headers** `missing-param`
  - TS UnifiedPayParams includes disputeWindow?(validated 3600..30d), httpMethod?, httpBody?, httpHeaders? letting client.pay set a custom dispute window and drive x402 paid POST/PUT. Python UnifiedPayParams lacks all four (HTTP options live only on the separate X402PayParams subclass). So client.pay() cannot set a dispute window or send an x402 paid POST with a body.
  - TS: `sdk-js/src/types/adapter.ts:131-210` · PY: `python-sdk-v2/src/agirails/adapters/types.py:104-125`
  - Fix: Add dispute_window, http_method, http_body, http_headers to UnifiedPayParams; have adapters honor them.
- **BasicAdapter.pay always uses default dispute window; ignores caller value** `behavior-diff`
  - TS BasicAdapter.payBasic reads and validates params.disputeWindow. Python BasicAdapter.pay hardcodes dispute_window = validate_dispute_window(None) (always 172800s) and BasicPayParams has no dispute_window field. A Python basic caller cannot set the dispute window, changing on-chain DELIVERED proof and release timing vs TS.
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:45-57,192` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:56-72,184-185`
  - Fix: Add dispute_window to BasicPayParams/UnifiedPayParams and pass it through validate_dispute_window.

### delivery-aip16

- **Entire AIP-16 delivery subsystem absent in Python** _[AIP-16]_ `missing-module`
  - TS ships a full 14-file `src/delivery/` encrypted delivery channel (types, eip712, keys, crypto, nonce-keys, validate, setupBuilder, envelopeBuilder, channel, channelLog, MockDeliveryChannel, RelayDeliveryChannel) re-exported as the `@agirails/sdk/delivery` subpath. Python has none of it; the only 'delivery' file is AIP-4 delivery_proof.py (a different protocol). A Python buyer/provider cannot participate in the AIP-16 secure delivery flow at all.
  - TS: `sdk-js/src/delivery/index.ts:1-229` · PY: `ABSENT`
  - Fix: Create `src/agirails/delivery/` package mirroring the 14 TS files (types, eip712, keys, crypto, nonce_keys, validate, setup_builder, envelope_builder, channel, channel_log, mock_delivery_channel, relay_delivery_channel, __init__). Add an x25519-capable dep (`cryptography` for X25519+HKDF+AES-GCM, all three are in `cryptography.hazmat`). Port byte-for-byte.
- **DeliverySetupBuilder (build/verify/computeHash) missing** _[AIP-16]_ `missing-class`
  - TS DeliverySetupBuilder: async build(params) signs DeliverySetupWireV1 (defaults: expiresInSec=3600, acceptedChannels=['agirails-relay-v1'], skew 900s); enforces signerAddress==signer.getAddress(), public→pubkey must be canonical-empty, encrypted→must NOT be; static verify (6-step order: shape→chain→kernel→sig→skew→expiry with stable codes setup_*); static computeHash=keccak256(canonicalJson(signed)). Python absent.
  - TS: `sdk-js/src/delivery/setupBuilder.ts:121-143,370-749` · PY: `ABSENT`
  - Fix: Port DeliverySetupBuilder with same defaults, validation order, error codes, and canonicalJson computeHash (canonical_json_dumps already exists in Python utils).
- **DeliveryEnvelopeBuilder (buildPublic/buildEncrypted/verify/decryptPayload/verifyAndDecrypt/computeHash) missing** _[AIP-16]_ `missing-class`
  - TS DeliveryEnvelopeBuilder: async buildPublic and buildEncrypted (full ECDH+HKDF+AES-GCM+AAD pipeline, returns BuildEnvelopeResult{wire,bodyBytes,blobKey}); static verify (7-step order incl. scheme-aware payloadHash recompute, signature recovery, timestamp skew last); static decryptPayload (ECDH with buyer priv key, rebuild AAD, GCM decrypt, JSON.parse); static verifyAndDecrypt; static computeHash. Python absent.
  - TS: `sdk-js/src/delivery/envelopeBuilder.ts:486-1148` · PY: `ABSENT`
  - Fix: Port both build paths and all static verify/decrypt helpers with identical step ordering and structured error codes (envelope_*).
- **DeliveryChannel abstraction + Mock/Relay implementations missing** _[AIP-16]_ `missing-class`
  - TS channel.ts DeliveryChannel interface (publishSetup/publishEnvelope/subscribeSetups/subscribeEnvelopes + optional getSetups/getEnvelopes/close) with dedup-after-verify and subscriber-error-isolation invariants; MockDeliveryChannel (in-process loopback, MockDeliveryChannelOptions); RelayDeliveryChannel (HTTP against /api/v1/delivery[/setup], POLL_INTERVAL_MS=1000, REQUEST_TIMEOUT_MS=8000, SSRF guard via assertSafePeerUrl, cursor pagination, RelayDeliveryChannelOptions{baseUrl,relayId,pollIntervalMs,requestTimeoutMs,allowPrivateHosts,log}); channelLog LogFn+noopLog. Python absent.
  - TS: `sdk-js/src/delivery/channel.ts:199-313; MockDeliveryChannel.ts:95-507; RelayDeliveryChannel.ts:62-372; channelLog.ts:100-130` · PY: `ABSENT`
  - Fix: Port abstract DeliveryChannel (Protocol/ABC), MockDeliveryChannel, RelayDeliveryChannel (httpx, same endpoints/cursor/timeouts/SSRF guard) and LogFn/noop_log. Reuse existing Python SSRF helper from negotiation RelayChannel if present.
- **Delivery runtime validators (validate.ts) missing** _[AIP-16]_ `missing-method`
  - validate.ts pure validators: isValidBytes32/12/16, isValidAddress, isValidUintString, isValidScheme/Privacy/Role, isCanonicalEmptyBytes32/12/16, validateSetupSigned/Wire, validateEnvelopeSigned/Wire, validateSchemeConsistency, ValidationResult; stable snake_case error identifiers (e.g. setup_txid_invalid, envelope_nonce_invalid); caps MAX_ACCEPTED_CHANNELS=32, MAX_CHANNEL_ID_LENGTH=256; signature shape 0x+130 hex. Python absent.
  - TS: `sdk-js/src/delivery/validate.ts:178-751` · PY: `ABSENT`
  - Fix: Port all validators returning {ok,error} with identical error identifiers and the same caps/regex bounds.
- **Per-builder nonce key constants missing** _[AIP-16]_ `missing-class`
  - DELIVERY_NONCE_KEY_SETUP='agirails.delivery.setup.v1' and DELIVERY_NONCE_KEY_ENVELOPE='agirails.delivery.envelope.v1' — distinct from each other and from AIP-4 'agirails.delivery.v1' for cross-feature/per-builder replay separation. Python absent.
  - TS: `sdk-js/src/delivery/nonce-keys.ts:73,86` · PY: `ABSENT`
  - Fix: Define the two literal constants and thread DELIVERY_NONCE_KEY_SETUP into the Python NonceManager in the setup builder.
- **DeliveryErrorCode taxonomy + DeliveryCryptoError/DeliveryEip712Error classes missing** _[AIP-16]_ `missing-class`
  - TS defines 28 stable DeliveryErrorCode strings (envelope_*, setup_*, crypto_*, channel_*) plus DeliveryError value shape, DeliveryCryptoError (code+details) and DeliveryEip712Error (code+details). These codes are machine-actionable and surfaced to callers; Python has none, so error parity for delivery flows is impossible.
  - TS: `sdk-js/src/delivery/types.ts:690-755; keys.ts:155-173; eip712.ts:191-205` · PY: `ABSENT`
  - Fix: Port the DeliveryErrorCode literal set, the DeliveryError shape, and the two exception classes with code+details attributes.
- **chainIdForNetwork mapping + mock-rejection missing** _[AIP-16]_ `missing-method`
  - chainIdForNetwork: base-sepolia→84532, base-mainnet→8453, mock→throws MOCK_NETWORK_NOT_SUPPORTED (refuses to sign a placeholder chainId). buildDeliveryDomain validates positive-int chainId and valid kernel address. Python absent.
  - TS: `sdk-js/src/delivery/eip712.ts:235-330` · PY: `ABSENT`
  - Fix: Port chain_id_for_network and build_delivery_domain with the same mock-throws behavior and validation.
- **Agent (level1) provider-side delivery hook missing in Python** _[AIP-16]_ `missing-method`
  - TS level1/Agent.ts wires delivery into processJob: AgentConfig gains deliveryChannel, deliverySigner, kernelAddress, chainId, smartWalletNonce; on DELIVERED transition the agent builds (public or encrypted) a DeliveryEnvelopeWireV1 for the handler result and publishes it on the channel. Python level1/agent.py has no delivery integration (only AIP-4 delivery-proof handling at agent.py:519).
  - TS: `sdk-js/src/level1/Agent.ts:28-29,175-245,448-460` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/level1/agent.py:519`
  - Fix: After porting the delivery package, add the same optional config fields and processJob publish hook to Python Agent.
- **CLI requester-side delivery flow (setup POST + envelope subscribe + decrypt) missing in Python** _[AIP-16]_ `missing-method`
  - TS cli/lib/runRequest.ts: requester generates ephemeral keypair, signs+POSTs DeliverySetupWireV1 (between createTransaction and settle), subscribes to envelopes in parallel with state polling, and verifyAndDecrypt's the body when one arrives within an envelope grace period (settlement never blocked). RunRequestResult also exposes receiptUrl/V3 framing. Python CLI request path has no delivery surface.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:50-160` · PY: `ABSENT`
  - Fix: Port the requester delivery wiring into the Python CLI request command (setup builder, channel subscribe, verify_and_decrypt) with the same grace-period/non-blocking semantics.

### cli

- **Python CLI has no .env auto-load at bootstrap** _[AIP-18]_ `behavior-diff`
  - TS index.ts:28-36 loads `.env` from cwd via dotenv (override:false) before any command runs, so the auto-generated ACTP_KEY_PASSWORD written by `actp init` is picked up by every downstream command (publish, test, balance) without sourcing. Python main.py has no dotenv load; secrets must be exported in the shell. Combined with init.py not writing .env, the entire AIP-18 4.6.2 zero-config password flow is absent.
  - TS: `sdk-js/src/cli/index.ts:21-36` · PY: `python-sdk-v2/src/agirails/cli/main.py:1-204 (ABSENT)`
  - Fix: Add `from dotenv import load_dotenv; load_dotenv(Path.cwd()/'.env', override=False)` at top of main.py (wrap in try/except).
- **`actp agent` command entirely missing in Python** `missing-method`
  - TS registers createAgentCommand (agent.ts, 256 LOC): channel-driven provider daemon (RelayChannel + ProviderOrchestrator), on-chain INITIATED sweep via getTransactionsByProvider, auto-quote per ProviderPolicy with multi-round counter handling, ZeroHash Level-0 skip, public-RPC warning. Python has no agent.py and main.py does not register it. Python serve.py even documents that on-chain INITIATED detection is 'handled by actp agent' but that command does not exist in Python, so on-chain provider pickup has no CLI entrypoint at all.
  - TS: `sdk-js/src/cli/commands/agent.ts:36-256; index.ts:170` · PY: `python-sdk-v2/src/agirails/cli/commands/ (no agent.py); main.py (ABSENT)`
  - Fix: Port agent.ts to commands/agent.py + register in main.py. Requires ProviderOrchestrator + RelayChannel + serviceNameForHash + usingPublicRpc parity.
- **RunRequestResult lacks receipt_url and delivery_error; no buyer-side receipt push** _[AIP-16]_ `missing-method`
  - TS RunRequestResult has receiptUrl (via pushReceiptOnSettled on SETTLED for real networks) and deliveryError. The V3 framed receipt + 'Receipt: <url>' wow-artifact depend on it. Python RunRequestResult only has tx_id/final_state/elapsed_ms/settled/payload — no receipt_url, no delivery_error — and run_request never calls any receipt-push. So `actp request`/`actp test` in Python can never surface a clickable receipt URL.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:227-265,721-775` · PY: `python-sdk-v2/src/agirails/cli/lib/run_request.py:56-63,241-247`
  - Fix: Add receipt_url + delivery_error fields to RunRequestResult; port receipts/push.pushReceiptOnSettled and call it after settle on testnet/mainnet.
- **AIP-18 buyer identity scaffold + one-command wow flow missing from init** _[AIP-18]_ `missing-method`
  - TS init.ts --intent pay writes a private pay-only {slug}.md (generateBuyerIdentityFile: name/intent:pay/servicesNeeded/budget/wallet, DEC-4) and the post-init handler chains runPublish (buyer link + 1k test USDC mint) -> runTest, so `actp init --mode testnet --intent pay --test` is a single end-to-end settled-escrow command. Python init.py has no --intent, no --scaffold, no buyer file generation, and no post-init test/publish chaining. The buyer onboarding wow flow does not exist.
  - TS: `sdk-js/src/cli/commands/init.ts:482-515,665-843` · PY: `python-sdk-v2/src/agirails/cli/commands/init.py (ABSENT)`
  - Fix: Add --intent/--service/--price/--scaffold/--wallet/--test/--no-test options; port generateBuyerIdentityFile + offerPostInitTest + runScaffold templates.
- **diff/pull not buyer-aware (intent:pay)** _[AIP-18]_ `behavior-diff`
  - TS diff.ts/pull.ts detect a V4 intent:pay file and short-circuit to status:'buyer-local' (inSync/hasOnChainConfig=false, budget-private note) instead of doing a misleading on-chain diff. They also resolve the .actp identity pointer when the path is the default. Python diff.py/pull.py have no buyer branch and no identity-pointer resolution — a pay-only buyer gets a confusing 'no-remote / run publish' result.
  - TS: `sdk-js/src/cli/commands/diff.ts:66-108; sdk-js/src/cli/commands/pull.ts:77-111` · PY: `python-sdk-v2/src/agirails/cli/commands/diff.py:43-144; pull.py:30-143`
  - Fix: Add V4 intent:pay detection (buyer-local result) + resolve_identity_path() default-path handling to diff.py and pull.py.
- **`actp request` does not wire AIP-16 delivery channel or render V3 receipt** _[AIP-16]_ `behavior-diff`
  - TS request.ts constructs a RelayDeliveryChannel + expectedKernelAddress/expectedChainId/deliveryPrivacy:'public', resolves agirails.app slug URLs to addresses, and renders renderReceiptV3 + receiptUrl. Python request.py calls run_request without any delivery args (they don't exist), does not resolve slug URLs (explicitly deferred to '3.1'), and prints only the reflection text — no V3 framed receipt, no receipt URL.
  - TS: `sdk-js/src/cli/commands/request.ts:38-50,109-158,213-228,251-254` · PY: `python-sdk-v2/src/agirails/cli/commands/request.py:43-176`
  - Fix: After porting run_request delivery surface + renderReceiptV3, wire them into request.py and add slug URL resolution mirroring pay.py/discoverAgents.
- **`actp pay` missing --service rejection, --dispute-window, and slug URL resolution** `missing-param`
  - TS pay.ts rejects --service with the canonical PAY_SERVICE_REJECTION_MESSAGE and exit 64 (EX_USAGE) to route users to `actp request`; supports -w/--dispute-window (default 172800); and resolves agirails.app/a/<slug> URLs to wallet addresses via discoverAgents. Python pay.py has --description (not in TS pay), no --service handling, no --dispute-window, and no slug resolution.
  - TS: `sdk-js/src/cli/commands/pay.ts:24-32,69-122` · PY: `python-sdk-v2/src/agirails/cli/commands/pay.py:31-44,100-122`
  - Fix: Add --dispute-window option, --service interception (exit 64 + directive), and slug URL resolution to pay.py. Reconcile --description (port to TS or drop from Python).
- **`actp tx` lacks create/deliver/settle/cancel ergonomic subcommands** `missing-method`
  - TS tx has create/status/list/deliver/settle/cancel. tx deliver auto-applies COMMITTED->IN_PROGRESS->DELIVERED (idempotent) and tx status shows fee breakdown for SETTLED + canAccept/canComplete/canDispute actions. Python tx has only status/list/transition (a raw single-state transition). Buyers/providers on Python must hand-drive each intermediate state via `tx transition` and get no fee breakdown or action hints.
  - TS: `sdk-js/src/cli/commands/tx.ts:24-36,120-201,304-491` · PY: `python-sdk-v2/src/agirails/cli/commands/tx.py:33-264`
  - Fix: Add tx create/deliver/settle/cancel subcommands; deliver should auto-apply IN_PROGRESS; status should compute fee breakdown + available actions.
- **`actp sync` command missing in Python** `missing-method`
  - TS registers createSyncCommand (sync.ts): bidirectional reconcile of local/web/chain (newest wins, loser snapshotted), then publishes the winning config unless --no-publish; options [path] -n/--network -a/--address -s/--slug --no-publish. Python has no sync.py and main.py does not register sync.
  - TS: `sdk-js/src/cli/commands/sync.ts:24-40; index.ts:139` · PY: `python-sdk-v2/src/agirails/cli/commands/ (no sync.py); main.py (ABSENT)`
  - Fix: Port sync.ts to commands/sync.py using config/sync_operations.reconcile; register in main.py.
- **V3 framed ceremonial receipt (renderReceiptV3) not ported** `missing-method`
  - TS receipt.ts exports renderReceiptV3 (FIX-5 wow-path framed receipt with perspective buyer|provider, counterparty, reflection, receiptUrl) used by test.ts and request.ts. Python receipt.py only has render_receipt (V2 wrapper) — no V3, no perspective, no framed output. Even if test/request were upgraded, there is no V3 renderer to call.
  - TS: `sdk-js/src/cli/commands/receipt.ts:201-339` · PY: `python-sdk-v2/src/agirails/cli/commands/receipt.py:77`
  - Fix: Port renderReceiptV3 + ReceiptDataV3 (perspective/counterparty/reflection/receiptUrl) to receipt.py.

### negotiation

- **NegotiationChannel transport abstraction entirely missing** _[AIP-2.1]_ `missing-module`
  - TS defines the NegotiationChannel interface (post/subscribeTxId/subscribeAgent/close), the NegotiationMessage discriminated union (agirails.quote.v1/counteroffer.v1/counteraccept.v1), Subscription, DeliveredMessage, and type guards isQuoteEnvelope/isCounterOfferEnvelope/isCounterAcceptEnvelope/envelopeTxId/envelopeChainId. This is the single transport bus that funnels ALL AIP-2.1 §6 message flow so EIP-712 verification + dedup live in one place. Python has no NegotiationChannel concept at all — only a receive-side server/quote_channel.py handler for counter-offers (no post, no subscribe, no agent firehose, no quote/counteraccept handling).
  - TS: `sdk-js/src/negotiation/NegotiationChannel.ts:41-174` · PY: `ABSENT`
  - Fix: Port NegotiationChannel.ts: define the message union + Subscription + DeliveredMessage Protocol/ABC, the three type guards, and envelope_tx_id/envelope_chain_id helpers. This is the foundation the buyer/provider orchestrators subscribe to.
- **MockChannel (in-memory test transport) missing** _[AIP-2.1]_ `missing-class`
  - TS ships MockChannel implementing NegotiationChannel for in-memory two-party message exchange with identical EIP-712 verify (QuoteBuilder/CounterOfferBuilder/CounterAcceptBuilder.verify), dedup-after-verify ordering, microtask fan-out, message replay on subscribe, and test introspection helpers (getAllMessages/getMessagesForTxId/activeSubscriptionCount). MockChannelConfig has kernelAddressByChainId + skipVerify. Python has no equivalent, so the channel-driven negotiation path cannot even be unit-tested in Python.
  - TS: `sdk-js/src/negotiation/MockChannel.ts:71-232` · PY: `ABSENT`
  - Fix: Port MockChannel with the same dedup-after-verify ordering (verify FIRST, then add signature to delivered set) — the comment at MockChannel.ts:190-195 calls out that dedup-before-verify lets a tampered reused-signature message poison the dedup set and drop the legit one. Replicate exactly.
- **RelayChannel (production polling transport) missing** _[AIP-2.1]_ `missing-class`
  - TS ships RelayChannel implementing NegotiationChannel by polling agirails.app: POST /api/v1/negotiations/{txId}/messages, GET .../messages, GET .../inbox/{agentDid}. RelayChannelConfig: baseUrl (default agirails.app), kernelAddressByChainId, pollIntervalMs, allowInsecureTargets. It enforces Apex audit FIND-011 SSRF guard assertSafePeerUrl(baseUrl) (blocks http/loopback/RFC1918/link-local unless allowInsecureTargets). This is the DEFAULT transport for buyers without endpoints. Python has nothing.
  - TS: `sdk-js/src/negotiation/RelayChannel.ts:40-103` · PY: `ABSENT`
  - Fix: Port RelayChannel including the assertSafePeerUrl SSRF guard (P0 sub-concern) and the same /api/v1/negotiations REST paths, cursor-based polling, and per-chain kernel-address verify-on-receive.
- **ProviderOrchestrator (channel-driven auto-respond) missing** _[AIP-2.1]_ `missing-class`
  - TS ProviderOrchestrator (3.5.0) implements the provider half of AIP-2.1 §6: evaluateRequest()->QuoteDecision, quote() (build+sign QuoteMessage, submitQuote on-chain, post on channel, seed txState), start() (subscribeAgent firehose, auto-accept->build+post CounterAcceptMessage / auto-requote->build+post new QuoteMessage governed by concede strategy & max_requotes / walk), stop(), evaluateCounter() (mandatory verify THEN decide), getPolicy(). Config exposes counterDecider BYO-brain hook + CounterContext/CounterDecision/CounterDecider types. Python's server/policy_engine.evaluate_counter is a STATELESS per-message verdict that explicitly does NOT auto-send replies and does NOT track max_requotes (docstring: 'the operator handles delivery') — i.e. the pre-3.5.0 design. No start()/quote()/channel auto-respond, no requote message emission, no BYO counterDecider.
  - TS: `sdk-js/src/negotiation/ProviderOrchestrator.ts:155-454` · PY: `src/agirails/server/policy_engine.py:57-160 (partial, divergent)`
  - Fix: Port ProviderOrchestrator into negotiation/ with start()/stop()/quote()/evaluateRequest()/evaluateCounter()/getPolicy(), per-tx TxState (lastQuote/requotesUsed/consumerDID), channel auto-respond, and the counterDecider hook. Requires NegotiationChannel + ProviderPolicyEngine.evaluateCounter (concede math) ported first.
- **DecisionEngine.evaluateQuote() + BuyerQuoteDecider BYO-brain missing** _[AIP-2.1]_ `missing-method`
  - TS DecisionEngine has evaluateQuote(quote, policy, roundsUsedSoFar)->QuoteEvaluation {accept|counter(amountBaseUnits)|reject} implementing AIP-2.1 §5.2 accept/counter/reject decision tree in BigInt base units, plus the BuyerQuoteDecider type + QuoteForEvaluation/QuoteEvaluation. Decision tree: quoted>max->reject; final_offer->accept-if-affordable; quoted<=target->accept; rounds exhausted->accept-if-affordable; counter_strategy='walk'->reject; else counter at undercut(target)/midpoint clamped to PLATFORM_MIN 50_000 and strictly < quoted. Uses humanToBaseUnits string-scaling (no Number*1e6). Python DecisionEngine has rank() ONLY — no evaluate_quote, no decider type. Without this the buyer cannot make per-quote counter decisions.
  - TS: `sdk-js/src/negotiation/DecisionEngine.ts:101-105,252-333` · PY: `src/agirails/negotiation/decision_engine.py:71-196 (rank only)`
  - Fix: Add evaluate_quote() to Python DecisionEngine using int (Python ints are arbitrary precision) for base-unit math; replicate the exact decision-tree order and the PLATFORM_MIN=50000 clamp, strict counter<quoted check, target default = max/2. Add a BuyerQuoteDecider Callable type.
- **BuyerOrchestrator channel-driven multi-round negotiation loop missing** _[AIP-2.1]_ `missing-method`
  - TS BuyerOrchestrator runs _runNegotiationRound: opens a NegotiationChannel subscribeTxId per tx, awaits the first quote.v1 on the channel, then loops up to rounds_per_provider: evaluate via decider -> accept (acceptQuote+linkEscrow at provider amount) / reject (CANCELLED) / counter (build+sign CounterOfferMessage, channel.post, await counteraccept.v1 or new quote.v1). Bind-check on counter-accept (txId/inReplyTo==counterHash/acceptedAmount==counterAmount). Python BuyerOrchestrator is the legacy fixed-price polling flow ONLY: waitForState(QUOTED|COMMITTED) then immediately reserve+linkEscrow at the buyer's own offered price — never reads a signed QuoteMessage, never counters, never accepts a provider re-quote. No CounterOfferMessage is ever built or sent.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:534-568,721-965` · PY: `src/agirails/negotiation/buyer_orchestrator.py:404-580 (fixed-price only)`
  - Fix: Port _run_negotiation_round + the message queue/_wait_for_next_message microtask routing + _commit_at_amount. Depends on NegotiationChannel + CounterOfferBuilder + evaluate_quote being ported first.
- **BuyerNegotiationContext + decideQuote constructor arg missing** _[AIP-2.1]_ `missing-param`
  - TS BuyerOrchestrator constructor takes a 5th arg negotiation: BuyerNegotiationContext {signer, kernelAddress, chainId, nonceManager, negotiationChannel, decideQuote} and a 6th arg client?: ACTPClient, plus fail-fast validation: if negotiationChannel set but signer/kernelAddress/chainId missing it THROWS (audit finding G — silent fall-through to fixed-price). Python BuyerOrchestrator constructor is (policy, runtime, requester_address, actp_dir) only — no negotiation context, no decideQuote BYO-brain hook, no client AA-routing arg, no fail-fast validation.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:104-212` · PY: `src/agirails/negotiation/buyer_orchestrator.py:149-165`
  - Fix: Add a BuyerNegotiationContext dataclass + optional decide_quote Callable + optional client param to the Python constructor, with the same missing-field fail-fast error message (lists which of signer/kernel_address/chain_id are missing).
- **ProviderOrchestrator counterDecider BYO-brain hook missing** _[AIP-2.1]_ `missing-param`
  - TS ProviderOrchestratorConfig.counterDecider: CounterDecider lets a host override the accept/reject/requote decision (e.g. an LLM), while signature/band/expiry verify ALWAYS runs first (evaluateCounter calls counterVerifier.verify before consulting the decider). CounterContext surfaces {counter, lastQuoteAmountBaseUnits, requotesUsed, policy}. Python has no ProviderOrchestrator and server/policy_engine.evaluate_counter has no decider injection point at all.
  - TS: `sdk-js/src/negotiation/ProviderOrchestrator.ts:87,107-139,338-362` · PY: `ABSENT`
  - Fix: When porting ProviderOrchestrator, add a counter_decider Callable[[CounterContext], CounterDecision|Awaitable] config field; keep verify mandatory and unconditional before the decider runs.
- **BuyerOrchestrator AA-aware write routing (client.standard.*) missing** _[AIP-12]_ `missing-method`
  - TS BuyerOrchestrator accepts an optional ACTPClient and routes on-chain writes (_createTransaction/_transitionState/_linkEscrow/_acceptQuote) through client.standard.* when present so AGIRAILS Smart Wallets get Paymaster-sponsored gasless UserOps (PRD §5.6 invariant: gasless requesters must never be forced to sign with the raw EOA), with base-unit<->human conversion helpers (_baseUnitsToHuman). Python BuyerOrchestrator writes only directly to self._runtime — no client, no AA routing, so a gasless Python buyer would be forced onto the raw EOA path.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:1144-1219` · PY: `src/agirails/negotiation/buyer_orchestrator.py:362-519 (runtime-only)`
  - Fix: Add optional client param and route writes through client.standard.* when set, falling back to runtime otherwise; port _base_units_to_human for the parseAmount round-trip.

### protocol

- **Kernel missing submitQuote()** _[AIP-2]_ `missing-method`
  - TS ACTPKernel.submitQuote(txId, quoteHash) (ACTPKernel.ts:330-358) validates state==INITIATED, validates quoteHash non-zero bytes32, ABI-encodes ['bytes32'] and transitions INITIATED->QUOTED with the encoded proof. Python ACTPKernel has no submit_quote (grep confirms absent in kernel.py). Provider quote submission via kernel is unavailable in Python; callers must hand-roll transition_state with manually-encoded proof, risking encoding mismatch.
  - TS: `protocol/ACTPKernel.ts:330-358` · PY: `ABSENT (protocol/kernel.py)`
  - Fix: Add async submit_quote(transaction_id, quote_hash) validating non-zero bytes32, eth_abi.encode(['bytes32'],[quote_hash]) then transition_state(txId, QUOTED, proof).
- **Kernel missing getEconomicParams()** `missing-method`
  - TS ACTPKernel.getEconomicParams (ACTPKernel.ts:667-684) reads platformFeeBps(), requesterPenaltyBps(), feeRecipient() in parallel and returns EconomicParams. Python only has get_platform_fee_bps() (kernel.py:898-900); no requester_penalty_bps()/fee_recipient() reader nor a combined economic-params accessor.
  - TS: `protocol/ACTPKernel.ts:667-684` · PY: `protocol/kernel.py:898-900`
  - Fix: Add get_economic_params() returning platform_fee_bps, requester_penalty_bps, fee_recipient (baseFeeDenominator=10000).
- **Kernel getTransaction lacks legacy 16-field BAD_DATA fallback** `behavior-diff`
  - TS getTransaction (ACTPKernel.ts:564-616) catches ethers BAD_DATA / 'could not decode result data' and retries with LEGACY_GET_TRANSACTION_IFACE (16-field tuple) to read older deployments like Base Mainnet kernel 0x132B...2d29, surfacing real txs instead of false TX_NOT_FOUND. Python get_transaction (kernel.py:880-896) only does TransactionView.from_tuple expecting the V3 21-field shape and documents loud-failure on pre-V3 contracts. Reading current Base Mainnet kernel from Python raises a decode error rather than degrading gracefully.
  - TS: `protocol/ACTPKernel.ts:17-19,564-616` · PY: `protocol/kernel.py:233-278,880-896`
  - Fix: Add a legacy 16-field decode fallback (eth_abi.decode against the older tuple) on decode/BAD_DATA error, mapping missing V3 fields to defaults.
- **ProofGenerator missing encodeProof/decodeProof for on-chain proof submission** _[AIP-4]_ `missing-method`
  - TS ProofGenerator.encodeProof (ProofGenerator.ts:140-148) ABI-encodes ['bytes32','bytes32','uint256'] = [txId, contentHash, timestamp] for on-chain proof, and decodeProof (ProofGenerator.ts:151-170) reverses it. Python proofs.py has no encode_proof/decode_proof (grep confirms none). Python cannot produce/consume the canonical on-chain proof bytes the TS path uses.
  - TS: `protocol/ProofGenerator.ts:140-170` · PY: `ABSENT (protocol/proofs.py)`
  - Fix: Add encode_proof/decode_proof using eth_abi with exact ['bytes32','bytes32','uint256'] tuple of (txId, content_hash/keccak, timestamp).
- **ProofGenerator missing verifyDeliverable, hashFromUrl, generateDeliveryProof + URL SSRF guards** _[AIP-4]_ `missing-method`
  - TS ProofGenerator provides generateDeliveryProof (computes keccak contentHash, enforces size/mimeType), verifyDeliverable(deliverable, expectedHash), hashFromUrl(url) with URLValidationConfig (SSRF/private-IP guards, size/timeout caps) (ProofGenerator.ts:98-337). Python ProofGenerator.create_delivery_proof (proofs.py:221-247) only assembles a DeliveryProof dataclass from a pre-computed output_hash; no verify_deliverable, no hash_from_url, and no URL validation. The remote-content hashing + SSRF protection surface is absent.
  - TS: `protocol/ProofGenerator.ts:98-337` · PY: `protocol/proofs.py:221-247`
  - Fix: Port verify_deliverable, hash_from_url with URL validation (block private/loopback IPs, max size + timeout), and generate_delivery_proof computing keccak content hash + size/mimeType.
- **EventMonitor lacks adaptive getLogs chunking + ACTP_SWEEP_BLOCK_WINDOW + ranged history** `behavior-diff`
  - TS EventMonitor.getTransactionHistory accepts a range and uses queryFilterChunked which recursively halves the block window on RPC 'block range too large' errors (isBlockRangeError covering -32600/-32005/'limit exceeded' etc.) and surfaces blockNumber+logIndex for deterministic newest-first selection (EventMonitor.ts:113-207). ACTP_SWEEP_BLOCK_WINDOW is consumed here and in runtime for catch-up sweeps. Python EventMonitor (events.py) uses fixed get_events(from_block,to_block) with no chunking/splitting, no ACTP_SWEEP_BLOCK_WINDOW env var, and no ranged get_transaction_history; on throttled RPCs a wide scan throws and the catch-up sweep cannot run on any RPC the way TS guarantees.
  - TS: `protocol/EventMonitor.ts:113-207` · PY: `protocol/events.py:333-665`
  - Fix: Add adaptive split-on-range-error chunking to get_events, honor ACTP_SWEEP_BLOCK_WINDOW, and add ranged get_transaction_history returning block_number/log_index for newest-first selection.
- **MessageSigner missing signMessage/signQuoteRequest/signQuoteResponse + nonce-tracker replay integration** `missing-method`
  - TS MessageSigner has signMessage(ACTPMessage) with bytes32 nonce-format validation + low-entropy/sequential-nonce warnings (MessageSigner.ts:154-214), signQuoteRequest/signQuoteResponse (219-244), and verifySignature/verifySignatureOrThrow integrating IReceivedNonceTracker for replay protection (275-374), plus didToAddress (EIP-3770) / addressToDID. Python MessageSigner has sign_request/response/delivery_proof/typed_data and verify_signature with EIP-2 low-s reject, but no generic signMessage, no quote-request/response signers, no nonce-format validation/low-entropy warnings, and no ReceivedNonceTracker integration in verify (the tracker exists only in utils, unwired here).
  - TS: `protocol/MessageSigner.ts:154-374` · PY: `protocol/messages.py:344-575`
  - Fix: Add generic sign_message with nonce validation, quote-request/response signers, and wire ReceivedNonceTracker into verify_signature for replay protection to match TS.
- **compute_service_type_hash has SHA256 fallback that silently breaks hash parity** `behavior-diff`
  - Python compute_service_type_hash (agent_registry.py:210-227) returns keccak(text=service_type) only if eth_utils imports; otherwise falls back to hashlib.sha256 of the utf-8 string. TS computeServiceTypeHash (AgentRegistry.ts:98-115) is always keccak256(toUtf8Bytes(serviceType)). If eth_utils is unavailable the Python serviceTypeHash silently diverges from TS and from on-chain expectations, producing wrong filter/registration hashes with no error.
  - TS: `protocol/AgentRegistry.ts:98-115` · PY: `protocol/agent_registry.py:210-227`
  - Fix: Remove the SHA256 fallback; require eth_utils.keccak (hard error if missing) to guarantee keccak256 parity.
- **DIDManager is an off-chain document builder in Python vs on-chain ERC-1056 registry wrapper in TS** `behavior-diff`
  - TS DIDManager (DIDManager.ts) wraps an on-chain ERC-1056 ethr-DID registry: getOwner, changeOwner, addDelegate, revokeDelegate, validDelegate, setAttribute, revokeAttribute, getChanged, getNonce, plus onOwnerChanged/onDelegateChanged/onAttributeChanged event subscriptions. Python DIDManager (did.py:308-537) is an off-chain builder: create_did, create_did_document, resolve, verify_did_ownership, sign_for_did — none of the ERC-1056 on-chain mutation/query/event methods exist. Agents managing on-chain DID ownership/delegates/attributes through the SDK cannot do so from Python.
  - TS: `protocol/DIDManager.ts:135-620` · PY: `protocol/did.py:308-537`
  - Fix: If ERC-1056 DID management is supported, add an on-chain DIDManager binding (getOwner/changeOwner/delegates/attributes/nonce + events). Otherwise document that Python intentionally only supports off-chain DID documents.

### wallet

- **AutoWalletProvider.signTypedData (Smart Wallet ERC-1271/6492) absent in Python** `missing-method`
  - TS AutoWalletProvider.signTypedData lazily constructs a viem toCoinbaseSmartAccount (version 1.1 to match SMART_WALLET_FACTORY 0xBA5ED110), runs a critical address-parity check between computeSmartWalletAddress and viem getAddress() (mismatch throws X402SignatureFailedError), and produces a replay-safe ERC-1271/ERC-6492-wrapped signature for x402 v2. Python AutoWalletProvider has no signTypedData and its IWalletProvider Protocol declares only 4 methods, so a Tier-1 wallet cannot produce on-chain-valid Smart Wallet signatures for x402 v2.
  - TS: `sdk-js/src/wallet/AutoWalletProvider.ts:239-358` · PY: `python-sdk-v2/src/agirails/wallet/auto_wallet_provider.py ABSENT`
  - Fix: Implement Smart Wallet EIP-712 signing producing ERC-1271 SignatureWrapper (deployed)/ERC-6492 (counterfactual) with Coinbase replay-safe hash and an address-parity assertion. Gated behind x402 v2 parity (Python X402Adapter still uses transfer_fn callback).
- **EOAWalletProvider.signTypedData absent in Python** `missing-method`
  - TS EOAWalletProvider.signTypedData delegates to ethers.Wallet.signTypedData after stripping the EIP712Domain entry from the types bag, wrapping failures in X402SignatureFailedError. Python EOAWalletProvider has no sign_typed_data, so Tier-2 wallets cannot sign x402 v2 EIP-712 payloads through the wallet abstraction.
  - TS: `sdk-js/src/wallet/EOAWalletProvider.ts:80-103` · PY: `python-sdk-v2/src/agirails/wallet/eoa_wallet_provider.py ABSENT`
  - Fix: Add async sign_typed_data using eth_account encode_typed_data/sign_typed_data, stripping EIP712Domain from types, surfacing an X402SignatureFailed-equivalent error.
- **getReadProvider absent on both Python wallet providers** `missing-method`
  - TS AutoWalletProvider.getReadProvider and EOAWalletProvider.getReadProvider expose the underlying read-only provider so X402Adapter can call USDC.allowance() before a Permit2 approve (avoids re-sponsoring the same approve across restarts/scale). Neither Python wallet provider exposes get_read_provider and the Python IWalletProvider Protocol omits it.
  - TS: `sdk-js/src/wallet/AutoWalletProvider.ts:207-209; sdk-js/src/wallet/EOAWalletProvider.ts:76-78; sdk-js/src/adapters/X402Adapter.ts:681-723` · PY: `python-sdk-v2/src/agirails/wallet/auto_wallet_provider.py and eoa_wallet_provider.py ABSENT`
  - Fix: Add get_read_provider() returning the web3 instance (or a read wrapper exposing call({to,data})); have Python X402Adapter pre-check allowance before approve.
- **DualNonceManager.read_entry_point_nonce not public + set_cached_actp_nonce missing** `missing-method`
  - TS exposes readEntryPointNonce() publicly (so payACTPBatched can re-read the EntryPoint nonce after a consumed UserOp during collision retry) and setCachedActpNonce(nonce). Python has only private _read_entry_point_nonce and no set_cached_actp_nonce. These are prerequisites for the pay_actp_batched retry loop.
  - TS: `sdk-js/src/wallet/aa/DualNonceManager.ts:150-157,225-227` · PY: `python-sdk-v2/src/agirails/wallet/aa/dual_nonce_manager.py:175-184; set_cached_actp_nonce ABSENT`
  - Fix: Add public read_entry_point_nonce and set_cached_actp_nonce(nonce: int).
- **DualNonceManager missing known-deployment-block hint; AutoWalletConfig.actp_kernel_deployment_block not threaded** `missing-param`
  - TS AutoWalletConfig has actpKernelDeploymentBlock, threaded from networks.ts into DualNonceManager(knownDeploymentBlock) and validated once (code at hint and no code at hint-1, else binary search) to skip a block-0 search when deriving nonce from events. Python AutoWalletConfig has no such field and DualNonceManager takes no deployment-block param, so even after the event fallback is ported it would re-scan from block 0. The value exists in Python networks.py but is used only by BlockchainRuntime sweeps, not the AA nonce manager.
  - TS: `sdk-js/src/wallet/AutoWalletProvider.ts:55-56,112-117; sdk-js/src/wallet/aa/DualNonceManager.ts:83-95,236-293; sdk-js/src/ACTPClient.ts:907` · PY: `python-sdk-v2/src/agirails/wallet/auto_wallet_provider.py:116-141,217-221`
  - Fix: Add actp_kernel_deployment_block to AutoWalletConfig, thread networks.py value through ACTPClient to AutoWalletProvider to DualNonceManager, add hint validation.
- **BundlerClient does not treat timeout/abort as non-transient (slow failover, defeats fast+quiet)** `behavior-diff`
  - TS isNonTransient treats AbortError/aborted messages as non-transient so a hung primary bundler fails over to backup immediately instead of burning all retries (the AA failover fast+quiet on slow primary fix), and classifies AA validation codes -32521..-32500 as non-transient. Python _is_non_transient only checks codes -32700..-32600 and the aa+invalid/rejected message pattern; it has NO httpx timeout/abort handling and NO AA code-range check, so a slow primary burns max_retries with exponential backoff before failover.
  - TS: `sdk-js/src/wallet/aa/BundlerClient.ts:270-291` · PY: `python-sdk-v2/src/agirails/wallet/aa/bundler_client.py:289-303`
  - Fix: In _is_non_transient return True for httpx timeout exceptions (and any aborted/timeout message) and for BundlerRPCError codes in -32521..-32500, so _call_with_fallback flips to backup immediately.
- **BundlerClient request timeout 30s vs TS 20s** `behavior-diff`
  - TS BundlerClient default timeoutMs is 20000 (short enough that an occasionally-hung CDP fails over to the backup quickly). Python BundlerConfig.timeout_s defaults to 30.0, so even after fixing timeout-as-non-transient Python waits 50 percent longer before failover.
  - TS: `sdk-js/src/wallet/aa/BundlerClient.ts:71` · PY: `python-sdk-v2/src/agirails/wallet/aa/bundler_client.py:49`
  - Fix: Change BundlerConfig.timeout_s default to 20.0.
- **TransactionBatcher missing build_erc8004_register_batch + Scenario A omits ERC-8004 identity NFT mint** `behavior-diff`
  - TS buildActivationBatch scenario A optionally prepends ERC-8004 IdentityRegistry.register(agentURI) (mints the agent NFT) when erc8004IdentityRegistry is provided, building agentURI = ipfs://bareCID after stripping gateway/ipfs prefixes, yielding 4 calls. Python build_activation_batch scenario A always produces only 3 calls; ActivationBatchParams has no erc8004_identity_registry field and build_erc8004_register_batch does not exist. TS ACTPClient wires erc8004IdentityRegistry into activation params, so a first-activation Tier-1 agent on Python never mints its ERC-8004 identity NFT in the activation batch.
  - TS: `sdk-js/src/wallet/aa/TransactionBatcher.ts:178-198,361-387; sdk-js/src/ACTPClient.ts:1718` · PY: `python-sdk-v2/src/agirails/wallet/aa/transaction_batcher.py:87-98,408-455`
  - Fix: Add build_erc8004_register_batch(registry, agent_uri) and erc8004_identity_registry to ActivationBatchParams; in scenario A prepend the ERC-8004 register call with bare-CID to ipfs:// normalization; thread the registry address through the activation pipeline.
- **SmartWalletRouter.verify_release_attestation lacks runtime.isAttestationRequired() gating** `behavior-diff`
  - TS verifyReleaseAttestation queries runtime.isAttestationRequired() (or falls back to bool(easHelper)); if attestation is required it throws when attestationUID is missing and throws if required-but-no-easHelper, enforcing the secure-release attestation requirement at the wallet-routing layer. Python verify_release_attestation only verifies when both attestation_uid and eas_helper are present; it never enforces a requirement (no isAttestationRequired path, no throw on missing uid). A Smart-Wallet-routed release that should require an attestation can proceed without one if the requirement is encoded only in the runtime flag.
  - TS: `sdk-js/src/wallet/SmartWalletRouter.ts:223-248` · PY: `python-sdk-v2/src/agirails/wallet/smart_wallet_router.py:350-365`
  - Fix: Mirror TS: read runtime.is_attestation_required() (duck-typed) else bool(eas_helper); raise if required and uid missing, and if required and no eas_helper, before verify_and_record.

### runtime

- **BlockchainRuntime.subscribeProviderJobs missing in Python** `missing-method`
  - TS live TransactionCreated subscription INITIATED-only with unsubscribe; Python absent.
  - TS: `BlockchainRuntime.ts:793-822` · PY: `ABSENT`
- **Adaptive getLogs chunking missing + bare-except swallow in Python EventMonitor** `missing-method`
  - TS bisects on block-range errors; Python no chunking, except-pass hides range errors; no get_transaction_history(role,range).
  - TS: `EventMonitor.ts:113-207,182-207` · PY: `events.py:585-624,606`
- **ACTP_SWEEP_BLOCK_WINDOW + sweepBlockWindow config absent in Python** `missing-param`
  - TS default 7200, config>env>default bounds the sweep; Python has neither.
  - TS: `BlockchainRuntime.ts:81,156-180` · PY: `ABSENT`
- **MockRuntime.getTransaction lazy auto-settle not in Python** `behavior-diff`
  - TS auto-settles DELIVERED+window-expired on read; Python returns as-is, terminal state disagrees across SDKs.
  - TS: `MockRuntime.ts:525-565` · PY: `mock_runtime.py:536-540`
- **MockState version 1.0 vs 2.0.0; mock-state files incompatible** `behavior-diff`
  - Each SDK rejects the other's mock-state.json; shapes differ (accounts/usdcBalance+serviceHash vs balances).
  - TS: `MockState.ts:252-267` · PY: `mock_state_manager.py:52,341-358`
- **MockRuntime missing events accessor, getState, transfer in Python** `missing-method`
  - TS exposes events accessor, getState(), transfer(); Python has none.
  - TS: `MockRuntime.ts:320-361,1215-1262` · PY: `ABSENT`
- **MockRuntime.createTransaction does not derive serviceHash in Python** `behavior-diff`
  - TS derives bytes32 serviceHash for routing (PRD 5.2 Layer B), backfilled on load; Python MockTransaction has no service_hash field.
  - TS: `MockRuntime.ts:458-489` · PY: `mock_runtime.py:285-296`
- **CreateTransactionParams missing requesterAgentId (AIP-14) in Python** _[AIP-14]_ `missing-param`
  - TS has requesterAgentId + string agentId; Python int agent_id, no requester_agent_id, so requester ERC-8004 id not threaded.
  - TS: `IACTPRuntime.ts:38-40` · PY: `base.py:35-41`

### storage

- **setHashesFromData (compute hashes from request/delivery JSON) missing in Python builder** _[AIP-7]_ `missing-method`
  - TS ArchiveBundleBuilder.setHashesFromData(request, delivery, serviceHash) canonicalizes request/delivery via recursive sortObjectKeys + JSON.stringify and sets requestHash=keccak256(json), deliveryHash=keccak256(json), serviceHash=lowercased. Python builder only has set_hashes(request_hash, delivery_hash, service_hash) taking pre-computed hashes. A module-level compute_json_hash(dict) exists, but no builder method computing both hashes from raw objects in one call, so callers must replicate canonicalization.
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:255-271` · PY: `python-sdk-v2/src/agirails/storage/archive_bundle_builder.py:297-319`
  - Fix: Add ArchiveBundleBuilder.set_hashes_from_data(request,delivery,service_hash) using compute_json_hash and verify it matches TS keccak256(JSON.stringify(sortObjectKeys(...))) byte-for-byte.
- **ArchiveBundleBuilder.fromBundle static factory missing in Python** _[AIP-7]_ `missing-method`
  - TS exposes static ArchiveBundleBuilder.fromBundle(bundle) to rehydrate a builder from an existing ArchiveBundle for modification. Python ArchiveBundleBuilder has no equivalent classmethod.
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:436-455` · PY: `ABSENT`
  - Fix: Add classmethod from_bundle(cls, bundle: ArchiveBundle) populating all private fields from the bundle.
- **Builder setProtocolVersion / setArchiveSchemaVersion missing in Python (versions hardcoded)** _[AIP-7]_ `missing-method`
  - TS builder has setProtocolVersion(v) and setArchiveSchemaVersion(v) with semver validation, defaulting to '1.0.0'. Python builder has no setters; build() always injects module constants PROTOCOL_VERSION='1.0.0' and ARCHIVE_SCHEMA_VERSION='1.0.0', so a caller cannot override protocol/schema version via the builder.
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:114-132,407-409` · PY: `python-sdk-v2/src/agirails/storage/archive_bundle_builder.py:432-434`
  - Fix: Add set_protocol_version / set_archive_schema_version with semver guard and use the instance values in build().
- **FilebaseClient.uploadBinary / downloadBinary not present in Python** _[AIP-7]_ `missing-method`
  - TS FilebaseClient has uploadBinary(data,contentType,{key,metadata}) and downloadBinary(cid)->DownloadResult<Buffer> with content-type->extension mapping and size enforcement. Python only has generic upload(content,filename,content_type) and download(cid)->DownloadResult(bytes). Byte-oriented Python upload covers binary, but the explicit uploadBinary/downloadBinary names and getExtensionFromContentType key generation are absent.
  - TS: `sdk-js/src/storage/FilebaseClient.ts:402-450,453-571,653-664` · PY: `python-sdk-v2/src/agirails/storage/filebase_client.py:103-197,227-331`
  - Fix: Optionally add upload_binary/download_binary thin wrappers and content-type extension mapping to match TS naming.
- **FilebaseClient.exists(cid) missing in Python** _[AIP-7]_ `missing-method`
  - TS FilebaseClient.exists(cid) does a HEAD on the gateway and returns boolean. Python FilebaseClient has no exists() method.
  - TS: `sdk-js/src/storage/FilebaseClient.ts:579-600` · PY: `ABSENT`
  - Fix: Add async exists(cid) doing httpx HEAD against gateway, returning response.is_success, swallowing errors -> False.
- **ArweaveClient.exists(txId), getCurrency/getNetwork getters missing; estimateCost renamed to get_upload_price** _[AIP-7]_ `missing-method`
  - TS ArweaveClient exposes exists(txId)->bool (HEAD), estimateCost(sizeBytes) (Python equivalent get_upload_price — different name), getCurrency()->IrysCurrency and getNetwork()->IrysNetwork getters. Python has no exists(), no getCurrency/getNetwork getters (currency/network only via get_stats()), and renames estimateCost to get_upload_price.
  - TS: `sdk-js/src/storage/ArweaveClient.ts:299-315,738-759,768-777` · PY: `python-sdk-v2/src/agirails/storage/arweave_client.py:177-201`
  - Fix: Add async exists(tx_id), currency/network properties, and alias estimate_cost->get_upload_price for parity.
- **getCircuitBreakerStatus / resetCircuitBreaker absent on both Python clients** _[AIP-7]_ `missing-method`
  - TS both clients expose getCircuitBreakerStatus() (state/failures/isHealthy) and resetCircuitBreaker() for manual recovery. Python exposes only a circuit_breaker_state property and get_stats() containing circuit_breaker info; there is no public reset and no structured status object, so callers cannot manually reset after a known outage.
  - TS: `sdk-js/src/storage/FilebaseClient.ts:763-789; sdk-js/src/storage/ArweaveClient.ts:923-945` · PY: `python-sdk-v2/src/agirails/storage/filebase_client.py:98-101,398-411; python-sdk-v2/src/agirails/storage/arweave_client.py:141-144,540-553`
  - Fix: Add get_circuit_breaker_status() and reset_circuit_breaker() to both Python clients delegating to CircuitBreaker.reset/get_state/get_failure_count.
- **Per-field regex validation in builder setters weaker/absent in Python (signature 130-hex, CID, numeric amounts)** _[AIP-7]_ `behavior-diff`
  - TS builder setters strictly validate each input: addresses via ADDRESS_PATTERN, references via CID_PATTERN, hashes via HASH_PATTERN, signatures via SIGNATURE_PATTERN (0x+130 hex = 65 bytes), attestation via HASH_PATTERN, settlement amount/platformFee via /^\d+$/, archivedAt>0. Python builder setters do almost no validation at set-time — they just lowercase and store; set_settlement does not validate escrow_amount/platform_fee are numeric strings nor escrow_to address; signatures are never length-checked (no 130-hex rule anywhere). Pydantic models enforce some patterns (address/hash/easUID) at sub-model construction, but signature length, CID format, and numeric-string amounts are NOT enforced. Python accepts malformed signatures/amounts/CIDs that TS rejects; error type differs (pydantic ValidationError vs ValidationError(field,msg)).
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:181-194,203-220,280-302,311-321,330-368` · PY: `python-sdk-v2/src/agirails/storage/archive_bundle_builder.py:252-396`
  - Fix: Add set-time validation in Python builder setters: signature regex ^0x[0-9a-fA-F]{130}$, CID via validate_cid, escrow_amount/platform_fee via ^\d+$, address checks, archived_at>0 — raising a consistent validation error.

### cross-cutting: top-level coverage + index.ts public-export parity +…

- **Provider-side negotiation orchestration (ProviderOrchestrator / ProviderPolicyEngine) missing in Python** _[AIP-2.1]_ `missing-class`
  - TS exports ProviderOrchestrator (negotiation/ProviderOrchestrator.ts, AIP-2.1 §5.2 Phase 2) and ProviderPolicyEngine (negotiation/ProviderPolicy.ts) plus types ProviderOrchestratorConfig, QuoteDecision, QuoteResult, CounterDecision, CounterContext, CounterDecider, ProviderPolicy, ProviderPolicyViolation, ProviderPolicyResult, IncomingRequest. Python negotiation/ contains ONLY buyer-side modules (buyer_orchestrator, decision_engine, policy_engine, session_store). The provider negotiation surface is partially scattered into server/policy.py (a ProviderPolicy dataclass) and server/policy_engine.py (evaluate_counter function), but there is no ProviderOrchestrator class and no ProviderPolicyEngine class with the TS method surface. A Python provider agent cannot drive autonomous quote/counter-offer negotiation the way the TS SDK provides.
  - TS: `sdk-js/src/negotiation/ProviderOrchestrator.ts; ProviderPolicy.ts; index.ts:183-198` · PY: `negotiation/__init__.py (no ProviderOrchestrator/ProviderPolicyEngine); server/policy.py (only a ProviderPolicy dataclass); server/policy_engine.py (evaluate_counter fn)`
  - Fix: Port ProviderOrchestrator + ProviderPolicyEngine to Python negotiation/ with the full method/type surface, and export from negotiation/__init__.py and top-level __init__.py. Wire it to server/quote_channel.py for the channel-driven provider flow.
- **Channel-driven multi-round BuyerOrchestrator (AIP-2.1 §6) missing in Python** _[AIP-2.1]_ `missing-method`
  - TS BuyerOrchestrator accepts a NegotiationChannel transport (negotiationChannel config), with _onChannelMessage inbound dispatch, per-txId message queues, and subscription/publish over RelayChannel (production) or MockChannel (tests) — this is the headline AIP-2.1 §6 channel-driven multi-round negotiation shipped in TS 3.5.x. Python negotiation/buyer_orchestrator.py has NO channel support: grep shows no negotiation_channel param, no _on_channel_message, no subscribe/publish. Python buyer negotiation is therefore fixed-price / non-channel only. Cross-SDK multi-round negotiation between a Python buyer and a TS/relay provider is not possible.
  - TS: `sdk-js/src/negotiation/BuyerOrchestrator.ts:32-38,119,180-189,215-276,463 (NegotiationChannel wiring); BuyerOrchestrator.channel.test.ts` · PY: `negotiation/buyer_orchestrator.py (no channel/subscribe/publish references)`
  - Fix: Add NegotiationChannel abstraction + RelayChannel + MockChannel to Python, extend BuyerOrchestrator with a negotiation_channel config and inbound message dispatch, mirroring the TS validation that requires signer+kernel_address+chain_id+channel together.
- **NegotiationChannel abstraction + RelayChannel + MockChannel + envelope type guards missing in Python** _[AIP-2.1]_ `missing-class`
  - TS exports from negotiation/NegotiationChannel.ts: NegotiationChannel, NegotiationMessage, Subscription, DeliveredMessage types and runtime guards isQuoteEnvelope, isCounterOfferEnvelope, isCounterAcceptEnvelope, envelopeTxId, envelopeChainId; plus RelayChannel (RelayChannelConfig) and MockChannel (MockChannelConfig). None exist in Python (grep for RelayChannel/MockChannel/NegotiationChannel returns nothing in agirails/). Without these, developers cannot wire a custom transport, implement MockChannel-style tests, or use the envelope type guards — the same rationale TS index.ts:233-236 cites for exporting them.
  - TS: `sdk-js/src/negotiation/NegotiationChannel.ts; RelayChannel.ts; MockChannel.ts; index.ts:237-253` · PY: `ABSENT`
  - Fix: Port NegotiationChannel/RelayChannel/MockChannel and the envelope guard helpers; export from negotiation/__init__.py and top-level __init__.py.
- **verifyQuoteHashOnChain helper missing in Python** _[AIP-2.1]_ `missing-method`
  - TS exports verifyQuoteHashOnChain (negotiation/verifyQuoteOnChain.ts) plus VerifySource, VerifyOnChainResult types — used to verify a received quote's hash is anchored on-chain before commit (anti-tamper guard in autonomous negotiation). No Python equivalent (grep verify_quote/verifyQuote returns nothing).
  - TS: `sdk-js/src/negotiation/verifyQuoteOnChain.ts; index.ts:225-229` · PY: `ABSENT`
  - Fix: Port verify_quote_hash_on_chain (reads ACTPKernel anchored quote hash via web3) and export it; add to negotiation/__init__.py.
- **QuoteChannelClient missing in Python (only the handler side is ported)** _[AIP-2.1]_ `missing-class`
  - TS transport/QuoteChannel.ts exports QuoteChannelClient AND QuoteChannelHandler, InMemoryDedupStore, buildChannelPath, plus types ChannelPayload, DedupStore, HandlerContext, HandlerResult, QuoteChannelClientConfig, QuoteChannelHandlerConfig. Python server/quote_channel.py ports QuoteChannelHandler, InMemoryDedupStore, build_channel_path — but NOT QuoteChannelClient. The client side (requester posting quote requests to a provider's channel endpoint) has no Python analog, so a Python buyer cannot use the HTTP quote-channel transport against a provider.
  - TS: `sdk-js/src/transport/QuoteChannel.ts (QuoteChannelClient); index.ts:175-180,254-261` · PY: `server/quote_channel.py (handler+dedup+path only, no client)`
  - Fix: Port QuoteChannelClient to Python (httpx-based POST to channel path) and export it; consider a dedicated transport/ package to mirror TS layout.
- **X402 error model differs: TS subclass hierarchy (10 classes) vs Python single class + enum** `behavior-diff`
  - TS errors/X402Errors.ts defines 10 distinct exception subclasses (X402Error base + X402ConfigError, X402PublishRequiredError, X402UnsupportedWalletError, X402NetworkNotAllowedError, X402AmountExceededError, X402ApprovalFailedError, X402SignatureFailedError, X402SettlementProofMissingError, X402PaymentFailedError) each extending ACTPError with a specific code; all are public exports. Python models x402 errors as a single X402Error(Exception) plus an X402ErrorCode enum in types/x402.py — it is NOT an ACTPError subclass and none of the 9 specific subclasses exist, and none are exported from errors/__init__.py or top-level __init__.py. Callers cannot `except X402PublishRequiredError` etc.; type-specific error handling and the ACTPError base relationship diverge across SDKs.
  - TS: `sdk-js/src/errors/X402Errors.ts:18-177; index.ts:73-84` · PY: `types/x402.py:145-160 (X402ErrorCode enum + X402Error(Exception)); errors/__init__.py (no X402* exports)`
  - Fix: Define the 9 X402 subclasses in errors/, subclass ACTPError, map to the same codes, and export them from errors/__init__.py and top-level __init__.py for parity and try/except ergonomics.
- **AIP-16 and full-multiround-negotiation e2e/integration test suites have no Python analog** _[AIP-16]_ `test-gap`
  - TS has src/__tests__/aip16-cross-repo-eip712.test.ts, aip16-e2e-mock-flow.test.ts, aip16-e2e-stress.test.ts, src/__e2e__/full-multiround-negotiation.e2e.test.ts, cli-actp-serve.e2e.test.ts, state-machine-happy-path.e2e.test.ts, plus delivery/*.test.ts (crypto, keys, eip712, envelopeBuilder, validate, h4/h5/aip16-fix1 hardening tests). Python tests/ has test_cross_sdk/{test_aip21_parity,test_python_signed_determinism} and test_negotiation/test_buyer_orchestrator, but NO aip16/delivery-channel tests and no full multiround channel e2e (because the features are absent). The cross-SDK eip712 determinism vectors for AIP-16 delivery envelopes are not exercised on the Python side, so any future port lacks regression guardrails.
  - TS: `sdk-js/src/__tests__/aip16-*.test.ts; sdk-js/src/__e2e__/full-multiround-negotiation.e2e.test.ts; sdk-js/src/delivery/*.test.ts` · PY: `python-sdk-v2/tests/ (no aip16/delivery-channel/multiround-channel tests)`
  - Fix: When porting AIP-16 + channel negotiation, add Python parity tests using the same cross-repo EIP-712 golden vectors and a multiround channel e2e mirroring the TS e2e.
- **Major version lag: Python 3.0.1 vs TS 4.8.0 — feature drift across a major boundary** `behavior-diff`
  - Python SDK declares version 3.0.1 while TS is 4.8.0. The memory index claims Python tracks TS, but the public surface confirms a full major version of features (AIP-16 encrypted delivery, provider-side + channel-driven negotiation, QuoteChannelClient, verifyQuoteHashOnChain) landed in TS (3.5.x→4.x) without Python ports. This is the umbrella driver for the gaps above; the prior per-subsystem diffs that asserted parity were measuring against an older TS baseline.
  - TS: `sdk-js/package.json version 4.8.0` · PY: `python-sdk-v2/src/agirails/version.py __version__ = '3.0.1'`
  - Fix: Treat the AIP-16 delivery channel and provider/channel negotiation as the blocking work for a Python 4.x parity release; align version once ported.

### api-registry

- **check_slug returns raw dict; missing typed owner/draft fields used by slug-ownership recognition** _[AIP-18]_ `behavior-diff`
  - TS CheckSlugResult is a typed interface with owner?{wallet,agentId} and draft? fields (agirailsApp.ts:32-57). TS publish.ts:306-349 consumes slugResult.owner to RECOVER the caller's own agent_id (Smart Wallet slug ownership recognition) instead of auto-renaming, and slugResult.draft to trigger draft adoption. Python check_slug returns a bare Dict[str,Any] (agirails_app.py:167-179) and publish.py:349-379 only reads .get('available')/.get('suggestion') and auto-renames on collision — it never inspects owner or draft. A buyer/provider re-publishing their own already-published slug gets silently renamed to slug-2 in Python.
  - TS: `sdk-js/src/api/agirailsApp.ts:32-57; sdk-js/src/cli/commands/publish.ts:306-349` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:167-179; /Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/cli/commands/publish.py:349-379`
  - Fix: Add a typed CheckSlugResult dataclass with owner{wallet,agent_id} and draft fields; in publish.py, on not-available, check owner (recover own agent_id when owner.wallet==caller wallet) and draft (adopt via claim_code) before falling back to rename.
- **UpsertAgentParams missing signer field (AA Smart Wallet ownership proof)** _[AIP-12]_ `missing-param`
  - TS UpsertAgentParams has optional signer (agirailsApp.ts:76): when wallet is a Smart Wallet, the EOA signer is sent so the server can recoverSigner(msg,sig)==signer then derive the Smart Wallet from signer. TS publish.ts:782 passes signer: walletAddress. Python UpsertAgentParams (agirails_app.py:52-78) has no signer field and to_camel_case_dict never emits it, so AA Smart Wallet publishes cannot prove signer controls the wallet via this path.
  - TS: `sdk-js/src/api/agirailsApp.ts:76; sdk-js/src/cli/commands/publish.ts:782` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:52-78`
  - Fix: Add signer: Optional[str] to UpsertAgentParams and emit it in to_camel_case_dict when set; pass EOA signer from publish flow for AA wallets.
- **UpsertAgentParams missing config field (profile display payload)** `missing-param`
  - TS UpsertAgentParams.config (Record<string,unknown>, agirailsApp.ts:92) carries name/description/capabilities/pricing for profile display; TS publish.ts:791 populates it. Python UpsertAgentParams has no config field, so the Python publish upsert (publish.py:124-135) never sends profile config — profiles created via Python publish will lack display metadata.
  - TS: `sdk-js/src/api/agirailsApp.ts:92; sdk-js/src/cli/commands/publish.ts:791` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:52-78`
  - Fix: Add config: Optional[Dict[str,Any]] to UpsertAgentParams; emit when present; populate from parsed AGIRAILS.md in publish flow.
- **UpsertAgentParams missing claimCode field (draft adoption)** _[AIP-18]_ `missing-param`
  - TS UpsertAgentParams.claimCode (agirailsApp.ts:98) lets a publish ADOPT a pending web draft (wallet='pending:onboarding') instead of failing/renaming; TS publish.ts:790 conditionally sends it (draftClaimCode). Python UpsertAgentParams has no claim_code field, so the Python SDK cannot adopt a web-created draft slug — draft-adoption flow is entirely missing on the Python publish path.
  - TS: `sdk-js/src/api/agirailsApp.ts:98; sdk-js/src/cli/commands/publish.ts:349,790` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:52-78`
  - Fix: Add claim_code: Optional[str] to UpsertAgentParams + emit in to_camel_case_dict; wire draft detection from check_slug into publish flow.
- **UpsertAgentParams agent_id is required (str) but TS agentId is optional (pay-only buyers)** _[AIP-18]_ `signature-diff`
  - TS agentId is optional (agirailsApp.ts:67): pay-only buyer agents do not register on AgentRegistry (no NFT, no agent_id) and upsert with wallet signature alone. Python UpsertAgentParams.agent_id is a required positional str (agirails_app.py:56) and is always emitted as 'agentId' in to_camel_case_dict (line 71) — a pay-only buyer cannot construct valid params without a fake agent_id, and an empty string is still sent rather than omitted. configCid is likewise mandatory in Python (config_cid: str, line 60) while TS makes it optional (pay-only buyers publish no service file).
  - TS: `sdk-js/src/api/agirailsApp.ts:59-99` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:52-78`
  - Fix: Make agent_id and config_cid Optional in UpsertAgentParams; omit agentId/configCid keys from the wire payload when None (matches AIP-18 DEC-4 buyer upsert).
- **Default agirails.app base URL differs: TS uses www subdomain, Python does not** `behavior-diff`
  - TS AGIRAILS_APP_BASE_URL defaults to 'https://www.agirails.app' (agirailsApp.ts:26). Python defaults to 'https://agirails.app' in BOTH agirails_app.py:36 and discover.py:33 (no www). If the platform serves the API canonically on www (or apex redirects drop POST bodies / change CORS), Python publish/claim/discover calls hit a different host than TS. This affects every endpoint when AGIRAILS_APP_URL env var is unset.
  - TS: `sdk-js/src/api/agirailsApp.ts:25-26` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/agirails_app.py:36; /Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/discover.py:33`
  - Fix: Change Python default to 'https://www.agirails.app' in both modules to match TS, or confirm apex is canonical and update TS — must be identical to avoid redirect/CORS divergence.
- **No standalone AgentRegistryClient.publishConfig on-chain write wrapper in Python (validation + gas buffer + 'Not registered' mapping)** `missing-method`
  - TS AgentRegistryClient.publishConfig(cid,hash) (AgentRegistryClient.ts:77-120) does the on-chain AgentRegistry.publishConfig write with input validation (cid non-empty, cid<=128 chars, hash non-zero, hash bytes32 regex), estimateGas*1.2 buffer, optional gasSettings, and maps revert 'Not registered'->TransactionRevertedError('Agent not registered...'). Python has NO equivalent single-signer publishConfig write wrapper: config/publish_pipeline.py publish_config() is IPFS-upload only, and the actual on-chain publishConfig write only exists via the AA TransactionBatcher (build_publish_config_batch). The cid/hash validation guards (length<=128, bytes32 regex, non-zero hash) are absent from the Python write path, and there is no friendly 'Not registered' error mapping.
  - TS: `sdk-js/src/registry/AgentRegistryClient.ts:77-120` · PY: `ABSENT (closest: /Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/config/publish_pipeline.py:294 is IPFS-only; on-chain write only via wallet/aa/transaction_batcher.py build_publish_config_batch)`
  - Fix: Add a Python AgentRegistry.publish_config(cid, hash) (or a registry client) performing the same validation (cid<=128, bytes32 regex, non-zero), gas estimate *1.2, and 'Not registered'->TransactionReverted mapping, for the non-AA single-signer publish path.

### receipts

- **V2 EIP-712 receipt-push module (receipts/push.ts) entirely absent in Python** _[AIP-7]_ `missing-module`
  - TS receipts/push.ts is the new SETTLED 'wow' push path (pushReceiptOnSettled, formatSettledLine, RECEIPT_WRITE_DOMAIN_V2/TYPES_V2, ParticipantRole, chainIdForNetwork). Python receipts/ contains ONLY web_receipt.py, which is a port of the LEGACY cli/receiptUpload.ts (V1). There is no Python equivalent of push.ts at all — grep for push_receipt/pushReceipt/ReceiptWriteV2/participant_role/format_settled_line returns nothing.
  - TS: `sdk-js/src/receipts/push.ts:1-265` · PY: `ABSENT (python-sdk-v2/src/agirails/receipts/ has only web_receipt.py + __init__.py)`
  - Fix: Port push.ts to receipts/push.py: pushReceiptOnSettled, formatSettledLine, RECEIPT_WRITE_DOMAIN_V2/TYPES_V2, PushReceiptArgs/Result. Add to receipts/__init__.py and top-level agirails.__init__ exports.
- **pushReceiptOnSettled not wired at SETTLED in run_request — no receipt push** _[AIP-7]_ `behavior-diff`
  - TS cli/lib/runRequest.ts step 12 (lines 721-775): on SETTLED with a real network and signer, it computes feeWei via computeDisplayFee, clamps netWei to >=0, resolves kernelAddress from getNetwork, then calls pushReceiptOnSettled with participantRole='requester' and requesterAddress=client.info.address (smart-wallet aware), assigning the resulting URL to receiptUrl. Python run_request.py has NO step 12 — it builds RunRequestResult and returns; no receipt is ever posted to the Platform from the buyer/requester path.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:721-775` · PY: `python-sdk-v2/src/agirails/cli/lib/run_request.py:241 (RunRequestResult returned, no push)`
  - Fix: After settlement in run_request, when private_key present and network in (testnet,mainnet), compute fee/net, resolve kernel address, and call the ported push_receipt_on_settled with participant_role='requester' and requester_address=client.info.address; populate receipt_url on the result.
- **RunRequestResult missing receipt_url field** _[AIP-7]_ `missing-method`
  - TS RunRequestResult includes receiptUrl: string|null (runRequest.ts:249,798) which is surfaced to CLI commands so they can print the clickable receipt URL. Python RunRequestResult (frozen dataclass: tx_id, final_state, elapsed_ms, settled, payload) has no receipt_url field, so even if a push were added there is no carrier to surface it.
  - TS: `sdk-js/src/cli/lib/runRequest.ts:249,792-800` · PY: `python-sdk-v2/src/agirails/cli/lib/run_request.py:56-62`
  - Fix: Add receipt_url: Optional[str] = None to RunRequestResult and set it from the push result.
- **renderReceiptV3 (V3 framed ceremonial receipt) absent — Python still V1 box receipt** _[AIP-7]_ `missing-method`
  - TS cli/commands/receipt.ts renderReceiptV3(ReceiptDataV3, Output) renders the ceremonial framed receipt with: a reflection block, a 'Receipt URL' block (https://agirails.app/r/r_...) with word-aware wrapping, perspective='buyer'|'provider' copy direction (paid vs earned, From/To swap), nowFn injectable clock, ethTxHash, counterparty/requester shortAddr fallback. Python cli/commands/receipt.py only has render_receipt(ReceiptData,...) — the OLD V1 box (agent/service/amount/fee/net/network/tx + timing), with no reflection, no URL block, no perspective, no nowFn.
  - TS: `sdk-js/src/cli/commands/receipt.ts:210-272,339,520-540` · PY: `python-sdk-v2/src/agirails/cli/commands/receipt.py:25-131`
  - Fix: Port renderReceiptV3 + ReceiptDataV3 (reflection, receipt_url, perspective, now_fn, eth_tx_hash, counterparty/requester). Keep V1 render_receipt for tx-status compatibility.
- **Buyer-side V3 framed receipt + receiptUrl not rendered by request CLI** _[AIP-7]_ `behavior-diff`
  - TS cli/commands/request.ts:213 calls renderReceiptV3 with perspective='buyer', counterparty slug, reflection=payloadPreview, and receiptUrl=result.receiptUrl, producing the framed clickable buyer receipt. Python cli/commands/request.py prints only flat lines: print_success('Settled in X ms (state: ...)') and optionally print_success('Reflection: ...'). No framed receipt, no receipt URL, no buyer perspective.
  - TS: `sdk-js/src/cli/commands/request.ts:205-235` · PY: `python-sdk-v2/src/agirails/cli/commands/request.py:162-166`
  - Fix: After the ported run_request returns, render the V3 buyer receipt with reflection + receipt_url instead of flat print lines.
- **Provider first-job ceremonial receipt absent in level1 Agent** _[AIP-7]_ `behavior-diff`
  - TS level1/Agent.ts:1966-2010 renders a V3 provider-perspective first-job ceremonial receipt on jobsCompleted===1 (testnet/mainnet only), gated by config.showFirstJobReceipt!==false and env ACTP_NO_FIRST_JOB_RECEIPT!=='1', best-effort/swallowed on error. Python level1/agent.py has zero receipt/render logic (grep returns nothing).
  - TS: `sdk-js/src/level1/Agent.ts:259-264,1966-2010` · PY: `python-sdk-v2/src/agirails/level1/agent.py (no receipt logic)`
  - Fix: Add show_first_job_receipt config + ACTP_NO_FIRST_JOB_RECEIPT env handling to the Python Agent; on first completed job render the V3 provider receipt best-effort.

### erc8004

- **ERC8004Network type set diverges (no 'ethereum'; 'base' renamed to 'base-mainnet')** `signature-diff`
  - TS ERC8004Network = 'ethereum' | 'base' | 'base-sepolia' with separate ethereum & base entries in IDENTITY/REPUTATION/DEFAULT_RPC maps (ethereum RPC https://eth.llamarpc.com). Python ERC8004Network = Literal['base-mainnet','base-sepolia'] — no 'ethereum' support at all, and the mainnet key is 'base-mainnet' not 'base'. Any caller passing TS network names ('base'/'ethereum') to the Python bridge KeyErrors; cross-SDK config is not portable. Note registry addresses for ethereum and base are identical in TS (canonical CREATE2), so the missing entry is a feature/portability gap not an address mismatch.
  - TS: `sdk-js/src/types/erc8004.ts:23,212-216,224-228,269-273` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:26-41`
  - Fix: Add 'ethereum' and 'base' to Python ERC8004Network and the three constant dicts (ethereum RPC https://eth.llamarpc.com, base->same canonical addresses), or document the rename and centralize a network-name mapping; keep registry addresses identical to TS (they already match).
- **isValidAgentId weaker in Python — accepts 0x-prefixed / URL-like IDs and has no uint256 upper bound** `behavior-diff`
  - TS isValidAgentId rejects strings starting with '0x' or containing '://' and enforces 0 <= BigInt(id) < 2^256 (ERC8004Bridge.ts:362-378). Python is_valid_erc8004_agent_id only does `int(agent_id) >= 0` (types/erc8004.py:277-282). Python would accept '0x1f' (int('0x1f',?) actually raises so returns False) but more importantly accepts arbitrarily large integers above 2^256 and negative-rejection only — and the adapter routing relies on agent-id vs address/URL discrimination upstream; the bridge's own guard is looser, so a malformed/oversized id reaches the contract call and may produce a confusing revert instead of a clean INVALID_AGENT_ID.
  - TS: `sdk-js/src/erc8004/ERC8004Bridge.ts:362-378` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:277-282`
  - Fix: Mirror TS: reject ids starting with '0x' or containing '://', and enforce 0 <= int(id) < 2**256 in is_valid_erc8004_agent_id.
- **get_agents_by_owner raises instead of returning [] (TS never throws)** `behavior-diff`
  - TS getAgentsByOwner returns [] on invalid address and on any error (catches and warns) — ERC8004Bridge.ts:309-333. Python get_agents_by_owner RAISES ERC8004Error(NETWORK_ERROR) on invalid owner address AND on any RPC failure — bridge.py:208-230. This is an opposite error contract: callers written against TS expecting a safe empty list get an unhandled exception in Python.
  - TS: `sdk-js/src/erc8004/ERC8004Bridge.ts:309-334` · PY: `python-sdk-v2/src/agirails/erc8004/bridge.py:195-230`
  - Fix: Make Python get_agents_by_owner return [] on invalid address and on exceptions (log a warning), matching TS non-throwing contract.
- **ReputationReporter missing endpoint/feedbackURI/capability/reason params and dispute feedbackURI=reason behavior** `missing-param`
  - TS reportSettlement accepts {capability, endpoint, feedbackURI} and passes tag2=capability, endpoint, feedbackURI on-chain; reportDispute accepts {capability, reason} passing tag2=capability and feedbackURI=reason. Python report_settlement(agent_id, tx_id) and report_dispute(agent_id, tx_id, agent_won) accept none of these — so capability/endpoint/feedbackURI/reason are never recorded on-chain. (Compounded by the wrong ABI which has no slots for them.)
  - TS: `sdk-js/src/erc8004/ReputationReporter.ts:129-164,249-256,320-353` · PY: `python-sdk-v2/src/agirails/erc8004/reputation_reporter.py:88-152`
  - Fix: Add capability/endpoint/feedback_uri to report_settlement and capability/reason to report_dispute, threading into the corrected 8-param giveFeedback.
- **ReportResult shape divergence (txHash/blockNumber/gasUsed vs tx_hash/agent_id/feedback_hash/tag)** `signature-diff`
  - TS ReportResult = {txHash, blockNumber, gasUsed:bigint}. Python ReportResult = {tx_hash, agent_id, feedback_hash, tag} — different fields entirely; Python omits blockNumber and gasUsed and adds agent_id/feedback_hash/tag. Cross-SDK consumers and tests can't rely on a common shape.
  - TS: `sdk-js/src/erc8004/ReputationReporter.ts:169-178` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:252-267`
  - Fix: Decide canonical shape (TS is source of truth): add block_number and gas_used to Python ReportResult and populate from receipt (receipt['blockNumber'], receipt['gasUsed']).

### errors-utils-types-builders-settle

- **X402 error taxonomy fully divergent: 9 ACTPError-derived subclasses + isPaymasterGateError absent in Python** _[AIP-18]_ `missing-class`
  - TS errors/X402Errors.ts defines X402Error (extends ACTPError) plus X402ConfigError, X402PublishRequiredError, X402UnsupportedWalletError, X402NetworkNotAllowedError, X402AmountExceededError, X402ApprovalFailedError, X402SignatureFailedError, X402SettlementProofMissingError, X402PaymentFailedError -- each with a stable string code (X402_CONFIG_ERROR, X402_PUBLISH_REQUIRED, etc.) catchable via instanceof ACTPError/X402Error; plus helper isPaymasterGateError(e). Python has NONE in errors/. Its only x402 error is types/x402.py::X402Error(Exception) (NOT ACTPError-derived) with an X402ErrorCode enum (NOT_402_RESPONSE/MISSING_HEADERS/...) -- a different code system and base class. Consumers cannot catch x402 failures via ACTPError, cannot match X402_PUBLISH_REQUIRED to prompt 'actp publish', and have no equivalent of the actionable X402PublishRequiredError message.
  - TS: `sdk-js/src/errors/X402Errors.ts:18-198` · PY: `python-sdk-v2/src/agirails/types/x402.py:145-200 (divergent X402Error+enum); errors/__init__.py (no X402 exports)`
  - Fix: Add errors/x402.py with X402Error(ACTPError) and the 8 subclasses + is_paymaster_gate_error(); export from errors/__init__. Alias or reconcile types/x402.X402Error. Match string codes exactly for cross-SDK error-code parity.
- **DeliveryProofBuilder.buildEncryptedProof (AIP-16 encrypted delivery variant) absent in Python** _[AIP-16]_ `missing-method`
  - TS DeliveryProofBuilder exposes buildPublicProof, build (alias), and buildEncryptedProof (AIP-16 Rev5 sec6 DEC-3): takes a signed DeliveryEnvelopeWireV1, computes envelopeHash = DeliveryEnvelopeBuilder.computeHash, uploads ENCRYPTED wire to IPFS (never plaintext), EAS-anchors envelopeHash, EIP-712 signs the proof, returns {deliveryProof, deliveryProofCID, attestationUID, encryptedEnvelopeCID, envelopeHash}. Python builders/delivery_proof.py has no buildEncryptedProof, no buildPublicProof, no IPFS/EAS/EIP-712 orchestration -- it is a fluent builder that only assembles a DeliveryProofMessage dataclass (build()->to_message()). The AIP-16 encrypted-delivery anchoring path has no builder-level equivalent on the Python side.
  - TS: `sdk-js/src/builders/DeliveryProofBuilder.ts:202-463 (buildPublicProof + buildEncryptedProof)` · PY: `python-sdk-v2/src/agirails/builders/delivery_proof.py:203-501 (fluent only, no encrypted variant)`
  - Fix: If Python ships AIP-16, add an encrypted delivery-proof builder mirroring buildEncryptedProof: txId/chainId consistency checks vs envelope.signed, envelope_hash anchoring, upload encrypted wire (not plaintext), EAS attest, EIP-712 sign. Verify the AIP-16 delivery/ port exists in Python before treating as P1 vs P0.
- **SettleOnInteract missing releaseRouter (AA/Smart-Wallet-aware settlement routing)** _[AIP-12]_ `missing-param`
  - TS SettleOnInteract constructor takes a 4th param releaseRouter?: ReleaseRouter and, when present, routes releaseEscrow through it (StandardAdapter->SmartWalletRouter) so AGIRAILS Smart Wallet providers (0 ETH on signer EOA) settle via Paymaster-sponsored UserOps instead of reverting on intrinsic gas; falls back to runtime.releaseEscrow otherwise. Python SettleOnInteract only accepts (runtime, provider_address, cooldown_s) and always calls runtime.release_escrow directly -- Smart Wallet providers would hit raw-EOA settlement and revert during the background sweep.
  - TS: `sdk-js/src/settle/SettleOnInteract.ts:13-16,39-44,74-84 (ReleaseRouter param + routing)` · PY: `python-sdk-v2/src/agirails/settle/settle_on_interact.py:32-79 (no release_router, direct runtime.release_escrow)`
  - Fix: Add optional release_router param to SettleOnInteract.__init__ and prefer release_router.release_escrow(tx_id) when provided, mirroring TS, so AA-enabled provider sweeps go through SmartWalletRouter/Paymaster.
- **retry util: TS rich retryable-error classification + withRetryResult + onRetry + retry-after absent in Python** `behavior-diff`
  - TS retry.ts classifies retryable errors via HTTP status codes (408/429/500/502/503/504), errno set (ECONNRESET/ECONNREFUSED/ETIMEDOUT/ENOTFOUND/...), AbortError/TimeoutError names, and message substrings, exposes isRetryableError, calculateBackoffDelay, withRetry (throws) AND withRetryResult (never-throws, returns {result,error,attempts,totalTimeMs,success}), an onRetry callback, and honors StorageRateLimitError.details.retryAfter. Python retry.py classifies ONLY by exception-type tuple (retryable_errors), no isRetryableError/status/errno/message logic, no withRetryResult/RetryResult, no onRetry, no retry-after honoring. Jitter differs (TS +/-10% around capped delay; Python FULL jitter random.uniform(0,delay)) and default max delay differs (TS 10000ms vs Python 30000ms).
  - TS: `sdk-js/src/utils/retry.ts:111-364` · PY: `python-sdk-v2/src/agirails/utils/retry.py:62-205`
  - Fix: Port isRetryableError (status/errno/message), withRetryResult + RetryResult, onRetry, retry-after honoring; align jitter to +/-jitterFactor and default max delay to 10s, OR document the intentional difference. Low protocol risk (no hashing), P1 feature-parity.

### server (provider server app, policy/policy_engine, QuoteChannel tra…

- **Python has no QuoteChannelClient (send-side transport)** _[AIP-2.1]_ `missing-class`
  - TS exports QuoteChannelClient with sendQuote(peerEndpoint, quote) and sendCounter(peerEndpoint, counter) which POST a signed ChannelPayload to the peer's /quote-channel/{chainId}/{txId} endpoint via fetch with an AbortController timeout (default 10s, configurable timeoutMs/fetchImpl). This is how a buyer posts counter-offers and a provider posts quotes off-chain. Python has only the receive-side QuoteChannelHandler; there is no client to POST messages out, so a Python provider/buyer cannot send quotes or counters over the HTTPS channel using the SDK.
  - TS: `sdk-js/src/transport/QuoteChannel.ts:159-222 (class), src/index.ts:176` · PY: `ABSENT (grep send_quote/send_counter/QuoteChannelClient → no hits under python-sdk-v2/src/agirails)`
  - Fix: Add a QuoteChannelClient to python-sdk-v2/src/agirails/server/quote_channel.py (or a transport module) with send_quote/send_counter using httpx/requests + timeout, building URL via build_channel_path, posting {type, message} JSON, raising on non-2xx; export it from server/__init__.py and the top-level package.
- **Python QuoteChannelHandler does not handle agirails.quote.v1 (forward direction)** _[AIP-2.1]_ `behavior-diff`
  - TS QuoteChannelHandler.handle() accepts BOTH 'agirails.quote.v1' (verified via QuoteBuilder.verify) and 'agirails.counteroffer.v1' (verified via CounterOfferBuilder.verify), dedups on type:provider:nonce for quotes and type:consumer:nonce for counters. Python handler explicitly rejects anything except agirails.counteroffer.v1 with a 400 ('Only agirails.counteroffer.v1 is supported by this handler in v1'). So a Python receiver cannot ingest/verify provider quotes over the channel — only buyer counter-offers. This is an intentional v1 narrowing documented in the docstring, but it is a real surface gap vs TS.
  - TS: `sdk-js/src/transport/QuoteChannel.ts:280-355 (isChannelPayload covers both, step 5 branches on payload.type), 55-57 (ChannelPayload union)` · PY: `python-sdk-v2/src/agirails/server/quote_channel.py:162-172 (rejects non-counteroffer), 128-135 (docstring: only counteroffer.v1)`
  - Fix: Once Python QuoteBuilder gains EIP-712 verify symmetry, extend the handler to accept agirails.quote.v1, parse the quote dict, verify via QuoteBuilder.verify, and dedup keyed type:provider:nonce — mirroring TS step 5/6 branching.
- **Python has no buildX402Server / server x402 factory module** `missing-module`
  - TS src/server/ exports buildX402Server(config) plus X402ServerConfig/X402RouteDefinition/X402ServerResult, published as the '@agirails/sdk/server' subpath. It validates payTo (0x+40hex), CAIP-2 network, per-route 'METHOD /path', duplicate routes, price format/positivity, maxTimeoutSeconds, advertises Permit2, and returns a ready-to-mount x402HTTPResourceServer + routes config for @x402/express|hono|next. Python has no equivalent: grep for build_x402_server/X402ServerConfig/ResourceServer/facilitator under agirails src returns nothing. A Python seller cannot stand up an x402 v2 paid-route resource server via the SDK.
  - TS: `sdk-js/src/server/buildX402Server.ts:154-277 (factory), src/server/index.ts:32-37 (exports), package.json:18-21 ('./server' export)` · PY: `ABSENT (no x402 server helper anywhere in python-sdk-v2/src/agirails)`
  - Fix: Decide whether Python needs an x402 resource-server helper (depends on a Python x402 library). If keeping parity, add agirails/server/x402_server.py exposing build_x402_server with identical validation + route-config output, or document this as a JS-only seller helper with a clear parity exception.


---

## P2 — Polish / Messaging / Docs (70)

### level1-agent

- **First-job V3 framed receipt ceremony absent (showFirstJobReceipt / ACTP_NO_FIRST_JOB_RECEIPT)** `missing-method`
  - TS renders a ceremonial 'FIRST TRANSACTION RECEIPT' to stdout on the agent's first completed job (testnet/mainnet, gated by showFirstJobReceipt config default true and ACTP_NO_FIRST_JOB_RECEIPT=1 opt-out, jobsCompleted===1). Python has no first-job receipt, no showFirstJobReceipt config field, no env opt-out. Earn-side onboarding wow-moment is missing.
  - TS: `sdk-js/src/level1/Agent.ts:252-264,1966-2010` · PY: `ABSENT`
  - Fix: Add show_first_job_receipt to AgentConfig and render the V3 receipt once on jobs_completed==1 (testnet/mainnet, ACTP_NO_FIRST_JOB_RECEIPT opt-out).
- **start() is not idempotent (raises instead of noop on running/paused)** `behavior-diff`
  - TS start() on an already running/paused agent logs a warning and returns (idempotent noop, PRD §5.3). Python start() raises RuntimeError if status is RUNNING or STARTING (and does not noop on PAUSED). Behavior/contract divergence for double-start.
  - TS: `sdk-js/src/level1/Agent.ts:564-576` · PY: `python-sdk-v2/src/agirails/level1/agent.py:251-252`
  - Fix: Make start() a logged noop when already running/paused to match TS PRD §5.3.
- **Partial-start cleanup of polling task on failure missing** `behavior-diff`
  - TS start() catch block calls stopPolling()+unsubscribe() so a partial start (e.g. subscription threw after the timer armed) does not leak the polling timer/subscription. Python start() catch only sets status STOPPED and emits error; if create_task already armed the poll loop before a later failure, the task is not cancelled. (Python arms polling only after client.create succeeds, narrowing the window, but there is no explicit cleanup symmetry.)
  - TS: `sdk-js/src/level1/Agent.ts:604-613` · PY: `python-sdk-v2/src/agirails/level1/agent.py:290-301`
  - Fix: Cancel _polling_task and any subscription in the start() except block before re-raising.
- **getBalanceAsync does not aggregate locked/pending from provider transactions** `behavior-diff`
  - TS getBalanceAsync iterates getTransactionsByProvider and sums locked (COMMITTED/IN_PROGRESS/DELIVERED) and pending (INITIATED/QUOTED) amounts in addition to USDC. Python _update_balance only sets usdc from client.get_balance and leaves locked/pending at the default '0.00'. AgentBalance.locked/pending are always zero in Python.
  - TS: `sdk-js/src/level1/Agent.ts:898-954` · PY: `python-sdk-v2/src/agirails/level1/agent.py:541-545`
  - Fix: Aggregate locked/pending from get_transactions_by_provider like TS.
- **Lifecycle status guard on incoming tx (drop when not running/starting) missing** `behavior-diff`
  - TS handleIncomingTransaction drops incoming txs unless status is 'running' or 'starting', preventing a paused/stopping agent from accepting new jobs via a queued callback. Python _process_transaction has no such guard (the only status check is in _poll_for_jobs at the loop level), so a tx already dequeued can still be processed during pause/stop transitions.
  - TS: `sdk-js/src/level1/Agent.ts:1133-1142` · PY: `python-sdk-v2/src/agirails/level1/agent.py:664-678`
  - Fix: Add a running/starting status guard at the top of _process_transaction.
- **ServiceFilter.custom may be async in TS but Python only supports sync** `signature-diff`
  - TS ServiceFilter.custom is (job) => boolean | Promise<boolean> and shouldAutoAccept awaits it (Agent.ts:1426). Python ServiceFilter.custom is typed Callable[[Job], bool] and ServiceFilter.matches calls it synchronously (config.py:163) — an async custom filter would return a coroutine treated as truthy, silently accepting. Async custom filters are unsupported.
  - TS: `sdk-js/src/level1/Agent.ts:52-53,1424-1435` · PY: `python-sdk-v2/src/agirails/level1/config.py:147,163`
  - Fix: Support awaitable custom filters: detect coroutine and await it in the auto-accept path (matches_job/_should_auto_accept).
- **ServiceConfig.description/capabilities and agent-level ServiceFilter on AgentConfig parity-OK but provide() options shape differs** `signature-diff`
  - TS provide(serviceOrConfig, handler, options?: Partial<ServiceConfig>) merges arbitrary ServiceConfig fields; Python provide(service, handler, *, filter, pricing, timeout) exposes only three keyword options and cannot pass description/capabilities/delivery when given a string service. Minor API-ergonomics divergence.
  - TS: `sdk-js/src/level1/Agent.ts:771-810` · PY: `python-sdk-v2/src/agirails/level1/agent.py:375-428`
  - Fix: Accept the full ServiceConfig field set (description/capabilities/delivery) in the keyword options of provide().
- **request() signature and semantics diverge** `signature-diff`
  - TS Agent.request(service, options: Omit<RequestOptions,'network'>) delegates to level0 basicRequest with the agent network and updates totalSpent. Python Agent.request(service, input, *, provider, budget, timeout=300) re-implements its own create_transaction+link_escrow+poll loop returning {tx_id,status} and does NOT update stats.total_spent. Different parameter shape, different return type, and no totalSpent accounting.
  - TS: `sdk-js/src/level1/Agent.ts:819-837` · PY: `python-sdk-v2/src/agirails/level1/agent.py:452-525`
  - Fix: Align request() to delegate to level0.request with RequestOptions-shaped args and update total_spent; return a RequestResult-equivalent.
- **Service name validation differs from TS validateServiceName / state directory path validation absent** `security-diff`
  - TS provide() runs validateServiceName (injection guard) and the ctor validates stateDirectory against ~/.agirails via validatePath (path-traversal guard). Python _register_service does no service-name validation, and AgentConfig.__post_init__ validates only the agent name (alphanumeric/dash/underscore, <=64), not service names or state_directory traversal. Security hardening present in TS is missing in Python.
  - TS: `sdk-js/src/level1/Agent.ts:502-522,785-793` · PY: `python-sdk-v2/src/agirails/level1/agent.py:430-446`
  - Fix: Run a validate_service_name on service names and validate state_directory against a sandbox base like TS.
- **PricingStrategy.cost.api / ServiceCost.api (auto API-cost) field absent** `missing-param`
  - TS ServiceCost supports an optional api field ('openai:gpt-4-turbo' etc.) and estimateApiCost hook (currently returns 0). Python CostModel has only base + per_unit dict; no api field or estimate_api_cost. Forward-compat field missing (low impact since TS returns 0 today).
  - TS: `sdk-js/src/level1/pricing/PricingStrategy.ts:48-67,217-223` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:21-58`
  - Fix: Add api field to CostModel and an estimate_api_cost stub for parity.
- **PriceCalculation.breakdown absent in Python** `missing-param`
  - TS PriceCalculation includes a breakdown {baseCost, unitCost, units?, apiCost?} for debugging. Python PriceCalculation has cost/price/profit/margin_percent/decision/reason/counter_offer but no breakdown field, so the per-component cost decomposition TS exposes is unavailable.
  - TS: `sdk-js/src/level1/pricing/PricingStrategy.ts:191-197,118-125` · PY: `python-sdk-v2/src/agirails/level1/pricing.py:114-138`
  - Fix: Add a breakdown field to PriceCalculation populated by calculate_price.
- **JobContext shape differs (state is a dict, not get/set API; progress message default)** `signature-diff`
  - TS JobContext.state is {get<T>(key), set<T>(key,value)} and progress(percent, message?). Python JobContext.state is a raw dict property and adds get_progress()/_trigger_cancel() (extra) while log methods take **meta kwargs vs TS (message, meta?). Handler code is not portable between SDKs without adaptation. Python also clamps progress percent (0-100) which TS does not.
  - TS: `sdk-js/src/level1/types/Job.ts:141-178` · PY: `python-sdk-v2/src/agirails/level1/job.py:104-149`
  - Fix: Offer a get/set state facade and align progress/log signatures for cross-SDK handler portability.
- **Polling interval differs (TS 5s vs Python 2s)** `behavior-diff`
  - TS startPolling uses a 5000ms interval; Python POLL_INTERVAL is 2.0s. Different load profile / job-pickup cadence against the same runtime/RPC. Minor but a divergence consumers may tune around.
  - TS: `sdk-js/src/level1/Agent.ts:1003` · PY: `python-sdk-v2/src/agirails/level1/agent.py:135`
  - Fix: Align to 5s (or make configurable) to match TS cadence.

### core-client

- **getAddress()/info.address returns lowercase, not EIP-55 checksummed** `behavior-diff`
  - TS normalizes the requester address with ethers.getAddress() (EIP-55 checksum) before storing in info.address / returning from getAddress(). Python Address.normalize() returns address.lower(), so info.address and get_address() are all-lowercase. Case-insensitive on-chain so not a correctness bug, but a visible API divergence and string-equality comparisons vs checksummed addresses differ.
  - TS: `ACTPClient.ts:1079-1086, 1180-1182` · PY: `client.py:311-312, 751-758; utils/helpers.py:356-366`
  - Fix: Make Address.normalize return EIP-55 checksum (web3 to_checksum_address) or checksum in create()/get_address for parity.
- **ACTPClientInfo missing walletTier field** _[AIP-12]_ `missing-param`
  - TS ACTPClientInfo includes walletTier ('auto'|'eoa'|undefined) populated from walletProvider.getWalletInfo().tier, letting callers introspect Smart Wallet vs EOA. Python ACTPClientInfo dataclass has only mode/address/state_directory — no wallet_tier — so tier is not surfaced.
  - TS: `ACTPClient.ts:418-427, 1081-1086` · PY: `client.py:53-63`
  - Fix: Add wallet_tier to ACTPClientInfo and populate from wallet_provider.get_wallet_info().tier in create().
- **getWalletProvider() accessor missing** _[AIP-12]_ `missing-method`
  - TS exposes getWalletProvider() returning the IWalletProvider (testnet/mainnet) for advanced operations. Python stores _wallet_provider but exposes no public accessor.
  - TS: `ACTPClient.ts:1683-1685` · PY: `client.py (ABSENT)`
  - Fix: Add get_wallet_provider() returning self._wallet_provider.
- **getRegisteredAdapters() accessor missing** `missing-method`
  - TS exposes getRegisteredAdapters() -> string[] (registry.getIds(), e.g. ['basic','standard','x402']). Python has register_adapter() but no getter to enumerate registered adapter IDs.
  - TS: `ACTPClient.ts:1645-1647` · PY: `client.py:210-216`
  - Fix: Add get_registered_adapters() delegating to registry.get_ids().
- **toJSON() private-key-safe serialization missing** `missing-method`
  - TS implements toJSON() returning a sanitized object {mode,address,stateDirectory,isInitialized,_warning} excluding privateKey/signer, protecting against accidental JSON.stringify/log leakage. Python has __repr__/__str__ (truncated address, no key) but no toJSON()/__getstate__ equivalent, so json.dumps/pickle of the client is not guarded the same way.
  - TS: `ACTPClient.ts:1236-1245` · PY: `client.py:842-854`
  - Fix: Add a to_dict()/__getstate__ that strips sensitive fields for parity.
- **BasicAdapter has no routeUrlPayment callback / HTTP-recipient fallback; client not passed as activationProvider** `behavior-diff`
  - TS passes the ACTPClient (this) into BasicAdapter as activationProvider, and BasicAdapter.pay() detects http(s) recipients and delegates to client.routeUrlPayment() (router-based x402). Python BasicAdapter is constructed without the client (no activation_provider), has no URL detection in pay(), and routeUrlPayment is absent on the client. client.pay() still routes URLs via router.select_and_resolve, but client.basic.pay(url) will not fall back to x402 the way TS does, and the dedicated ValidationError guidance is absent.
  - TS: `ACTPClient.ts:670, 1394-1407; adapters/BasicAdapter.ts:370-432` · PY: `client.py:161-167, 684-726; adapters/basic.py:125`
  - Fix: Pass the client into BasicAdapter as activation_provider and add route_url_payment() to the client; detect http(s) in BasicAdapter.pay and delegate.
- **Python ACTPClientConfig.contracts/gas_settings/eas_config typed as loose dicts vs TS structured shapes** `signature-diff`
  - TS ACTPClientConfig.contracts is {actpKernel?,escrowVault?,usdc?,agentRegistry?}, gasSettings is {maxFeePerGas?:bigint,maxPriorityFeePerGas?:bigint}, easConfig is EASConfig. Python uses Optional[Dict[str,str]] / Optional[Dict[str,Any]] for these, losing the structured field contracts and bigint typing. Minor surface/typing divergence; values still flow through to the blockchain runtime.
  - TS: `ACTPClient.ts:364-389` · PY: `client.py:89-91`
  - Fix: Introduce typed config substructures (dataclasses/TypedDicts) for contracts/gas_settings/eas_config for parity.
- **Python pay() auto-coerces dict to UnifiedPayParams; TS takes typed UnifiedPayParams only** `signature-diff`
  - Python ACTPClient.pay accepts Union[UnifiedPayParams, dict] and does UnifiedPayParams(**params) for dicts. TS pay(params: UnifiedPayParams) takes the typed object only. Minor ergonomic divergence; both then route via selectAndResolve. Not a correctness issue.
  - TS: `ACTPClient.ts:1370-1387` · PY: `client.py:684-726`
  - Fix: Acceptable Pythonic convenience; document or keep for parity-friendliness.

### erc8004

- **Missing Bridge method getStats parity is fine but ReputationReporter.getStats absent in Python** `missing-method`
  - TS ReputationReporter exposes getStats()->{network, reportedCount} (ReputationReporter.ts:425-430). Python ReputationReporter has no get_stats. Minor observability gap.
  - TS: `sdk-js/src/erc8004/ReputationReporter.ts:422-430` · PY: `python-sdk-v2/src/agirails/erc8004/reputation_reporter.py:183-189`
  - Fix: Add get_stats() returning {'network': self._config.network, 'reported_count': len(self._reported)}.
- **Identity ABI missing register() (publish flow) in Python** `missing-method`
  - TS ERC8004_IDENTITY_ABI includes `register(string agentURI) external returns (uint256 agentId)` for the publish/registration flow (types/erc8004.ts:245). Python ERC8004_IDENTITY_ABI has only the four view functions. If/when the Python publish pipeline registers an ERC-8004 identity it has no ABI entry.
  - TS: `sdk-js/src/types/erc8004.ts:244-246` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:57-89`
  - Fix: Add the register(string)->uint256 fragment to Python ERC8004_IDENTITY_ABI to match TS.
- **revokeLatest ABI/signature divergence and no revoke method** `signature-diff`
  - TS revokeLatest is `revokeLatest(uint256 agentId, uint64 feedbackIndex)` and IERC8004ReputationRegistry exposes it. Python ABI declares `revokeLatest(uint256 agentId)` with no feedbackIndex (types/erc8004.py:118-124), and neither SDK exposes a public revoke method, but the Python fragment selector would be wrong if ever called.
  - TS: `sdk-js/src/types/erc8004.ts:255 ; sdk-js/src/erc8004/ReputationReporter.ts:99` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:118-124`
  - Fix: Correct Python revokeLatest fragment to (uint256 agentId, uint64 feedbackIndex).
- **readFeedback view function absent in Python ABI** `missing-method`
  - TS ERC8004_REPUTATION_ABI includes readFeedback(uint256,uint64) returning a feedback tuple (types/erc8004.ts:258). Python ABI omits it. Not currently called by the reporter, but part of the declared surface.
  - TS: `sdk-js/src/types/erc8004.ts:258` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:91-125`
  - Fix: Add readFeedback fragment to Python ABI for parity.
- **ERC8004ErrorCode enum missing 5 codes in Python** `missing-class`
  - TS ERC8004ErrorCode has 9 members: AGENT_NOT_FOUND, INVALID_AGENT_ID, WALLET_NOT_FOUND, METADATA_FETCH_FAILED, REPORT_FAILED, ALREADY_REPORTED, NOT_AUTHORIZED, NETWORK_ERROR, INVALID_NETWORK. Python has only 4: AGENT_NOT_FOUND, INVALID_AGENT_ID, NETWORK_ERROR, METADATA_FETCH_FAILED. Missing WALLET_NOT_FOUND, REPORT_FAILED, ALREADY_REPORTED, NOT_AUTHORIZED, INVALID_NETWORK.
  - TS: `sdk-js/src/types/erc8004.ts:165-180` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:132-138`
  - Fix: Add the 5 missing enum members to Python ERC8004ErrorCode for parity.
- **ERC8004Error constructor arg order/shape differs (message,code,agentId,cause vs code,message,details)** `signature-diff`
  - TS ERC8004Error(message, code, agentId?, cause?) with .name='ERC8004Error'. Python ERC8004Error(code, message, details?) producing message '[CODE] message'. Different positional order and field model (agentId/cause vs details dict). Cross-SDK error handling and message format differ.
  - TS: `sdk-js/src/types/erc8004.ts:185-200` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:141-160`
  - Fix: Optionally align field model; at minimum document the intentional Pythonic shape. Low priority since errors are SDK-internal.
- **Bridge resolveAgent error classification (not-found vs network) less precise in Python** `behavior-diff`
  - TS resolveAgent distinguishes 'nonexistent'/'ERC721'/'invalid token' errors -> AGENT_NOT_FOUND vs other -> NETWORK_ERROR, and treats ZeroAddress owner as not-found (ERC8004Bridge.ts:238-269). Python wraps ANY ownerOf failure as AGENT_NOT_FOUND (bridge.py:155-163) and does not separately check ZeroAddress owner. A genuine RPC/network failure is mislabeled AGENT_NOT_FOUND in Python.
  - TS: `sdk-js/src/erc8004/ERC8004Bridge.ts:233-269` · PY: `python-sdk-v2/src/agirails/erc8004/bridge.py:154-169`
  - Fix: Inspect exception text for ERC721/nonexistent to choose AGENT_NOT_FOUND vs NETWORK_ERROR; also map ZeroAddress owner to AGENT_NOT_FOUND.
- **AgentMetadata field shape differs (capabilities/endpoints/arbitrary extensions vs services/external_url/raw)** `signature-diff`
  - TS ERC8004AgentMetadata has name, description, image, paymentAddress, wallet, capabilities[], endpoints{api,webhook}, plus arbitrary [key:string]:unknown. Python dataclass has name, description, wallet, payment_address, services[], image, external_url, raw — no capabilities/endpoints typed fields (raw holds the full dict). payment_address parsing reads both 'paymentAddress' and 'payment_address' (bridge.py:303); TS reads only 'paymentAddress'. Minor schema drift; both surface raw/extension data differently.
  - TS: `sdk-js/src/types/erc8004.ts:57-84` · PY: `python-sdk-v2/src/agirails/types/erc8004.py:168-183 ; python-sdk-v2/src/agirails/erc8004/bridge.py:299-308`
  - Fix: Align metadata field names with TS (capabilities, endpoints) or document the Python superset; keep raw for forward-compat.

### adapters

- **Router identity access + PaymentMetadata key casing diverge** `behavior-diff`
  - TS router reads metadata.identity?.type is erc8004 structurally. Python checks identity via hasattr(identity, type) which works only if a PaymentIdentity object is passed; a dict-shaped identity silently fails the erc8004 branch, while other keys use dict.get. Also TS keys are camelCase (preferredAdapter/requiresEscrow) vs Python snake_case, so cross-SDK metadata payloads are not interchangeable.
  - TS: `sdk-js/src/adapters/AdapterRouter.ts:115-180; types/adapter.ts:80-122` · PY: `python-sdk-v2/src/agirails/adapters/adapter_router.py:129-199; types.py:80-96`
  - Fix: Support both dict and object identity forms; document/accept camelCase vs snake_case metadata keys.
- **Router HTTP-without-x402 behavior diverges (Python raises, TS falls through)** `behavior-diff`
  - When the target is HTTP(S) and no x402 adapter is registered/handles, TS router falls through to the priority loop / basic last-resort; Python raises RuntimeError immediately. Python is arguably better UX but is a divergence.
  - TS: `sdk-js/src/adapters/AdapterRouter.ts:161-172` · PY: `python-sdk-v2/src/agirails/adapters/adapter_router.py:183-192`
  - Fix: Pick canonical behavior; if keeping Python early-raise, backport to TS, else make Python fall through. Document it.
- **Router validation uses hand-rolled checks instead of zod schema** `behavior-diff`
  - TS validateParams runs the full UnifiedPayParamsSchema (zod) enforcing types (amount positive-number/non-empty string, deadline string|number, disputeWindow int 3600..30d, httpMethod enum) before manual security checks. Python _validate_params only checks to-required, amount-not-None, plus manual security/description checks; negative amount, malformed deadline, out-of-range dispute_window are not caught at the router layer.
  - TS: `sdk-js/src/adapters/AdapterRouter.ts:211-254; types/adapter.ts:192-210` · PY: `python-sdk-v2/src/agirails/adapters/adapter_router.py:217-258`
  - Fix: Add schema-equivalent validation (pydantic or explicit) matching zod constraints.
- **BaseAdapter missing validate_bytes32, validate_timestamp, encode_dispute_window_proof** `missing-method`
  - TS BaseAdapter provides validateBytes32 (66-char hex, lowercased), validateTimestamp (positive, year-3000 guard), encodeDisputeWindowProof (ABI uint256). Python BaseAdapter has none, so the missing deliver() proof encoding has no shared helper guaranteeing identical ABI bytes to TS.
  - TS: `sdk-js/src/adapters/BaseAdapter.ts:368-504` · PY: `python-sdk-v2/src/agirails/adapters/base.py:33-317`
  - Fix: Add validate_bytes32, validate_timestamp, encode_dispute_window_proof (eth_abi encode uint256 seconds).
- **validate_address normalizes to lowercase; TS to EIP-55 checksum** `behavior-diff`
  - TS validateAddress returns ethers.getAddress() (EIP-55 checksummed); Python returns Address.normalize() (lowercase). On-chain hashing is unaffected, but cross-SDK string-equality/display comparison of returned provider/requester values differs.
  - TS: `sdk-js/src/adapters/BaseAdapter.ts:213-243` · PY: `python-sdk-v2/src/agirails/adapters/base.py:244-276`
  - Fix: Return EIP-55 checksummed addresses from Python validate_address to match TS, or document lowercase; ensure result provider/requester casing matches across SDKs.
- **BasicPayParams/StandardTransactionParams field drift; agent_id dropped from standard** `signature-diff`
  - TS BasicPayParams (to,amount,deadline,disputeWindow); Python (to,amount,deadline,description) adds description drops disputeWindow. TS StandardTransactionParams (provider,amount,deadline,disputeWindow,serviceDescription,agentId); Python (provider,amount,deadline,dispute_window,description,service_hash) renames serviceDescription to description, adds service_hash py-extra, DROPS agentId so ERC-8004 agent id cannot be threaded into create_transaction for reputation. TS standard.pay maps erc8004AgentId; Python std_params never carries agent_id.
  - TS: `sdk-js/src/adapters/BasicAdapter.ts:45-57; StandardAdapter.ts:35-53` · PY: `python-sdk-v2/src/agirails/adapters/basic.py:56-72; standard.py:32-52`
  - Fix: Add agent_id to StandardTransactionParams and thread it into create_transaction; add dispute_window to BasicPayParams; reconcile description vs service_description naming.

### storage

- **setArchivedAt positivity guard differs (TS rejects <=0; Python accepts any int)** _[AIP-7]_ `behavior-diff`
  - TS setArchivedAt validates ts>0 and defaults to now when undefined; build() also defaults archivedAt to now if unset. Python set_archived_at stores any int with no >0 check; default is int(time.time()). A 0/negative timestamp is rejected in TS, accepted in Python (pydantic archived_at has ge=0 so 0 passes; negative fails only at model build, not at the setter).
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:165-172` · PY: `python-sdk-v2/src/agirails/storage/archive_bundle_builder.py:239-250`
  - Fix: Add a >0 guard in set_archived_at to mirror TS (align on >0 vs pydantic >=0).
- **validate_archive_bundle differs in depth/error-type/shape from TS validateArchiveBundle** _[AIP-7]_ `behavior-diff`
  - TS validateArchiveBundle is a type guard checking presence of required top-level fields and type===ARCHIVE_BUNDLE_TYPE, throwing ValidationError(field,msg) per missing field. Python validate_archive_bundle does deeper content validation (tx_id hash, chain_id, addresses, CIDs, hashes, final_state) and aggregates all errors into one ArchiveBundleValidationError. Close but not identical: Python validates CID/hash content TS does not (TS defers to builder setters), and error type/message format differ.
  - TS: `sdk-js/src/storage/ArchiveBundleBuilder.ts:528-561` · PY: `python-sdk-v2/src/agirails/storage/archive_bundle_builder.py:103-159`
  - Fix: Acceptable divergence; document that Python validate_archive_bundle is stricter and reconcile error class naming across SDKs.
- **IPFS gateway allowlist differs: Python missing nftstorage.link** _[AIP-7]_ `behavior-diff`
  - TS ALLOWED_IPFS_GATEWAYS = [ipfs.filebase.io, gateway.pinata.cloud, cloudflare-ipfs.com, ipfs.io, dweb.link, w3s.link, nftstorage.link]. Python ALLOWED_IPFS_GATEWAYS omits nftstorage.link (has the other 6). A download via nftstorage.link that TS permits is SSRF-rejected by Python. Also TS stores bare domains and validateGatewayURL parses host; Python stores full https:// origins and compares scheme://netloc — equivalent for these hosts but a different matching strategy.
  - TS: `sdk-js/src/utils/validation.ts:47-65` · PY: `python-sdk-v2/src/agirails/utils/validation.py:665-678`
  - Fix: Add 'https://nftstorage.link' to Python ALLOWED_IPFS_GATEWAYS to match TS.
- **DownloadResult shape diverges: TS returns parsed data<T>; Python returns raw bytes** _[AIP-7]_ `signature-diff`
  - TS DownloadResult<T> carries parsed data (downloadJSON returns {data:T}). Python DownloadResult.data is always bytes; parsing is done by separate download_json/download_bundle which return the dict/model directly (not a DownloadResult). TS uploadedAt/downloadedAt are JS Date; Python uses tz-aware datetime. Net behavior reachable on both sides but the return-type contract differs (no DownloadResult-with-parsed-data in Python).
  - TS: `sdk-js/src/storage/types.ts:321-331; sdk-js/src/storage/FilebaseClient.ts:270-392` · PY: `python-sdk-v2/src/agirails/storage/types.py:465-482; python-sdk-v2/src/agirails/storage/filebase_client.py:333-349`
  - Fix: Acceptable language-idiom difference; document it. If strict parity wanted, add a typed parsed-data variant.
- **ArchiveTags 'Content-Type' key represented as Content_Type in Python TypedDict** _[AIP-7]_ `behavior-diff`
  - TS ArchiveTags interface uses literal key 'Content-Type'. Python TypedDict uses Content_Type (underscore) since Python identifiers can't contain hyphens. The actual upload tag names are produced separately as ('Content-Type', ...) tuples in upload_bundle, so on-wire tags match TS; but the ArchiveTags type itself misrepresents the key and would mislead a consumer constructing it.
  - TS: `sdk-js/src/storage/types.ts:340-348` · PY: `python-sdk-v2/src/agirails/storage/types.py:489-498`
  - Fix: Use a functional TypedDict with field aliasing or a plain dict[str,str] alias so 'Content-Type' is representable; tag emission in upload_bundle already matches.

### level0 (Simple-tier primitives: provide / request / Provider / Serv…

- **request() error types differ from TS (TimeoutError/NoProviderFoundError/ValidationError)** `behavior-diff`
  - TS throws domain errors NoProviderFoundError, TimeoutError (with txId/wasCancelled/currentState attached), and ValidationError, and re-wraps unknown errors as `Request failed: ...` (request.ts:343-351). Python raises builtin ValueError for missing provider, builtin TimeoutError without the txId/wasCancelled/currentState fields (request.py:465, 711), and re-raises rather than wrapping. Callers cannot do instanceof-style discrimination matching TS.
  - TS: `level0/request.ts:343-351` · PY: `level0/request.py:465,711,807-809`
  - Fix: Use the SDK's typed errors (NoProviderFound/Timeout/Validation) and attach tx_id/was_cancelled/current_state to the timeout error.
- **request() onProgress states/percentages diverge** `behavior-diff`
  - TS emits onProgress at initiated(10), waiting(10+min(80, attempts/maxAttempts*80)), and settled(100) (request.ts:175-315). Python RequestHandle emits progress capped at 90 using a time-based formula and never emits the final settled(100)/'Transaction completed!' update (request.py:450-458). Reported progress curve and terminal event differ.
  - TS: `level0/request.ts:309-315` · PY: `level0/request.py:449-458`
  - Fix: Mirror TS progress milestones including the final settled(100) callback.
- **request() omits the options.input-dropped warning (4.0.0 transport change)** `behavior-diff`
  - TS request() logs a warning that options.input is not transported in 4.0.0 (handler receives job.input={}), pending the agirails.request.v1 envelope (request.ts:139-144). Python request() still embeds input into the JSON service_description (request.py:759) and emits no such warning, so behavior and messaging both diverge from the documented 4.x contract.
  - TS: `level0/request.ts:139-144` · PY: `level0/request.py:759`
  - Fix: Stop transporting input on-chain and emit the same 4.0.0 input-dropped warning, or document the deliberate divergence.
- **Python budget→USDC wei uses float math (precision loss) vs TS string math** `behavior-diff`
  - TS converts budget to 6-dp USDC wei using string splitting to avoid float precision loss (request.ts:107-111). Python uses str(int(budget * 1_000_000)) (request.py:744), which can lose precision for fractional budgets (e.g. 0.1*1e6 float error). Resulting on-chain amounts can differ by 1 wei for some decimals.
  - TS: `level0/request.ts:106-111` · PY: `level0/request.py:743-744`
  - Fix: Use Decimal or string-split math identical to TS for the wei conversion.

### protocol

- **Kernel missing estimateCreateTransaction()** `missing-method`
  - TS exposes ACTPKernel.estimateCreateTransaction(params) (ACTPKernel.ts:689-713) for standalone gas estimation. Python folds estimation into create_transaction via _estimate_gas but has no public estimate_create_transaction method.
  - TS: `protocol/ACTPKernel.ts:689-713` · PY: `ABSENT (protocol/kernel.py)`
  - Fix: Expose estimate_create_transaction(params) helper for parity.
- **EventMonitor declares but never parses AttestationAnchored/MilestoneReleased/EscrowReleased/EscrowCompleted** `missing-event`
  - Python EventType enum (events.py:44-58) declares ATTESTATION_ANCHORED, MILESTONE_RELEASED, ESCROW_RELEASED, ESCROW_COMPLETED, but _get_kernel_events/_get_escrow_events only parse TransactionCreated, StateTransitioned, EscrowCreated, EscrowPayout (events.py:585-665). TS exposes onEscrowReleased + onStateChanged; its history path reads getTransaction so it is event-name agnostic. Net: Python silently never emits the 4 declared-but-unparsed event types.
  - TS: `protocol/EventMonitor.ts:284-318` · PY: `protocol/events.py:44-58,585-665`
  - Fix: Implement parsers for the declared event types or remove them from the enum to avoid implying coverage.
- **EscrowVault ABI missing ReentrancyGuardReentrantCall and SafeERC20FailedOperation custom errors** `behavior-diff`
  - TS abi/EscrowVault.json includes error ReentrancyGuardReentrantCall() and error SafeERC20FailedOperation(address). Python abis/escrow_vault.json omits both (functions+events otherwise identical). web3.py cannot decode these custom revert reasons, so a reentrancy/SafeERC20 revert surfaces as an opaque/unknown error in Python instead of a named reason. No functional/state impact — message-decoding only.
  - TS: `abi/EscrowVault.json` · PY: `abis/escrow_vault.json`
  - Fix: Add the two error entries to the Python EscrowVault ABI for revert-reason decoding parity.
- **No IdentityRegistry ABI bundled in Python protocol abis directory** `missing-module`
  - TS ships abi/IdentityRegistry.json (ERC-8004 identity registry) and abi/ERC20.json. Python abis/ has only actp_kernel.json, agent_registry.json, escrow_vault.json, usdc.json (usdc covers ERC20 surface). There is no IdentityRegistry ABI in the Python protocol abis directory, so any ERC-8004 identity-registry read bound from this directory has no local ABI (Python ERC-8004 may live elsewhere, but within protocol/abis it is absent).
  - TS: `abi/IdentityRegistry.json` · PY: `abis/ (IdentityRegistry ABSENT)`
  - Fix: Bundle IdentityRegistry.json under python abis/ if the Python ERC-8004 bridge reads from this location, for directory-level parity.

### server (provider server app, policy/policy_engine, QuoteChannel tra…

- **Python missing DedupStore interface + ChannelPayload/config type exports** _[AIP-2.1]_ `missing-class`
  - TS exports the DedupStore interface (the swappable atomic recordOnce contract that lets callers plug Redis/DynamoDB/Postgres for multi-worker production) plus type exports ChannelPayload, QuoteChannelClientConfig, QuoteChannelHandlerConfig, HandlerContext, HandlerResult. Python only ships the concrete InMemoryDedupStore (no abstract Protocol) and the dataclasses HandlerContext/HandlerResult; there is no DedupStore Protocol so callers cannot type a custom distributed store, and there is no ChannelPayload type. The handler accepts dedup_store: Optional[InMemoryDedupStore] (concrete type) rather than a Protocol, so a Redis-backed store would not type-check.
  - TS: `sdk-js/src/transport/QuoteChannel.ts:63-83 (DedupStore interface), src/index.ts:254-261 (type exports)` · PY: `python-sdk-v2/src/agirails/server/quote_channel.py:58-97 (only concrete InMemoryDedupStore), 140 (dedup_store typed as Optional[InMemoryDedupStore])`
  - Fix: Add a typing.Protocol DedupStore with record_once(key, ttl_ms) -> str and type the handler's dedup_store param as Optional[DedupStore]; optionally add a ChannelPayload TypedDict. Low risk, improves extensibility parity.
- **Python server policy is a simplified standalone port, not the negotiation orchestrator TS serve uses** _[AIP-2.1]_ `behavior-diff`
  - TS `actp serve` constructs a full ProviderOrchestrator (negotiation/ProviderOrchestrator + ProviderPolicyEngine) and calls orchestrator.evaluateCounter — the same negotiation engine used elsewhere, supporting multi-round concede strategy, injectable CounterDecider hooks (BYO-brain), services list, min-deadline, etc. Python server uses its own slimmed policy.py/policy_engine.py (evaluate_counter) that explicitly models 'only the fields the v1 daemon needs' and notes services/min_deadline_seconds/max_requotes are stored-but-not-enforced and concede is per-message stateless (no session round tracking, no injectable decider). Verdict math is close but not the same code path, and the injectable decider hook present in TS negotiation is absent on the Python server path.
  - TS: `sdk-js/src/cli/commands/serve.ts:141-147 (ProviderOrchestrator), src/index.ts:183-192 (ProviderOrchestrator/CounterDecider exports)` · PY: `python-sdk-v2/src/agirails/server/policy_engine.py:55-149 (standalone evaluate_counter), policy.py:8-11 (docstring: 'working subset … will be ported incrementally')`
  - Fix: Either back the Python server with a real ProviderOrchestrator/ProviderPolicyEngine port (if those exist in python-sdk-v2/negotiation) including injectable decider + multi-round state, or explicitly document the v1 server-policy subset as an accepted parity gap. Verify Python negotiation/ has an orchestrator before wiring.
- **Python serve has no slow-loris / body-cap hardening equivalent** _[AIP-2.1]_ `security-diff`
  - TS serve.ts hardens the raw http server: headersTimeout=10s, requestTimeout=15s, and readBody enforces a 64 KiB byte cap + 10s wall-clock deadline (defense-in-depth against slow-trickle/oversized bodies), destroying the socket on violation. Python serve.py delegates to uvicorn defaults (uvicorn.run) and FastAPI request.json() with no explicit max-body or per-request timeout configured, so a Python daemon relies entirely on uvicorn/proxy defaults for slow-loris and large-body protection. The 64KiB body cap that bounds memory on the TS side is not replicated.
  - TS: `sdk-js/src/cli/commands/serve.ts:184-185 (timeouts), 304-339 (readBody 64KiB/10s caps)` · PY: `python-sdk-v2/src/agirails/cli/commands/serve.py:140-142 (uvicorn.run, no limit_concurrency/timeout/body cap), app.py:79-85 (request.json with no size guard)`
  - Fix: Configure uvicorn timeouts (timeout_keep_alive) and add a request-body size guard (e.g. read Content-Length / cap body bytes in the route or via middleware) to match the TS 64KiB/10s posture.
- **Python QuoteChannelClient + SSRF + quote.v1 paths are untested (no client/quote-direction tests)** _[AIP-2.1]_ `test-gap`
  - TS QuoteChannel.test.ts has 37 tests including assertSafePeerUrl SSRF cases (loopback, link-local/metadata, RFC1918, IPv6 ULA, IPv4-mapped-IPv6, *.localhost) and QuoteChannelClient send/timeout/error cases. Python tests (tests/test_server/test_actp_serve.py, test_serve_e2e.py) cover the handler + serve daemon but cannot test a client/SSRF/quote.v1 path because those features don't exist on the Python side. Once the missing client + SSRF guard + quote.v1 handling are ported, equivalent tests must be added to preserve the security invariants.
  - TS: `sdk-js/src/transport/QuoteChannel.test.ts:75-137 (SSRF), 331-395 (client)` · PY: `python-sdk-v2/tests/test_server/test_actp_serve.py, test_serve_e2e.py (handler/daemon only; no client/SSRF/quote.v1)`
  - Fix: After porting QuoteChannelClient + assert_safe_peer_url + quote.v1 handling, port the corresponding TS test cases 1:1 (SSRF literal cases, client send/timeout/non-2xx, quote.v1 verify+dedup).

### cli

- **No public-RPC warning anywhere in Python CLI** `missing-event`
  - TS agent.ts warns once when a 24/7 on-chain listener runs on a public RPC (usingPublicRpc) because eth_getLogs is capped (~2000 blocks) and long-lived filters drop -> jobs silently missed; tells the user to set BASE_SEPOLIA_RPC/BASE_MAINNET_RPC. Python has no usingPublicRpc check and no agent/serve public-RPC warning, so a Python provider on a public RPC silently misses jobs with no diagnostic.
  - TS: `sdk-js/src/cli/commands/agent.ts:152-159; config/networks.ts:31` · PY: `python-sdk-v2/src/agirails/cli/ (ABSENT)`
  - Fix: Port usingPublicRpc to config/networks.py and emit the warning in the ported agent command (and serve if it gains an on-chain watcher).
- **testjobs templates directory not ported** `missing-module`
  - TS has cli/testjobs/ (index.ts, types.ts, 8 templates: automation, code-review, content-writing, data-analysis, generic, security-audit, testing, translation) used to seed realistic test jobs. Python CLI has no testjobs directory; test.py uses a tiny inline _TEST_JOBS dict (3 entries) instead.
  - TS: `sdk-js/src/cli/testjobs/index.ts; templates/*.ts` · PY: `python-sdk-v2/src/agirails/cli/ (no testjobs/)`
  - Fix: Port the testjobs templates + index/types if the test/request flows are expected to use the richer job catalog.
- **diff/pull default network differs (base-mainnet vs base-sepolia)** `behavior-diff`
  - TS diff.ts and pull.ts default -n/--network to 'base-sepolia'. Python diff.py and pull.py default --network to 'base-mainnet'. A user running `actp diff`/`actp pull` with no flag hits mainnet on Python but testnet on TS — divergent default target chain for a read that can mislead about sync state.
  - TS: `sdk-js/src/cli/commands/diff.ts:26; pull.ts (default base-sepolia)` · PY: `python-sdk-v2/src/agirails/cli/commands/diff.py:44-49; pull.py:34-39`
  - Fix: Change Python diff/pull --network default to 'base-sepolia' to match TS.
- **diff/pull path is an option (--path) in Python vs positional argument in TS** `signature-diff`
  - TS diff/pull/sync take the AGIRAILS.md path as a positional [path] argument (default ./AGIRAILS.md) and honor the identity pointer. Python diff.py/pull.py expose it as -p/--path option only. `actp diff path/to/file.md` works on TS but is rejected on Python (parsed as an unexpected argument).
  - TS: `sdk-js/src/cli/commands/diff.ts:25; pull.ts; sync.ts:28` · PY: `python-sdk-v2/src/agirails/cli/commands/diff.py:56-61; pull.py:46-51`
  - Fix: Change Python diff/pull path to a typer.Argument with default ./AGIRAILS.md and add identity-pointer resolution.

### cross-cutting: top-level coverage + index.ts public-export parity +…

- **config getNetwork / NetworkConfig not re-exported from top-level Python package** `missing-param`
  - TS index.ts re-exports getNetwork and NetworkConfig at the package root. Python has get_network + NetworkConfig in config/networks.py and config/__init__.py, but they are NOT re-exported from the top-level agirails/__init__.py (grep confirms get_network absent there). `from agirails import get_network` fails; users must import from agirails.config. Minor surface/discoverability divergence.
  - TS: `sdk-js/src/index.ts:264-265` · PY: `config/__init__.py:21 (present) but top-level __init__.py (absent)`
  - Fix: Add get_network and NetworkConfig to agirails/__init__.py imports and __all__.
- **EASHelper/EASConfig not surfaced at top-level Python package the way TS index exports them** _[AIP-7]_ `missing-param`
  - TS index.ts:161 exports EASHelper and EASConfig at the package root. Python exposes EASHelper conditionally inside the protocol web3 try-block of __init__.py and from protocol/__init__.py, but there is no EASConfig export and EASHelper is only available when web3 import succeeds. Functionally close but the EASConfig type and unconditional top-level availability differ.
  - TS: `sdk-js/src/index.ts:161 (EASHelper, EASConfig)` · PY: `protocol/__init__.py:96 (EASHelper conditional); no EASConfig`
  - Fix: Confirm an EASConfig analog exists/needed; if so export it. Document that EASHelper is web3-gated (HAS_WEB3_PROTOCOL).
- **IPFSClient type / IPFSClientConfig present in TS utils, absent in Python** _[AIP-7]_ `missing-class`
  - TS exports IPFSClient and IPFSClientConfig types from utils/IPFSClient (kubo-rpc-client backed). Python has no class IPFSClient / IPFSClientConfig (grep returns nothing); IPFS uploads in Python go via FilebaseClient (S3-style) only. TS intentionally keeps IPFSClient out of the main index for ESM reasons but the type is still exported; Python lacks the kubo direct-IPFS path entirely. Low impact since Filebase covers the AIP-7 storage path, but a kubo/direct-IPFS capability gap exists.
  - TS: `sdk-js/src/utils/IPFSClient.ts; index.ts:281; package.json dep kubo-rpc-client 6.1.0` · PY: `ABSENT (only storage/FilebaseClient)`
  - Fix: If direct-IPFS (kubo) parity is desired, add an ipfshttpclient/httpx-based IPFSClient; otherwise document Filebase as the sole IPFS path and mark as intentional.

### receipts

- **formatSettledLine CLI helper absent** _[AIP-7]_ `missing-method`
  - TS push.ts exports formatSettledLine({participantRole, netDisplay, grossDisplay, counterpartyDisplay, receiptUrl}) producing the one-line '[SETTLED] Earned/Paid ... \n Receipt: <url>' summary. No Python equivalent (grep format_settled_line empty). Lower priority since Python lacks the push path it serves.
  - TS: `sdk-js/src/receipts/push.ts:239-264` · PY: `ABSENT`
  - Fix: Port formatSettledLine alongside push_receipt_on_settled if/when the push path is implemented.
- **reason field on push failure (400 vs 422 disambiguation) absent** _[AIP-7]_ `missing-method`
  - TS PushReceiptResult.reason carries 'post_failed:<status> <error>: <detail>' / 'prepare_failed:<status>' so a missing-field 400 and an on-chain-desync 422 are distinguishable to callers/operators (both otherwise null the URL). This diagnostic surface does not exist in Python (no push path). Note web_receipt.py's ReceiptUploadFailure.reason is the V1-path analog but not the V2 push.
  - TS: `sdk-js/src/receipts/push.ts:99-113,190-232` · PY: `ABSENT`
  - Fix: Mirror the reason string scheme in the ported push so 400/422 stay distinguishable.

### wallet

- **Failover logs at warning (noisy) instead of debug (quiet) in bundler + paymaster** `behavior-diff`
  - TS logs recovered failover and retries at debug so a primary-slow then backup-works recovery does not alarm users mid-flow (the quiet half of fast+quiet). Python logs Primary bundler failed trying backup and per-retry messages at logger.warning, and paymaster failover at logger.warning, surfacing normal resilience as user-facing warnings.
  - TS: `sdk-js/src/wallet/aa/BundlerClient.ts:176-179,201-205; sdk-js/src/wallet/aa/PaymasterClient.ts:119-122` · PY: `python-sdk-v2/src/agirails/wallet/aa/bundler_client.py:197-201,219-224; paymaster_client.py:137-141`
  - Fix: Lower recovered-failover and retry logs to logger.debug in both bundler and paymaster; keep the both-failed error surfaced.
- **AutoWalletProvider fee-data source differs (getFeeData vs eth_fee_history)** `behavior-diff`
  - TS submitUserOp uses provider.getFeeData() and sets maxFeePerGas = feeData.maxFeePerGas (2 gwei / 1 gwei fallbacks). Python _submit_user_op computes from eth_fee_history: max_fee = baseFee*2 + priorityFee. Different gas-pricing formulas; under volatile base fees they produce materially different fees. Not a hash/correctness divergence but a behavioral one affecting inclusion/cost.
  - TS: `sdk-js/src/wallet/AutoWalletProvider.ts:507-510` · PY: `python-sdk-v2/src/agirails/wallet/auto_wallet_provider.py:416-421`
  - Fix: Align the fee strategy (eth_maxPriorityFeePerGas + a documented base-fee multiplier) so TS and Python price UserOps identically, or document the divergence.

### api-registry

- **setListed gas-estimate buffer mismatch (TS 1.15 / Python 1.20) and missing 'Not registered' mapping** `behavior-diff`
  - TS AgentRegistryClient.setListed (AgentRegistryClient.ts:128-158) applies estimateGas*1.15 (15% buffer) and maps 'Not registered'->TransactionRevertedError. Python AgentRegistry.set_listed (agent_registry.py:691-709) goes through generic _build_transaction which applies *1.2 (20% buffer, line 512) and has no 'Not registered' friendly mapping. The buffer divergence (15% vs 20%) is cosmetic but the missing error mapping means Python surfaces a raw revert string instead of the actionable 'Agent not registered. Register first...' message.
  - TS: `sdk-js/src/registry/AgentRegistryClient.ts:128-158` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/protocol/agent_registry.py:691-709,495-514`
  - Fix: Optionally align gas buffer; add a 'Not registered' detection in set_listed to raise a friendly error matching TS.
- **agirails_app API functions not exported from api/__init__ (parity-consistent with TS but a discoverability note)** `behavior-diff`
  - Python api/__init__.py exports only discover_* (api/__init__.py:3-5); the agirails_app functions (check_slug, upsert_agent, get_claim_challenge, claim_agent, request_claim_code) are reachable only via direct module import. This MATCHES TS, where agirailsApp functions are also NOT re-exported from index.ts and are imported by path in CLI/BuyerOrchestrator. So this is consistent with TS and only a polish note — NOT a functional gap.
  - TS: `sdk-js/src/index.ts (no agirailsApp re-export); sdk-js/src/cli/commands/*.ts import by path` · PY: `/Users/damir/Arha/AGIRAILS/SDK and Runtime/python-sdk-v2/src/agirails/api/__init__.py:1-5`
  - Fix: Optional: export agirails_app functions from api/__init__ for parity-of-discoverability; not required since TS also imports them by path.

### errors-utils-types-builders-settle

- **Missing storage validators/sanitizers: sanitizeErrorMessage, createSafeError, validateSemver/Hash/Signature, validateArweaveTxId, SwapExecutionError, InvalidArweaveTxIdError** _[AIP-7]_ `missing-method`
  - TS utils/validation.ts exports sanitizeErrorMessage (redacts private keys/AWS keys/bearer tokens/api keys), createSafeError, validateSemver, validateHash, validateSignature, validateArweaveTxId; TS errors include SwapExecutionError and InvalidArweaveTxIdError. Python has no sanitize_error_message/create_safe_error (only sanitize_for_logging on a single value), no validate_semver/validate_hash/validate_signature/validate_arweave_txid, and errors/ lacks SwapExecutionError and InvalidArweaveTxIdError. Python's validation surface is otherwise strong (SSRF endpoint check, CID, gateway allowlist, address/amount/deadline/tx_id/dispute_window/bytes32/service metadata).
  - TS: `sdk-js/src/utils/validation.ts:340-540 (validateArweaveTxId/Semver/Hash/Signature, sanitizeErrorMessage, createSafeError)` · PY: `python-sdk-v2/src/agirails/utils/validation.py (no semver/hash/signature/arweave/sanitize_error_message); errors/storage.py (no SwapExecutionError/InvalidArweaveTxIdError)`
  - Fix: Add validate_semver/validate_hash/validate_signature/validate_arweave_txid, sanitize_error_message + create_safe_error (regex redaction parity), and SwapExecutionError/InvalidArweaveTxIdError to errors/storage.py. Mostly storage/AIP-7 surface; low protocol risk.
- **Top-level transaction InsufficientFundsError(required, available) not present in Python (only storage-tier InsufficientFundsError exists)** `signature-diff`
  - TS errors/index.ts InsufficientFundsError extends ACTPError with constructor(required: bigint, available: bigint), code INSUFFICIENT_FUNDS, message 'Insufficient funds: need X wei, have Y wei'. Python's InsufficientFundsError lives in errors/storage.py and extends ArweaveError (storage tier) with a different constructor/semantics, not exported from errors/__init__. Python's nearest transaction-tier analog is InsufficientBalanceError(address, required, available) (code INSUFFICIENT_BALANCE) -- different name/code than TS. A consumer catching the TS-named transaction error or matching code INSUFFICIENT_FUNDS will not find a parity equivalent.
  - TS: `sdk-js/src/errors/index.ts:16-26` · PY: `python-sdk-v2/src/agirails/errors/storage.py:408 (InsufficientFundsError extends ArweaveError); errors/transaction.py:106 (InsufficientBalanceError)`
  - Fix: Either add a transaction-tier InsufficientFundsError(required, available) with code INSUFFICIENT_FUNDS to match TS, or document that Python uses InsufficientBalanceError for the same case. Reconcile so error codes match cross-SDK.

### negotiation

- **verifyQuoteHashOnChain VerifySource telemetry tags (aip2/legacy) absent** _[AIP-2.1]_ `behavior-diff`
  - TS tags every successful on-chain quote match with source='aip2'|'legacy' and threads hashSource into RoundResult.reason for observability of how many txs still use the legacy pre-AIP-2.1 hash path (planned removal in 2 minor releases). Python has neither the verifier nor the telemetry tag.
  - TS: `sdk-js/src/negotiation/verifyQuoteOnChain.ts:37-47` · PY: `ABSENT`
  - Fix: Include the source tag in the ported verify result and surface it in RoundResult.reason like TS (source: aip2/legacy/counteraccept).

### runtime

- **P2 gaps grouped: polling/wss, envelope hooks, gas-est/connection/max, min_amount_wei, tx_id, MockStateManager hardening, serviceHash-field mismap** `behavior-diff`
  - pollingInterval-1000ms+transport-wss-throw (BlockchainRuntime.ts:90,91-103); AIP-16 envelope hooks (MockRuntime.ts:298,542-592); estimate*Gas/getConnectionStatus/maxTransactionAmount (415-427,1195-1292); min_amount_wei only Python (mock_runtime.py:262-269); tx_id deterministic-vs-random (MockRuntime.ts:1435-1474); MockStateManager no size/nesting/symlink caps (MockStateManager.ts:103-166); get_transaction serviceHash in service_description field (blockchain_runtime.py:548-568).
  - TS: `BlockchainRuntime.ts:90,415-427; MockRuntime.ts:298,444-453,1435-1474; MockStateManager.ts:103-166` · PY: `blockchain_runtime.py:195-271,548-568; mock_runtime.py:262-269; mock_state_manager.py:123-207`

### config-publish-sync

- **config-publish-sync functions not exported from main Python package barrel for V4 (parity of public surface)** `missing-class`
  - Once the V4/buyerLink/reconcile/slug/defaults modules are ported they must be re-exported from agirails/config/__init__.py (and likely the top-level package) to match the TS public surface. Currently config/__init__.py exports only the v1 agirailsmd, networks, pending_publish, publish_pipeline, sync_operations symbols.
  - TS: `config/* module exports` · PY: `config/__init__.py:1-106`
  - Fix: After porting, add the new symbols to __all__ in config/__init__.py.


---

## py-extra — Python has, TS does not (12)

- **X402AdapterConfig/X402PayResult expose deprecated fee/relay surface absent from current TS** (adapters)
  - Python X402AdapterConfig exposes relay_address/approve_fn/relay_pay_fn/platform_fee_bps and X402PayResult.fee_breakdown is populated on the relay path. TS deprecated the X402Relay fee flow (feeBreakdown deprecated, never populated since 3.3.0; x402 pays seller directly, zero fee). Python relay path + X402PayParams/X402PayResult dataclasses are py-extra tied to the legacy protocol.
- **PriceCalculation.counter_offer is a Python-only field (TS has none)** (level1-agent)
  - Python PriceCalculation adds counter_offer: Optional[float] (suggested counter price) and PricingStrategy.below_price/below_cost include an 'accept' literal not present in TS BelowPriceBehavior/BelowCostBehavior ('reject'|'counter-offer'). TS computes the provider ideal price separately (calculation.price) and has no counter_offer field, and disallows a below-cost 'accept'. Reconcile so the wire/decision semantics match (TS has no 'accept'-below-cost mode).
- **Python level0 exposes extra surface not present in TS (py-extra)** (level0 (Simple-tier primitives: provide / request / Provider / ServiceDirectory))
  - Python level0 adds APIs with no TS level0 counterpart: ServiceQuery + ServiceEntry + find/find_by_capability/find_by_pattern/update; Provider.service() decorator, handle_request(), create_provider(); provide.py unprovide/list_provided/get_provider/reset_global_provider/set_provider_client/start_provider/stop_provider; request.py RequestHandle, RequestStatus enum, LegacyRequestResult, request_batch, set_request_client/get_request_client, ProgressInfo. These are independent design choices that need reconciling with the TS surface (decide keep vs align).
- **Python nonce.py is a tx-nonce manager not present as a TS protocol module** (protocol)
  - TS has no protocol/nonce.py; its SecureNonce + ReceivedNonceTracker live in utils/. Python protocol/nonce.py is a blockchain transaction NonceManager/NonceManagerPool (sequential account nonce tracking) — a Python-side addition not present as a TS protocol module. The message-level SecureNonce/ReceivedNonceTracker do exist in Python utils/ (parity outside this subsystem). Flagging the extra protocol-scoped module for reconciliation; not a defect.
- **normalize_body exported in Python but internal (normalizeBody) in TS** (config-publish-sync)
  - Python exports normalize_body in config/__init__.py __all__; in TS normalizeBody is a module-private helper (not exported from agirailsmd.ts). Minor surface-area divergence — harmless but worth noting for reconciliation. Behavior is equivalent (CRLF/CR->LF, rstrip per line, trim).
- **Python SmartWalletRouter has acceptQuote routing that TS lacks (reconcile direction)** (wallet)
  - Python SmartWalletRouter adds encode_accept_quote_tx + send_accept_quote and standard.py.accept_quote routes acceptQuote through the Smart Wallet (msg.sender == requester). TS SmartWalletRouter has no acceptQuote encoder/sender and TS StandardAdapter.acceptQuote calls runtime.acceptQuote directly via the EOA, so on TS a Tier-1 acceptQuote would have msg.sender == EOA != requester. Python is arguably MORE correct; reconcile by porting acceptQuote routing INTO TS rather than removing it from Python.
- **keystore: Python adds ACTP_DIR override + network-tier name mapping not in TS keystore** (wallet)
  - Python resolve_private_key honors an ACTP_DIR env var for the keystore dir and _normalize_network_tier maps chain names (base-sepolia to testnet, base-mainnet/base to mainnet) before policy enforcement. TS keystore.ts has neither (accepts only literal mainnet/testnet/mock and resolves the dir from stateDirectory/cwd). Net effect: passing network base-mainnet to TS resolvePrivateKey hits the unknown then fail-closed branch while Python treats it as mainnet. Reconcile by adding the same normalization + ACTP_DIR support to TS keystore.
- **Python app.py returns policy verdict in HTTP response body; TS serve.ts only logs it** (server (provider server app, policy/policy_engine, QuoteChannel transport vs PY server/))
  - Python create_app's POST handler runs evaluate_counter on success and injects {verdict: {action, reason, recommended_amount}} (or verdict_error) into the JSON response body returned to the buyer. TS serve.ts computes the verdict via orchestrator.evaluateCounter but ONLY logs it (output.info) — the HTTP response is strictly result.body ({accepted, duplicate}). This is a wire-contract divergence: a buyer hitting the Python daemon sees the provider's negotiation verdict inline, while the TS daemon never returns it (operator delivers replies out-of-band per AIP-2.1 §5.3). Reconcile so both SDKs expose the same response shape.
- **Python pay accepts URL/agent-ID routing while TS pay is address+slug only** (cli)
  - Python pay.py argument help is 'Provider address (0x...), HTTP endpoint, or agent ID' and routes through the unified adapter router (x402/ERC-8004), whereas TS pay.ts is a Level-0 primitive that only accepts a provider address or agirails.app slug URL (HTTP/agent-ID routing belongs to other flows). This is a behavioral/routing divergence in what `actp pay <to>` accepts — should be reconciled so the two CLIs route identically. Python also has a --description option not present in TS pay.
- **Python ArweaveClient adds GraphQL discovery API not present in TS storage client** (storage)
  - Python ArweaveClient has query_by_tags(tags,limit), find_archives_by_chain(chain_id,limit) and find_archive_by_tx(tx_id) hitting https://arweave.net/graphql to discover archive TX IDs by tags. The TS ArweaveClient has no such discovery methods. Extra Python surface to reconcile (add to TS or mark Python-only).
- **compute_content_hash input contract collision: Python takes bytes, TS takes object (porting footgun)** (storage)
  - TS exports computeContentHash(data:object) which canonicalizes (sortKeysRecursive + JSON.stringify) then keccak256. Python exports compute_content_hash(content:bytes) which keccaks raw bytes with NO canonicalization, plus a separate compute_json_hash(dict) that does the canonicalizing keccak. The identically-named function has a DIFFERENT input contract (bytes vs object), so code ported from TS passing an object to Python compute_content_hash yields wrong results. Python also exports PROTOCOL_VERSION/ARCHIVE_SCHEMA_VERSION/CircuitBreakerConfig, which TS does not export as named symbols (TS uses inline config literal).
- **Python error model adds DEBUG_MODE redaction + extra error classes not present in TS (reconcile)** (errors-utils-types-builders-settle)
  - Python ACTPError adds a security layer absent in TS: AGIRAILS_DEBUG env gate, _redact_sensitive_details over SENSITIVE_KEYS, to_dict(include_sensitive=) and redacted __repr__. TS ACTPError is a plain Error with code/txHash/details and no redaction. Also Python errors/ carries extra classes with no TS counterpart: EscrowNotFoundError, DisputeWindowActiveError, ContractPausedError, TransientRPCError, TransactionError, EscrowError, MockStateCorrupted/Version/LockError, Filebase*, SSRFProtectionError, CircuitBreakerOpenError, ArchiveBundleValidationError. Additive (not regressions) but should be reconciled so cross-SDK error-code expectations are documented.
