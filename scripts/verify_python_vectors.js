/**
 * Reverse cross-SDK parity verifier — TS verifies Python-signed messages.
 *
 * Loads each python_signed_*.json fixture under tests/fixtures/cross_sdk/
 * and runs the TypeScript SDK's verifier against it:
 *
 *   1. EIP-712 signature recovery via ethers.verifyTypedData →
 *      recovered address must equal expectedSigner from the fixture.
 *   2. TS-side computeHash(message) must equal expectedHash from the
 *      Python-emitted fixture.
 *
 * If either check fails, the SDKs have drifted on EIP-712 type
 * ordering, struct field encoding, canonical-JSON key ordering, or
 * keccak input bytes — and integrators on different stacks would
 * stop agreeing on transaction hashes.
 *
 * Run from the python-sdk-v2 directory:
 *
 *   NODE_PATH=../sdk-js/node_modules node scripts/verify_python_vectors.js
 *
 * Exits 0 on full pass; non-zero on any mismatch (with details).
 *
 * @see scripts/generate_python_parity_vectors.py (sibling, Python side)
 * @see scripts/generate_parity_vectors.js (TS → Python direction, step B)
 */

const path = require('path');
const fs = require('fs');
const { verifyTypedData } = require('ethers');

const TS_SDK = path.resolve(__dirname, '../../sdk-js');
const {
  AIP21CounterOfferTypes,
  CounterOfferBuilder,
} = require(path.join(TS_SDK, 'dist/builders/CounterOfferBuilder'));
const {
  AIP21CounterAcceptTypes,
  CounterAcceptBuilder,
} = require(path.join(TS_SDK, 'dist/builders/CounterAcceptBuilder'));

const FIXTURE_DIR = path.resolve(__dirname, '../tests/fixtures/cross_sdk');

function loadJSON(file) {
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

function buildOfferDomain(msg) {
  return {
    name: 'AGIRAILS',
    version: '1',
    chainId: msg.chainId,
    verifyingContract: '', // verifyingContract is provided per-call via kernelAddress
  };
}

function verifyCounterOffer(fixture) {
  const msg = fixture.message;
  const domain = {
    name: 'AGIRAILS',
    version: '1',
    chainId: msg.chainId,
    verifyingContract: fixture.kernelAddress,
  };

  // Reconstruct the "signed shape" — same as CounterOfferBuilder
  // toSignedShape() but inline so we don't accidentally inherit any
  // Python-side normalization.
  // justificationHash is keccak256(canonicalJsonStringify(justification))
  // when justification is set; ZeroHash otherwise.
  let justificationHash =
    '0x0000000000000000000000000000000000000000000000000000000000000000';
  if (msg.justification && Object.keys(msg.justification).length > 0) {
    // We rely on the Python side to have computed compute_hash(msg) using
    // CanonicalJSON over msg.justification — verify TS computes the same.
    const { keccak256, toUtf8Bytes } = require('ethers');
    const {
      canonicalJsonStringify,
    } = require(path.join(TS_SDK, 'dist/utils/canonicalJson'));
    justificationHash = keccak256(toUtf8Bytes(canonicalJsonStringify(msg.justification)));
  }

  const signed = {
    txId: msg.txId,
    consumer: msg.consumer,
    provider: msg.provider,
    quoteAmount: msg.quoteAmount,
    counterAmount: msg.counterAmount,
    maxPrice: msg.maxPrice,
    currency: msg.currency,
    decimals: msg.decimals,
    inReplyTo: msg.inReplyTo,
    counteredAt: msg.counteredAt,
    expiresAt: msg.expiresAt,
    justificationHash,
    chainId: msg.chainId,
    nonce: msg.nonce,
  };

  const recovered = verifyTypedData(
    domain,
    AIP21CounterOfferTypes,
    signed,
    msg.signature,
  );

  if (recovered.toLowerCase() !== fixture.expectedSigner.toLowerCase()) {
    return {
      ok: false,
      reason: `Signature recovers to ${recovered}, expected ${fixture.expectedSigner}`,
    };
  }

  const tsHash = new CounterOfferBuilder().computeHash(msg);
  if (tsHash.toLowerCase() !== fixture.expectedHash.toLowerCase()) {
    return {
      ok: false,
      reason: `Hash mismatch: TS=${tsHash}, Python=${fixture.expectedHash}`,
    };
  }
  return { ok: true };
}

function verifyCounterAccept(fixture) {
  const msg = fixture.message;
  const domain = {
    name: 'AGIRAILS',
    version: '1',
    chainId: msg.chainId,
    verifyingContract: fixture.kernelAddress,
  };
  const signed = {
    txId: msg.txId,
    provider: msg.provider,
    consumer: msg.consumer,
    acceptedAmount: msg.acceptedAmount,
    inReplyTo: msg.inReplyTo,
    acceptedAt: msg.acceptedAt,
    chainId: msg.chainId,
    nonce: msg.nonce,
  };

  const recovered = verifyTypedData(
    domain,
    AIP21CounterAcceptTypes,
    signed,
    msg.signature,
  );
  if (recovered.toLowerCase() !== fixture.expectedSigner.toLowerCase()) {
    return {
      ok: false,
      reason: `Signature recovers to ${recovered}, expected ${fixture.expectedSigner}`,
    };
  }

  const tsHash = new CounterAcceptBuilder().computeHash(msg);
  if (tsHash.toLowerCase() !== fixture.expectedHash.toLowerCase()) {
    return {
      ok: false,
      reason: `Hash mismatch: TS=${tsHash}, Python=${fixture.expectedHash}`,
    };
  }
  return { ok: true };
}

function main() {
  const manifestPath = path.join(FIXTURE_DIR, 'python_signed_manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.error(
      `Manifest not found: ${manifestPath}\n` +
        `Regenerate with: python3 scripts/generate_python_parity_vectors.py`,
    );
    process.exit(2);
  }
  const manifest = loadJSON(manifestPath);
  console.log(
    `Verifying Python-signed fixtures (SDK ${manifest.python_sdk_version}, ` +
      `${manifest.fixtures.length} fixtures)…`,
  );

  let failed = 0;
  for (const label of manifest.fixtures) {
    const fixture = loadJSON(path.join(FIXTURE_DIR, `${label}.json`));
    const fn =
      fixture.fixtureKind === 'counter_offer'
        ? verifyCounterOffer
        : verifyCounterAccept;
    const result = fn(fixture);
    if (result.ok) {
      console.log(`  ✓ ${label}`);
    } else {
      console.error(`  ✗ ${label}: ${result.reason}`);
      failed += 1;
    }
  }

  if (failed > 0) {
    console.error(`\n${failed} fixture(s) failed.`);
    process.exit(1);
  }
  console.log(`\nAll ${manifest.fixtures.length} fixtures verified.`);
}

main();
