/**
 * Cross-SDK parity vector generator.
 *
 * Signs AIP-2.1 CounterOffer + CounterAccept messages with the TypeScript
 * SDK's builders using DETERMINISTIC inputs (fixed private keys, fixed
 * timestamps, fixed amounts). Emits JSON vectors to
 *   tests/fixtures/cross_sdk/
 * which the Python test suite consumes and verifies.
 *
 * If TS-side serialization, EIP-712 type definitions, or canonical-JSON
 * encoding drifts even by a single byte from the Python implementation,
 * the recovered signer address mismatches and the parity test fails.
 *
 * Run from the python-sdk-v2 directory:
 *
 *   node scripts/generate_parity_vectors.js
 *
 * Re-run after any change to either SDK's AIP-2.1 wire format; commit
 * the regenerated fixtures so CI can replay them.
 *
 * @see ../../../sdk-js/src/builders/CounterOfferBuilder.ts
 * @see src/agirails/builders/counter_offer.py
 */

const path = require('path');
const fs = require('fs');
const { Wallet } = require('ethers');

const TS_SDK = path.resolve(__dirname, '../../sdk-js');
const {
  CounterOfferBuilder,
} = require(path.join(TS_SDK, 'dist/builders/CounterOfferBuilder'));
const {
  CounterAcceptBuilder,
} = require(path.join(TS_SDK, 'dist/builders/CounterAcceptBuilder'));
const {
  InMemoryNonceManager,
} = require(path.join(TS_SDK, 'dist/utils/NonceManager'));

// Deterministic test wallets. NEVER use these keys for anything real;
// they're hard-coded so the vectors are reproducible across machines.
const BUYER_KEY    = '0x' + '11'.repeat(32);
const PROVIDER_KEY = '0x' + '22'.repeat(32);

const buyer    = new Wallet(BUYER_KEY);
const provider = new Wallet(PROVIDER_KEY);

const KERNEL = '0x' + 'A'.repeat(40);   // doesn't have to be real, just consistent
const TX_ID  = '0x' + 'a'.repeat(64);
const QUOTE_HASH = '0x' + 'b'.repeat(64);
const CHAIN_ID = 84532;

// Pin builder clocks so vectors are byte-identical across runs.
const FIXED_NOW_SEC = 1_700_000_000;
const ORIGINAL_NOW = Date.now;
Date.now = () => FIXED_NOW_SEC * 1000;

async function build_counter_offer_vector(label, params) {
  const nm = new InMemoryNonceManager();
  // Force nonce 1 — InMemoryNonceManager starts at 1 already, but assert.
  const builder = new CounterOfferBuilder(buyer, nm);
  const msg = await builder.build({
    txId: TX_ID,
    consumer: `did:ethr:${CHAIN_ID}:${buyer.address}`,
    provider: `did:ethr:${CHAIN_ID}:${provider.address}`,
    quoteAmount: '1500000',
    counterAmount: '800000',
    maxPrice: '2000000',
    inReplyTo: QUOTE_HASH,
    chainId: CHAIN_ID,
    kernelAddress: KERNEL,
    expiresAt: FIXED_NOW_SEC + 3600,
    justification: params.justification ?? undefined,
  });
  const hash = builder.computeHash(msg);
  return {
    label,
    fixtureKind: 'counter_offer',
    kernelAddress: KERNEL,
    expectedSigner: buyer.address,
    expectedHash: hash,
    message: msg,
  };
}

async function build_counter_accept_vector(label, params) {
  const nm = new InMemoryNonceManager();
  const builder = new CounterAcceptBuilder(provider, nm);
  const msg = await builder.build({
    txId: TX_ID,
    provider: `did:ethr:${CHAIN_ID}:${provider.address}`,
    consumer: `did:ethr:${CHAIN_ID}:${buyer.address}`,
    acceptedAmount: '800000',
    inReplyTo: QUOTE_HASH,
    chainId: CHAIN_ID,
    kernelAddress: KERNEL,
    ...params,
  });
  const hash = builder.computeHash(msg);
  return {
    label,
    fixtureKind: 'counter_accept',
    kernelAddress: KERNEL,
    expectedSigner: provider.address,
    expectedHash: hash,
    message: msg,
  };
}

async function main() {
  const outDir = path.resolve(__dirname, '../tests/fixtures/cross_sdk');
  fs.mkdirSync(outDir, { recursive: true });

  const fixtures = [];

  fixtures.push(await build_counter_offer_vector('counter_offer_basic', {}));

  fixtures.push(
    await build_counter_offer_vector('counter_offer_with_justification', {
      justification: {
        reason: 'market rate is lower',
        marketRate: 0.75,
        breakdown: { observed_quotes: 3 },
      },
    }),
  );

  fixtures.push(await build_counter_accept_vector('counter_accept_basic', {}));

  // Mainnet chain variant — confirms chainId is bound into the EIP-712 domain.
  fixtures.push(
    await build_counter_accept_vector('counter_accept_mainnet', {
      provider: `did:ethr:8453:${provider.address}`,
      consumer: `did:ethr:8453:${buyer.address}`,
      chainId: 8453,
    }),
  );

  // Write each fixture as its own JSON file for easy diffing.
  for (const f of fixtures) {
    const fpath = path.join(outDir, `${f.label}.json`);
    fs.writeFileSync(fpath, JSON.stringify(f, null, 2) + '\n');
    console.log(`wrote ${path.relative(process.cwd(), fpath)}`);
  }

  // Write a manifest so the Python test discovers all vectors.
  const manifest = {
    generated_by: 'sdk-js/dist (CounterOfferBuilder + CounterAcceptBuilder)',
    ts_sdk_version: require(path.join(TS_SDK, 'package.json')).version,
    pinned_now_sec: FIXED_NOW_SEC,
    buyer_address: buyer.address,
    provider_address: provider.address,
    fixtures: fixtures.map((f) => f.label),
  };
  fs.writeFileSync(
    path.join(outDir, 'manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n',
  );
  console.log(`wrote ${path.relative(process.cwd(), path.join(outDir, 'manifest.json'))}`);

  Date.now = ORIGINAL_NOW;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
