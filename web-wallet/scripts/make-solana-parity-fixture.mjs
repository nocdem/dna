// Generates test/fixtures/solana-kit-parity.json: the Solana send flow's exact
// bytes and JSON-RPC requests, produced by the wallet's own src/ code with every
// RPC response stubbed to a fixed value (no network).
//
// The committed fixture was generated ONCE from web wallet 0.1.22 (commit
// 84f331f3), whose Solana path ran on @solana/web3.js 1.99.0, BEFORE the
// migration to @solana/kit (0.1.23). test/solana-kit-parity.test.js replays the
// same stubs against the kit code and requires byte-identical results.
//
// How it can lie: re-running this script after the migration overwrites the
// web3.js reference with output of the code under test, and the parity test then
// compares the kit code with itself. Do not regenerate it to make a test pass.
//
// Usage (from web-wallet/): node scripts/make-solana-parity-fixture.mjs
import { writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { encodeBase58, decodeBase58, sha256, toUtf8Bytes, getBytes } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS } from '@solana-program/token';
import { deriveWallet } from '../src/keys.js';
import { prepare } from '../src/adapters/solana.js';
import { CHAINS } from '../src/config.js';

// Public test mnemonic used across test/*.test.js (wallet.test.js, security.test.js, solana-rpc.test.js).
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
// A non-pacing endpoint: CHAINS.solana.endpoint is paced 1200 ms per read (src/rpc-transport.js).
const endpoint = 'https://rpc.example';
const base58 = bytes => encodeBase58(bytes);
const recipient = base58(ed25519.getPublicKey(new Uint8Array(32).fill(2)));
const blockhash = base58(getBytes(sha256(toUtf8Bytes('nodus web wallet solana parity blockhash'))));
const wallet = deriveWallet(phrase);
const owner = wallet.addresses.solana;
const token = CHAINS.solana.tokens[1];
const [ownerAta] = await findAssociatedTokenPda({ mint: token.address, owner, tokenProgram: TOKEN_PROGRAM_ADDRESS });

function responsesFor({ ataExists }) {
  return {
    getGenesisHash: CHAINS.solana.genesisHash,
    getTokenAccountsByOwner: { context: { slot: 1 }, value: [{ pubkey: ownerAta, account: { executable: false, owner: TOKEN_PROGRAM_ADDRESS, lamports: 2039280, rentEpoch: 0, space: 165, data: { program: 'spl-token', space: 165, parsed: { type: 'account', info: { isNative: false, state: 'initialized', mint: token.address, owner, tokenAmount: { amount: '5000000', decimals: 6, uiAmount: 5, uiAmountString: '5' } } } } } }] },
    getAccountInfo: { context: { slot: 1 }, value: ataExists ? { data: ['', 'base64'], executable: false, lamports: 2039280, owner: TOKEN_PROGRAM_ADDRESS, rentEpoch: 0, space: 165 } : null },
    getMinimumBalanceForRentExemption: 2039280,
    getLatestBlockhash: { context: { slot: 1 }, value: { blockhash, lastValidBlockHeight: 300000123 } },
    getFeeForMessage: { context: { slot: 1 }, value: 5000 },
    getBalance: { context: { slot: 1 }, value: 1000000000 },
    getBlockHeight: 300000000
  };
}
function splitWire(bytes) {
  // Legacy wire transaction: compact-u16 signature count, 64-byte signatures, message.
  assert.ok(bytes[0] < 0x80, 'signature count fits one compact-u16 byte');
  const count = bytes[0];
  return { signatures: Array.from({ length: count }, (_, i) => bytes.slice(1 + 64 * i, 65 + 64 * i)), message: bytes.slice(1 + 64 * count) };
}
async function runCase(name, asset, units, ataExists) {
  const responses = responsesFor({ ataExists }), requests = [];
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: body.method, params: body.params });
    if (body.method === 'sendTransaction') {
      const { signatures } = splitWire(new Uint8Array(Buffer.from(body.params[0], 'base64')));
      return Response.json({ jsonrpc: '2.0', id: body.id, result: base58(signatures[0]) });
    }
    assert.ok(Object.hasOwn(responses, body.method), 'unexpected method ' + body.method);
    return Response.json({ jsonrpc: '2.0', id: body.id, result: responses[body.method] });
  };
  const transfer = await prepare({ wallet, to: recipient, asset, units, endpoint });
  let broadcast;
  const returned = await transfer.send(details => { broadcast = details; });
  const feeCall = requests.find(r => r.method === 'getFeeForMessage'), sendCall = requests.find(r => r.method === 'sendTransaction');
  const wire = new Uint8Array(Buffer.from(sendCall.params[0], 'base64'));
  const { signatures, message } = splitWire(wire);
  assert.equal(signatures.length, 1);
  assert.equal(Buffer.from(message).toString('base64'), feeCall.params[0], 'fee estimate used the broadcast message');
  assert.ok(ed25519.verify(signatures[0], message, decodeBase58Bytes(owner)), 'signature verifies under the wallet key');
  assert.equal(returned, base58(signatures[0]));
  return { name, asset, units: units.toString(), ataExists, responses, requests: requests.map(({ url, method, params }) => ({ url, method, params })),
    fee: transfer.fee, broadcast, returned, wireBase64: sendCall.params[0], messageBase64: Buffer.from(message).toString('base64'),
    signatureBase58: base58(signatures[0]), signatureHex: Buffer.from(signatures[0]).toString('hex') };
}
function decodeBase58Bytes(text) {
  const bytes = getBytes('0x' + decodeBase58(text).toString(16).padStart(64, '0'));
  assert.equal(bytes.length, 32); return bytes;
}
const cases = [
  await runCase('sol-transfer', { symbol: 'SOL', decimals: 9 }, 1500000n, true),
  await runCase('spl-transfer-existing-ata', token, 1250000n, true),
  await runCase('spl-transfer-creates-ata', token, 1250000n, false)
];
const fixture = {
  source: 'Generated once by scripts/make-solana-parity-fixture.mjs from web wallet 0.1.22 (84f331f3), Solana path on @solana/web3.js 1.99.0, before the @solana/kit migration. Regenerating after the migration replaces the reference with the code under test.',
  phrase: 'test mnemonic: abandon x23 + art (same as test/*.test.js)', endpoint, owner, recipient, blockhash, ownerAta, cases
};
writeFileSync(new URL('../test/fixtures/solana-kit-parity.json', import.meta.url), JSON.stringify(fixture, null, 2) + '\n');
for (const c of cases) console.log(`${c.name}: ${c.requests.length} requests (${c.requests.map(r => r.method).join(', ')}), wire ${Buffer.from(c.wireBase64, 'base64').length} B, signature ${c.signatureBase58}, fee "${c.fee}"`);
