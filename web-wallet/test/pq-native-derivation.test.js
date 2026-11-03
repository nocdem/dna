// Native-rule derivation gates for Soqucoin, Tidecoin, XION and Splendor (plan
// docs/plans/approved/2026-11-03-pq-native.md sections 1.1-1.4 and 6; Kurultay 52 conditions 1, 2, 7).
// Proves, with the real receive wasm and public phrases only:
//  - derivePqAddresses('abandon x23 art') gives the addresses of each chain's own wallet: Soqucoin equals
//    SoquShield's published known answer (test/fixtures/soqu-derivation-kat.json, copied with its source
//    commit), Tidecoin equals the two answers of the real Tidecoin Wallet 0.3.1 extension run
//    (docs/research-evidence/2026-11-03-tidecoin-extension-run), XION and Splendor equal the output of
//    the native modules run by test/receive-reference (Cosmos SDK 64fd208a hd package; go-bip39 + circl);
//  - the Soqucoin stagenet vector of the known-answer file has the same witness program as the mainnet one
//    (the key does not depend on the network);
//  - the Soqucoin retry rule: for a phrase whose retry-0 key starts with 0xFF, soqucoinSigningSeed and the
//    published address use the retry-1 seed; pqChainSeed(..., 'soqucoin') refuses to answer;
//  - the old Nodus-label addresses of the four chains appear nowhere in the result;
//  - the XION zero-parent branch (Kurultay 52 condition 1): the JavaScript compressed key, child key and
//    chain code for a zero parent scalar equal the secp-zero oracle output (decred v4.4.1 / Cosmos hdpath.go).
// Needs: src/pq/receive-keygen.wasm (built), test/fixtures/pq-receive.json and soqu-derivation-kat.json.
// Leaves: nothing.
// Can falsely pass: the Soqucoin retry case is a Python mirror of key_service.dart with the pinned node
// keygen (no native answer exists for a 0xFF path); XION and Splendor rest on the native-module oracle, not
// on a published vector; the Tidecoin anchors are two extension runs, not all seeds; and the check is
// void if the fixture were regenerated from src/pq (forbidden by test/receive-reference/prepare_fixtures.py).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bech32m } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1';
import { derivePqAddresses, pqChainSeed, soqucoinSigningSeed, xionCompressedPublicKey, xionHdChild } from '../src/pq/receive.js';
import { receiveWasmBytes } from './fixtures/pq-port-vectors.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json', import.meta.url)));
const kat = JSON.parse(readFileSync(new URL('./fixtures/soqu-derivation-kat.json', import.meta.url)));
const wasmBytes = receiveWasmBytes();
const hex = bytes => Buffer.from(bytes).toString('hex');
const fromHex = text => Uint8Array.from(Buffer.from(text, 'hex'));
const abandon = fixture.vectors[0].phrase;
assert.equal(abandon, 'abandon '.repeat(23) + 'art');
// Answers of the real Tidecoin Wallet 0.3.1 extension (vectors[0] and vectors[1] phrases).
const TIDECOIN_EXTENSION = ['tbc1q6mcneezrufd6dpv5qey8tvnq9ztwwyczurx9d5', 'tbc1qq9tucj6wucylxsl9v29qndvsvh37mhg6r94qrg'];
// Addresses Nodus showed for 'abandon x23 art' before the native rules (plan section 1).
const OLD_ADDRESSES = ['sq1pd2yz04w9ju0dlz4k0aqdse859jgx8tar8euejcts89ckggunjflsa97cv4',
  'xion1wegdp6q4534spq84lagu7xnhdsx8ycgvqhlgv2', 'EfPFP2NC2SE5WcBkpLW3JTd6M5n6HAMXB4',
  'SQ:8aec6d86388c38b12dcecb40f02219ee512b647136468e2d8c736938272a3eaa'];
const program = address => bech32m.decode(address, 90).words.slice(1);

test('abandon x23 art: Soqucoin equals the SoquShield known answer, others equal their native sources', async () => {
  const { addresses, errors } = await derivePqAddresses(abandon, { wasmBytes });
  assert.deepEqual(errors, {});
  const main = kat.vectors.find(v => v.network === 'mainnet' && v.accountIndex === 0).address;
  assert.equal(kat.mnemonic, abandon);
  assert.equal(addresses.soqucoin.mainnet, main);
  assert.equal(addresses.tidecoin.mainnet, TIDECOIN_EXTENSION[0]);
  assert.deepEqual(addresses.xion, fixture.vectors[0].addresses.xion);
  assert.deepEqual(addresses.splendor, fixture.vectors[0].addresses.splendor);
  const text = JSON.stringify(addresses);
  for (const old of OLD_ADDRESSES) assert.ok(!text.includes(old), `old address ${old} must not appear`);
});

test('Soqucoin stagenet known answer has the same witness program as the mainnet address Nodus shows', async () => {
  const stagenet = kat.vectors.find(v => v.network === 'stagenet' && v.accountIndex === 0).address;
  const { addresses } = await derivePqAddresses(abandon, { wasmBytes });
  assert.ok(stagenet.startsWith('ssq1') && addresses.soqucoin.mainnet.startsWith('sq1'));
  assert.deepEqual(program(stagenet), program(addresses.soqucoin.mainnet));
});

test('both extension answers are reproduced through derivePqAddresses', async () => {
  for (const [index, expected] of TIDECOIN_EXTENSION.entries()) {
    const { addresses, errors } = await derivePqAddresses(fixture.vectors[index].phrase, { wasmBytes });
    assert.deepEqual(errors, {});
    assert.equal(addresses.tidecoin.mainnet, expected);
    assert.ok(!JSON.stringify(addresses).includes(fixture.legacyTidecoin[index].addresses.tidecoin.mainnet), 'old Base58 address must not appear');
  }
});

test('Soqucoin retry rule: a 0xFF retry-0 key selects the retry-1 seed and address', async () => {
  const retry = fixture.soqucoinRetry;
  assert.equal(retry.retry, 1);
  assert.equal(retry.pk.slice(0, 2) === 'ff', false, 'selected key must not start with 0xFF');
  const seed = await soqucoinSigningSeed(retry.phrase, { wasmBytes });
  try {
    assert.equal(hex(seed), retry.seed);
    assert.notEqual(hex(seed), retry.retry0Seed, 'the retry-0 seed must not be returned');
  } finally { seed.fill(0); }
  const { addresses, errors } = await derivePqAddresses(retry.phrase, { wasmBytes });
  assert.deepEqual(errors, {});
  assert.equal(addresses.soqucoin.mainnet, retry.address);
  assert.throws(() => pqChainSeed(retry.phrase, 'soqucoin'), /soqucoinSigningSeed/);
});

test('XION zero-parent branch equals the Cosmos/decred native trace (secp-zero oracle)', () => {
  assert.ok(fixture.xionZeroParent.length > 0);
  const zero = new Uint8Array(32);
  for (const row of fixture.xionZeroParent) {
    assert.equal(hex(xionCompressedPublicKey(zero)), row.compressed);
    assert.equal(row.compressed, '02' + '00'.repeat(32));
    const child = xionHdChild(zero, fromHex(row.chain), 0);
    assert.equal(hex(child.key), row.childKey);
    assert.equal(hex(child.chain), row.childChain);
  }
});

test('XION non-zero parent uses the curve library (self-consistency control, not a native answer)', () => {
  const one = new Uint8Array(32); one[31] = 1;
  assert.equal(hex(xionCompressedPublicKey(one)), hex(secp256k1.getPublicKey(one, true)));
  assert.notEqual(hex(xionCompressedPublicKey(one)), '02' + '00'.repeat(32), 'only the zero scalar takes the zero branch');
  assert.throws(() => xionCompressedPublicKey(new Uint8Array(31)));
});
