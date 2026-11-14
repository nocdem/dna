import test from 'node:test';
import assert from 'node:assert/strict';
import { keccak256 } from 'ethers';
import { IXIOS_NETWORK, IXIOS_NETWORKS, ixiosNetwork, ixiosMethod, IXIOS_EMPTY_CODE_HASH, ixiosProofCodeEmpty } from '../src/pq/ixios/network.js';

// What this file proves: the table of Ixios networks holds, for the main entry, exactly the
// constants the wallet used before the test network existed (literal copies below, written
// from the pre-change source at ed11a7751, not read from the code under test), and, for the
// test entry, the values observed on the live test node. It also proves the entries are
// frozen, that an unknown id fails closed, and the getProof account-code rule.
// It leaves nothing behind and makes no request.
// Falsely passes if: a literal below is later "fixed" to follow a code change (the diff of
// the main literals must stay empty); the test literals are checked against the same
// probe evidence they were copied from, so a wrong probe reading would pass here (the live
// read-only check against the node covers that).

// The main entry as it was before the test network (src/pq/ixios/network.js:9-17,
// balance.js:15, preflight.js:7-8).
const MAIN = {
  id: 'mainnet', label: 'Mainnet', endpoint: 'https://ixios-rpc.innova.limited',
  rpcOptions: [{ url: 'https://ixios-rpc.innova.limited', label: 'Ixios public RPC' }],
  genesisHash: '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f',
  chainId: 1, aegisHeight: 32400000, rpcNamespace: 'eth', codeQuery: 'getCode',
};
// The test entry: values observed on https://nx-rpc.ixoflow.io on 2026-11-12, recorded in
// docs/research-evidence/2026-11-12-ixios-testnet-rpc/probes.txt (ixios_chainId = 0x3,
// block 1 parentHash = genesis, ixios_getProof present, eth_* and ixios_getCode absent) and
// SUMMARY.md. Aegis 300 is the reference's value for chain id 3 (plan section 2.4).
const TEST = {
  id: 'testnet', label: 'Testnet', endpoint: 'https://nx-rpc.ixoflow.io',
  rpcOptions: [{ url: 'https://nx-rpc.ixoflow.io', label: 'Ixios test network RPC' }],
  genesisHash: '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe',
  chainId: 3, aegisHeight: 300, rpcNamespace: 'ixios', codeQuery: 'getProof',
};
const EMPTY = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const ZERO = '0x' + '00'.repeat(32);
const ADDRESS = '0x' + 'Ab'.repeat(48);

test('the main entry equals the literal copy of the constants the wallet had before the test network', () => {
  assert.deepEqual(IXIOS_NETWORKS.mainnet, MAIN);
  assert.equal(ixiosNetwork('mainnet'), IXIOS_NETWORKS.mainnet);
});

// Changed 2026-11-14 (operator, decisions/2026-09-23-ixios-send-mainnet-first.md "Değişiklik 3"): the base no longer carries the
// "Send IXIOS from the extension." note; each surface sets receiveOnly and the note from the shared send gate.
test('IXIOS_NETWORK (display config): same fields and values, fail-closed receiveOnly, no send note of its own', () => {
  assert.deepEqual(IXIOS_NETWORK, {
    networkGroup: 'pq',
    name: 'Ixios', symbol: 'IXIOS', decimals: 18, icon: 'ixios.png', tokens: [], receiveOnly: true,
    endpoint: 'https://ixios-rpc.innova.limited', rpcOptions: [{ url: 'https://ixios-rpc.innova.limited', label: 'Ixios public RPC' }],
  });
});

test('the test entry carries the observed test network values', () => {
  assert.deepEqual(IXIOS_NETWORKS.testnet, TEST);
  assert.equal(ixiosNetwork('testnet'), IXIOS_NETWORKS.testnet);
  assert.deepEqual(Object.keys(IXIOS_NETWORKS), ['mainnet', 'testnet']);
});

test('method names are the entry namespace, an underscore and the name', () => {
  assert.equal(ixiosMethod(IXIOS_NETWORKS.mainnet, 'getBalance'), 'eth_getBalance');
  assert.equal(ixiosMethod(IXIOS_NETWORKS.mainnet, 'getBlockByNumber'), 'eth_getBlockByNumber');
  assert.equal(ixiosMethod(IXIOS_NETWORKS.testnet, 'getBalance'), 'ixios_getBalance');
  assert.equal(ixiosMethod(IXIOS_NETWORKS.testnet, 'sendRawTransaction'), 'ixios_sendRawTransaction');
});

test('the table and its entries are frozen (numbers, not BigInt, so an entry can cross a message port)', () => {
  assert.ok(Object.isFrozen(IXIOS_NETWORKS));
  for (const entry of Object.values(IXIOS_NETWORKS)) {
    assert.ok(Object.isFrozen(entry), entry.id);
    assert.ok(Object.isFrozen(entry.rpcOptions), entry.id);
    for (const option of entry.rpcOptions) assert.ok(Object.isFrozen(option), entry.id);
    assert.equal(typeof entry.chainId, 'number'); assert.equal(typeof entry.aegisHeight, 'number');
    assert.doesNotThrow(() => structuredClone(entry));
    assert.throws(() => { entry.endpoint = 'https://example.invalid'; }, TypeError);
  }
});

test('an id that is not in the table throws', () => {
  for (const id of ['', 'mainnet ', 'Mainnet', '1', '__proto__', 'constructor', 'toString', undefined, null, 1, {}, ['mainnet']]) {
    assert.throws(() => ixiosNetwork(id), /^Error: Unknown Ixios network\.$/, String(id));
  }
});

test('IXIOS_EMPTY_CODE_HASH is the Keccak-256 of the empty string', () => {
  assert.equal(IXIOS_EMPTY_CODE_HASH, EMPTY);
  assert.equal(IXIOS_EMPTY_CODE_HASH, keccak256('0x'));
});

test('getProof account code: the zero hash (no account) and the empty-code hash mean no code; another hash means code', () => {
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS, codeHash: ZERO }), true);
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS, codeHash: EMPTY }), true);
  // The node reports the address in its own letter case; the comparison ignores case.
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS.toLowerCase(), codeHash: EMPTY }), true);
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS, codeHash: '0x' + '11'.repeat(32) }), false);
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS, codeHash: EMPTY.slice(0, -2) + '71' }), false);
  // Other fields of a real answer (balance, nonce, proofs) are not read.
  assert.equal(ixiosProofCodeEmpty(ADDRESS, { address: ADDRESS, codeHash: EMPTY, balance: '0x1', nonce: '0x0', accountProof: ['0x00'] }), true);
});

test('getProof account code: a wrong address, a non-object or a malformed hash throws', () => {
  const bad = [
    { address: '0x' + 'cd'.repeat(48), codeHash: EMPTY },
    { codeHash: EMPTY },
    { address: ADDRESS },
    { address: ADDRESS, codeHash: null },
    { address: ADDRESS, codeHash: '0x' },
    { address: ADDRESS, codeHash: EMPTY.slice(0, -2) },
    { address: ADDRESS, codeHash: EMPTY + '00' },
    { address: ADDRESS, codeHash: EMPTY.replace('0x', '') },
    { address: ADDRESS, codeHash: '0x' + 'zz'.repeat(32) },
    { address: ADDRESS, codeHash: 1 },
    { address: 5, codeHash: EMPTY },
    null, undefined, '0x', 7, [],
  ];
  for (const answer of bad) assert.throws(() => ixiosProofCodeEmpty(ADDRESS, answer), /^Error: Invalid Ixios account code\.$/, JSON.stringify(answer));
  assert.throws(() => ixiosProofCodeEmpty(undefined, { address: ADDRESS, codeHash: EMPTY }), /^Error: Invalid Ixios account code\.$/);
});
