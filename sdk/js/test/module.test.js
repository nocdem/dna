// Identity and the release send module (node-environment build,
// scripts/build-wasm.sh -> wasm/send-node.mjs, -DNODUS_SEND_RELEASE).
// What it proves:
//   - deriveIdentity (the wallet's derive.js + mldsa87.wasm) gives, for the
//     wallet's own public test phrases, the Nodus address the native C
//     derivation gave (web-wallet/test/fixtures/nodus-addresses.json), and
//     its EVM address is web-wallet/src/evm/address.js
//     evmAddressFromFingerprint of that address (its first 32 bytes);
//   - with the wasm built: the RELEASE module derives the SAME identity from
//     the same phrase on its own (nsw_identify — C, no network; the client
//     refuses a different address), for every fixture phrase — an
//     independent second derivation (C qgp_dsa87_keypair_derand + SHA3-512);
//   - the release module accepts the wallet's pinned EVM ruleset identity
//     (nsw_evm_net_set compares it with its compiled bytes) and offers
//     evmBuild; a wrong EVM ruleset hash leaves smart contracts off;
//   - send-node.wasm is byte-identical to the wallet's shipped
//     src/nodus/send.wasm (same sources and flags, only the JS glue's
//     ENVIRONMENT differs), carries no test-only export, and exports the
//     release offline EVM builder nsw_evm_offline_build (web wallet 0.1.64);
//   - NodusEvm.buildOffline through the RELEASE build, no network: an
//     offline DEPOSIT and an offline CALL (call data + one access-list
//     entry) are signed, and every field read back from the signed bytes is
//     the request's — op, amount / to / data length / gas limit / nonce,
//     chain id, expiry tip + 90; the envelope's legs are [CORE op 9] + [EVM
//     op] with the EVM leg's ruleset version = the pinned one
//     (DEFAULT_EVM_NETWORK); the SENDER is this identity: the DEPOSIT's
//     recipient (SHA3-512 of the signing key, computed by the module) is
//     its Nodus address, and the CALL envelope carries a 2592-byte ML-DSA-87
//     public key whose SHA3-512 is that address — so its EVM sender (the
//     first 32 bytes) is the identity's EVM address; the inputs add up to
//     lock + fee + change; two builds of one request share the intent id
//     and differ in the hedged signature; a wrong expiry refuses.
// Requires: `npm ci` in web-wallet/; for the module tests, scripts/build-wasm.sh
// (else they SKIP). No network: nothing here opens a connection.
// How it can lie: the fixture phrases are public test vectors and the coins,
// tip and gas price are SYNTHETIC; nothing here shows that a node accepts
// anything the module builds. The CALL sender check finds the key anywhere
// in the envelope (it does not parse the authorization section).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { NodusEvm, deriveIdentity, DEFAULT_WASM_DIR, DEFAULT_NETWORK, DEFAULT_EVM_NETWORK, evmAddressFromFingerprint } from '../src/index.js';
import { createNodusSendModule } from '../../../web-wallet/src/nodus/send-module.js';

const { vectors } = JSON.parse(readFileSync(new URL('../../../web-wallet/test/fixtures/nodus-addresses.json', import.meta.url), 'utf8'));
const GLUE = join(DEFAULT_WASM_DIR, 'send-node.mjs');
const BUILT = existsSync(GLUE);
const NOT_BUILT = 'wasm/send-node.mjs not built (run scripts/build-wasm.sh) — module coverage ABSENT';
const loadGlue = () => import(pathToFileURL(GLUE).href);

test('deriveIdentity = the native C address of the wallet fixtures; EVM address = address.js of it', async () => {
  assert.ok(vectors.length >= 2);
  for (const { phrase, address } of vectors) {
    const id = await deriveIdentity(phrase);
    assert.equal(id.fingerprint, address);
    assert.equal(id.evmAddress, evmAddressFromFingerprint(address));
    assert.equal(id.evmAddress, address.slice(0, 64));
    assert.match(id.displayAddress, /^0x[0-9a-fA-F]{64}$/);
  }
  await assert.rejects(deriveIdentity('abandon '.repeat(12)), /24-word/);
});

test('the release module derives the same identity itself (nsw_identify, no network)', { skip: BUILT ? false : NOT_BUILT }, async () => {
  for (const { phrase, address } of vectors) {
    const evm = await NodusEvm.open({ phrase });
    try {
      assert.equal(evm.state, 'identified');
      assert.equal(evm.fingerprint, address);
      assert.equal(evm.address, address.slice(0, 64));
      assert.equal(evm.chainId, DEFAULT_NETWORK.chainId);
      // reads need the session: refused, nothing is sent
      await assert.rejects(evm.account(), /not ready/);
    } finally { evm.close(); }
    assert.equal(evm.state, 'locked');
  }
});

test('the release module takes the pinned EVM ruleset identity and refuses another', { skip: BUILT ? false : NOT_BUILT }, async () => {
  const ok = await createNodusSendModule(DEFAULT_NETWORK, { evm: DEFAULT_EVM_NETWORK, loadGlue });
  try {
    assert.equal(typeof ok.evmBuild, 'function');
    assert.equal(typeof ok.evmQuery, 'function');
    assert.ok(Number.isSafeInteger(ok.evmGeneration) && ok.evmGeneration > 0);
  } finally { ok.release(); }
  const wrong = await createNodusSendModule(DEFAULT_NETWORK, { evm: { ...DEFAULT_EVM_NETWORK, evmRulesetHash: '0'.repeat(128) }, loadGlue });
  try { assert.equal(wrong.evmBuild, undefined, 'a wrong EVM ruleset identity must leave building off'); } finally { wrong.release(); }
});

test('send-node.wasm = the shipped send.wasm, with no test-only export', { skip: BUILT ? false : NOT_BUILT }, () => {
  const built = readFileSync(join(DEFAULT_WASM_DIR, 'send-node.wasm'));
  const shipped = readFileSync(new URL('../../../web-wallet/src/nodus/send.wasm', import.meta.url));
  assert.ok(built.equals(shipped), 'send-node.wasm differs from web-wallet/src/nodus/send.wasm — rebuild (wallet or SDK) from the same tree');
  const exports = WebAssembly.Module.exports(new WebAssembly.Module(built)).map(e => e.name);
  assert.ok(!exports.some(n => n.startsWith('nsw_test_')), 'a test-only export is in the release build');
  assert.ok(!exports.includes('nsw_test_evm_build'));
  for (const n of ['nsw_evm_deposit', 'nsw_evm_call', 'nsw_evm_create', 'nsw_evm_withdraw', 'nsw_evm_query', 'nsw_evm_offline_build']) assert.ok(exports.includes(n), n);
});

// shared/dnac/env_wire.h "Canonical wire layout": the leg headers
function legsOf(envelope) {
  const b = Buffer.from(envelope), n = b.readUInt16BE(41);
  return Array.from({ length: n }, (_, i) => { const h = 43 + 30 * i; return { domain: b.readUInt32BE(h), op: b.readUInt32BE(h + 4), ver: b.readUInt32BE(h + 8) }; });
}
// the 2592-byte windows of `bytes` whose SHA3-512 is `fingerprint`
function carriesKeyOf(bytes, fingerprint) {
  const b = Buffer.from(bytes);
  for (let i = 0; i + 2592 <= b.length; i++) if (createHash('sha3-512').update(b.subarray(i, i + 2592)).digest('hex') === fingerprint) return true;
  return false;
}
const OFFLINE = {
  tip: 5000n, gasPrice: 7n,
  coins: [{ nullifier: 'a1'.repeat(64), amount: '100000000' }, { nullifier: 'b2'.repeat(64), amount: '300000000' }, { nullifier: 'c3'.repeat(64), amount: '50000000' }]
};

test('NodusEvm.buildOffline: an offline DEPOSIT and CALL through the release build, read back from the signed bytes', { skip: BUILT ? false : NOT_BUILT }, async () => {
  const { phrase, address } = vectors[0];
  const id = await deriveIdentity(phrase);
  const amounts = new Map(OFFLINE.coins.map(c => [c.nullifier, BigInt(c.amount)]));
  const inSum = inputs => inputs.reduce((s, n) => s + amounts.get(n), 0n);

  const dep = await NodusEvm.buildOffline({ phrase, ...OFFLINE, op: 'deposit', amount: 120000000n, nonce: 4n });
  const d = dep.decoded;
  assert.equal(d.op, 'deposit');
  assert.equal(d.amount, '120000000');
  assert.equal(d.nonce, '4');
  assert.equal(d.chainId, DEFAULT_NETWORK.chainId);
  assert.equal(d.expiryHeight, '5090');
  assert.equal(d.recipient, address, 'the deposit credits this identity (SHA3-512 of the signing key)');
  assert.equal(d.recipient.slice(0, 64), id.evmAddress, 'its EVM sender is the identity\'s EVM address');
  assert.equal(inSum(d.inputs), 120000000n + BigInt(d.fee) + BigInt(d.change), 'inputs = amount + fee + change');
  assert.deepEqual(legsOf(dep.envelope).map(l => [l.domain, l.op]), [[1, 9], [2, 3]]);
  assert.equal(legsOf(dep.envelope)[1].ver, DEFAULT_EVM_NETWORK.evmRulesetVersion);
  assert.match(dep.intentId, /^[0-9a-f]{128}$/);

  const to = '0x' + 'ab'.repeat(32), data = '0xa9059cbb' + '00'.repeat(64);
  const call = await NodusEvm.buildOffline({
    phrase, ...OFFLINE, op: 'call', to, data, gasLimit: 60000n, nonce: 5n,
    accessList: [{ address: '0x' + 'cd'.repeat(32), storageKeys: ['01'.repeat(32)] }]
  });
  const c = call.decoded;
  assert.equal(c.op, 'call');
  assert.equal(c.to, 'ab'.repeat(32));
  assert.equal(c.dataLength, 68);
  assert.equal(c.gasLimit, '60000');
  assert.equal(c.nonce, '5');
  assert.equal(c.valueWei, '00'.repeat(32));
  assert.equal(c.amount, '', 'a call carries no bridge amount');
  assert.equal(c.chainId, DEFAULT_NETWORK.chainId);
  assert.deepEqual(legsOf(call.envelope).map(l => [l.domain, l.op]), [[1, 9], [2, 1]]);
  assert.equal(legsOf(call.envelope)[1].ver, DEFAULT_EVM_NETWORK.evmRulesetVersion);
  assert.ok(carriesKeyOf(call.envelope, address), 'the CALL is signed by this identity\'s key (EVM sender = its EVM address)');
  assert.equal(inSum(c.inputs), BigInt(c.fee) + BigInt(c.change), 'inputs = fee + change (a call locks nothing)');

  // hedged signature: the same request again, the same intent, other bytes
  const again = await NodusEvm.buildOffline({ phrase, ...OFFLINE, op: 'deposit', amount: 120000000n, nonce: 4n });
  assert.equal(again.intentId, dep.intentId);
  assert.notDeepEqual(again.envelope, dep.envelope);
  // the module checks the expiry rule (tip + 90)
  await assert.rejects(NodusEvm.buildOffline({ phrase, ...OFFLINE, expiryHeight: 5091n, op: 'deposit', amount: 1n, nonce: 0n }), /validity must end at block 5090/);
});
