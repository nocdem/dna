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
//     ENVIRONMENT differs), and carries no test-only export;
//   - BLOCKED (reported, SKIPPED — a skip is not a pass): an offline EVM
//     DEPOSIT / CALL envelope through the release build. The only offline EVM
//     builder, nsw_test_evm_build, is compiled only with
//     -DNODUS_SEND_TEST_FIXED_RANDOM (web-wallet/crypto/nodus-send-wasm.c
//     "#ifdef NODUS_SEND_TEST_FIXED_RANDOM" before nsw_test_evm_build;
//     build-nodus-send-wasm.sh exports_test). The release build's EVM
//     builders (nsw_evm_call / _create / _deposit / _withdraw / _redeem)
//     need a connected node. The test below asserts that absence so a future
//     release export is noticed.
// Requires: `npm ci` in web-wallet/; for the module tests, scripts/build-wasm.sh
// (else they SKIP). No network: nothing here opens a connection.
// How it can lie: the fixture phrases are public test vectors; nothing here
// shows that a node accepts anything the module builds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
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
  // the BLOCKED sub-part's cause, pinned: no offline EVM builder in release
  assert.ok(!exports.includes('nsw_test_evm_build'));
  assert.ok(!exports.some(n => /^nsw_evm_.*offline/.test(n)));
  for (const n of ['nsw_evm_deposit', 'nsw_evm_call', 'nsw_evm_create', 'nsw_evm_withdraw', 'nsw_evm_query']) assert.ok(exports.includes(n), n);
});

test('offline DEPOSIT / CALL envelope through the release build', {
  skip: 'BLOCKED: the release build has no offline EVM builder (nsw_test_evm_build exists only under -DNODUS_SEND_TEST_FIXED_RANDOM); coverage ABSENT'
}, () => {});
