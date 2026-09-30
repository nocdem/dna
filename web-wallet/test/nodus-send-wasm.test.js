// The NODUS send module (package (c3)): the shipped artefact, the network
// settings gate, and — when the parity builds exist — WASM <-> native parity
// (design docs/plans/2026-09-25-web-wallet-nodus-send-design.md §2, test
// plan item 2).
//
// Always run (no build needed beyond the committed src/nodus/send.*):
//   - send.wasm exports every entry point send-module.js calls, and NO
//     test-only entry point (the fixed-randomness build never ships);
//   - its randomness import is WASI random_get (getentropy -> the browser
//     CSPRNG, crypto/nodus-send-wasm.c header);
//   - with NODUS_SEND_NETWORK null the factory is null (NODUS receive-only);
//   - the network settings validator accepts/refuses the documented shapes.
//
// Parity (needs both, else those tests SKIP — a skip is not a pass):
//   NODUS_SEND_PARITY_OUT  dir from `scripts/build-nodus-send-wasm.sh parity`
//   NODUS_SEND_VECTOR_BIN  binary from `scripts/build-nodus-send-native-vector.sh`
// Inputs are SYNTHETIC (fixed seed, made-up coins and chain id): they prove
// that the builds agree with each other, not that a node accepts the result.
// What each parity test proves:
//   - TEST wasm (fixed randomness) == native vector, byte for byte;
//   - the shipped send.wasm (hedged signature; loaded through the node glue
//     of the same link, checked byte-identical): same intent_id and decoded
//     fields as the native vector, different wire_id (the signature is
//     randomized — design D7: intent_id excludes the authorization bytes).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { NODUS_SEND_NETWORK, nodusSendModuleFactory, validateNodusSendNetwork } from '../src/nodus/send-module.js';

const wasmBytes = readFileSync(new URL('../src/nodus/send.wasm', import.meta.url));
const glue = readFileSync(new URL('../src/nodus/send.js', import.meta.url), 'utf8');

const ENTRY_POINTS = [
  'nsw_error', 'nsw_seed_buf', 'nsw_req_reset', 'nsw_req_add_coin', 'nsw_out_seed_buf', 'nsw_out_seed_load',
  'nsw_offline_build', 'nsw_built_env', 'nsw_built_env_len', 'nsw_built_intent', 'nsw_built_wire', 'nsw_built_chain',
  'nsw_built_recipient', 'nsw_built_amount', 'nsw_built_fee', 'nsw_built_change', 'nsw_built_expiry', 'nsw_built_n_in',
  'nsw_built_in', 'nsw_net_reset', 'nsw_net_set_chain', 'nsw_net_add_endpoint', 'nsw_net_add_pin', 'nsw_unlock',
  'nsw_balance', 'nsw_list', 'nsw_build_and_sign', 'nsw_req_env_alloc', 'nsw_submit', 'nsw_scan', 'nsw_tick',
  'nsw_cancel', 'nsw_lock', 'nsw_fingerprint', 'nsw_chain_hex', 'nsw_bal_total', 'nsw_bal_spendable', 'nsw_list_tip',
  'nsw_list_truncated', 'nsw_list_count', 'nsw_list_nul', 'nsw_list_amount', 'nsw_scan_tip', 'nsw_scan_height',
  'nsw_scan_found'
];

test('the shipped send.wasm exports the module entry points and no test-only one', () => {
  assert.deepEqual([...wasmBytes.subarray(0, 4)], [0, 0x61, 0x73, 0x6d]);
  const module = new WebAssembly.Module(wasmBytes);
  const exports = new Set(WebAssembly.Module.exports(module).map(({ name }) => name));
  for (const name of ENTRY_POINTS) assert.ok(exports.has(name), `missing export ${name}`);
  assert.ok(![...exports].some(name => name.startsWith('nsw_test_')), 'a test-only entry point is in the shipped module');
  const imports = WebAssembly.Module.imports(module).map(({ module: from, name }) => `${from}.${name}`);
  assert.ok(imports.includes('wasi_snapshot_preview1.random_get'), 'randomness is not the WASI random_get import');
  assert.ok(imports.includes('env.emscripten_sleep'), 'no Asyncify sleep import');
  assert.match(glue, /new URL\("send\.wasm",import\.meta\.url\)/);
  assert.match(glue, /export default createNodusSendWasm/);
});

test('no network settings in this build: the factory is null and NODUS stays receive-only', () => {
  assert.equal(NODUS_SEND_NETWORK, null);
  assert.equal(nodusSendModuleFactory, null);
});

test('network settings: the documented shape is accepted, everything else refused', () => {
  const good = { chainId: 'a'.repeat(64), scheme: 'wss', endpoints: [{ host: '203.0.113.7', port: 443 }], pins: ['b'.repeat(128)] };
  const net = validateNodusSendNetwork(good);
  assert.deepEqual(net, good);
  assert.ok(Object.isFrozen(net) && Object.isFrozen(net.endpoints) && Object.isFrozen(net.pins));
  assert.deepEqual(validateNodusSendNetwork({ ...good, scheme: 'ws', endpoints: [{ host: '127.0.0.1', port: 14005 }] }).scheme, 'ws');
  const refused = [
    null, {}, { ...good, chainId: 'A'.repeat(64) }, { ...good, chainId: 'a'.repeat(63) },
    { ...good, scheme: 'http' }, { ...good, scheme: 'ws' },
    { ...good, endpoints: [] }, { ...good, endpoints: Array(9).fill({ host: '203.0.113.7', port: 443 }) },
    { ...good, endpoints: [{ host: 'node.example', port: 443 }] }, { ...good, endpoints: [{ host: '256.0.0.1', port: 443 }] },
    { ...good, endpoints: [{ host: '203.0.113.7', port: 0 }] }, { ...good, endpoints: [{ host: '203.0.113.7', port: '443' }] },
    { ...good, pins: [] }, { ...good, pins: ['b'.repeat(127)] }, { ...good, pins: ['b'.repeat(128), 'b'.repeat(128)] },
    { ...good, pins: Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(128, '0')) }
  ];
  for (const network of refused) assert.throws(() => validateNodusSendNetwork(network), /Nodus network settings/);
});

// ── parity ──────────────────────────────────────────────────────────────
const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT, VECTOR_BIN = process.env.NODUS_SEND_VECTOR_BIN;
const skipParity = !PARITY_OUT || !VECTOR_BIN
  ? 'set NODUS_SEND_PARITY_OUT and NODUS_SEND_VECTOR_BIN (build-nodus-send-wasm.sh parity, build-nodus-send-native-vector.sh)'
  : false;

const hex = bytes => Buffer.from(bytes).toString('hex');
const fill = (length, start) => Uint8Array.from({ length }, (_, i) => (start + i * 7) & 0xff);
// SYNTHETIC inputs. Largest-first selection takes the two 1-NODUS coins for
// 1.5 NODUS + fee, so the envelope has 2 inputs and 2 outputs (recipient +
// change): 64 bytes of output seeds, and one hedged signature = 32 bytes of
// signing randomness.
const INPUT = {
  seed: fill(32, 1), chain: '11'.repeat(32), tip: '1000', gas: '121', to: 'cd'.repeat(64), amount: '150000000',
  expiry: '1090', coins: [['a1'.repeat(64), '100000000'], ['b2'.repeat(64), '100000000'], ['c3'.repeat(64), '50000000']],
  outSeeds: fill(64, 40), signRandom: fill(32, 90)
};

function nativeVector() {
  const args = ['--seed', hex(INPUT.seed), '--chain', INPUT.chain, '--tip', INPUT.tip, '--gas', INPUT.gas, '--to', INPUT.to,
    '--amount', INPUT.amount, '--expiry', INPUT.expiry, '--out-seeds', hex(INPUT.outSeeds), '--sign-random', hex(INPUT.signRandom)];
  for (const [nullifier, amount] of INPUT.coins) args.push('--coin', `${nullifier}:${amount}`);
  const out = { input: [] };
  for (const line of execFileSync(VECTOR_BIN, args, { encoding: 'utf8' }).trim().split('\n')) {
    const at = line.indexOf('='), key = line.slice(0, at), value = line.slice(at + 1);
    if (key === 'input') out.input.push(value); else out[key] = value;
  }
  return out;
}

async function wasmBuild(file, { fixedRandom }) {
  const path = join(PARITY_OUT, file);
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  const M = await create();
  const num = (name, types = [], args = []) => M.ccall(name, 'number', types, args);
  const str = (name, types = [], args = []) => M.ccall(name, 'string', types, args);
  assert.equal(typeof M._nsw_test_random_buf === 'function', fixedRandom, 'test-only randomness entry point presence');
  M.HEAPU8.set(INPUT.seed, num('nsw_seed_buf'));
  M.HEAPU8.set(INPUT.outSeeds, num('nsw_out_seed_buf'));
  assert.equal(num('nsw_out_seed_load', ['number'], [INPUT.outSeeds.length]), 0);
  if (fixedRandom) {
    M.HEAPU8.set(INPUT.signRandom, num('nsw_test_random_buf'));
    assert.equal(num('nsw_test_random_load', ['number'], [INPUT.signRandom.length]), 0);
  }
  num('nsw_req_reset');
  for (const [nullifier, amount] of INPUT.coins) assert.equal(num('nsw_req_add_coin', ['string', 'string'], [nullifier, amount]), 0, str('nsw_error'));
  const rc = num('nsw_offline_build', ['string', 'string', 'string', 'string', 'string', 'string'],
    [INPUT.chain, INPUT.tip, INPUT.gas, INPUT.to, INPUT.amount, INPUT.expiry]);
  assert.equal(rc, 0, str('nsw_error'));
  const at = num('nsw_built_env'), length = num('nsw_built_env_len');
  const input = [];
  for (let i = 0; i < num('nsw_built_n_in'); i++) input.push(str('nsw_built_in', ['number'], [i]));
  return {
    envelope: hex(M.HEAPU8.subarray(at, at + length)), wire_id: str('nsw_built_wire'), intent_id: str('nsw_built_intent'),
    chain_id: str('nsw_built_chain'), recipient: str('nsw_built_recipient'), amount: str('nsw_built_amount'),
    fee: str('nsw_built_fee'), change: str('nsw_built_change'), expiry: str('nsw_built_expiry'), input
  };
}

test('parity: TEST wasm (fixed randomness) and the native vector build the same envelope byte for byte', { skip: skipParity }, async () => {
  const native = nativeVector(), wasm = await wasmBuild('send-test-node.mjs', { fixedRandom: true });
  assert.deepEqual(wasm, native);
  assert.match(native.intent_id, /^[0-9a-f]{128}$/);
  assert.equal(native.recipient, INPUT.to);
  assert.equal(native.amount, INPUT.amount);
  assert.equal(native.expiry, INPUT.expiry);
  assert.equal(native.chain_id, INPUT.chain);
  assert.deepEqual(native.input, [INPUT.coins[0][0], INPUT.coins[1][0]]);
  assert.equal(BigInt(native.amount) + BigInt(native.fee) + BigInt(native.change), 200000000n);
});

test('parity: the shipped wasm (hedged signature) has the same intent_id, a different wire_id', { skip: skipParity }, async () => {
  // send-node.mjs differs from the shipped glue only in ENVIRONMENT; its
  // .wasm must be the shipped binary itself, byte for byte.
  assert.ok(readFileSync(join(PARITY_OUT, 'send-node.wasm')).equals(wasmBytes), 'send-node.wasm is not the shipped send.wasm — rebuild both');
  const native = nativeVector(), wasm = await wasmBuild('send-node.mjs', { fixedRandom: false });
  for (const key of ['intent_id', 'chain_id', 'recipient', 'amount', 'fee', 'change', 'expiry', 'input']) assert.deepEqual(wasm[key], native[key], key);
  assert.notEqual(wasm.wire_id, native.wire_id);
  assert.notEqual(wasm.envelope, native.envelope);
  assert.equal(wasm.envelope.length, native.envelope.length);
});
