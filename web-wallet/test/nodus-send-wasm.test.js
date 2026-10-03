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
// Genesis claim (0.1.26): the claim data shape (always run); with the parity
// builds, the claim built by TEST wasm == native vector byte for byte, the
// shipped wasm agrees on every identity field with different bytes (hedged
// signature), and the EMBEDDED testnet claim data passes the module's own
// checks (manifest re-hash, allocation root) while a wrong hash or leaf is
// refused. The claim parity tree is SYNTHETIC (see CLAIM below).
// Chain-name registration (HF-4): with NODUS_SEND_PARITY_OUT only (no native
// vector — see "chain-name registration parity" below).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { NODUS_SEND_NETWORK, nodusSendModuleFactory, validateNodusSendNetwork, NODUS_CLAIM_DATA, validateNodusClaimData } from '../src/nodus/send-module.js';

const wasmBytes = readFileSync(new URL('../src/nodus/send.wasm', import.meta.url));
const glue = readFileSync(new URL('../src/nodus/send.js', import.meta.url), 'utf8');

const ENTRY_POINTS = [
  'nsw_error', 'nsw_seed_buf', 'nsw_req_reset', 'nsw_req_add_coin', 'nsw_out_seed_buf', 'nsw_out_seed_load',
  'nsw_offline_build', 'nsw_built_env', 'nsw_built_env_len', 'nsw_built_intent', 'nsw_built_wire', 'nsw_built_chain',
  'nsw_built_recipient', 'nsw_built_amount', 'nsw_built_fee', 'nsw_built_change', 'nsw_built_expiry', 'nsw_built_n_in',
  'nsw_built_in', 'nsw_net_reset', 'nsw_net_set_chain', 'nsw_net_add_endpoint', 'nsw_net_add_pin', 'nsw_unlock',
  // the split unlock: identify (local) and connect (network)
  'nsw_identify', 'nsw_connect',
  'nsw_balance', 'nsw_list', 'nsw_build_and_sign', 'nsw_req_env_alloc', 'nsw_submit', 'nsw_scan', 'nsw_tick',
  'nsw_cancel', 'nsw_lock', 'nsw_fingerprint', 'nsw_chain_hex', 'nsw_bal_total', 'nsw_bal_spendable', 'nsw_list_tip',
  'nsw_list_truncated', 'nsw_list_count', 'nsw_list_nul', 'nsw_list_amount', 'nsw_scan_tip', 'nsw_scan_height',
  'nsw_scan_found',
  // genesis claim (0.1.26)
  'nsw_claim_reset', 'nsw_claim_set_manifest', 'nsw_claim_add_leaf', 'nsw_claim_seal', 'nsw_claim_offline_build',
  'nsw_claim_status', 'nsw_claim_build', 'nsw_claim_submit', 'nsw_claim_found', 'nsw_claim_window', 'nsw_claim_claimed',
  'nsw_claim_amount', 'nsw_claim_tip', 'nsw_claim_start', 'nsw_claim_end', 'nsw_claim_output', 'nsw_claim_built_bytes',
  'nsw_claim_built_len', 'nsw_claim_built_id', 'nsw_claim_built_nullifier', 'nsw_claim_built_output',
  'nsw_claim_built_recipient', 'nsw_claim_built_chain', 'nsw_claim_built_amount', 'nsw_claim_built_leaf',
  // staking (0.1.29)
  'nsw_built_op', 'nsw_built_commission', 'nsw_stake_offline_build', 'nsw_const_min_delegation', 'nsw_const_self_stake',
  'nsw_const_commission_max', 'nsw_const_undelegate_lock_epochs', 'nsw_const_epoch_length', 'nsw_validators', 'nsw_val_count',
  'nsw_val_truncated', 'nsw_val_fp', 'nsw_val_self', 'nsw_val_delegated', 'nsw_val_commission', 'nsw_val_status',
  'nsw_val_delegators', 'nsw_const_max_delegators',
  'nsw_delegations', 'nsw_del_count', 'nsw_del_fp', 'nsw_del_amount', 'nsw_del_block', 'nsw_stake_build',
  // HF-4: rule-set generation, chain names, a name owner's profile address
  'nsw_name_ok', 'nsw_ruleset_info', 'nsw_ri_gen', 'nsw_ri_tip', 'nsw_ri_h', 'nsw_name_lookup', 'nsw_name_of',
  'nsw_name_found', 'nsw_name_owner', 'nsw_name_name', 'nsw_name_registered', 'nsw_name_committed',
  'nsw_profile_address', 'nsw_profile_addr',
  // HF-4: chain-name registration (nodus-cli name register, shared builder nodus_v2_name.c)
  'nsw_built_name', 'nsw_built_price', 'nsw_name_offline_build', 'nsw_name_prices', 'nsw_np_price', 'nsw_np_sched_count',
  'nsw_np_sched_param', 'nsw_np_sched_value', 'nsw_np_sched_effective', 'nsw_name_build'
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

test('the shipped network settings are the testnet: valid shape, wss only, six endpoints (EU-5 first), 7 validator pins', () => {
  const net = validateNodusSendNetwork(NODUS_SEND_NETWORK);
  assert.equal(net.chainId, 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114');
  assert.equal(net.scheme, 'wss');
  assert.deepEqual(net.endpoints.map(e => `${e.host}:${e.port}`), ['164.68.116.180:443', '154.38.182.161:443', '161.97.85.25:443', '156.67.24.125:443', '156.67.25.251:443', '164.68.105.227:443']);
  assert.equal(net.pins.length, 7);
  assert.equal(typeof nodusSendModuleFactory, 'function');
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

// Genesis claim data (0.1.26). The shape check only — the cryptographic
// checks (manifest re-hash, snapshot root) are the module's and are pinned by
// the "embedded testnet claim data seals" parity test below.
test('claim data: the shipped testnet data has the documented shape (one Founder leaf, 50,000,000 NODUS)', () => {
  const data = validateNodusClaimData(NODUS_CLAIM_DATA);
  assert.equal(data.manifest.length, 862);   // 431 bytes, as stored in v2_manifests
  assert.equal(data.manifestHash, '1807f972ba232b6822a0a2a622376a208b5730f10ad5099eb079d469713a17c2589b52fc069b6a67003de06ed78d027f17200377bb6136944594fe1ca431b4b8');
  assert.deepEqual(data.leaves, [{
    sourceId: '0'.repeat(127) + '1',
    destBinding: '7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd',
    amount: '5000000000000000'
  }]);
  assert.ok(Object.isFrozen(data) && Object.isFrozen(data.leaves) && Object.isFrozen(data.leaves[0]));
});

test('claim data: the documented shape is accepted, everything else refused', () => {
  const leaf = { sourceId: '01', destBinding: 'a'.repeat(128), amount: '1' };
  const good = { manifest: '00ff', manifestHash: 'b'.repeat(128), leaves: [leaf] };
  assert.deepEqual(validateNodusClaimData(good), good);
  const refused = [
    null, {}, { ...good, manifest: '' }, { ...good, manifest: '0' }, { ...good, manifest: '0G' }, { ...good, manifest: 'AB' },
    { ...good, manifest: '00'.repeat(8193) }, { ...good, manifestHash: 'b'.repeat(127) }, { ...good, manifestHash: 'B'.repeat(128) },
    { ...good, leaves: [] }, { ...good, leaves: Array(257).fill(leaf) },
    { ...good, leaves: [{ ...leaf, sourceId: '' }] }, { ...good, leaves: [{ ...leaf, sourceId: '0' }] },
    { ...good, leaves: [{ ...leaf, sourceId: '00'.repeat(129) }] }, { ...good, leaves: [{ ...leaf, destBinding: 'a'.repeat(127) }] },
    { ...good, leaves: [{ ...leaf, amount: '0' }] }, { ...good, leaves: [{ ...leaf, amount: '01' }] },
    { ...good, leaves: [{ ...leaf, amount: '18446744073709551616' }] }, { ...good, leaves: [{ ...leaf, amount: 1 }] }
  ];
  for (const data of refused) assert.throws(() => validateNodusClaimData(data), /Nodus claim data/, JSON.stringify(data)?.slice(0, 80));
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

// ── genesis claim parity (0.1.26) ──────────────────────────────────────
// SYNTHETIC tree: the testnet manifest with its allocation root, leaf count
// and total replaced by three made-up leaves (the vector's `claim-manifest`
// mode re-encodes it with the shared codec); the middle one belongs to the
// fixed seed, so the claim carries a two-sibling proof. It proves the builds
// agree with each other, not that a node accepts the claim — no chain ever
// committed this manifest.
const CLAIM = {
  seed: fill(32, 3), chain: '22'.repeat(32), signRandom: fill(32, 150),
  self: '02:300000000', others: [`01:${'ab'.repeat(64)}:100000000`, `03:${'cd'.repeat(64)}:5`]
};

function vectorLines(args) {
  const out = { leaf: [] };
  for (const line of execFileSync(VECTOR_BIN, args, { encoding: 'utf8' }).trim().split('\n')) {
    const at = line.indexOf('='), key = line.slice(0, at), value = line.slice(at + 1);
    if (key === 'leaf') out.leaf.push(value); else out[key] = value;
  }
  return out;
}
function claimManifest() {
  const args = ['claim-manifest', '--base', NODUS_CLAIM_DATA.manifest, '--seed', hex(CLAIM.seed), '--self-leaf', CLAIM.self];
  for (const leaf of CLAIM.others) args.push('--leaf', leaf);
  return vectorLines(args);
}
function nativeClaim(tree) {
  const args = ['claim', '--seed', hex(CLAIM.seed), '--chain', CLAIM.chain, '--manifest', tree.manifest, '--manifest-hash', tree.manifest_hash];
  for (const leaf of tree.leaf) args.push('--leaf', leaf);
  args.push('--sign-random', hex(CLAIM.signRandom));
  const { leaf, ...out } = vectorLines(args);
  return out;
}
async function loadParity(file, fixedRandom) {
  const path = join(PARITY_OUT, file);
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  const M = await create();
  assert.equal(typeof M._nsw_test_random_buf === 'function', fixedRandom, 'test-only randomness entry point presence');
  const num = (name, types = [], args = []) => M.ccall(name, 'number', types, args);
  const str = (name, types = [], args = []) => M.ccall(name, 'string', types, args);
  return { M, num, str };
}
// Loads claim data into a module; returns the first failing step's rc (0 = sealed).
function loadClaimData({ num }, manifest, manifestHash, leaves) {
  let rc = num('nsw_claim_reset');
  if (rc === 0) rc = num('nsw_claim_set_manifest', ['string', 'string'], [manifest, manifestHash]);
  for (const leaf of leaves) if (rc === 0) rc = num('nsw_claim_add_leaf', ['string', 'string', 'string'], leaf);
  if (rc === 0) rc = num('nsw_claim_seal');
  return rc;
}
async function wasmClaim(file, { fixedRandom }, tree) {
  const mod = await loadParity(file, fixedRandom), { M, num, str } = mod;
  assert.equal(loadClaimData(mod, tree.manifest, tree.manifest_hash, tree.leaf.map(leaf => leaf.split(':'))), 0, str('nsw_error'));
  M.HEAPU8.set(CLAIM.seed, num('nsw_seed_buf'));
  if (fixedRandom) {
    M.HEAPU8.set(CLAIM.signRandom, num('nsw_test_random_buf'));
    assert.equal(num('nsw_test_random_load', ['number'], [CLAIM.signRandom.length]), 0);
  }
  assert.equal(num('nsw_claim_offline_build', ['string'], [CLAIM.chain]), 0, str('nsw_error'));
  const at = num('nsw_claim_built_bytes'), length = num('nsw_claim_built_len');
  return {
    claim: hex(M.HEAPU8.subarray(at, at + length)), claim_id: str('nsw_claim_built_id'), nullifier: str('nsw_claim_built_nullifier'),
    output_id: str('nsw_claim_built_output'), recipient: str('nsw_claim_built_recipient'), amount: str('nsw_claim_built_amount'),
    chain_id: str('nsw_claim_built_chain'), leaf_index: str('nsw_claim_built_leaf')
  };
}

test('claim parity: TEST wasm (fixed randomness) and the native vector build the same claim byte for byte', { skip: skipParity }, async () => {
  const tree = claimManifest();
  assert.equal(tree.leaf.length, 3);
  const self = tree.leaf.find(leaf => leaf.startsWith('02:')).split(':')[1];
  const native = nativeClaim(tree), wasm = await wasmClaim('send-test-node.mjs', { fixedRandom: true }, tree);
  assert.deepEqual(wasm, native);
  assert.equal(native.recipient, self);
  assert.equal(native.amount, '300000000');       // conv 1/1 in the testnet manifest
  assert.equal(native.leaf_index, '1');           // source ids 01 < 02 < 03
  assert.equal(native.chain_id, CLAIM.chain);
  for (const key of ['claim_id', 'nullifier', 'output_id']) assert.match(native[key], /^[0-9a-f]{128}$/, key);
  assert.notEqual(native.nullifier, native.output_id);
});

test('claim parity: the shipped wasm (hedged signature) has the same identity, different bytes', { skip: skipParity }, async () => {
  assert.ok(readFileSync(join(PARITY_OUT, 'send-node.wasm')).equals(wasmBytes), 'send-node.wasm is not the shipped send.wasm — rebuild both');
  const tree = claimManifest(), native = nativeClaim(tree), wasm = await wasmClaim('send-node.mjs', { fixedRandom: false }, tree);
  for (const key of ['nullifier', 'output_id', 'recipient', 'amount', 'chain_id', 'leaf_index']) assert.equal(wasm[key], native[key], key);
  assert.notEqual(wasm.claim, native.claim);
  assert.notEqual(wasm.claim_id, native.claim_id);
  assert.equal(wasm.claim.length, native.claim.length);
});

// ── staking parity (0.1.29) ────────────────────────────────────────────
// SYNTHETIC inputs (fixed seed, made-up validator key, coins and chain id).
// The staking builder draws no randomness of its own (the change seed is
// SHA3-512 of the inputs), so only the two hedged signatures consume
// signing randomness: 2 × 32 bytes. Selection is ascending by nullifier
// (cmd_v2_stake's), taken until lock + fee is covered.
const STAKE = {
  seed: fill(32, 5), chain: '33'.repeat(32), tip: '2000', expiry: '2090', gas: '3', signRandom: fill(64, 60),
  validator: hex(fill(2592, 17)),
  deleg: { amount: '10000000000', coins: [['d4'.repeat(64), '6000000000'], ['e5'.repeat(64), '6000000000'], ['f6'.repeat(64), '2000000']] },
  undeleg: { amount: '5000000000', coins: [['d4'.repeat(64), '6000000000'], ['e5'.repeat(64), '6000000000']] },
  bond: { amount: '1000000000000000', commission: '1250', coins: [['a7'.repeat(64), '1000000100000000']] }
};
const OPS = { stake: 1, delegate: 2, undelegate: 4 };
const stakeCase = op => op === 'stake'
  ? { validator: '', amount: STAKE.bond.amount, commission: STAKE.bond.commission, coins: STAKE.bond.coins }
  : { validator: STAKE.validator, amount: STAKE[op === 'delegate' ? 'deleg' : 'undeleg'].amount, commission: '0', coins: STAKE[op === 'delegate' ? 'deleg' : 'undeleg'].coins };
function nativeStake(op) {
  const c = stakeCase(op);
  const args = ['stake', '--op', op, '--seed', hex(STAKE.seed), '--chain', STAKE.chain, '--tip', STAKE.tip, '--gas', STAKE.gas,
    '--amount', c.amount, '--commission', c.commission, '--expiry', STAKE.expiry, '--sign-random', hex(STAKE.signRandom)];
  if (c.validator) args.push('--validator', c.validator);
  for (const [nullifier, amount] of c.coins) args.push('--coin', `${nullifier}:${amount}`);
  const out = { input: [] };
  for (const line of execFileSync(VECTOR_BIN, args, { encoding: 'utf8' }).trim().split('\n')) {
    const at = line.indexOf('='), key = line.slice(0, at), value = line.slice(at + 1);
    if (key === 'input') out.input.push(value); else out[key] = value;
  }
  return out;
}
async function wasmStake(file, { fixedRandom }, op) {
  const c = stakeCase(op), { M, num, str } = await loadParity(file, fixedRandom);
  M.HEAPU8.set(STAKE.seed, num('nsw_seed_buf'));
  if (fixedRandom) {
    M.HEAPU8.set(STAKE.signRandom, num('nsw_test_random_buf'));
    assert.equal(num('nsw_test_random_load', ['number'], [STAKE.signRandom.length]), 0);
  }
  num('nsw_req_reset');
  for (const [nullifier, amount] of c.coins) assert.equal(num('nsw_req_add_coin', ['string', 'string'], [nullifier, amount]), 0, str('nsw_error'));
  const rc = num('nsw_stake_offline_build', ['number', 'string', 'string', 'string', 'string', 'string', 'string', 'string'],
    [OPS[op], STAKE.chain, STAKE.tip, STAKE.gas, c.validator, c.amount, c.commission, STAKE.expiry]);
  assert.equal(rc, 0, str('nsw_error'));
  const at = num('nsw_built_env'), length = num('nsw_built_env_len'), input = [];
  for (let i = 0; i < num('nsw_built_n_in'); i++) input.push(str('nsw_built_in', ['number'], [i]));
  return {
    envelope: hex(M.HEAPU8.subarray(at, at + length)), wire_id: str('nsw_built_wire'), intent_id: str('nsw_built_intent'),
    chain_id: str('nsw_built_chain'), op: String(num('nsw_built_op')), recipient: str('nsw_built_recipient'), amount: str('nsw_built_amount'),
    commission: str('nsw_built_commission'), fee: str('nsw_built_fee'), change: str('nsw_built_change'), expiry: str('nsw_built_expiry'), input
  };
}

for (const op of ['delegate', 'undelegate', 'stake']) {
  test(`staking parity (${op}): TEST wasm and the native vector build the same envelope byte for byte`, { skip: skipParity }, async () => {
    const c = stakeCase(op), native = nativeStake(op), wasm = await wasmStake('send-test-node.mjs', { fixedRandom: true }, op);
    assert.deepEqual(wasm, native);
    assert.equal(native.op, String(OPS[op]));
    assert.equal(native.amount, c.amount);
    assert.equal(native.expiry, STAKE.expiry);
    assert.equal(native.chain_id, STAKE.chain);
    // gas price 3: 400 000 units × 3 = 1 200 000, above the 1 000 000 floor
    assert.equal(native.fee, '1200000');
    const inSum = native.input.reduce((sum, n) => sum + BigInt(c.coins.find(([nul]) => nul === n)[1]), 0n);
    const lock = op === 'undelegate' ? 0n : BigInt(c.amount);
    assert.equal(inSum, lock + BigInt(native.fee) + BigInt(native.change), 'inputs = lock + fee + change');
    if (op === 'stake') assert.equal(native.commission, STAKE.bond.commission);
    else assert.equal(native.recipient, createHash('sha3-512').update(Buffer.from(c.validator, 'hex')).digest('hex'));
    // ascending by nullifier, stopping once covered
    assert.deepEqual(native.input, op === 'delegate' ? [c.coins[0][0], c.coins[1][0]] : [c.coins[0][0]]);
  });
  test(`staking parity (${op}): the shipped wasm has the same intent_id, a different wire_id`, { skip: skipParity }, async () => {
    assert.ok(readFileSync(join(PARITY_OUT, 'send-node.wasm')).equals(wasmBytes), 'send-node.wasm is not the shipped send.wasm — rebuild both');
    const native = nativeStake(op), wasm = await wasmStake('send-node.mjs', { fixedRandom: false }, op);
    for (const key of ['intent_id', 'chain_id', 'op', 'recipient', 'amount', 'commission', 'fee', 'change', 'expiry', 'input']) assert.deepEqual(wasm[key], native[key], key);
    assert.notEqual(wasm.wire_id, native.wire_id);
    assert.equal(wasm.envelope.length, native.envelope.length);
  });
}

test('staking refusals in the module: a wrong bond, a commission above 50%, an UNSTAKE op, a validator key for STAKE', { skip: skipParity }, async () => {
  const { M, num, str } = await loadParity('send-node.mjs', false);
  const build = (op, validator, amount, commission, coins) => {
    M.HEAPU8.set(STAKE.seed, num('nsw_seed_buf'));
    num('nsw_req_reset');
    for (const [nullifier, value] of coins) num('nsw_req_add_coin', ['string', 'string'], [nullifier, value]);
    return num('nsw_stake_offline_build', ['number', 'string', 'string', 'string', 'string', 'string', 'string', 'string'],
      [op, STAKE.chain, STAKE.tip, STAKE.gas, validator, amount, commission, STAKE.expiry]);
  };
  assert.notEqual(build(1, '', '999999999999999', '0', STAKE.bond.coins), 0); assert.match(str('nsw_error'), /exactly 10,000,000/);
  assert.notEqual(build(1, '', STAKE.bond.amount, '5001', STAKE.bond.coins), 0); assert.match(str('nsw_error'), /commission/i);
  assert.notEqual(build(3, STAKE.validator, '1', '0', STAKE.deleg.coins), 0); assert.match(str('nsw_error'), /Unknown staking action/);
  assert.notEqual(build(1, STAKE.validator, STAKE.bond.amount, '0', STAKE.bond.coins), 0); assert.match(str('nsw_error'), /Invalid offline staking input/);
  assert.notEqual(build(2, STAKE.validator, '100000000000', '0', STAKE.deleg.coins), 0); assert.match(str('nsw_error'), /Insufficient/);
  assert.equal(num('nsw_built_env_len'), 0, 'nothing built after a refusal');
  // the chain constants the wallet shows (dnac.h)
  assert.equal(str('nsw_const_min_delegation'), '10000000000');
  assert.equal(str('nsw_const_self_stake'), '1000000000000000');
  assert.equal(str('nsw_const_commission_max'), '5000');
  assert.equal(str('nsw_const_undelegate_lock_epochs'), '12');
  assert.equal(str('nsw_const_epoch_length'), '720');
  // the per-validator delegator cap (nodus_types.h NODUS_MAX_DELEGATORS_PER_VALIDATOR)
  assert.equal(str('nsw_const_max_delegators'), '2048');
  // no listing yet: a row's delegator count is unknown (-1), never 0
  assert.equal(num('nsw_val_delegators', ['number'], [0]), -1);
});

// ── chain-name registration parity (HF-4) ──────────────────────────────
// NO native vector here: the name section of nodus-send-wasm.c is built
// only into the two emcc modules (the native vector's script,
// scripts/build-nodus-send-native-vector.sh, does not link
// nodus/src/client/nodus_v2_name.c). What these prove instead:
//   - TEST wasm, fed the same randomness twice, builds the same envelope byte
//     for byte, and its CORE call is EXACTLY the layout nodus-cli wrote before
//     the builder moved — the same literal bytes as the nodus ctest
//     test_v2_name_build N1 fixture (same coins, name, price, floor fee and
//     change), with this test's own change seed and owner;
//   - the shipped wasm (hedged signature) has the same intent_id and decoded
//     fields, a different wire_id;
//   - the module's refusals: generation 1, a name outside the rule, price 0,
//     change seeds given but not used.
// SYNTHETIC inputs (fixed seed, made-up coins and chain id, gas price 0 —
// one fee pass, one change seed).
const skipNameParity = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (build-nodus-send-wasm.sh parity)' : false;
const NAME = {
  seed: fill(32, 7), chain: '44'.repeat(32), tip: '3000', gas: '0', price: '50000000000', expiry: '3090', name: 'punk',
  coins: [['33'.repeat(64), '40000000000'], ['11'.repeat(64), '20000000000'], ['22'.repeat(64), '5000000000']],
  outSeeds: fill(32, 160), signRandom: fill(32, 200)
};
async function wasmName(file, { fixedRandom }, over = {}) {
  const input = { ...NAME, ...over }, { M, num, str } = await loadParity(file, fixedRandom);
  M.HEAPU8.set(input.seed, num('nsw_seed_buf'));
  M.HEAPU8.set(input.outSeeds, num('nsw_out_seed_buf'));
  assert.equal(num('nsw_out_seed_load', ['number'], [input.outSeeds.length]), 0);
  if (fixedRandom) {
    M.HEAPU8.set(input.signRandom, num('nsw_test_random_buf'));
    assert.equal(num('nsw_test_random_load', ['number'], [input.signRandom.length]), 0);
  }
  num('nsw_req_reset');
  for (const [nullifier, amount] of input.coins) assert.equal(num('nsw_req_add_coin', ['string', 'string'], [nullifier, amount]), 0, str('nsw_error'));
  const rc = num('nsw_name_offline_build', ['number', 'string', 'string', 'string', 'string', 'string', 'string'],
    [input.gen ?? 2, input.name, input.chain, input.tip, input.gas, input.price, input.expiry]);
  if (rc !== 0) return { rc, error: str('nsw_error'), envLen: num('nsw_built_env_len') };
  const at = num('nsw_built_env'), length = num('nsw_built_env_len'), inputs = [];
  for (let i = 0; i < num('nsw_built_n_in'); i++) inputs.push(str('nsw_built_in', ['number'], [i]));
  return {
    rc, envelope: hex(M.HEAPU8.subarray(at, at + length)), wire_id: str('nsw_built_wire'), intent_id: str('nsw_built_intent'),
    chain_id: str('nsw_built_chain'), name: str('nsw_built_name'), price: str('nsw_built_price'), owner: str('nsw_built_recipient'),
    fee: str('nsw_built_fee'), change: str('nsw_built_change'), expiry: str('nsw_built_expiry'), inputs, op: num('nsw_built_op')
  };
}

test('name parity: TEST wasm builds the same registration twice, with the pre-move nodus-cli call layout', { skip: skipNameParity }, async () => {
  const a = await wasmName('send-test-node.mjs', { fixedRandom: true }), b = await wasmName('send-test-node.mjs', { fixedRandom: true });
  assert.equal(a.rc, 0, a.error);
  assert.deepEqual(a, b);
  assert.equal(a.name, 'punk'); assert.equal(a.price, NAME.price); assert.equal(a.op, 0);
  assert.equal(a.fee, '1000000', 'the floor at gas price 0');
  assert.equal(a.change, '9999000000', '6·10^10 − 5·10^10 − 10^6');
  assert.equal(a.expiry, NAME.expiry); assert.equal(a.chain_id, NAME.chain);
  assert.deepEqual(a.inputs, ['11'.repeat(64), '33'.repeat(64)], 'largest first (40, 20), written ascending');
  // the CORE call, byte for byte: name_len ‖ name ‖ price u64 BE ‖ in 2 ‖
  // nullifiers ‖ out 1 ‖ owner hex (ASCII) ‖ change u64 BE ‖ native token ‖
  // the change seed
  const call = '04' + Buffer.from('punk').toString('hex') + '0000000ba43b7400' + '02' + '11'.repeat(64) + '33'.repeat(64) + '01' +
    Buffer.from(a.owner).toString('hex') + '0000000253fca1c0' + '00'.repeat(64) + hex(NAME.outSeeds);
  assert.ok(a.envelope.includes(call), 'the envelope carries the nodus-cli call bytes');
});

test('name parity: the shipped wasm (hedged signature) has the same intent_id, a different wire_id', { skip: skipNameParity }, async () => {
  assert.ok(readFileSync(join(PARITY_OUT, 'send-node.wasm')).equals(wasmBytes), 'send-node.wasm is not the shipped send.wasm — rebuild both');
  const fixed = await wasmName('send-test-node.mjs', { fixedRandom: true }), shipped = await wasmName('send-node.mjs', { fixedRandom: false });
  assert.equal(shipped.rc, 0, shipped.error);
  for (const key of ['intent_id', 'chain_id', 'name', 'price', 'owner', 'fee', 'change', 'expiry', 'inputs']) assert.deepEqual(shipped[key], fixed[key], key);
  assert.notEqual(shipped.wire_id, fixed.wire_id);
  assert.equal(shipped.envelope.length, fixed.envelope.length);
});

test('name refusals in the module: generation 1, a name outside the rule, price 0, unused change seeds', { skip: skipNameParity }, async () => {
  const gen1 = await wasmName('send-node.mjs', { fixedRandom: false }, { gen: 1 });
  assert.notEqual(gen1.rc, 0); assert.match(gen1.error, /Invalid offline name input/); assert.equal(gen1.envLen, 0);
  const upper = await wasmName('send-node.mjs', { fixedRandom: false }, { name: 'PUNK' });
  assert.notEqual(upper.rc, 0); assert.match(upper.error, /Not a chain name/);
  const hexlike = await wasmName('send-node.mjs', { fixedRandom: false }, { name: 'deadbeef' });
  assert.notEqual(hexlike.rc, 0); assert.match(hexlike.error, /Not a chain name/);
  const free = await wasmName('send-node.mjs', { fixedRandom: false }, { price: '0' });
  assert.notEqual(free.rc, 0); assert.match(free.error, /gave no price/);
  const extra = await wasmName('send-node.mjs', { fixedRandom: false }, { outSeeds: fill(64, 160) });
  assert.notEqual(extra.rc, 0); assert.match(extra.error, /used 32 of the 64/); assert.equal(extra.envLen, 0);
});

test('claim data: the embedded testnet data seals in the shipped module; a wrong hash or leaf is refused', { skip: skipParity }, async () => {
  const mod = await loadParity('send-node.mjs', false);
  const leaves = NODUS_CLAIM_DATA.leaves.map(leaf => [leaf.sourceId, leaf.destBinding, leaf.amount]);
  assert.equal(loadClaimData(mod, NODUS_CLAIM_DATA.manifest, NODUS_CLAIM_DATA.manifestHash, leaves), 0, mod.str('nsw_error'));
  const wrongHash = NODUS_CLAIM_DATA.manifestHash.slice(0, -1) + (NODUS_CLAIM_DATA.manifestHash.endsWith('0') ? '1' : '0');
  assert.notEqual(loadClaimData(mod, NODUS_CLAIM_DATA.manifest, wrongHash, leaves), 0);
  assert.match(mod.str('nsw_error'), /pinned hash/);
  assert.notEqual(loadClaimData(mod, NODUS_CLAIM_DATA.manifest, NODUS_CLAIM_DATA.manifestHash, [[leaves[0][0], leaves[0][1], '4999999999999999']]), 0);
  assert.match(mod.str('nsw_error'), /allocation root/);
  assert.notEqual(loadClaimData(mod, NODUS_CLAIM_DATA.manifest, NODUS_CLAIM_DATA.manifestHash, [[leaves[0][0], 'ab'.repeat(64), leaves[0][2]]]), 0);
  assert.match(mod.str('nsw_error'), /allocation root/);
  // No allocation for another key: the offline build refuses before signing.
  assert.equal(loadClaimData(mod, NODUS_CLAIM_DATA.manifest, NODUS_CLAIM_DATA.manifestHash, leaves), 0);
  mod.M.HEAPU8.set(CLAIM.seed, mod.num('nsw_seed_buf'));
  assert.notEqual(mod.num('nsw_claim_offline_build', ['string'], [NODUS_SEND_NETWORK.chainId]), 0);
  assert.match(mod.str('nsw_error'), /no allocation/);
});
