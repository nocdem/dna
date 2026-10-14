// HF-6 in the NODUS send module (design docs/plans/2026-10-12-connect-hf6-
// screens-design.md §2, §3; docs/plans/2026-10-03-hf5-validator-owner-stake-
// design.md rev 6 §2, §6.1, §11.3, §11.5): the node-consent check and the
// four generation-4 envelopes (STAKE, STORAGE_REGISTER, STORAGE_EXIT —
// node_fp ‖ owner_fp, 128 bytes —, UNSTAKE — "Stop being a witness", op 3,
// validator_id ‖ owner_fp, 128 bytes, fee only) of crypto/nodus-send-wasm.c
// "HF-6: NODE CONSENT". No ROTATE: the khan removed it from HF-6 (decision
// docs/plans/decisions/2026-10-13-kurultay-18-summary.md item 1; the owner
// in UNSTAKE / STORAGE_EXIT is item 2, "C2").
//
// Always run (no build needed beyond the committed src/nodus/send.*):
//   - send.wasm exports the HF-6 entry points and no test-only one.
//
// Parity (needs the builds, else those tests SKIP — a skip is not a pass):
//   NODUS_SEND_PARITY_OUT  dir from `scripts/build-nodus-send-wasm.sh parity`
//   NODUS_SEND_VECTOR_BIN  binary from `scripts/build-nodus-send-native-vector.sh`
// What each proves:
//   - ORACLE (PARITY_OUT only): the consent message the module builds with
//     the codec (shared/dnac/valbind_wire.c) has the SHA3-512 the
//     independent oracle shared/dnac/tests/valbind_oracle.py printed
//     (valbind_oracle_out.txt "consent_*.sha3_512"), for ops 1 and 3 (op 2,
//     the removed ROTATE, is still a value of the shared codec, but the
//     wallet never makes nor accepts one — it is not pinned here).
//     The oracle has no signature (its key is a filler, not a key pair), so
//     a SIGNED consent comes from the native vector's `hf6-consent` mode —
//     the node's side, as nodus-cli `validator consent` makes it.
//   - CONSENT CHECK: a valid consent passes all seven checks in the shipped
//     module; each check fails alone on the one defect aimed at it; invalid
//     arguments are an error, not a check result; the JS bridge normalises
//     line ends and the missing final newline of a paste, nothing else.
//   - ENVELOPES: TEST wasm (fixed randomness) == native vector byte for
//     byte for all four ops; the shipped wasm (hedged signatures) has the
//     same intent_id and decoded fields, a different wire_id; the module's
//     refusals (generation 3, a bond below STAKE_MIN, a storage bond that
//     is not exact, a consent failing a check, a consent for STORAGE_EXIT
//     or UNSTAKE, an all-zero witness id for UNSTAKE, op 10 — the removed
//     ROTATE) build nothing. BONDS (BUGS W-20): the STAKE floor and the
//     storage bond are the node-reported values (dnac_fee_info, passed to
//     the offline build): a non-default one is what is built (TEST wasm ==
//     native vector), "0" is the compiled default, a value outside the
//     node handler's range builds nothing. UNSTAKE / STORAGE_EXIT: the whole 128-byte
//     call — target ‖ owner_fp, owner_fp = SHA3-512 of the wallet key — is
//     in the envelope, no amount; UNSTAKE has no node key (node_fp ""), the
//     read-back names the witness. The owner and status checks against the
//     ROW (owner_fp == the row's owner, ACTIVE / ELIGIBLE) are the CHAIN's
//     (rtn_unstake2_exec / rtn_storage_exit_exec) — not exercised here.
// Inputs are SYNTHETIC (fixed seeds, made-up coins, chain id and
// validator_id): they prove the builds agree with each other and with the
// codec, not that a node accepts the result. The generation-4 pins are the
// merged hf6 header's (nodus/include/nodus/nodus_ruleset_pins.h: SYSTEM
// v10, CORE v8); no value of them is restated in this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { createNodusSendModule } from '../src/nodus/send-module.js';

const wasmBytes = readFileSync(new URL('../src/nodus/send.wasm', import.meta.url));

const HF6_ENTRY_POINTS = [
  'nsw_hf6_consent_check', 'nsw_hf6_build', 'nsw_hf6_offline_build', 'nsw_built_gen4', 'nsw_built_node_fp',
  'nsw_built_validator_id', 'nsw_built_consent_expiry', 'nsw_hf6_bonds', 'nsw_hb_stake_min', 'nsw_hb_storage_bond',
  'nsw_const_consent_window', 'nsw_hf6_generation', 'nsw_const_min_tenure_blocks', 'nsw_const_storage_exit_lock_epochs',
  'nsw_const_validator_unbond_epochs'
];

test('the shipped send.wasm exports the HF-6 entry points and no test-only one', () => {
  const exports = new Set(WebAssembly.Module.exports(new WebAssembly.Module(wasmBytes)).map(({ name }) => name));
  for (const name of HF6_ENTRY_POINTS) assert.ok(exports.has(name), `missing export ${name}`);
  // the bonds are chain parameters read from the node (BUGS W-20): no
  // compiled-constant export the page could show instead
  for (const name of ['nsw_const_hf6_stake_min', 'nsw_const_hf6_storage_bond']) assert.ok(!exports.has(name), `stale export ${name}`);
  assert.ok(!exports.has('nsw_test_valbind_msg_sha3'), 'the test-only consent message hash is in the shipped module');
  assert.ok(![...exports].some(name => name.startsWith('nsw_test_')), 'a test-only entry point is in the shipped module');
});

// ── parity setup ────────────────────────────────────────────────────────
const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT, VECTOR_BIN = process.env.NODUS_SEND_VECTOR_BIN;
const skipWasm = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (build-nodus-send-wasm.sh parity)' : false;
const skipParity = !PARITY_OUT || !VECTOR_BIN
  ? 'set NODUS_SEND_PARITY_OUT and NODUS_SEND_VECTOR_BIN (build-nodus-send-wasm.sh parity, build-nodus-send-native-vector.sh)'
  : false;

const hex = bytes => Buffer.from(bytes).toString('hex');
const fill = (length, start) => Uint8Array.from({ length }, (_, i) => (start + i * 7) & 0xff);
const sha3 = bytes => createHash('sha3-512').update(bytes).digest();

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

function vector(args) {
  const out = { input: [] };
  for (const line of execFileSync(VECTOR_BIN, args, { encoding: 'utf8', maxBuffer: 1 << 24 }).trim().split('\n')) {
    const at = line.indexOf('='), key = line.slice(0, at), value = line.slice(at + 1);
    if (key === 'input') out.input.push(value); else out[key] = value;
  }
  return out;
}

// ── oracle pin (shared/dnac/tests/valbind_oracle.py, its output file) ───
// fill(label, n) = SHA3-512(label ‖ u32 BE i) for i = 0, 1, … truncated to n
// (valbind_oracle.py fill); chain = fill("chain", 32), owner = fill("owner",
// 64), pk = fill("pk", 2592), a non-zero subject = fill("subject", 64),
// expiry 1000 (valbind_oracle.py main).
const oracleFill = (label, n) => {
  const parts = [];
  for (let i = 0, got = 0; got < n; i++, got += 64) {
    const idx = Buffer.alloc(4);
    idx.writeUInt32BE(i);
    parts.push(sha3(Buffer.concat([Buffer.from(label, 'ascii'), idx])));
  }
  return Buffer.concat(parts).subarray(0, n);
};
const ORACLE_PINS = {   // valbind_oracle_out.txt lines "consent_<op>.sha3_512"
  1: '4d1c9e26243a03fe751e87e2d5752d6cf516e9dab23c892c576887d3f89e88a76508fe09f008a16a8e6da43921794fafe5f8647b778bda5c76d1e61e9bab4d92',
  3: '6272275ce84e3c90ccc9958ff928cf50ce22983a16df93ad0fb558c80c1dd37a02870c159b8a99df93cd36b36f46d145326df7637934590bb50c0725a5f5a9ec'
};

test('oracle: the module builds the consent message the independent oracle hashed (ops 1, 3)', { skip: skipWasm }, async () => {
  const { str } = await loadParity('send-test-node.mjs', true);
  const chain = hex(oracleFill('chain', 32)), owner = hex(oracleFill('owner', 64)), pk = hex(oracleFill('pk', 2592));
  // the oracle's own input line "sha3_512(pk)" — the filler is reproduced
  assert.equal(hex(sha3(Buffer.from(pk, 'hex'))), 'fd10d000876b1e26b735802afe031b9d8a471f5580cf0b0e7a6b18561373727d70046d6774f128fc27f1e1a67dab5e2992bfe3d58cf22578fe7371d124d5f3ee');
  const msgHash = (op, subject) => str('nsw_test_valbind_msg_sha3', ['number', 'string', 'string', 'string', 'string', 'string'], [op, chain, subject, owner, pk, '1000']);
  assert.equal(msgHash(1, '00'.repeat(64)), ORACLE_PINS[1]);
  assert.equal(msgHash(3, '00'.repeat(64)), ORACLE_PINS[3]);
  // the codec's op/subject rule: STAKE / STORAGE_REGISTER with a subject, op 4
  assert.equal(msgHash(1, hex(oracleFill('subject', 64))), '');
  assert.equal(msgHash(3, hex(oracleFill('subject', 64))), '');
  assert.equal(msgHash(4, '00'.repeat(64)), '');
});

// ── consents (the node's side: the native vector's hf6-consent mode) ────
const HF6 = {
  seed: fill(32, 9),                      // the wallet (owner) seed
  nodeSeed: fill(32, 21),                 // the witness / storage node seed
  chain: '55'.repeat(32), tip: '5000', expiry: '5090', gas: '3', consentExpiry: '5600',
  validatorId: 'ab'.repeat(64),
  consentRandom: fill(32, 77), signRandom: fill(64, 120)
};

function makeConsent({ op, nodeSeed = HF6.nodeSeed, chain = HF6.chain, owner, expiry = HF6.consentExpiry }) {
  const args = ['hf6-consent', '--op', op, '--node-seed', hex(nodeSeed), '--chain', chain, '--expiry', expiry,
    '--sign-random', hex(HF6.consentRandom)];
  if (owner) args.push('--owner', owner); else args.push('--owner-seed', hex(HF6.seed));
  const out = vector(args);
  return { text: Buffer.from(out.consent, 'hex').toString('utf8'), hex: out.consent, nodeFp: out.node_fp, owner: out.owner };
}

const CHECK_IDS = ['format', 'op', 'chain', 'owner', 'subject', 'expiry', 'signature'];
// nsw_hf6_consent_check(op, text, chain, owner, tip, window): no subject
// argument — the subject of both consent ops is 64 zero bytes
function consentCheck({ str }, { op, text, chain = HF6.chain, owner, tip = HF6.tip, window = '720' }) {
  return JSON.parse(str('nsw_hf6_consent_check', ['number', 'string', 'string', 'string', 'string', 'string'],
    [op, text, chain, owner, tip, window]));
}
// Exactly the named checks failed, every other one passed.
function failedOnly(result, ...ids) {
  assert.deepEqual(result.checks.map(c => c.id), CHECK_IDS);
  assert.equal(result.error, '');
  assert.deepEqual(result.checks.filter(c => !c.ok).map(c => c.id), ids, JSON.stringify(result.checks));
  assert.equal(result.ok, ids.length === 0);
  for (const c of result.checks) assert.ok(typeof c.detail === 'string' && c.detail.length > 0, c.id);
}

test('consent check: a valid consent passes every check, for each of the two ops', { skip: skipParity }, async () => {
  const mod = await loadParity('send-node.mjs', false);
  for (const [op, code] of [['stake', 1], ['storage', 3]]) {
    const c = makeConsent({ op });
    assert.equal(c.nodeFp, hex(sha3(Buffer.from(c.text.split('\n')[5].slice('consensus_pk '.length), 'hex'))));
    const r = consentCheck(mod, { op: code, text: c.text, owner: c.owner });
    failedOnly(r);
    assert.equal(r.node_fp, c.nodeFp);
    assert.equal(r.expiry, HF6.consentExpiry);
  }
});

test('consent check: each check fails alone on its own defect', { skip: skipParity }, async () => {
  const mod = await loadParity('send-node.mjs', false);
  const stake = makeConsent({ op: 'stake' });
  const base = { op: 1, text: stake.text, owner: stake.owner };
  // format: a line missing, an uppercase digit, a missing final newline in C
  // (the JS bridge adds it — see below), a leading zero in the expiry, a
  // non-zero subject (the container's op/subject rule), and a ROTATE
  // consent (op 2 with a validator_id as subject — the shape nodus-cli
  // made before Kurultay #18): the container refuses op 2, so it is not a
  // consent at all
  const lines = stake.text.split('\n');
  const withSubject = stake.text.replace(/^subject 0+$/m, `subject ${HF6.validatorId}`);
  assert.notEqual(withSubject, stake.text, 'the subject line was replaced');
  for (const text of [lines.slice(0, 7).join('\n') + '\n', stake.text.replace(/^chain_id ./m, 'chain_id A'),
    stake.text.slice(0, -1), stake.text.replace(/^expiry /m, 'expiry 0'), '',
    withSubject, withSubject.replace(/^op 1$/m, 'op 2')]) {
    const r = consentCheck(mod, { ...base, text });
    assert.deepEqual(r.checks.filter(c => !c.ok).map(c => c.id), CHECK_IDS, 'a text that does not parse fails every check');
    assert.equal(r.ok, false); assert.equal(r.node_fp, ''); assert.equal(r.expiry, '');
  }
  // op: a STAKE consent on the storage screen (subject zero for both)
  failedOnly(consentCheck(mod, { ...base, op: 3 }), 'op');
  // chain
  failedOnly(consentCheck(mod, { ...base, chain: '66'.repeat(32) }), 'chain');
  // owner
  failedOnly(consentCheck(mod, { ...base, owner: 'cd'.repeat(64) }), 'owner');
  // subject: the container itself refuses a non-zero subject for both ops
  // (above), so the "subject" line passes whenever the text parses
  // expiry: expired (tip == expiry); with window 720, 721 ahead fails and
  // 720 ahead passes (design §2: expiry <= tip + E); a window above 720
  // cannot widen the chain's own rule, dna_valbind_expiry_ok(tip + 1,
  // expiry) — at most tip + 721 — so 722 ahead fails with any window; a
  // narrower caller window; an unknown tip (0)
  const ahead = n => String(Number(HF6.consentExpiry) - n);
  failedOnly(consentCheck(mod, { ...base, tip: HF6.consentExpiry }), 'expiry');
  failedOnly(consentCheck(mod, { ...base, tip: ahead(721) }), 'expiry');
  failedOnly(consentCheck(mod, { ...base, tip: ahead(720) }));
  failedOnly(consentCheck(mod, { ...base, tip: ahead(721), window: '100000' }));
  failedOnly(consentCheck(mod, { ...base, tip: ahead(722), window: '100000' }), 'expiry');
  failedOnly(consentCheck(mod, { ...base, window: '10' }), 'expiry');
  failedOnly(consentCheck(mod, { ...base, tip: '0' }), 'expiry');
  // signature: one hex digit of the signature changed (still lowercase hex)
  const sigLine = lines[7], flipped = sigLine.slice(0, 40) + (sigLine[40] === '0' ? '1' : '0') + sigLine.slice(41);
  failedOnly(consentCheck(mod, { ...base, text: [...lines.slice(0, 7), flipped, ''].join('\n') }), 'signature');
  // the node_fp is the signed key's, even when another check fails
  assert.equal(consentCheck(mod, { ...base, owner: 'cd'.repeat(64) }).node_fp, stake.nodeFp);
  // invalid ARGUMENTS: an error, no checks — op 2 (the removed ROTATE) and
  // op 4 are no consent action
  for (const args of [{ ...base, op: 2 }, { ...base, op: 4 }, { ...base, owner: 'CD'.repeat(64) }, { ...base, chain: '5'.repeat(63) },
    { ...base, tip: '01' }, { ...base, window: '0' }]) {
    const r = consentCheck(mod, args);
    assert.notEqual(r.error, '', JSON.stringify(args).slice(0, 60)); assert.equal(r.ok, false); assert.deepEqual(r.checks, []);
  }
});

test('consent check through the JS bridge: the pinned chain, the wallet\'s own owner, a pasted text normalised', { skip: skipParity }, async () => {
  const network = { chainId: HF6.chain, scheme: 'wss', endpoints: [{ host: '203.0.113.7', port: 443 }], pins: ['b'.repeat(128)] };
  const api = await createNodusSendModule(network, { loadGlue: () => import(pathToFileURL(join(PARITY_OUT, 'send-node.mjs')).href), startIndex: 0 });
  assert.throws(() => api.consentCheck({ op: 'stake', text: 'x', tip: HF6.tip }), /not unlocked/);
  const { fingerprint } = await api.identify({ seed: Uint8Array.from(HF6.seed) });
  const stake = makeConsent({ op: 'stake' });
  assert.equal(fingerprint, stake.owner);
  // a Windows paste without its final newline, with blank space around it
  const pasted = `\r\n  ${stake.text.trimEnd().replace(/\n/g, '\r\n')}  \r\n`;
  const r = api.consentCheck({ op: 'stake', text: pasted, tip: HF6.tip });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal(r.nodeFp, stake.nodeFp); assert.equal(r.expiry, HF6.consentExpiry);
  // a consent for another wallet fails on owner only
  const other = makeConsent({ op: 'stake', owner: 'cd'.repeat(64) });
  const o = api.consentCheck({ op: 'stake', text: other.text, tip: HF6.tip });
  assert.equal(o.ok, false); assert.deepEqual(o.checks.filter(c => !c.ok).map(c => c.id), ['owner']);
  // no rotate consent action (Kurultay #18 item 1)
  assert.throws(() => api.consentCheck({ op: 'rotate', text: stake.text, tip: HF6.tip }), /Unknown consent action/);
  // a paste over 16384 bytes is refused in JS, before the ccall copies it
  // onto the module's 1 MiB C stack (red-team round 1, Astra F2) — 2 MiB
  // would overflow that stack; the module stays usable afterwards
  const huge = `${stake.text}${'x'.repeat(2 * 1024 * 1024)}`;
  assert.throws(() => api.consentCheck({ op: 'stake', text: huge, tip: HF6.tip }), /too long/);
  assert.throws(() => api.consentCheck({ op: 'stake', text: 'é'.repeat(8193), tip: HF6.tip }), /too long/, 'counted in UTF-8 bytes');
  assert.equal(api.consentCheck({ op: 'stake', text: stake.text, tip: HF6.tip }).ok, true);
  // the screens' values
  assert.deepEqual({ ...api.hf6Rules }, { consentWindow: '720', generation: 4 }, 'no bond constants: the bonds come from hf6Bonds()');
  assert.equal(typeof api.hf6Bonds, 'function');
  api.lock();
});

// ── envelope parity (generation 4) ──────────────────────────────────────
// Selection is ascending by nullifier until lock + fee is covered; gas price
// 3: 400 000 units × 3 = 1 200 000, above the 1 000 000 floor.
const ENV_OPS = { stake: 1, 'storage-register': 7, 'storage-exit': 8, unstake: 3 };
function envCase(op) {
  // UNSTAKE: the witness's validator_id, no consent, fee only — one coin
  if (op === 'unstake') return { consent: null, target: HF6.validatorId, amount: '0', commission: '0', coins: [['17'.repeat(64), '5000000']], lock: 0n, inputs: ['17'.repeat(64)] };
  const nodeFp = makeConsent({ op: 'storage' }).nodeFp;
  switch (op) {
    // the first coin covers bond + fee: one input
    case 'stake': return { consent: makeConsent({ op: 'stake' }), target: '', amount: '200000000000000', commission: '1000',
      coins: [['a1'.repeat(64), '200000100000000'], ['b2'.repeat(64), '7']], lock: 200000000000000n, inputs: ['a1'.repeat(64)] };
    // the first coin is exactly the bond, the fee needs the second
    case 'storage-register': return { consent: makeConsent({ op: 'storage' }), target: '', amount: '100000000000000', commission: '0',
      coins: [['d4'.repeat(64), '100000000000000'], ['e5'.repeat(64), '100000000']], lock: 100000000000000n, inputs: ['d4'.repeat(64), 'e5'.repeat(64)] };
    default: return { consent: null, target: nodeFp, amount: '0', commission: '0', coins: [['f6'.repeat(64), '5000000']], lock: 0n, inputs: ['f6'.repeat(64)] };
  }
}
function nativeHf6(op, c, gen = '4') {
  const args = ['hf6', '--gen', gen, '--op', op, '--seed', hex(HF6.seed), '--chain', HF6.chain, '--tip', HF6.tip, '--gas', HF6.gas,
    '--amount', c.amount, '--commission', c.commission, '--expiry', HF6.expiry, '--sign-random', hex(HF6.signRandom)];
  if (c.consent) args.push('--consent', c.consent.hex);
  if (c.target) args.push('--target', c.target);
  // the node-reported bonds (BUGS W-20); absent = "0" = not reported
  if (c.stakeMin) args.push('--stake-min', c.stakeMin);
  if (c.storageBond) args.push('--storage-bond', c.storageBond);
  for (const [nullifier, amount] of c.coins) args.push('--coin', `${nullifier}:${amount}`);
  return vector(args);
}
const HF6_BUILD_TYPES = ['number', 'number', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string'];
function wasmHf6({ M, num, str }, fixedRandom, op, c, gen = 4) {
  M.HEAPU8.set(HF6.seed, num('nsw_seed_buf'));
  if (fixedRandom) {
    M.HEAPU8.set(HF6.signRandom, num('nsw_test_random_buf'));
    assert.equal(num('nsw_test_random_load', ['number'], [HF6.signRandom.length]), 0);
  }
  num('nsw_req_reset');
  for (const [nullifier, amount] of c.coins) assert.equal(num('nsw_req_add_coin', ['string', 'string'], [nullifier, amount]), 0, str('nsw_error'));
  const rc = num('nsw_hf6_offline_build', HF6_BUILD_TYPES,
    [gen, ENV_OPS[op], HF6.chain, HF6.tip, HF6.gas, c.consent ? c.consent.text : '', c.target, c.amount, c.commission, HF6.expiry,
      c.stakeMin || '0', c.storageBond || '0']);
  if (rc !== 0) return { rc, error: str('nsw_error'), envLen: num('nsw_built_env_len') };
  const at = num('nsw_built_env'), length = num('nsw_built_env_len'), input = [];
  for (let i = 0; i < num('nsw_built_n_in'); i++) input.push(str('nsw_built_in', ['number'], [i]));
  return {
    envelope: hex(M.HEAPU8.subarray(at, at + length)), wire_id: str('nsw_built_wire'), intent_id: str('nsw_built_intent'),
    chain_id: str('nsw_built_chain'), op: String(num('nsw_built_op')), gen4: String(num('nsw_built_gen4')),
    recipient: str('nsw_built_recipient'), node_fp: str('nsw_built_node_fp'), validator_id: str('nsw_built_validator_id'),
    amount: str('nsw_built_amount'), commission: str('nsw_built_commission'), consent_expiry: str('nsw_built_consent_expiry'),
    fee: str('nsw_built_fee'), change: str('nsw_built_change'), expiry: str('nsw_built_expiry'), input
  };
}
// The generation-4 SYSTEM call lengths (nodus_v2_stake.h NODUS_V2_STAKE2_
// CALL_LEN 7301 / _STREG_ 7299 / _STEXIT_ 128 / _UNSTAKE2_ 128 — the last
// two node_fp ‖ owner_fp and validator_id ‖ owner_fp since Kurultay #18
// item 2, "C2").
const CALL_LEN = { stake: 7301, 'storage-register': 7299, 'storage-exit': 128, unstake: 128 };

for (const op of Object.keys(ENV_OPS)) {
  test(`hf6 parity (${op}): TEST wasm and the native vector build the same envelope byte for byte`, { skip: skipParity }, async () => {
    const c = envCase(op), native = nativeHf6(op, c), wasm = wasmHf6(await loadParity('send-test-node.mjs', true), true, op, c);
    assert.deepEqual(wasm, native);
    assert.equal(native.op, String(ENV_OPS[op]));
    assert.equal(native.gen4, '1');
    assert.equal(native.chain_id, HF6.chain);
    assert.equal(native.expiry, HF6.expiry);
    assert.equal(native.recipient, c.consent ? c.consent.owner : makeConsent({ op: 'stake' }).owner, 'the owner is the wallet');
    assert.equal(native.amount, c.lock.toString());
    assert.equal(native.fee, '1200000');
    // UNSTAKE's call carries no node key: no node fingerprint
    assert.equal(native.node_fp, op === 'unstake' ? '' : c.consent ? c.consent.nodeFp : c.target);
    assert.equal(native.validator_id, op === 'unstake' ? HF6.validatorId : '');
    assert.equal(native.consent_expiry, c.consent ? HF6.consentExpiry : '');
    assert.equal(native.commission, op === 'stake' ? c.commission : '');
    const inSum = native.input.reduce((sum, n) => sum + BigInt(c.coins.find(([nul]) => nul === n)[1]), 0n);
    assert.equal(inSum, c.lock + BigInt(native.fee) + BigInt(native.change), 'inputs = lock + fee + change');
    assert.deepEqual(native.input, c.inputs, 'ascending by nullifier, stopping once covered');
    // the SYSTEM call carries the consent bytes the node signed (not for EXIT)
    const env = Buffer.from(native.envelope, 'hex');
    if (c.consent) {
      const sig = c.consent.text.split('\n')[7].slice('sig '.length), pk = c.consent.text.split('\n')[5].slice('consensus_pk '.length);
      assert.ok(env.includes(Buffer.from(pk + sig, 'hex')), 'consensus_pk ‖ consent_sig in the call');
    } else {
      // STORAGE_EXIT: node_fp ‖ owner_fp; UNSTAKE: validator_id ‖ owner_fp —
      // the whole 128-byte call, owner_fp = SHA3-512 of the wallet key (the
      // owner the hf6-consent mode derives from the same seed)
      const call = Buffer.concat([Buffer.from(c.target, 'hex'), Buffer.from(native.recipient, 'hex')]);
      assert.equal(call.length, CALL_LEN[op]);
      assert.ok(env.includes(call), op === 'unstake' ? 'validator_id ‖ owner_fp in the call' : 'node_fp ‖ owner_fp in the call');
    }
    assert.ok(env.length > CALL_LEN[op]);
  });
  test(`hf6 parity (${op}): the shipped wasm has the same intent_id, a different wire_id`, { skip: skipParity }, async () => {
    assert.ok(readFileSync(join(PARITY_OUT, 'send-node.wasm')).equals(wasmBytes), 'send-node.wasm is not the shipped send.wasm — rebuild both');
    const c = envCase(op), native = nativeHf6(op, c), wasm = wasmHf6(await loadParity('send-node.mjs', false), false, op, c);
    for (const key of ['intent_id', 'chain_id', 'op', 'gen4', 'recipient', 'node_fp', 'validator_id', 'amount', 'commission',
      'consent_expiry', 'fee', 'change', 'expiry', 'input']) assert.deepEqual(wasm[key], native[key], key);
    assert.notEqual(wasm.wire_id, native.wire_id);
    assert.equal(wasm.envelope.length, native.envelope.length);
  });
}

test('hf6 refusals in the module: generation 3, the bonds, a failing consent, a consent for leaving storage, the UNSTAKE arguments, op 10 (no ROTATE)',{ skip: skipParity }, async () => {
  const mod = await loadParity('send-node.mjs', false);
  const refused = (r, pattern) => {
    assert.notEqual(r.rc, 0); assert.match(r.error, pattern); assert.equal(r.envLen, 0, 'nothing built after a refusal');
  };
  for (const op of Object.keys(ENV_OPS)) refused(wasmHf6(mod, false, op, envCase(op), 3), /Not yet available/);
  const stake = envCase('stake');
  refused(wasmHf6(mod, false, 'stake', { ...stake, amount: '199999999999999' }), /at least 2000000 NODUS/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, commission: '5001' }), /commission/i);
  const streg = envCase('storage-register');
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, amount: '100000000000001' }), /exactly 1000000 NODUS/);
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, amount: '99999999999999' }), /exactly 1000000 NODUS/);
  // the consent is re-checked inside the build: another owner, another op,
  // an expired one, a broken signature
  refused(wasmHf6(mod, false, 'stake', { ...stake, consent: makeConsent({ op: 'stake', owner: 'cd'.repeat(64) }) }), /another wallet/);
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, consent: makeConsent({ op: 'stake' }) }), /not for becoming a storage node/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, consent: makeConsent({ op: 'stake', expiry: HF6.tip }) }), /expired/);
  const lines = stake.consent.text.split('\n'), sig = lines[7];
  const broken = { ...stake.consent, text: [...lines.slice(0, 7), sig.slice(0, 50) + (sig[50] === '0' ? '1' : '0') + sig.slice(51), ''].join('\n') };
  refused(wasmHf6(mod, false, 'stake', { ...stake, consent: broken }), /signature/);
  // STORAGE_EXIT takes no consent; the others need one; the wrong targets
  refused(wasmHf6(mod, false, 'storage-exit', { ...envCase('storage-exit'), consent: stake.consent }), /Invalid offline/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, consent: null }), /Invalid offline/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, target: HF6.validatorId }), /Invalid offline/);
  refused(wasmHf6(mod, false, 'storage-exit', { ...envCase('storage-exit'), amount: '1' }), /Invalid witness or storage request/);
  // op 10 (the removed ROTATE, Kurultay #18 item 1) and consent op 2: no
  // build, in the module and in the native vector (same C function)
  const rotateOp = mod.num('nsw_hf6_offline_build', HF6_BUILD_TYPES,
    [4, 10, HF6.chain, HF6.tip, HF6.gas, stake.consent.text, HF6.validatorId, '0', '0', HF6.expiry, '0', '0']);
  refused({ rc: rotateOp, error: mod.str('nsw_error'), envLen: mod.num('nsw_built_env_len') }, /Invalid offline/);
  assert.throws(() => nativeHf6('rotate', { ...envCase('unstake') }));
  assert.throws(() => vector(['hf6-consent', '--op', 'rotate', '--node-seed', hex(HF6.nodeSeed), '--chain', HF6.chain, '--expiry', HF6.consentExpiry,
    '--sign-random', hex(HF6.consentRandom), '--owner-seed', hex(HF6.seed)]));
  // UNSTAKE: no consent, a non-zero witness id, no amount
  const unstake = envCase('unstake');
  refused(wasmHf6(mod, false, 'unstake', { ...unstake, consent: stake.consent }), /Invalid offline/);
  refused(wasmHf6(mod, false, 'unstake', { ...unstake, target: '' }), /Invalid offline/);
  refused(wasmHf6(mod, false, 'unstake', { ...unstake, target: '00'.repeat(64) }), /Invalid witness: choose one of your witnesses/);
  refused(wasmHf6(mod, false, 'unstake', { ...unstake, amount: '1' }), /Invalid witness or storage request/);
  // the native vector refuses the same all-zero id (the same C function)
  assert.throws(() => nativeHf6('unstake', { ...unstake, target: '00'.repeat(64) }));
  // the screens' values (valbind_wire.h, nodus_witness_runtime.h)
  assert.equal(mod.str('nsw_const_consent_window'), '720');
  assert.equal(mod.num('nsw_hf6_generation'), 4);
  // the UNSTAKE bond lock, in epochs (dnac.h DNAC_VALIDATOR_UNBOND_EPOCHS)
  assert.equal(mod.str('nsw_const_validator_unbond_epochs'), '84');
});

// BUGS W-20: the bonds are the node-reported chain parameters (dnac_fee_info
// "stake_min" / "storage_bond", params 19 / 21) — nsw_hf6_bonds_of: "0" (an
// older node) is the compiled default (nodus-cli cmd_v2_stake's rule), a
// value outside the range the node's handler answers with
// (nodus_witness_handlers.c: stake_min [100,000 NODUS, INT64_MAX raw],
// storage_bond [100,000, 1,000,000 NODUS]) builds nothing.
test('hf6 bonds: a node-reported storage bond / stake minimum other than the default is what is built; 0 is the default; out of range is refused', { skip: skipParity }, async () => {
  const mod = await loadParity('send-node.mjs', false);
  const refused = (r, pattern) => {
    assert.notEqual(r.rc, 0); assert.match(r.error, pattern); assert.equal(r.envLen, 0, 'nothing built after a refusal');
  };
  const streg = envCase('storage-register'), stake = envCase('stake');
  // 500,000 NODUS storage bond: built exactly, and the TEST wasm equals the
  // native vector byte for byte with the same reported value
  const half = { ...streg, storageBond: '50000000000000', amount: '50000000000000' };
  const built = wasmHf6(mod, false, 'storage-register', half);
  assert.equal(built.amount, '50000000000000');
  assert.deepEqual(built.input, ['d4'.repeat(64)], 'the first coin covers the smaller bond and the fee');
  assert.deepEqual(wasmHf6(await loadParity('send-test-node.mjs', true), true, 'storage-register', half), nativeHf6('storage-register', half));
  // that node's value, not the compiled one, is the rule
  refused(wasmHf6(mod, false, 'storage-register', { ...half, amount: '100000000000000' }), /exactly 500000 NODUS/);
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, storageBond: '15000050000000', amount: '100000000000000' }), /exactly 150000\.5 NODUS/);
  // a stake minimum of 150,000.5 NODUS: below it refused, at it built
  const low = { ...stake, stakeMin: '15000050000000' };
  refused(wasmHf6(mod, false, 'stake', { ...low, amount: '15000049999999' }), /at least 150000\.5 NODUS/);
  assert.equal(wasmHf6(mod, false, 'stake', { ...low, amount: '15000050000000' }).amount, '15000050000000');
  // "0" = not reported = the compiled default (2,000,000 / 1,000,000 NODUS)
  assert.equal(wasmHf6(mod, false, 'storage-register', { ...streg, storageBond: '0' }).amount, '100000000000000');
  refused(wasmHf6(mod, false, 'stake', { ...stake, stakeMin: '0', amount: '199999999999999' }), /at least 2000000 NODUS/);
  // outside the handler's ranges: nothing built, whatever the amount
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, storageBond: '100000000000001' }), /storage bond outside the network's range/);
  refused(wasmHf6(mod, false, 'storage-register', { ...streg, storageBond: '9999999999999', amount: '9999999999999' }), /storage bond outside the network's range/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, stakeMin: '9999999999999' }), /witness bond minimum outside the network's range/);
  refused(wasmHf6(mod, false, 'stake', { ...stake, stakeMin: '9223372036854775808' }), /witness bond minimum outside the network's range/);
  // the range edges are accepted
  assert.equal(wasmHf6(mod, false, 'storage-register', { ...streg, storageBond: '10000000000000', amount: '10000000000000' }).amount, '10000000000000');
  assert.equal(wasmHf6(mod, false, 'stake', { ...stake, stakeMin: '10000000000000' }).amount, stake.amount);
  // an unparsable reported value is an invalid input
  refused(wasmHf6(mod, false, 'stake', { ...stake, stakeMin: '01' }), /Invalid offline/);
});
