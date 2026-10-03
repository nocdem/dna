// Shared vaults (src/vaults/, crypto/nodus-send-wasm.c "VAULTS",
// nodus/src/client/nodus_v2_msig.c): the vault message kinds, the
// Foundation preset, the kept record, a request's state, and — with the
// parity build — descriptor / address parity against the C and the
// co-signer's read-back refusing every changed field.
//
// Governing records: docs/plans/decisions/2026-09-29-general-multisig.md,
// docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md.
//
// Always run: the message kinds (encode / decode / every refusal), the
// Foundation preset bytes against its documented address (SHA3-512 here,
// node:crypto — an independent hash of the same bytes the C hashes), the
// kept-record checks, the request states and expiry arithmetic, the
// store's vault index, and that the shipped send.wasm exports the vault
// entry points and none of the test-only ones.
//
// Parity (needs NODUS_SEND_PARITY_OUT from `scripts/build-nodus-send-wasm.sh
// parity`; else SKIPPED — a skip is not a pass):
//   - the module's address for the Foundation code == the documented one ==
//     SHA3-512 here; its member IDs == SHA3-512 of each key slice here;
//     the code rebuilt from the three keys in another order is byte-equal;
//   - a request built offline (TEST wasm, fixed randomness) travels as its
//     parts and is rebuilt from the receiver's own code; the read-back shows
//     the recipient, the amount, the change to the vault, the fee and the
//     last valid block; an amount byte, the fee, the digest, the chain id or
//     a past-expiry tip is refused; a request read at a tip past its last
//     block is 'expired'.
// Inputs are SYNTHETIC (made-up coins and chain id): they prove the page
// and the C agree, not that a node accepts the payment (nodus ctest
// test_v2_msig M6 runs the chain's auth hook on a combined one).
// Written, NOT run by its author (the BUILDER rule).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { FOUNDATION_VAULT } from '../src/vaults/foundation.js';
import {
  encodeShare, encodeRequest, encodeApproval, decodeVaultMessage, vaultCodeShape, vaultLabel, makeVaultRecord,
  checkVaultRecord, recordForStorage, applyScan, requestState, blocksLeft, listedFor, collectVaultItems,
  VAULT_LABEL_MAX, VAULT_PAYLOAD_MAX
} from '../src/vaults/core.js';
import { emptyState, checkState } from '../src/connect/store.js';

const sha3 = hex => createHash('sha3-512').update(Buffer.from(hex, 'hex')).digest('hex');
const KEY_HEX = 2 * 2592;
const keysOf = code => { const out = []; for (let i = 36; i < code.length; i += KEY_HEX) out.push(code.slice(i, i + KEY_HEX)); return out; };
const DOCUMENTED_ADDRESS = '9885748173dadcb9b82def1811ff2b4ffbc27f621d1e1d86719649e9955f20c587733a98321b15b07baf36a5ab080ed5657ead25f655a979fae1a84de24a30c6';
const SIG_TEXT = `nodus-msig-sig v1\ndigest ${'ab'.repeat(64)}\npubkey ${'cd'.repeat(2592)}\nsig ${'ef'.repeat(4627)}\n`;
const REQUEST = { chain: '44'.repeat(32), tip: '5000', signers: '2', digest: '12'.repeat(64), env: '4e44532e'.repeat(40) };

// ── the Foundation preset ───────────────────────────────────────────────

test('the Foundation preset: NDS.MSIG.v1, 2 of 3, its bytes hash to the documented address', () => {
  assert.equal(FOUNDATION_VAULT.address, DOCUMENTED_ADDRESS, 'the decision record\'s address (2026-09-30 note)');
  assert.deepEqual(vaultCodeShape(FOUNDATION_VAULT.descriptor), { m: 2, n: 3 });
  assert.equal(FOUNDATION_VAULT.descriptor.length, 2 * 7794);
  assert.equal(sha3(FOUNDATION_VAULT.descriptor), DOCUMENTED_ADDRESS);
  const keys = keysOf(FOUNDATION_VAULT.descriptor);
  assert.equal(keys.length, 3);
  assert.ok(keys[0] < keys[1] && keys[1] < keys[2], 'keys strictly ascending (the one canonical order)');
  assert.equal(new Set(keys.map(sha3)).size, 3);
});

// ── the message kinds ───────────────────────────────────────────────────

test('vault message kinds round-trip, and nothing else is read as one', () => {
  const share = decodeVaultMessage(encodeShare({ code: FOUNDATION_VAULT.descriptor, label: 'Savings', created: '12' }));
  assert.deepEqual(share, { kind: 'share', code: FOUNDATION_VAULT.descriptor, label: 'Savings', created: '12' });
  const request = decodeVaultMessage(encodeRequest({ vault: DOCUMENTED_ADDRESS, request: REQUEST }));
  assert.deepEqual(request, { kind: 'request', vault: DOCUMENTED_ADDRESS, request: REQUEST });
  const approval = decodeVaultMessage(encodeApproval({ vault: DOCUMENTED_ADDRESS, digest: REQUEST.digest, signature: SIG_TEXT }));
  assert.deepEqual(approval, { kind: 'approval', vault: DOCUMENTED_ADDRESS, digest: REQUEST.digest, signature: SIG_TEXT });
  // plain chat text and other JSON are not vault items
  for (const text of ['hello', '{"type":"token_transfer"}', '{not json', '', '[1,2]']) assert.equal(decodeVaultMessage(text), null, text);
});

test('a vault item with any field out of shape is invalid, never partly read', () => {
  const base = JSON.parse(encodeRequest({ vault: DOCUMENTED_ADDRESS, request: REQUEST }));
  const bad = [
    { ...base, v: 2 }, { ...base, kind: 'other' }, { ...base, extra: 1 }, { ...base, vault: 'AB'.repeat(64) },
    { ...base, chain: '44'.repeat(31) }, { ...base, tip: '0' }, { ...base, tip: '012' }, { ...base, signers: '16' },
    { ...base, digest: '12'.repeat(63) }, { ...base, env: 'abc' }, { ...base, env: 'GG'.repeat(10) }
  ];
  for (const value of bad) assert.deepEqual(decodeVaultMessage(JSON.stringify(value)), { kind: 'invalid' }, JSON.stringify(value).slice(0, 80));
  const { env, ...missing } = base;
  assert.deepEqual(decodeVaultMessage(JSON.stringify(missing)), { kind: 'invalid' }, `missing env (${env.length})`);
  const share = JSON.parse(encodeShare({ code: FOUNDATION_VAULT.descriptor, label: '', created: '1' }));
  for (const value of [
    { ...share, code: FOUNDATION_VAULT.descriptor.slice(0, -2) },
    { ...share, code: '00' + FOUNDATION_VAULT.descriptor.slice(2) },
    { ...share, label: 'x'.repeat(VAULT_LABEL_MAX + 1) },
    { ...share, label: 'two\nlines' },
    { ...share, created: '0' }
  ]) assert.deepEqual(decodeVaultMessage(JSON.stringify(value)), { kind: 'invalid' });
  const approval = JSON.parse(encodeApproval({ vault: DOCUMENTED_ADDRESS, digest: REQUEST.digest, signature: SIG_TEXT }));
  assert.deepEqual(decodeVaultMessage(JSON.stringify({ ...approval, signature: 'nodus-msig-export v1\n' })), { kind: 'invalid' });
  assert.equal(decodeVaultMessage(' '.repeat(VAULT_PAYLOAD_MAX + 1)), null);
  assert.throws(() => vaultLabel(' '));
  assert.throws(() => encodeShare({ code: 'ab', label: '', created: '1' }));
});

// ── the kept record, its history, a request's state ─────────────────────

const INFO = { descriptor: FOUNDATION_VAULT.descriptor, address: DOCUMENTED_ADDRESS, m: 2, n: 3, members: keysOf(FOUNDATION_VAULT.descriptor).map(sha3) };

test('a kept vault record: made from the module answer, checked when read back, trimmed to one stored record', () => {
  const record = makeVaultRecord({ info: INFO, label: 'Foundation vault', created: '1', foundation: true });
  assert.deepEqual(checkVaultRecord(JSON.parse(JSON.stringify(record))), record);
  for (const broken of [{ ...record, m: 3 }, { ...record, members: record.members.slice(1) }, { ...record, cursor: '0' }, { ...record, coins: [{ id: 'x' }] }]) {
    assert.throws(() => checkVaultRecord(broken));
  }
  const big = { ...record, events: Array.from({ length: 32 }, (_, i) => ({ height: String(i + 1), received: true, amount: '1', id: 'ab'.repeat(64) })) };
  assert.ok(new TextEncoder().encode(JSON.stringify(recordForStorage(big))).length <= 60000);
});

test('block reading: coins replaced, cursor moved, history merged without repeats', () => {
  const record = makeVaultRecord({ info: INFO, created: '10' });
  const event = { height: '11', received: true, amount: '500', id: 'ab'.repeat(64) };
  const a = applyScan(record, { next: '210', tip: '400', coins: [{ id: '11'.repeat(64), amount: '500', unlock: '0', height: '11' }], events: [event] });
  assert.equal(a.cursor, '210');
  assert.equal(a.coins.length, 1);
  const b = applyScan(a, { next: '401', tip: '400', coins: [], events: [event] });
  assert.equal(b.events.length, 1, 'the same item is not added twice');
  assert.equal(b.coins.length, 0);
  assert.throws(() => applyScan(b, { next: '5', tip: '400', coins: [], events: [] }), /could not be read/);
});

test('a request\'s state and expiry', () => {
  const record = makeVaultRecord({ info: INFO, created: '1' });
  const review = { approvals: 2, expired: false, expiryHeight: '5090', tip: '5000', intentId: 'cd'.repeat(64) };
  assert.equal(requestState({ review, accepted: 1, record }), 'waiting');
  assert.equal(requestState({ review, accepted: 2, record }), 'ready');
  assert.equal(requestState({ review: { ...review, expired: true }, accepted: 2, record }), 'expired');
  assert.equal(requestState({ review, accepted: 0, record: { ...record, events: [{ height: '5001', received: false, amount: '1', id: review.intentId }] } }), 'paid');
  assert.equal(blocksLeft(review), 90n);
  assert.equal(blocksLeft({ ...review, tip: '6000' }), 0n);
});

test('a vault is listed only for its members unless watched by hand', () => {
  const record = makeVaultRecord({ info: INFO, created: '1' });
  assert.equal(listedFor(record, INFO.members[1]), true);
  assert.equal(listedFor(record, 'ee'.repeat(64)), false);
  assert.equal(listedFor({ ...record, watch: true }, 'ee'.repeat(64)), true);
});

test('requests and approvals are collected per vault from the stored messages', () => {
  const messages = [
    { fp: 'aa'.repeat(64), dir: 'in', at: 1, text: encodeRequest({ vault: DOCUMENTED_ADDRESS, request: REQUEST }) },
    { fp: 'aa'.repeat(64), dir: 'in', at: 2, text: encodeApproval({ vault: DOCUMENTED_ADDRESS, digest: REQUEST.digest, signature: SIG_TEXT }) },
    { fp: 'bb'.repeat(64), dir: 'in', at: 3, text: encodeApproval({ vault: DOCUMENTED_ADDRESS, digest: REQUEST.digest, signature: SIG_TEXT }) },
    { fp: 'bb'.repeat(64), dir: 'in', at: 4, text: encodeRequest({ vault: 'cc'.repeat(64), request: REQUEST }) },
    { fp: 'bb'.repeat(64), dir: 'in', at: 5, text: 'hello' }
  ];
  const items = collectVaultItems(messages, DOCUMENTED_ADDRESS);
  assert.equal(items.requests.size, 1);
  assert.equal(items.requests.get(REQUEST.digest).from, 'aa'.repeat(64));
  assert.deepEqual(items.approvals.get(REQUEST.digest), [SIG_TEXT], 'the same approval text counts once');
});

test('the Messages state keeps a vault index (store.js state.vaults)', () => {
  assert.deepEqual(checkState(emptyState()).vaults, {});
  const old = emptyState(); delete old.vaults;
  assert.deepEqual(checkState(old).vaults, {}, 'a state saved before vaults gets the default');
  assert.doesNotThrow(() => checkState({ ...emptyState(), vaults: { [DOCUMENTED_ADDRESS]: { id: 'v00000000000000000001', at: '5' } } }));
  assert.throws(() => checkState({ ...emptyState(), vaults: { [DOCUMENTED_ADDRESS]: { id: 'p00000000000000000001', at: '5' } } }));
  assert.throws(() => checkState({ ...emptyState(), vaults: { nothex: { id: 'v00000000000000000001', at: '5' } } }));
});

// ── the shipped module ──────────────────────────────────────────────────

const VAULT_ENTRY_POINTS = [
  'nsw_msig_member_reset', 'nsw_msig_member_count', 'nsw_msig_member_add_self', 'nsw_msig_member_add', 'nsw_msig_create',
  'nsw_msig_load', 'nsw_msig_addr', 'nsw_msig_desc_hex', 'nsw_msig_m', 'nsw_msig_n', 'nsw_msig_member', 'nsw_msig_is_member',
  'nsw_msig_balance', 'nsw_msig_bal_total', 'nsw_msig_bal_spendable', 'nsw_msig_coins_reset', 'nsw_msig_coin_add',
  'nsw_msig_scan', 'nsw_msig_scan_next', 'nsw_msig_scan_tip', 'nsw_msig_coins_full', 'nsw_msig_coin_count',
  'nsw_msig_coin_id', 'nsw_msig_coin_amount', 'nsw_msig_coin_unlock', 'nsw_msig_coin_height', 'nsw_msig_event_count',
  'nsw_msig_event_height', 'nsw_msig_event_dir', 'nsw_msig_event_amount', 'nsw_msig_event_id', 'nsw_msig_prop_in',
  'nsw_msig_prop_chain', 'nsw_msig_prop_tip', 'nsw_msig_prop_signers', 'nsw_msig_prop_digest', 'nsw_msig_prop_env',
  'nsw_msig_text', 'nsw_msig_build', 'nsw_msig_review', 'nsw_msig_rv_ok', 'nsw_msig_rv_expired', 'nsw_msig_rv_member',
  'nsw_msig_rv_vault', 'nsw_msig_rv_m', 'nsw_msig_rv_n', 'nsw_msig_rv_k', 'nsw_msig_rv_fee', 'nsw_msig_rv_expiry',
  'nsw_msig_rv_now', 'nsw_msig_rv_intent', 'nsw_msig_rv_n_in', 'nsw_msig_rv_in', 'nsw_msig_rv_n_out',
  'nsw_msig_rv_out_owner', 'nsw_msig_rv_out_amount', 'nsw_msig_rv_out_change', 'nsw_msig_sign', 'nsw_msig_sig_reset',
  'nsw_msig_sig_add', 'nsw_msig_sig_count', 'nsw_msig_sig_signer', 'nsw_msig_submit', 'nsw_msig_intent', 'nsw_msig_wire'
];

test('the shipped send.wasm exports the vault entry points and none of the vault test ones', () => {
  const module = new WebAssembly.Module(readFileSync(new URL('../src/nodus/send.wasm', import.meta.url)));
  const exports = new Set(WebAssembly.Module.exports(module).map(({ name }) => name));
  for (const name of VAULT_ENTRY_POINTS) assert.ok(exports.has(name), `missing export ${name}`);
  for (const name of ['nsw_test_msig_member_add_pk', 'nsw_test_msig_build', 'nsw_test_msig_review']) assert.ok(!exports.has(name), `${name} shipped`);
});

// ── parity with the C (TEST wasm) ───────────────────────────────────────

const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT;
const skipParity = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (build-nodus-send-wasm.sh parity)' : false;

async function loadTest() {
  const path = join(PARITY_OUT, 'send-test-node.mjs');
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  const M = await create();
  const num = (name, types = [], args = []) => M.ccall(name, 'number', types, args);
  const str = (name, types = [], args = []) => M.ccall(name, 'string', types, args);
  return { M, num, str };
}

test('parity: the module derives the Foundation address and members as the C codec defines them', { skip: skipParity }, async () => {
  const { num, str } = await loadTest();
  assert.equal(num('nsw_msig_load', ['string'], [FOUNDATION_VAULT.descriptor]), 0, str('nsw_error'));
  assert.equal(str('nsw_msig_addr'), DOCUMENTED_ADDRESS);
  assert.equal(num('nsw_msig_m'), 2);
  assert.equal(num('nsw_msig_n'), 3);
  const keys = keysOf(FOUNDATION_VAULT.descriptor);
  for (let i = 0; i < 3; i++) assert.equal(str('nsw_msig_member', ['number'], [i]), sha3(keys[i]));
  // the code rebuilt from the keys in another order (nodus_v2_msig_desc_from_keys)
  num('nsw_msig_member_reset');
  for (const k of [keys[2], keys[0], keys[1]]) assert.equal(num('nsw_test_msig_member_add_pk', ['string'], [k]), 0, str('nsw_error'));
  assert.equal(num('nsw_msig_create', ['number'], [2]), 0, str('nsw_error'));
  assert.equal(str('nsw_msig_desc_hex'), FOUNDATION_VAULT.descriptor);
  assert.equal(str('nsw_msig_addr'), DOCUMENTED_ADDRESS);
  // refusals: another tag, a duplicate member, 1 member
  assert.notEqual(num('nsw_msig_load', ['string'], ['00' + FOUNDATION_VAULT.descriptor.slice(2)]), 0, 'a code with another tag is refused');
  num('nsw_msig_member_reset');
  assert.equal(num('nsw_test_msig_member_add_pk', ['string'], [keys[0]]), 0);
  assert.notEqual(num('nsw_test_msig_member_add_pk', ['string'], [keys[0]]), 0, 'a duplicate member is refused');
  assert.notEqual(num('nsw_msig_create', ['number'], [1]), 0, 'one member is not a vault');
});

const CHAIN = '44'.repeat(32), TO = '5a'.repeat(64);
const COINS = [['33'.repeat(64), '300000000'], ['11'.repeat(64), '200000000']];
async function builtRequest() {
  const mod = await loadTest(), { M, num, str } = mod;
  assert.equal(num('nsw_net_set_chain', ['string'], [CHAIN]), 0);
  assert.equal(num('nsw_msig_load', ['string'], [FOUNDATION_VAULT.descriptor]), 0, str('nsw_error'));
  num('nsw_msig_coins_reset');
  for (const [id, amount] of COINS) assert.equal(num('nsw_msig_coin_add', ['string', 'string', 'string', 'string'], [id, amount, '0', '7']), 0, str('nsw_error'));
  const seeds = Uint8Array.from({ length: 256 }, (_, i) => i);
  M.HEAPU8.set(seeds, num('nsw_test_random_buf'));
  assert.equal(num('nsw_test_random_load', ['number'], [seeds.length]), 0);
  assert.equal(num('nsw_test_msig_build', ['string', 'string', 'string', 'number', 'string', 'string', 'string'],
    [CHAIN, '5000', '0', 1, TO, '100000000', '5090']), 0, str('nsw_error'));
  const parts = { chain: str('nsw_msig_prop_chain'), tip: str('nsw_msig_prop_tip'), signers: str('nsw_msig_prop_signers'), digest: str('nsw_msig_prop_digest'), env: str('nsw_msig_prop_env') };
  return { mod, parts, exportText: str('nsw_msig_text') };
}
function readBack({ num, str }) {
  const outs = [];
  for (let i = 0; i < num('nsw_msig_rv_n_out'); i++) outs.push({ owner: str('nsw_msig_rv_out_owner', ['number'], [i]), amount: str('nsw_msig_rv_out_amount', ['number'], [i]), change: num('nsw_msig_rv_out_change', ['number'], [i]) });
  const ins = [];
  for (let i = 0; i < num('nsw_msig_rv_n_in'); i++) ins.push(str('nsw_msig_rv_in', ['number'], [i]));
  return { fee: str('nsw_msig_rv_fee'), expiry: str('nsw_msig_rv_expiry'), expired: num('nsw_msig_rv_expired'), k: num('nsw_msig_rv_k'), vault: str('nsw_msig_rv_vault'), outs, ins };
}
const propIn = ({ num }, p) => num('nsw_msig_prop_in', ['string', 'string', 'string', 'string', 'string'], [p.chain, p.tip, p.signers, p.digest, p.env]);

test('parity: a request travels as its parts, is rebuilt from the receiver\'s own vault code, and reads back field by field', { skip: skipParity }, async () => {
  const { parts, exportText } = await builtRequest();
  assert.ok(exportText.startsWith(`nodus-msig-export v1\nchain_id ${CHAIN}\ntip 5000\nsigners 2\ndigest ${parts.digest}\nenvelope `), 'nodus-cli\'s export text');
  // a second module, as the receiving member: only the parts and its own code
  const recv = await loadTest();
  assert.equal(recv.num('nsw_net_set_chain', ['string'], [CHAIN]), 0);
  assert.equal(recv.num('nsw_msig_load', ['string'], [FOUNDATION_VAULT.descriptor]), 0);
  assert.equal(propIn(recv, parts), 0, recv.str('nsw_error'));
  assert.equal(recv.str('nsw_msig_text'), exportText, 'the rebuilt export is byte-identical');
  assert.equal(recv.num('nsw_test_msig_review', ['string'], ['5000']), 0, recv.str('nsw_error'));
  const rv = readBack(recv);
  assert.equal(rv.vault, DOCUMENTED_ADDRESS);
  assert.equal(rv.k, 2);
  assert.equal(rv.expiry, '5090');
  assert.equal(rv.expired, 0);
  assert.equal(rv.fee, '1000000', 'the floor at gas price 0');
  assert.deepEqual(rv.ins, ['11'.repeat(64), '33'.repeat(64)], 'inputs ascending');
  assert.deepEqual(rv.outs, [
    { owner: TO, amount: '100000000', change: 0 },
    { owner: DOCUMENTED_ADDRESS, amount: String(500000000 - 100000000 - 1000000), change: 1 }
  ]);
  // read at a tip past its last valid block: expired
  assert.equal(recv.num('nsw_test_msig_review', ['string'], ['5090']), 0);
  assert.equal(recv.num('nsw_msig_rv_expired'), 1);
});

test('parity: the read-back refuses a request with any changed field', { skip: skipParity }, async () => {
  const { parts } = await builtRequest();
  const recv = await loadTest();
  assert.equal(recv.num('nsw_net_set_chain', ['string'], [CHAIN]), 0);
  assert.equal(recv.num('nsw_msig_load', ['string'], [FOUNDATION_VAULT.descriptor]), 0);
  const flip = (hex, byte) => hex.slice(0, 2 * byte) + (hex[2 * byte] === '0' ? '1' : '0') + hex.slice(2 * byte + 1);
  // env layout (shared/dnac/env_wire.h): expiry u64 at 17..24, fee u64 at 25..32;
  // the first output's amount low byte: call starts at 43 + 30 (one leg),
  // then 1 + 2×64 inputs, 1 count, 128 owner, 8 amount
  const cases = {
    'expiry': { ...parts, env: flip(parts.env, 24) },
    'fee': { ...parts, env: flip(parts.env, 32) },
    'amount': { ...parts, env: flip(parts.env, 73 + 1 + 128 + 1 + 128 + 7) },
    'digest': { ...parts, digest: flip(parts.digest, 0) }
  };
  for (const [what, p] of Object.entries(cases)) {
    assert.equal(propIn(recv, p), 0, `${what}: the parts still rebuild`);
    assert.notEqual(recv.num('nsw_test_msig_review', ['string'], ['5000']), 0, `${what}: the read-back refuses`);
    assert.equal(recv.num('nsw_msig_rv_ok'), 0, `${what}: nothing reviewed`);
  }
  assert.notEqual(propIn(recv, { ...parts, chain: '55'.repeat(32) }), 0, 'another network is refused at once');
  assert.equal(propIn(recv, { ...parts, tip: '5090' }), 0);
  assert.notEqual(recv.num('nsw_test_msig_review', ['string'], ['5090']), 0, 'a tip at which it has expired is refused by the preflight');
  assert.notEqual(propIn(recv, { ...parts, signers: '4' }), 0, 'more approvals than members is refused');
});
