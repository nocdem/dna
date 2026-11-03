// What this proves (operator's approved test and the blue team Finding 1 regression,
// docs/plans/approved/2026-11-03-pq-send-parity.md section 0 and section 5): the REAL
// web confirm callback, proof commit and failure handling sliced out of src/app.js,
// with the REAL persistActivity writer and its encrypted store, for CKB:
//  (a) a "Review same-transaction recovery" that ends with a network error leaves the
//      row non-terminal after a reload, keeps signedPayload and the new submissionId,
//      and a new CKB send stays refused by the unresolved block;
//  (b) the same error carrying ckbNotExposed:true during a recovery does NOT mark the
//      row failed / notSubmitted (the hold stays);
//  (c) the same flag on an INITIAL send after its durable write marks the row failed /
//      notSubmitted and runs the proof commit; a network error at the first simulation
//      (after disclosure) stays unknown;
//  (d) the recovery wallet guard throws "Wallet or network changed." before any request
//      once the wallet is locked or a different account / network is active;
//  (e) the recovery's durable write has a transaction identifier (hash = txid).
// Mocks: scripted CKB JSON-RPC fetcher, in-memory localStorage and Web Lock stand-ins
// (labelled fixtures; no live request). Signing is real (ckb-slh-sign.wasm).
// What it leaves behind: nothing. How it could falsely pass: the slices are cut from
// src/app.js by fixed markers (the assertions below fail loudly if a marker moves);
// the web `else` branch (src/app.js "record.status = 'unknown'") is deliberately NOT
// changed (operator: "oldugu gibi kalsin"), so the stored row stays 'pending' after a
// failed recovery while memory says 'unknown'; both are asserted non-terminal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { bech32m } from '@scure/base';
import { prepareCkbTransfer, ckbRecoveryTransfer } from '../src/pq/ckb-transfer.js';
import { prepareCkbExactRecovery } from '../src/pq/ckb-recovery.js';
import { ckbNetwork } from '../src/pq/ckb.js';
import { recordActivity, terminal } from '../src/activity.js';
import { activityKeyFor, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { createSubmissionProof, commitSubmissionProof, recoverSubmissionProofs, clearSubmissionProofs } from '../src/pq/submission-proof.js';

const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
const cut = (from, to, at = 0) => { const a = app.indexOf(from, at); assert.ok(a >= 0, `marker moved: ${from}`); const b = app.indexOf(to, a); assert.ok(b > a, `end marker moved: ${to}`); return { a, b, text: app.slice(a, b) }; };
const callbackAt = app.indexOf('const hash = await transfer.confirm(async details => {') + 'const hash = await transfer.confirm(async details => '.length;
assert.ok(callbackAt > 'const hash = await transfer.confirm(async details => '.length);
const callback = app.slice(callbackAt, app.indexOf('\n    });', callbackAt) + 6);
const proofSlice = cut('    if (submissionProof && ((transfer.chain', '    // The node answered "busy"').text;
const failureSlice = cut("    if (record) {\n      if ((transfer.chain === 'algorand'", '    closeReview();\n    if (transfer.kind === \'claim\') void refreshClaim();').text;
const persistSlice = cut('function persistActivity(', '// The last balances, saved encrypted', app.indexOf('function persistActivity(')).text;

const fx = JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json', import.meta.url))).vectors[0];
const address = fx.addresses.ckb.mainnet, net = ckbNetwork('mainnet');
const wasmBytes = readFileSync(new URL('../src/pq/ckb-slh-sign.wasm', import.meta.url));
const H = '0x' + 'ab'.repeat(32), T = '0x' + 'cd'.repeat(32), P = '0x' + 'ef'.repeat(32);
const payload = bech32m.fromWords(bech32m.decode(address, 1023).words);

function node({ simulate = 'ok' } = {}) {
  const lock = { code_hash: net.codeHash, hash_type: net.hashType, args: '0x' + Buffer.from(payload.slice(34)).toString('hex') };
  const out = { capacity: '0x' + (30000000000n).toString(16), lock, type: null };
  const state = { fee: 1000n, simulate, requests: [] };
  const header = { hash: H, number: '0x64', timestamp: '0x' + Date.now().toString(16) };
  const fetcher = async (url, options) => {
    const q = JSON.parse(options.body); state.requests.push(q.method);
    let result;
    switch (q.method) {
      case 'get_block_hash': result = q.params[0] === '0x0' ? net.genesisHash : H; break;
      case 'get_tip_header': result = header; break;
      case 'get_indexer_tip': result = { block_number: '0x64', block_hash: H }; break;
      case 'get_cells': result = { objects: [{ out_point: { tx_hash: T, index: '0x0' }, block_number: '0x63', tx_index: '0x1', output: out, output_data: '0x' }], last_cursor: '0x00' }; break;
      case 'get_transaction': result = q.params[0] === T
        ? { transaction: { hash: T, inputs: [{ previous_output: { tx_hash: P, index: '0x0' }, since: '0x0' }], outputs: [out], outputs_data: ['0x'] }, tx_status: { status: 'committed', block_hash: H, block_number: '0x63', tx_index: '0x1' } }
        : { transaction: null, tx_status: { status: 'unknown' } };
        break;
      case 'get_live_cell': result = { status: 'live', cell: { output: out, data: { content: '0x' } } }; break;
      case 'tx_pool_info': result = { tip_hash: H, tip_number: '0x64', min_fee_rate: '0x3e8', tx_size_limit: '0x7d000' }; break;
      case 'get_fee_rate_statistics': result = { mean: '0x103593', median: '0x81c6' }; break;
      case 'test_tx_pool_accept':
        if (state.simulate === 'network') throw Error('network down');
        result = { fee: '0x' + state.fee.toString(16), cycles: '0x193cc63' }; break;
      default: throw Error('Unexpected RPC ' + q.method);
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: q.id, result }));
  };
  return { fetcher, state };
}

// One browser tab: the real persistActivity, confirm callback and failure slices over an
// in-memory encrypted store.
async function tab(seedByte) {
  const id = Buffer.alloc(16, seedByte).toString('base64'), key = await activityKeyFor(fx.phrase, id);
  const values = new Map([['vault', 'vault']]);
  const storage = { getItem: k => values.get(k) ?? null, setItem: (k, v) => values.set(k, v) };
  const proofs = { get: async keys => Object.fromEntries(keys.map(k => [k, values.get(k)])), set: async v => { for (const [k, x] of Object.entries(v)) values.set(k, x); } };
  let mutex = Promise.resolve();
  const withActivityLock = f => { const p = mutex.then(f); mutex = p.catch(() => {}); return p; };
  const wallet = { addresses: { ckb: address }, recoveryPhrase: fx.phrase };
  const counters = { proofCommits: 0 };
  const c = { history: [], historyWrites: Promise.resolve(), activitySession: { id, key, vault: 'vault' }, wallet, localStorage: storage, VAULT_KEY: 'vault', ACTIVITY_KEY: 'activity', activityBlocked: false,
    submissionProofStorage: proofs, withActivityLock, parseActivity, recoverSubmissionProofs, serializeActivity, clearSubmissionProofs, terminal, quarantineLocks: () => [], quarantinedRows: [],
    recordActivity, createSubmissionProof, commitSubmissionProof: async (...a) => { counters.proofCommits++; return commitSubmissionProof(...a); },
    renderActivity() {}, trackActivity() {}, current: 1, revision: 1, transfer: undefined, record: undefined, submissionProof: undefined, error: undefined, Error };
  runInNewContext(persistSlice + ';globalThis.persistActivity=persistActivity;globalThis.callback = async details => ' + callback + ';', c);
  const reload = async () => parseActivity(values.get('activity'), id, { ckb: address }, key);
  const fail = async error => {
    c.error = error;
    await runInNewContext('(async()=>{' + proofSlice + '})()', c);
    await runInNewContext('(async()=>{' + failureSlice + '})()', c);
  };
  return { c, wallet, values, counters, reload, fail, id, key, proofs };
}

// An initial send whose simulation request fails after the signed transaction left.
async function ambiguousFirstSend(t) {
  const n = node({ simulate: 'network' });
  const transfer = await prepareCkbTransfer({ wallet: t.wallet, to: address, amountAtoms: 10000000000n, fetcher: n.fetcher, wasmBytes, rnd: new Uint8Array(32).fill(7) });
  n.state.fee = BigInt(transfer.feeAtoms);
  t.c.transfer = transfer;
  let failure;
  try { await transfer.confirm(details => t.c.callback(details)); } catch (e) { failure = e; }
  assert.ok(failure, 'the first send fails at the simulation');
  assert.match(failure.message, /network down/);
  assert.notEqual(failure.ckbNotExposed, true, 'the simulation request is after disclosure');
  await t.fail(failure);
  return { n, transfer, failure };
}

// The Review same-transaction recovery wrapper the page builds (reviewCkbRecovery).
async function recovery(t, n, { simulate, submit, assertCurrent = () => {} } = {}) {
  const row = t.c.history[0];
  const prepared = await prepareCkbExactRecovery(row, { assertCurrent, fetcher: n.fetcher, wasmBytes, simulate, submit });
  const transfer = ckbRecoveryTransfer(prepared, row);
  t.c.transfer = transfer; t.c.record = undefined; t.c.submissionProof = undefined;
  return { row, prepared, transfer };
}

test('(a) a recovery that ends with a network error stays unresolved after a reload and keeps the hold', async () => {
  const t = await tab(51), { n } = await ambiguousFirstSend(t);
  assert.equal(t.c.history[0].status, 'unknown');
  assert.equal(t.c.history[0].notSubmitted, undefined);
  const first = t.c.history[0], originalHash = first.hash, originalId = first.submissionId;
  const { transfer } = await recovery(t, n, { simulate: async () => { throw Error('network down'); } });
  assert.equal(transfer.isResubmission, true);
  let failure;
  try { await transfer.confirm(details => t.c.callback(details)); } catch (e) { failure = e; }
  assert.equal(failure?.message, 'network down');
  await t.fail(failure);
  const stored = await t.reload();
  assert.equal(stored.length, 1);
  const row = stored[0];
  assert.equal(row.hash, originalHash);
  assert.equal(terminal(row.savedStatus ?? row.status), false, 'the stored row is still unresolved');
  assert.notEqual(row.notSubmitted, true);
  assert.notEqual(row.status, 'failed');
  assert.ok(row.signedPayload?.data, 'signedPayload is kept');
  assert.notEqual(row.submissionId, originalId, 'the recovery attempt has a new identity');
  assert.equal(row.submissionId, t.c.history[0].submissionId);
  assert.equal(t.c.history[0].status, 'unknown');
  assert.doesNotMatch(String(t.c.history[0].note), /Nothing was broadcast/);
  // The page's unresolved block (src/app.js submit handler) lists CKB and finds this row.
  assert.ok(app.includes("['ethereum', 'bsc', 'algorand', 'soqucoin', 'splendor', 'asentum', 'ckb'].includes($('chain').value)"));
  assert.ok(stored.find(r => r.chain === 'ckb' && r.address === address && !terminal(r.savedStatus ?? r.status)), 'a new CKB send is refused: "A previous send on this network has no final result yet"');
});

test('(b) ckbNotExposed during a recovery does not cancel the earlier broadcast', async () => {
  const t = await tab(52), { n } = await ambiguousFirstSend(t);
  const { transfer } = await recovery(t, n, { simulate: async () => { throw Object.assign(Error('replay failed'), { ckbNotExposed: true }); } });
  let failure;
  try { await transfer.confirm(details => t.c.callback(details)); } catch (e) { failure = e; }
  assert.equal(failure?.ckbNotExposed, true);
  const commitsBefore = t.counters.proofCommits;
  await t.fail(failure);
  assert.equal(t.counters.proofCommits, commitsBefore, 'a recovery never commits a cancellation proof');
  const row = (await t.reload())[0];
  assert.notEqual(row.notSubmitted, true);
  assert.notEqual(row.status, 'failed');
  assert.equal(terminal(row.savedStatus ?? row.status), false);
  assert.ok(row.signedPayload?.data);
  assert.equal(t.c.history[0].status, 'unknown');
  assert.equal(t.c.history[0].notSubmitted, undefined);
});

test('(c) the flag on an initial send after its durable write marks it not submitted; a network error at the simulation does not', async () => {
  const t = await tab(53), n = node();
  const transfer = await prepareCkbTransfer({ wallet: t.wallet, to: address, amountAtoms: 10000000000n, fetcher: n.fetcher, wasmBytes, rnd: new Uint8Array(32).fill(7) });
  n.state.fee = BigInt(transfer.feeAtoms);
  t.c.transfer = transfer;
  const realNow = Date.now;
  let failure;
  try {
    // After the durable write the review expires: the real controller throws
    // "CKB review expired before simulation." with ckbNotExposed (no request was sent).
    await transfer.confirm(async details => { const r = await t.c.callback(details); Date.now = () => transfer.expiresAt; return r; });
  } catch (e) { failure = e; } finally { Date.now = realNow; }
  assert.match(failure?.message ?? '', /expired before simulation/);
  assert.equal(failure.ckbNotExposed, true);
  assert.ok(!n.state.requests.includes('test_tx_pool_accept'), 'no simulation request was sent');
  await t.fail(failure);
  assert.equal(t.counters.proofCommits, 1, 'the proof commit ran');
  const row = t.c.history[0];
  assert.equal(row.status, 'failed');
  assert.equal(row.notSubmitted, true);
  assert.equal(row.note, 'Cancelled before network submission. Nothing was broadcast.');
  const stored = (await t.reload())[0];
  // parseActivity returns every authenticated row as status 'pending' and keeps the
  // written status in savedStatus (src/activity-storage.js:383).
  assert.equal(stored.savedStatus, 'failed');
  assert.equal(stored.notSubmitted, true);
  // A network error at the first simulation request is after disclosure: unknown.
  const u = await tab(54), { failure: afterDisclosure } = await ambiguousFirstSend(u);
  assert.notEqual(afterDisclosure.ckbNotExposed, true);
  assert.equal(u.c.history[0].status, 'unknown');
  assert.equal(u.c.history[0].notSubmitted, undefined);
  assert.equal(u.counters.proofCommits, 0);
});

test('(d) the recovery wallet guard throws before any request once the wallet or account changes', async () => {
  const guardLine = cut('  const guard=()=>{', '\n', app.indexOf('async function reviewCkbRecovery')).text;
  const makeGuard = overrides => {
    const source = { locked: false, addresses: { ckb: address } };
    const ctx = { current: 1, revision: 1, source, wallet: source, row: { address }, pqSelections: { ckb: 'mainnet' }, $: () => ({ value: 'ckb' }), Error, ...overrides };
    runInNewContext(guardLine + ';globalThis.guard=guard;', ctx);
    return ctx;
  };
  const ok = makeGuard({}); ok.guard();
  for (const [name, change] of [['locked', c => { c.source.locked = true; }], ['other revision', c => { c.revision = 2; }], ['other wallet', c => { c.wallet = {}; }],
    ['other chain', c => { c.$ = () => ({ value: 'qtc' }); }], ['other network', c => { c.pqSelections.ckb = 'testnet'; }], ['other account', c => { c.source.addresses.ckb = 'ckb1other'; }]]) {
    const c = makeGuard({}); change(c);
    assert.throws(() => c.guard(), /Wallet or network changed\./, name);
  }
  // Through the real recovery module: the guard runs at confirm, before any simulation request.
  const t = await tab(55), { n } = await ambiguousFirstSend(t);
  const live = makeGuard({});
  let simulations = 0, attempts = 0;
  const { transfer } = await recovery(t, n, { assertCurrent: live.guard, simulate: async () => { simulations++; return { txid: t.c.history[0].hash, cycles: 1n }; } });
  live.source.locked = true;
  const requests = n.state.requests.length;
  await assert.rejects(transfer.confirm(async () => { attempts++; return { submissionId: 'ab'.repeat(16) }; }), /Wallet or network changed\./);
  assert.equal(simulations, 0);
  assert.equal(attempts, 0);
  assert.equal(n.state.requests.length, requests, 'no request after the guard failed');
});

test('(e) the recovery durable write carries the transaction identifier and replaces the row', async () => {
  const t = await tab(56), { n } = await ambiguousFirstSend(t);
  const original = t.c.history[0];
  const { prepared, transfer } = await recovery(t, n, { simulate: async ({ txid }) => ({ txid, cycles: 26462819n }), submit: async ({ txid }) => txid });
  assert.equal(transfer.hash, original.hash);
  const hash = await transfer.confirm(details => t.c.callback(details));
  assert.equal(hash, original.hash);
  assert.equal(t.c.history.length, 1, 'the earlier row is replaced, not duplicated');
  const row = t.c.history[0];
  assert.equal(row.hash, prepared.hash);
  assert.equal(row.hash, original.hash);
  assert.notEqual(row.submissionId, original.submissionId);
  assert.match(row.hash, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(transfer.review.map(r => r[0]), ['Action', 'Transaction ID', 'From', 'To', 'Amount', 'Fee', 'Recovery']);
  assert.equal(transfer.review[0][1], 'Resubmit EXACTLY the previously signed transaction; no new signature');
  const stored = await t.reload();
  assert.equal(stored[0].submissionId, row.submissionId);
});
