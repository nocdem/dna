// What this proves (operator 2026-11-14, decisions/2026-09-23-ixios-send-mainnet-first.md "Değişiklik 3"; design
// docs/plans/approved/2026-11-03-pq-send-parity.md section 8.1 and decision D5): the REAL web confirm callback, proof commit and
// failure handling sliced out of src/app.js, with the REAL persistActivity writer and its encrypted store, around the REAL
// Ixios adapter (src/pq/ixios-transfer.js) and recovery module, for Ixios:
//  (a) an exposed, uncertain post leaves the row unresolved with its signed bytes after a reload, commits no cancellation proof,
//      and a new send is refused by the adapter's unresolved check;
//  (b) an error flagged ixiosNotExposed on an INITIAL send after its durable write (here: the fresh check after signing fails)
//      marks the row failed / notSubmitted and commits the proof; the same flag during a recovery does NOT cancel the earlier
//      broadcast (D5: "failed / notSubmitted only when !transfer.isResubmission"; a failed replay stays unresolved, hold kept);
//  (c) a successful recovery re-sends the same bytes, replaces the row (same hash, fresh attempt identity), and its durable write
//      carries the transaction hash;
//  (d) the recovery wallet guard (cut from src/app.js) throws "Wallet or network changed." before any request once the wallet is
//      locked, the page moved on, another wallet object, chain, Ixios network or account is active;
//  (e) the durable writer scopes the "another submission is unresolved" refusal to ONE network: an unresolved mainnet row does not
//      block a test-network send, an unresolved row on the same network does (the extension keeps one bucket per network);
//  (f) the page wiring is present: the gas-price cap, the wallet guard and the unresolved callback are passed to prepare, the
//      Ixios row offers the recovery button and no abandon button, the Ixios gate reads the Ixios selection.
// Mocks (labelled fixtures; no live request): the scripted Ixios node, in-memory localStorage and Web Lock stand-ins. Signing,
// verification, the writer, the proof and the recovery modules are real.
// What it leaves behind: nothing. How it could falsely pass: the slices are cut from src/app.js by fixed markers (the assertions
// below fail loudly if a marker moves) and run in a vm context holding stand-ins for the page's variables, so a page variable
// that the slice uses but the stand-in lacks fails with a ReferenceError instead of passing; the web `else` branch (src/app.js
// "record.status = 'unknown'") is deliberately NOT changed (operator: "oldugu gibi kalsin"), so the stored row stays 'pending'
// after a failed recovery while memory says 'unknown'; both are asserted non-terminal; (f) is a text search of src/app.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { keccak256 } from 'ethers';
import { prepareIxiosTransfer, ixiosRecoveryTransfer } from '../src/pq/ixios-transfer.js';
import { prepareIxiosExactRecovery } from '../src/pq/ixios/recovery.js';
import { deriveIxiosAddress } from '../src/pq/ixios/derive.js';
import { ixiosChecksumAddress } from '../src/pq/ixios/address.js';
import { IXIOS_GENESIS_HASH } from '../src/pq/ixios/balance.js';
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

const phrase = JSON.parse(readFileSync(new URL('./fixtures/ixios-vectors.json', import.meta.url))).vectors[0].phrase;
const signWasm = readFileSync(new URL('../src/pq/mldsa87-sign.wasm', import.meta.url));
const verifyWasm = readFileSync(new URL('../src/pq/ixios/mldsa87-verify.wasm', import.meta.url));
const address = ixiosChecksumAddress(await deriveIxiosAddress(phrase, { wasmBytes: readFileSync(new URL('../src/nodus/mldsa87.wasm', import.meta.url)) }));
const to = '0x' + '01'.repeat(48);
const rnd = new Uint8Array(32).fill(7);
const MAIN = 'https://ixios-rpc.innova.limited', TEST = 'https://nx-rpc.ixoflow.io';
const CAP = { mainnet: '93000000000000000', testnet: '100000000000000000' };

// The scripted Ixios node (both networks by origin, each with its own method names). `post` may throw after the request left.
function node({ post } = {}) {
  const state = { requests: [], posted: [], postsOn: {} };
  const fetcher = async (target, options) => {
    const origin = new URL(String(target)).origin, test_ = origin === TEST;
    if (!test_ && origin !== MAIN) throw Error('Unexpected Ixios origin ' + origin);
    const q = JSON.parse(options.body), ns = test_ ? 'ixios' : 'eth';
    if (!q.method.startsWith(ns + '_')) throw Error(`Wrong method namespace ${q.method} at ${origin}`);
    const name = q.method.slice(ns.length + 1);
    state.requests.push({ origin, method: q.method });
    let result;
    if (name === 'chainId') result = test_ ? '0x3' : '0x1';
    else if (name === 'getBlockByNumber') result = q.params[0] === '0x1' ? { number: '0x1', parentHash: test_ ? '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe' : IXIOS_GENESIS_HASH } : { number: test_ ? '0x8ca0' : '0x1ee62ac', hash: '0x' + 'ab'.repeat(32), timestamp: '0x' + Date.now().toString(16) };
    else if (name === 'getTransactionCount') result = q.params[1] === 'pending' && state.postsOn[origin] ? '0x8' : '0x7';
    else if (name === 'getBalance') result = '0x' + (100000n * 10n ** 18n).toString(16);
    else if (name === 'gasPrice') result = '0x' + (test_ ? 10n ** 17n : 93000000000000000n).toString(16);
    else if (name === 'getCode' && !test_) result = '0x';
    else if (name === 'getProof' && test_) result = { address: q.params[0], codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', balance: '0x0', nonce: '0x0', accountProof: [], storageHash: '0x' + '00'.repeat(32), storageProof: [] };
    else if (name === 'estimateGas') result = '0x3e8';
    else if (name === 'getTransactionReceipt') result = null;
    else if (name === 'sendRawTransaction') {
      state.postsOn[origin] = (state.postsOn[origin] ?? 0) + 1; state.posted.push({ origin, raw: q.params[0] });
      result = post ? await post(q.params[0], origin) : keccak256(q.params[0]);
    } else throw Error('Unexpected Ixios RPC ' + q.method);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: q.id, result }));
  };
  return { fetcher, state };
}

// One browser tab: the real persistActivity, confirm callback and failure slices over an in-memory encrypted store.
async function tab(seedByte) {
  const id = Buffer.alloc(16, seedByte).toString('base64'), key = await activityKeyFor(phrase, id);
  const values = new Map([['vault', 'vault']]);
  const storage = { getItem: k => values.get(k) ?? null, setItem: (k, v) => values.set(k, v) };
  const proofs = { get: async keys => Object.fromEntries(keys.map(k => [k, values.get(k)])), set: async v => { for (const [k, x] of Object.entries(v)) values.set(k, x); } };
  let mutex = Promise.resolve();
  const withActivityLock = f => { const p = mutex.then(f); mutex = p.catch(() => {}); return p; };
  const wallet = { addresses: { ixios: address }, recoveryPhrase: phrase };
  const counters = { proofCommits: 0 };
  const c = { history: [], historyWrites: Promise.resolve(), activitySession: { id, key, vault: 'vault' }, wallet, localStorage: storage, VAULT_KEY: 'vault', ACTIVITY_KEY: 'activity', activityBlocked: false,
    submissionProofStorage: proofs, withActivityLock, parseActivity, recoverSubmissionProofs, serializeActivity, clearSubmissionProofs, terminal, quarantineLocks: () => [], quarantinedRows: [],
    recordActivity, createSubmissionProof, commitSubmissionProof: async (...a) => { counters.proofCommits++; return commitSubmissionProof(...a); },
    renderActivity() {}, trackActivity() {}, current: 1, revision: 1, transfer: undefined, record: undefined, submissionProof: undefined, error: undefined, Error };
  runInNewContext(persistSlice + ';globalThis.persistActivity=persistActivity;globalThis.callback = async details => ' + callback + ';', c);
  const reload = async () => parseActivity(values.get('activity'), id, { ixios: address }, key);
  const fail = async error => {
    c.error = error;
    await runInNewContext('(async()=>{' + proofSlice + '})()', c);
    await runInNewContext('(async()=>{' + failureSlice + '})()', c);
  };
  // The page's own unresolved test (src/app.js submit handler): an Ixios row of this address and network without a final result.
  const unresolved = networkId => () => c.history.some(row => row.chain === 'ixios' && row.address === address && row.networkId === networkId && !terminal(row.status));
  return { c, wallet, values, counters, reload, fail, id, key, proofs, unresolved };
}

// An initial send; `adapter` overrides the adapter's services (the scripted failures).
async function firstSend(t, n, { networkId = 'mainnet', adapter = {} } = {}) {
  const transfer = await prepareIxiosTransfer({ wallet: t.wallet, to, amount: '1', maxGasPrice: CAP[networkId], networkId, assertCurrent: () => {}, unresolved: t.unresolved(networkId), fetcher: n.fetcher, wasmBytes: signWasm, rnd, ...adapter });
  t.c.transfer = transfer;
  let failure;
  try { await transfer.confirm(details => t.c.callback(details)); } catch (e) { failure = e; }
  return { transfer, failure };
}
async function ambiguousFirstSend(t, options) {
  const n = node({ post: async () => { throw Error('network down'); } });
  const { transfer, failure } = await firstSend(t, n, options);
  assert.ok(failure, 'the post fails');
  assert.notEqual(failure.ixiosNotExposed, true, 'the request left: the outcome is uncertain');
  await t.fail(failure);
  return { n, transfer, failure };
}
// The "Review same-transaction recovery" wrapper the page builds (reviewIxiosRecovery).
async function recovery(t, n, { submit, assertCurrent = () => {}, row = t.c.history[0] } = {}) {
  const prepared = await prepareIxiosExactRecovery(row, { assertCurrent, fetcher: n.fetcher, wasmBytes: verifyWasm, ...(submit ? { submit } : {}) });
  const transfer = ixiosRecoveryTransfer(prepared, row);
  t.c.transfer = transfer; t.c.record = undefined; t.c.submissionProof = undefined;
  return { row, prepared, transfer };
}

test('(a) an uncertain post stays unresolved after a reload with its signed bytes, commits no proof, and refuses a new send', async () => {
  const t = await tab(61), { n } = await ambiguousFirstSend(t);
  assert.equal(n.state.posted.length, 1, 'one post, never retried');
  const row = t.c.history[0];
  assert.equal(row.chain, 'ixios');
  assert.equal(row.networkId, 'mainnet');
  assert.equal(row.status, 'unknown');
  assert.equal(row.notSubmitted, undefined);
  assert.equal(t.counters.proofCommits, 0, 'no cancellation proof: the request left');
  assert.doesNotMatch(String(row.note), /Nothing was broadcast/);
  const stored = (await t.reload())[0];
  assert.equal(stored.hash, row.hash);
  assert.equal(stored.submissionId, row.submissionId);
  assert.ok(stored.signedPayload?.data, 'the signed bytes are on disk');
  assert.equal(stored.signedPayload.data, n.state.posted[0].raw, 'the bytes written first are the bytes posted');
  assert.equal(terminal(stored.savedStatus ?? stored.status), false, 'unresolved after a reload');
  assert.notEqual(stored.notSubmitted, true);
  // The adapter refuses a new send while the row is unresolved (the page's callback reads the history).
  await assert.rejects(prepareIxiosTransfer({ wallet: t.wallet, to, amount: '1', maxGasPrice: CAP.mainnet, networkId: 'mainnet', assertCurrent: () => {}, unresolved: t.unresolved('mainnet'), fetcher: node().fetcher, wasmBytes: signWasm, rnd }), /previous Ixios transaction is unresolved/);
});

test('(b) not exposed after the durable write marks an initial send failed / notSubmitted with the proof; during a recovery it cancels nothing', async () => {
  // Initial send: the fresh check after signing fails, nothing is posted.
  const t = await tab(62), n = node();
  const { failure } = await firstSend(t, n, { adapter: { recheck: async () => { throw Error('fresh check failed'); } } });
  assert.equal(failure?.ixiosNotExposed, true);
  assert.equal(n.state.posted.length, 0);
  await t.fail(failure);
  assert.equal(t.counters.proofCommits, 1, 'the proof commit ran');
  const row = t.c.history[0];
  assert.equal(row.status, 'failed');
  assert.equal(row.notSubmitted, true);
  assert.equal(row.note, 'Cancelled before network submission. Nothing was broadcast.');
  const stored = (await t.reload())[0];
  assert.equal(stored.savedStatus, 'failed');
  assert.equal(stored.notSubmitted, true);
  // A failed, not-submitted row no longer blocks a new send.
  assert.equal(t.unresolved('mainnet')(), false);
  // Recovery: the same flag on a replay does not cancel the earlier broadcast.
  const u = await tab(63), { n: first } = await ambiguousFirstSend(u);
  const original = u.c.history[0], originalId = original.submissionId;
  const { transfer } = await recovery(u, first, { submit: async () => { throw Object.assign(Error('replay failed'), { ixiosNotExposed: true }); } });
  assert.equal(transfer.isResubmission, true);
  let failed;
  try { await transfer.confirm(details => u.c.callback(details)); } catch (e) { failed = e; }
  assert.equal(failed?.ixiosNotExposed, true);
  const commits = u.counters.proofCommits;
  await u.fail(failed);
  assert.equal(u.counters.proofCommits, commits, 'a recovery never commits a cancellation proof');
  const kept = u.c.history[0];
  assert.equal(kept.status, 'unknown');
  assert.equal(kept.notSubmitted, undefined);
  assert.equal(kept.hash, original.hash);
  assert.notEqual(kept.submissionId, originalId, 'the replay attempt has a fresh identity');
  assert.ok(kept.signedPayload?.data, 'the signed bytes are kept');
  const reloaded = (await u.reload())[0];
  assert.equal(terminal(reloaded.savedStatus ?? reloaded.status), false, 'still unresolved after a reload');
  assert.notEqual(reloaded.status, 'failed');
  assert.equal(reloaded.submissionId, kept.submissionId);
});

test('(c) a recovery re-sends the same bytes, replaces the row with a fresh attempt identity, and writes the transaction hash', async () => {
  const t = await tab(64), { n: first } = await ambiguousFirstSend(t);
  const original = t.c.history[0], originalRaw = first.state.posted[0].raw;
  const replay = node();
  const { prepared, transfer } = await recovery(t, replay);
  assert.deepEqual(transfer.review.map(r => r[0]), ['Action', 'Transaction ID', 'From', 'To', 'Amount', 'Maximum fee', 'Recovery']);
  assert.equal(transfer.review[0][1], 'Resubmit exactly the previously signed transaction; no new signature');
  const hash = await transfer.confirm(details => t.c.callback(details));
  assert.equal(hash, original.hash);
  assert.equal(replay.state.posted.length, 1);
  assert.equal(replay.state.posted[0].raw, originalRaw, 'exactly the bytes signed first');
  assert.equal(t.c.history.length, 1, 'the earlier row is replaced, not duplicated');
  const row = t.c.history[0];
  assert.equal(row.hash, prepared.hash);
  assert.match(row.hash, /^0x[0-9a-f]{64}$/);
  assert.notEqual(row.submissionId, original.submissionId);
  assert.equal((await t.reload())[0].submissionId, row.submissionId);
});

test('(d) the recovery wallet guard throws before any request once the wallet, the page, the Ixios network or the account changes', async () => {
  const guardLine = cut('  const guard=()=>{', '\n', app.indexOf('async function reviewIxiosRecovery')).text;
  const makeGuard = overrides => {
    const source = { locked: false, addresses: { ixios: address } };
    const ctx = { current: 1, revision: 1, source, wallet: source, row: { address, networkId: 'mainnet' }, ixiosSelection: 'mainnet', $: () => ({ value: 'ixios' }), Error, ...overrides };
    runInNewContext(guardLine + ';globalThis.guard=guard;', ctx);
    return ctx;
  };
  makeGuard({}).guard();
  for (const [name, change] of [['locked', c => { c.source.locked = true; }], ['other revision', c => { c.revision = 2; }], ['other wallet', c => { c.wallet = {}; }],
    ['other chain', c => { c.$ = () => ({ value: 'ckb' }); }], ['other Ixios network', c => { c.ixiosSelection = 'testnet'; }], ['other account', c => { c.source.addresses.ixios = '0x' + '02'.repeat(48); }]]) {
    const c = makeGuard({}); change(c);
    assert.throws(() => c.guard(), /Wallet or network changed\./, name);
  }
  // Through the real recovery module: the guard runs before any request.
  const t = await tab(65), { n } = await ambiguousFirstSend(t);
  const live = makeGuard({}), idle = node();
  live.source.locked = true;
  await assert.rejects(prepareIxiosExactRecovery(t.c.history[0], { assertCurrent: live.guard, fetcher: idle.fetcher, wasmBytes: verifyWasm }), /Wallet or network changed\./);
  assert.equal(idle.state.requests.length, 0, 'no request after the guard failed');
  // And at confirm: a guard that turns false after the review was prepared refuses the replay before the durable write and the post.
  const open = makeGuard({});
  const { transfer } = await recovery(t, n, { assertCurrent: open.guard });
  open.source.locked = true;
  const requests = n.state.requests.length, posts = n.state.posted.length; let writes = 0;
  await assert.rejects(transfer.confirm(async () => { writes++; return { submissionId: 'ab'.repeat(16) }; }), /Wallet or network changed\./);
  assert.equal(writes, 0);
  assert.equal(n.state.requests.length, requests);
  assert.equal(n.state.posted.length, posts);
});

test('(e) the durable writer scopes "another submission is unresolved" to one network', async () => {
  const t = await tab(66);
  await ambiguousFirstSend(t); // mainnet row unresolved, saved
  assert.equal(t.c.history.length, 1);
  // A test-network send is not blocked by it (own nonce space, own bucket in the extension).
  const test_ = node();
  const { failure } = await firstSend(t, test_, { networkId: 'testnet' });
  assert.equal(failure, undefined, failure?.message);
  assert.equal(test_.state.posted.length, 1);
  assert.equal(test_.state.posted[0].origin, TEST);
  assert.deepEqual(t.c.history.map(row => row.networkId).sort(), ['mainnet', 'testnet']);
  const stored = await t.reload();
  assert.deepEqual(stored.map(row => row.networkId).sort(), ['mainnet', 'testnet']);
  // A second unresolved row on the SAME network is refused by the writer even if the adapter's own check is bypassed.
  const u = await tab(67);
  await ambiguousFirstSend(u);
  const again = node();
  const { failure: refused } = await firstSend(u, again, { adapter: { unresolved: () => false } });
  assert.match(refused?.message ?? '', /Another ixios submission is unresolved/);
  assert.equal(again.state.posted.length, 0, 'refused before the post');
  assert.equal(refused.ixiosNotExposed, true);
});

test('(f) the page wiring: gas-price cap, wallet guard, unresolved callback, recovery button, no abandon, Ixios gate selection', () => {
  assert.ok(app.includes("...(chain === 'ixios' ? { maxGasPrice: $('ixios-max-gas-price').value, ixiosCurrent, ixiosUnresolved:"));
  assert.ok(app.includes("networkId: isPqChain(chain) ? pqSelections[chain] : chain === 'ixios' ? ixiosSelection : undefined"));
  assert.ok(app.includes("row.chain === 'ixios' ? reviewIxiosRecovery(row)"));
  assert.ok(app.includes("row.chain !== 'ixios' && row.chain !== NODUS_ASSET.chain"));
  assert.ok(app.includes("const gateNetwork = chain => chain === 'ixios' ? ixiosSelection : pqSelections[chain];"));
  assert.ok(app.includes("if ($('chain').value === 'ixios' && !activitySession)"), 'a saved wallet is required so an uncertain send survives a reload');
  assert.ok(app.includes("row.chain === 'ixios' && row.address === wallet.addresses.ixios && ixiosOnSelection(row) && !terminal(row.status)"));
  assert.ok(app.includes("$('ixios-fee-fields').hidden = !ixiosSends"));
  for (const page of ['index.html', 'connect-site/index.html']) assert.match(readFileSync(new URL('../' + page, import.meta.url), 'utf8'), /<div id="ixios-fee-fields" hidden><label for="ixios-max-gas-price">[^<]*<\/label><input id="ixios-max-gas-price" inputmode="numeric" autocomplete="off" pattern="\[0-9\]\+" disabled>/, page);
});
