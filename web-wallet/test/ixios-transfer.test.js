// What this proves (operator 2026-11-14, decisions/2026-09-23-ixios-send-mainnet-first.md "Değişiklik 3": Ixios sends on the web
// wallet and Connect the same as in the extension; design docs/plans/approved/2026-11-03-pq-send-parity.md section 8.1): the page
// adapter src/pq/ixios-transfer.js, over the REAL shared modules (review, preflight, signing with ml-dsa-87 wasm, submit, exact
// recovery), against a scripted Ixios node that answers both networks by origin with their own method names:
//  (1) the maximum gas price must be a positive integer text (the extension's pattern), refused before any request;
//  (2) an unlisted network id and a missing wallet guard are refused before any request;
//  (3) the review rows (send and recovery) equal the extension's: the same stubbed review goes through the extension's own
//      createIxios (extension/src/background/ixios.js) and through the adapter and the row lists are compared, mainnet and testnet;
//  (4) confirm runs seed -> sign -> durable write (the callback) -> seed zeroed -> ONE post: the callback sees zero posts, the
//      posted bytes are the bytes handed to it, the seed is all zero afterwards;
//  (5) a post that failed after the request left is NOT marked "not exposed" (the outcome stays uncertain) and a new review is
//      refused while the page reports the row unresolved; one review at a time per network, the other network is independent;
//  (6) every failure before the post (preflight after signing, expiry, wallet guard, wrong network answer) carries
//      ixiosNotExposed and posts nothing;
//  (7) recovery re-sends the SAME bytes (same hash), needs the wallet guard, needs a fresh attempt identity, refuses before any
//      request when the guard throws, and the recovery transfer is marked isResubmission with the row's previous attempt;
//  (8) a guard that turns false while a review is open (lock, other network, other account) refuses the confirm before the seed
//      is derived, before any durable write and before any request, and frees the reservation.
// Mocks (labelled fixtures, no live request): the Ixios node below, a fixed signing randomness. Signing and verification are real.
// Compile flags / environment: none. Leaves nothing behind (no files, no storage).
// How it could falsely pass: the node answers the values the extension's own fixture uses (gas price, nonce 7), so a change to a
// preflight rule is caught by test/ixios-preflight.test.js, not here; the row-parity test compares the adapter with the extension's
// code as it is today, so a row changed identically in both passes (the literal first row is pinned); "one post" counts requests
// of the scripted node, not a real mempool.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { prepareIxiosTransfer, ixiosRecoveryTransfer, ixiosRecoveryReviewRows, IXIOS_MAX_GAS_PRICE } from '../src/pq/ixios-transfer.js';
import { prepareIxiosExactRecovery } from '../src/pq/ixios/recovery.js';
import { ixiosSigningSeed, deriveIxiosAddress } from '../src/pq/ixios/derive.js';
import { ixiosChecksumAddress } from '../src/pq/ixios/address.js';
import { IXIOS_GENESIS_HASH } from '../src/pq/ixios/balance.js';
import { recordActivity } from '../src/activity.js';
import { createIxios } from '../extension/src/background/ixios.js';

const phrase = JSON.parse(readFileSync(new URL('./fixtures/ixios-vectors.json', import.meta.url))).vectors[0].phrase;
const signWasm = readFileSync(new URL('../src/pq/mldsa87-sign.wasm', import.meta.url));
const verifyWasm = readFileSync(new URL('../src/pq/ixios/mldsa87-verify.wasm', import.meta.url));
const address = ixiosChecksumAddress(await deriveIxiosAddress(phrase, { wasmBytes: readFileSync(new URL('../src/nodus/mldsa87.wasm', import.meta.url)) }));
const to = '0x' + '01'.repeat(48);
const rnd = new Uint8Array(32).fill(7);
const MAIN = 'https://ixios-rpc.innova.limited', TEST = 'https://nx-rpc.ixoflow.io';
const CAP = { mainnet: '93000000000000000', testnet: '100000000000000000' };
const freshWallet = () => ({ addresses: { ixios: address }, recoveryPhrase: phrase });

// The scripted Ixios node: both networks by origin, each with its own method namespace (eth_ on the main node, ixios_ on the
// test node); another origin or a method of the other namespace throws. `post(raw, origin)` answers sendRawTransaction (default:
// the transaction hash) and may throw to script a transport failure after the request left.
function node({ post, wrongGenesis = false } = {}) {
  const state = { requests: [], posted: [], postsOn: {}, wrongGenesis };
  const fetcher = async (target, options) => {
    const origin = new URL(String(target)).origin, test_ = origin === TEST;
    if (!test_ && origin !== MAIN) throw Error('Unexpected Ixios origin ' + origin);
    const q = JSON.parse(options.body), ns = test_ ? 'ixios' : 'eth';
    if (!q.method.startsWith(ns + '_')) throw Error(`Wrong method namespace ${q.method} at ${origin}`);
    const name = q.method.slice(ns.length + 1);
    state.requests.push({ origin, method: q.method });
    let result;
    if (name === 'chainId') result = test_ ? '0x3' : '0x1';
    else if (name === 'getBlockByNumber') result = q.params[0] === '0x1' ? { number: '0x1', parentHash: state.wrongGenesis ? '0x' + '00'.repeat(32) : test_ ? '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe' : IXIOS_GENESIS_HASH } : { number: test_ ? '0x8ca0' : '0x1ee62ac', hash: '0x' + 'ab'.repeat(32), timestamp: '0x' + Date.now().toString(16) };
    else if (name === 'getTransactionCount') result = q.params[1] === 'pending' && state.postsOn[origin] ? '0x8' : '0x7';
    else if (name === 'getBalance') result = '0x' + (100000n * 10n ** 18n).toString(16);
    else if (name === 'gasPrice') result = '0x' + (test_ ? 10n ** 17n : 93000000000000000n).toString(16);
    else if (name === 'getCode' && !test_) result = '0x';
    else if (name === 'getProof' && test_) result = { address: q.params[0], codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', balance: '0x0', nonce: '0x0', accountProof: [], storageHash: '0x' + '00'.repeat(32), storageProof: [] };
    else if (name === 'estimateGas') result = '0x3e8';
    else if (name === 'getTransactionReceipt') result = null;
    else if (name === 'sendRawTransaction') {
      state.postsOn[origin] = (state.postsOn[origin] ?? 0) + 1; state.posted.push({ origin, raw: q.params[0] });
      result = post ? await post(q.params[0], origin) : (await import('ethers')).keccak256(q.params[0]);
    } else throw Error('Unexpected Ixios RPC ' + q.method);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: q.id, result }));
  };
  return { state, fetcher };
}

const prepare = (n, overrides = {}) => prepareIxiosTransfer({ wallet: freshWallet(), to, amount: '1', maxGasPrice: CAP.mainnet, networkId: 'mainnet', assertCurrent: () => {}, fetcher: n.fetcher, wasmBytes: signWasm, rnd, ...overrides });
// confirm with a recording durable-write callback; resolves { hash } or { error }.
async function send(transfer, n) {
  const seen = {};
  const outcome = await transfer.confirm(async details => { seen.postsAtWrite = n.state.posted.length; seen.details = details; return { submissionId: 'ab'.repeat(16) }; }).then(hash => ({ hash }), error => ({ error }));
  return { seen, ...outcome };
}

test('(1) the maximum gas price must be a positive integer text; refused before any request', async () => {
  assert.equal(IXIOS_MAX_GAS_PRICE.source, '^[1-9][0-9]{0,77}$', 'the extension pattern (extension/src/background/ixios.js prepareSend)');
  for (const bad of [undefined, null, 5, '', '0', '01', '1.5', '-1', '1e3', ' 1', '1 ', '0x10', '1'.repeat(79)]) {
    const n = node();
    await assert.rejects(prepare(n, { maxGasPrice: bad }), /positive integer maximum gas price/, String(bad));
    assert.equal(n.state.requests.length, 0, `no request for ${String(bad)}`);
  }
});

test('(2) an unlisted network id and a missing wallet guard are refused before any request', async () => {
  for (const networkId of ['devnet', 'constructor', '__proto__', '']) {
    const n = node();
    await assert.rejects(prepare(n, { networkId }), /Unknown Ixios network/, String(networkId));
    assert.equal(n.state.requests.length, 0);
  }
  const n = node();
  await assert.rejects(prepare(n, { assertCurrent: undefined }), /wallet guard required/);
  await assert.rejects(prepare(n, { wallet: { addresses: {}, recoveryPhrase: phrase } }), /Ixios account unavailable/);
  await assert.rejects(prepare(n, { assertCurrent: () => { throw Error('Ixios account, wallet or network changed.'); } }), /changed/);
  assert.equal(n.state.requests.length, 0);
});

// The same stubbed review goes through the extension's createIxios and through the adapter.
function stubReview(networkId) {
  const gasPrice = networkId === 'testnet' ? 10n ** 17n : 93000000000000000n;
  return { from: address, to, amount: 10n ** 18n, gasPrice, gasLimit: 1000n, fee: gasPrice * 1000n, nonce: 7n, expiresAt: Date.now() + 60000, networkId, cancel: async () => {} };
}
function extensionFor(networkId, rows = []) {
  const network = networkId === 'testnet' ? { id: 'testnet', label: 'Testnet', endpoint: TEST } : { id: 'mainnet', label: 'Mainnet', endpoint: MAIN };
  const activity = { ready: Promise.resolve(), rows: () => rows, recoverSubmissionProofs: async () => {}, assertSendable() {}, async appendIxiosPendingWithProof() {}, rotateIxiosPending() {}, persist: async () => {}, error: () => '' };
  return createIxios({ storage: {}, lockCoordinator: { register() {}, assertUnlocked() {}, isLocked: false }, getWalletKeys: () => ({ getAddresses: () => ({ ixios: address }), getRecoveryPhrase: () => phrase }),
    getActivity: () => activity, getNetwork: () => network, watch: () => () => {}, prepare: async () => stubReview(networkId) });
}
test('(3) the send review rows equal the extension rows, on both networks', async () => {
  for (const networkId of ['mainnet', 'testnet']) {
    const args = { symbol: 'IXIOS', to, amount: '1', maxGasPrice: CAP[networkId] };
    const ext = await extensionFor(networkId).prepareSend(args);
    const web = await prepareIxiosTransfer({ wallet: freshWallet(), to, amount: '1', maxGasPrice: CAP[networkId], networkId, assertCurrent: () => {}, prepare: async () => stubReview(networkId) });
    assert.deepEqual(web.review, ext.review, networkId);
    assert.equal(web.fee, ext.fee);
    assert.equal(web.amount, ext.amount);
    assert.equal(web.networkId, ext.network);
    assert.deepEqual(web.review.map(row => row[0]), ['Network', 'From', 'To', 'Amount', 'Maximum fee', 'Gas price', 'Maximum approved gas price', 'Nonce', 'Scope', 'Authorization']);
    assert.deepEqual(web.review[0], ['Network', networkId === 'testnet' ? 'Ixios testnet' : 'Ixios mainnet']);
    assert.equal(web.review[6][1], CAP[networkId]);
  }
});
test('(3) the recovery review rows equal the extension rows', async () => {
  const hash = '0x' + 'cd'.repeat(32);
  const row = { chain: 'ixios', networkId: 'mainnet', address, to, hash, status: 'unknown', submissionId: 'ab'.repeat(16), amountAtoms: (10n ** 18n).toString(), feeAtoms: (93000000000000000000n).toString() };
  const prepared = { from: address, to, amountAtoms: row.amountAtoms, feeAtoms: row.feeAtoms, nonce: '7', gasPrice: '93000000000000000', gasLimit: '1000', hash, expiresAt: Date.now() + 60000, notice: 'Absence is inconclusive. This resubmits the exact previously signed transaction; it may already be pending.', cancel() {}, async confirm() {} };
  const ixios = createIxios({ storage: {}, lockCoordinator: { register() {}, assertUnlocked() {}, isLocked: false }, getWalletKeys: () => ({ getAddresses: () => ({ ixios: address }) }),
    getActivity: () => ({ ready: Promise.resolve(), rows: () => [row], recoverSubmissionProofs: async () => {}, assertSendable() {}, async appendIxiosPendingWithProof() {}, rotateIxiosPending() {}, persist: async () => {}, error: () => '' }),
    watch: () => () => {}, prepareRecovery: async () => prepared });
  const ext = await ixios.prepareResubmit(hash);
  const web = ixiosRecoveryTransfer(prepared, row);
  assert.deepEqual(web.review, ext.review);
  assert.deepEqual(ixiosRecoveryReviewRows(prepared), ext.review);
  assert.equal(web.review[0][1], 'Resubmit exactly the previously signed transaction; no new signature');
  assert.equal(web.isResubmission, true);
  assert.equal(web.previousSubmissionId, row.submissionId);
  assert.equal(web.fee, ext.fee);
});

test('(4) confirm: durable write before the one post, the posted bytes are the written bytes, the seed is zeroed', async () => {
  const n = node(), seeds = [];
  const transfer = await prepare(n, { deriveSeed: p => { const s = ixiosSigningSeed(p); seeds.push(s); return s; } });
  assert.equal(n.state.posted.length, 0, 'preparing posts nothing');
  assert.deepEqual(transfer.review[0], ['Network', 'Ixios mainnet']);
  const { seen, hash, error } = await send(transfer, n);
  assert.equal(error, undefined);
  assert.equal(seen.postsAtWrite, 0, 'the durable write happened before any post');
  assert.equal(n.state.posted.length, 1, 'exactly one post');
  assert.equal(n.state.posted[0].origin, MAIN);
  assert.equal(n.state.posted[0].raw, seen.details.signedPayload.data, 'the posted bytes are the bytes written first');
  assert.equal(hash, seen.details.hash);
  assert.deepEqual({ ...seen.details, signedPayload: undefined, hash: undefined }, { networkId: 'mainnet', from: address, to, amountAtoms: (10n ** 18n).toString(), feeAtoms: (93000000000000000000n).toString(), nonce: '7', gasPrice: '93000000000000000', gasLimit: '1000', hash: undefined, signedPayload: undefined });
  assert.equal(seeds.length, 1);
  assert.ok(seeds[0].every(byte => byte === 0), 'the seed was wiped');
  await assert.rejects(transfer.confirm(async () => ({ submissionId: 'cd'.repeat(16) })), error => /already closed/.test(error.message) && error.ixiosNotExposed === true, 'a review confirms once; the refusal posts nothing');
  assert.equal(n.state.posted.length, 1);
});

test('(4) the test network posts to its own node with its own names', async () => {
  const n = node(), transfer = await prepare(n, { networkId: 'testnet', maxGasPrice: CAP.testnet });
  assert.deepEqual(transfer.review[0], ['Network', 'Ixios testnet']);
  const { error } = await send(transfer, n);
  assert.equal(error, undefined);
  assert.deepEqual(n.state.posted.map(p => p.origin), [TEST]);
  assert.ok(n.state.requests.every(r => r.origin === TEST && r.method.startsWith('ixios_')), 'no main-node request');
});

test('(5) a transport failure after the request left is not "not exposed"; a new review is refused while the row is unresolved', async () => {
  const n = node({ post: async () => { throw Error('network down'); } });
  const transfer = await prepare(n);
  const { seen, error } = await send(transfer, n);
  assert.match(error?.message ?? '', /RPC unavailable/, 'the shared transport reports a request that failed');
  assert.equal(error.ixiosNotExposed, false, 'the post left: the outcome is uncertain, the page keeps the row unresolved');
  assert.equal(n.state.posted.length, 1, 'never retried');
  assert.ok(seen.details.signedPayload.data, 'the signed bytes were written first');
  // The page reports the unresolved row (a stored row with no final result) to the adapter.
  const row = recordActivity({ chain: 'ixios', from: address, to, symbol: 'IXIOS', amount: transfer.amount, endpoint: MAIN }, seen.details);
  row.status = 'unknown';
  const rows = [row], unresolved = () => rows.some(r => r.chain === 'ixios' && r.networkId === 'mainnet' && !['confirmed', 'failed'].includes(r.status));
  const fresh = node();
  await assert.rejects(prepare(fresh, { unresolved }), /previous Ixios transaction is unresolved/);
  assert.equal(fresh.state.requests.length, 0, 'refused before any request');
  // The test network has its own nonce space and its own rows: the same unresolved mainnet row does not block it.
  const other = node(), testUnresolved = () => rows.some(r => r.networkId === 'testnet' && !['confirmed', 'failed'].includes(r.status));
  assert.ok(await prepare(other, { networkId: 'testnet', maxGasPrice: CAP.testnet, unresolved: testUnresolved }));
});

test('(5) one review at a time per network; cancelling frees it; the other network is independent', async () => {
  const wallet = freshWallet(), n = node();
  const first = await prepare(n, { wallet });
  await assert.rejects(prepare(n, { wallet }), /nonce is already reserved/);
  const testnet = await prepare(n, { wallet, networkId: 'testnet', maxGasPrice: CAP.testnet });
  await testnet.cancel();
  await first.cancel();
  const again = await prepare(n, { wallet });
  assert.ok(again);
  // A new wallet object (after lock and unlock) starts with no reservation.
  assert.ok(await prepare(n));
  await again.cancel();
});

test('(5) after the durable write the in-memory reservation is freed: the row (unresolved until terminal) holds the nonce, not the page', async () => {
  const wallet = freshWallet(), n = node();
  const first = await prepare(n, { wallet });
  const { error } = await send(first, n);
  assert.equal(error, undefined);
  // The node still reports the nonce as pending, so the real preflight refuses a new send on its own.
  await assert.rejects(prepare(n, { wallet }), /unresolved pending nonce/);
  // Once the node reports the nonce as settled (and no row is unresolved) the same wallet object sends again: nothing is left
  // reserved in the page. A leaked reservation would answer "nonce is already reserved" here.
  n.state.postsOn = {};
  const next = await prepare(n, { wallet });
  assert.ok(next);
  await next.cancel();
});

test('(6) failures before the post carry ixiosNotExposed and post nothing', async () => {
  // (a) the fresh check after signing fails
  let n = node(), transfer = await prepare(n, { recheck: async () => { throw Error('fresh check failed'); } });
  let r = await send(transfer, n);
  assert.match(r.error?.message ?? '', /fresh check failed/);
  assert.equal(r.error.ixiosNotExposed, true);
  assert.equal(r.seen.postsAtWrite, 0, 'the signed row was written first');
  assert.equal(n.state.posted.length, 0);
  // (b) the review expires after the durable write
  n = node(); transfer = await prepare(n);
  const realNow = Date.now; let expired;
  try {
    expired = await transfer.confirm(async details => { Date.now = () => transfer.expiresAt; return { submissionId: 'ab'.repeat(16) }; }).then(() => ({}), error => ({ error }));
  } finally { Date.now = realNow; }
  assert.match(expired.error?.message ?? '', /expired/);
  assert.equal(expired.error.ixiosNotExposed, true);
  assert.equal(n.state.posted.length, 0);
  // (c) the wallet guard turns false after the durable write
  n = node(); let current = true;
  transfer = await prepare(n, { assertCurrent: () => { if (!current) throw Error('Ixios account, wallet or network changed.'); } });
  r = await transfer.confirm(async () => { current = false; return { submissionId: 'ab'.repeat(16) }; }).then(() => ({}), error => ({ error }));
  assert.match(r.error?.message ?? '', /changed/);
  assert.equal(r.error.ixiosNotExposed, true);
  assert.equal(n.state.posted.length, 0);
  // (d) the node starts answering another network (wrong genesis) right after the durable write: refused before the post
  n = node(); transfer = await prepare(n);
  r = await transfer.confirm(async () => { n.state.wrongGenesis = true; return { submissionId: 'ab'.repeat(16) }; }).then(() => ({}), error => ({ error }));
  assert.match(r.error?.message ?? '', /Wrong Ixios network/);
  assert.equal(r.error.ixiosNotExposed, true);
  assert.equal(n.state.posted.length, 0);
  // (e) a durable write that fails: nothing was posted, the error says so
  n = node(); transfer = await prepare(n);
  r = await transfer.confirm(async () => { throw Error('Wallet storage changed before broadcast. Review the transfer again.'); }).then(() => ({}), error => ({ error }));
  assert.match(r.error?.message ?? '', /Wallet storage changed/);
  assert.equal(r.error.ixiosNotExposed, true);
  assert.equal(n.state.posted.length, 0);
  // (f) no durable callback: refused, nothing signed or posted
  n = node(); transfer = await prepare(n);
  await assert.rejects(transfer.confirm(undefined), error => /Durable Ixios pending record is required/.test(error.message) && error.ixiosNotExposed === true);
  assert.equal(n.state.posted.length, 0);
});

test('(8) a guard that turns false during the review refuses the confirm before the seed, the durable write and any request, and frees the reservation', async () => {
  const wallet = freshWallet();
  for (const reason of ['the wallet was locked', 'the network was switched', 'the account changed']) {
    const n = node(), seeds = []; let current = true, writes = 0;
    const transfer = await prepare(n, { wallet, assertCurrent: () => { if (!current) throw Error('Ixios account, wallet or network changed.'); }, deriveSeed: p => { const s = ixiosSigningSeed(p); seeds.push(s); return s; } });
    current = false; n.state.requests.length = 0;
    await assert.rejects(transfer.confirm(async () => { writes++; return { submissionId: 'ab'.repeat(16) }; }), /Ixios account, wallet or network changed\./, reason);
    assert.equal(seeds.length, 0, `${reason}: no seed derived`);
    assert.equal(writes, 0, `${reason}: no durable write`);
    assert.equal(n.state.requests.length, 0, `${reason}: no request`);
    current = true;
    const again = await prepare(n, { wallet });
    assert.ok(again, `${reason}: the reservation was freed`);
    await again.cancel();
  }
});

test('(7) recovery re-sends the SAME bytes, needs the wallet guard and a fresh attempt identity, and refuses before any request when the guard throws', async () => {
  const first = node({ post: async () => { throw Error('network down'); } });
  const transfer = await prepare(first);
  const { seen, error } = await send(transfer, first);
  assert.ok(error);
  const row = recordActivity({ chain: 'ixios', from: address, to, symbol: 'IXIOS', amount: transfer.amount, endpoint: MAIN }, seen.details);
  row.status = 'unknown';
  const originalRaw = seen.details.signedPayload.data, originalHash = row.hash, originalId = row.submissionId;
  // The recovery wrapper requires the wallet guard.
  await assert.rejects(prepareIxiosExactRecovery(row, { fetcher: first.fetcher, wasmBytes: verifyWasm }), /wallet guard required/);
  // A guard that throws: no request at all.
  const idle = node(); let live = false;
  await assert.rejects(prepareIxiosExactRecovery(row, { fetcher: idle.fetcher, wasmBytes: verifyWasm, assertCurrent: () => { if (!live) throw Error('Wallet or network changed.'); } }), /Wallet or network changed\./);
  assert.equal(idle.state.requests.length, 0);
  // The replay: a node that accepts the same bytes.
  live = true;
  const second = node(); second.state.postsOn[MAIN] = 1;
  const prepared = await prepareIxiosExactRecovery(row, { fetcher: second.fetcher, wasmBytes: verifyWasm, assertCurrent: () => { if (!live) throw Error('Wallet or network changed.'); } });
  const recovery = ixiosRecoveryTransfer(prepared, row);
  assert.equal(recovery.isResubmission, true);
  assert.equal(recovery.previousSubmissionId, originalId);
  assert.equal(recovery.hash, originalHash);
  assert.equal(recovery.networkId, 'mainnet');
  // The durable attempt must be fresh: the previous identity is refused and nothing is posted.
  const stale = await recovery.confirm(async () => ({ submissionId: originalId })).then(() => ({}), e => ({ error: e }));
  assert.match(stale.error?.message ?? '', /Fresh Ixios attempt identity required/);
  assert.equal(second.state.posted.length, 0);
  // A second review of the same row (the first closed with its confirm).
  const again = ixiosRecoveryTransfer(await prepareIxiosExactRecovery(row, { fetcher: second.fetcher, wasmBytes: verifyWasm, assertCurrent: () => {} }), row);
  let written;
  const hash = await again.confirm(async details => { written = details; assert.equal(second.state.posted.length, 0, 'durable write before the post'); return { submissionId: 'cd'.repeat(16) }; });
  assert.equal(hash, originalHash);
  assert.equal(second.state.posted.length, 1);
  assert.equal(second.state.posted[0].raw, originalRaw, 'exactly the previously signed bytes');
  assert.equal(written.hash, originalHash);
  assert.equal(written.previousSubmissionId, originalId);
  assert.equal(written.signedPayload.data, originalRaw);
  assert.equal(first.state.posted.length, 1);
});
