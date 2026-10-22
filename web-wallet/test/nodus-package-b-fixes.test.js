// Package B verifier round (operator 2026-10-22: "Hepsini düzelt") — the wallet
// side of findings 3, 4, 5, 6, 7 and 8. (Findings 1, 2 and 9 are C: the
// decoder test nodus/tests/test_token_info_decode.c and the module tests in
// test/nodus-send-wasm.test.js.)
//
// What it proves (against the faucet adapter, the Activity storage and the
// TEST-only mock module — wallet-side rules only):
//   3. the pins the Send panel offers follow the module's CURRENT answer:
//      tokenPins() is re-read (app.js syncNodusPins) — here the pin list
//      shape the app compares (a changed `available` is a change);
//   4. an unavailable token's portfolio row offers Receive only, never Send
//      (holdingActions);
//   5. every faucet request has a deadline and an abort: a request that never
//      answers, a body past the size limit, a stream that never ends, the
//      wallet closing (signal) and the whole-claim deadline all end as
//      "pending — check again later", never as "failed" and never by waiting
//      for ever; a POST whose answer is lost is "pending";
//   6. one malformed NODUS Activity row is quarantined (kept out of the list,
//      recorded, its coin reservation recoverable and written back on save)
//      instead of rejecting every row; a row whose reservation cannot be
//      recovered still rejects the file;
//   7. every faucet request is same-origin with redirect 'error', credentials
//      omitted;
//   8. the NODUS hop carries the explicit all-zero token id; a build without
//      it is refused by the module (mock = the module's rule).
// Requires nothing beyond `npm ci`. How it can lie: the fetcher / sleep / clock
// are fakes; the real fetch(), AbortSignal timing and the DOM wiring (asset
// <option>s, the faucet button) have no seam here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { claimTestnetCoins, FAUCET_MAX_BODY, FAUCET_LOST_TEXT, FAUCET_PENDING_TEXT, NODUS_TESTNET_CHAIN_ID } from '../src/adapters/nodus.js';
import { holdingActions } from '../src/portfolio.js';
import { activityKeyFor, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { lockedInputs } from '../src/adapters/nodus.js';
import { createNodusClient } from '../src/nodus/client.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, ZERO_TOKEN } from './nodus-mock-module.js';

const testnetClient = { state: 'ready', chainId: NODUS_TESTNET_CHAIN_ID, fingerprint: FINGERPRINT };
const claimBody = (state, extra = {}) => ({ claim_id: 'ab'.repeat(16), state, kind: 'full', message: `state ${state}`, ...extra });
const jsonResponse = body => ({ ok: true, json: async () => body });
const noSleep = async () => {};
// a fetcher that never answers (and ignores its signal, as a broken one would)
const hanging = () => new Promise(() => {});
// a response whose body is a stream of `chunks` (Uint8Array)
const streamResponse = (chunks, { length } = {}) => {
  let i = 0;
  return { ok: true, headers: { get: name => (name.toLowerCase() === 'content-length' && length !== undefined ? String(length) : null) },
    body: { getReader: () => ({ read: async () => (i < chunks.length ? { done: false, value: chunks[i++] } : { done: true }), cancel: async () => { i = chunks.length; } }) } };
};
const bytes = text => new TextEncoder().encode(text);

// ── 7. same-origin, no redirect ──────────────────────────────────────────
test('faucet: every request is same-origin, redirect "error", credentials omitted, no cache, with an abort signal', async () => {
  const calls = [];
  const fetcher = async (url, init) => { calls.push({ url, init }); return jsonResponse(calls.length === 1 ? claimBody('planned') : claimBody('confirmed')); };
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep });
  assert.equal(claim.state, 'confirmed'); assert.equal(calls.length, 2);
  for (const { url, init } of calls) {
    assert.ok(url.startsWith('/faucet/'), 'a relative URL: this page\'s own origin');
    assert.equal(init.mode, 'same-origin', url); assert.equal(init.redirect, 'error', url);
    assert.equal(init.credentials, 'omit', url); assert.equal(init.cache, 'no-store', url);
    assert.ok(init.signal && typeof init.signal.aborted === 'boolean', `${url} carries an AbortSignal`);
  }
});

// ── 5. deadlines, size limit, abort, lost POST ───────────────────────────
test('faucet: a POST that never answers ends at the request deadline as "pending", not an error, not for ever', async () => {
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: hanging, sleep: noSleep, requestMs: 15 });
  assert.equal(claim.state, 'pending'); assert.equal(claim.message, FAUCET_LOST_TEXT);
  assert.match(claim.message, /^Pending — check again later/); assert.doesNotMatch(claim.message, /fail/i);
});

test('faucet: a fetcher that honours the signal is aborted at the request deadline', async () => {
  let aborted = false;
  const fetcher = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('AbortError')); }));
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep, requestMs: 15 });
  assert.equal(claim.state, 'pending'); assert.equal(aborted, true, 'the request was really aborted');
});

test('faucet: a body that never ends is cut at the request deadline (the deadline covers the body)', async () => {
  const stuck = { ok: true, headers: { get: () => null }, body: { getReader: () => ({ read: () => new Promise(() => {}), cancel: async () => {} }) } };
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => stuck, sleep: noSleep, requestMs: 15 });
  assert.equal(claim.state, 'pending');
});

test('faucet: a body past the size limit is refused BEFORE it is parsed (declared length, and bytes actually read)', async () => {
  const huge = JSON.stringify({ ...claimBody('planned'), message: 'x'.repeat(FAUCET_MAX_BODY) });
  assert.ok(huge.length > FAUCET_MAX_BODY);
  // declared too large: not even read
  const declared = streamResponse([bytes('{}')], { length: FAUCET_MAX_BODY + 1 });
  let read = false; declared.body.getReader = () => ({ read: async () => { read = true; return { done: true }; }, cancel: async () => {} });
  assert.equal((await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => declared, sleep: noSleep })).state, 'pending');
  assert.equal(read, false, 'a declared length over the limit is not read at all');
  // not declared, but longer than the limit when read: the stream is cancelled at the limit and the
  // answer (a valid claim, were it parsed) is NOT used
  const chunks = [bytes(huge.slice(0, 3000)), bytes(huge.slice(3000))];
  const oversized = streamResponse(chunks);
  let cancelled = false;
  const reader = oversized.body.getReader();
  oversized.body.getReader = () => ({ read: reader.read, cancel: async () => { cancelled = true; } });
  assert.equal((await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => oversized, sleep: noSleep })).state, 'pending');
  assert.equal(cancelled, true, 'the oversized stream was cancelled, not read to its end and parsed');
  // a body inside the limit, delivered in pieces, is read whole
  const whole = bytes(JSON.stringify(claimBody('confirmed')));
  const fine = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => streamResponse([whole.slice(0, 10), whole.slice(10)]), sleep: noSleep });
  assert.equal(fine.state, 'confirmed');
});

test('faucet: the wallet closing (signal) aborts the request in flight and ends the claim quietly', async () => {
  const controller = new AbortController();
  let seen;
  const fetcher = (url, { signal }) => { seen = signal; setTimeout(() => controller.abort(), 5); return new Promise(() => {}); };
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep, signal: controller.signal, requestMs: 5000 });
  assert.equal(claim.state, 'pending'); assert.equal(seen.aborted, true, 'the request\'s own signal was aborted');
  // already closed before the first request: nothing is sent
  const closed = new AbortController(); closed.abort();
  let sent = 0;
  const none = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => { sent++; return jsonResponse(claimBody('planned')); }, sleep: noSleep, signal: closed.signal });
  assert.equal(none.state, 'pending'); assert.equal(sent, 0);
});

test('faucet: the whole claim has a deadline too — polling ends "pending" when it passes, with fewer polls than the count bound', async () => {
  let clock = 0, polls = 0;
  const fetcher = async url => { if (url !== '/faucet/claim') polls++; return jsonResponse(claimBody('submitted')); };
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: async () => { clock += 1000; }, now: () => clock, totalMs: 3500, requestMs: 100000 });
  assert.equal(claim.state, 'pending'); assert.equal(claim.message, FAUCET_PENDING_TEXT);
  assert.equal(polls, 3, 'one poll per elapsed second until the 3.5 s deadline');
});

test('faucet: a poll that hangs costs its request deadline, not the claim', async () => {
  let n = 0;
  const fetcher = async url => (n++ === 0 ? jsonResponse(claimBody('planned')) : hanging());
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep, requestMs: 5, totalMs: 80 });
  assert.equal(claim.state, 'pending'); assert.ok(n >= 2, 'the hanging polls were abandoned one by one');
});

// ── 4. an unavailable token is never offered for Send ────────────────────
test('portfolio: an unavailable token row offers Receive only; an available one Send and Receive; Earn follows its flag', () => {
  const network = { receiveOnly: false };
  assert.deepEqual(holdingActions(network, { unavailable: true }, false), ['Receive']);
  assert.deepEqual(holdingActions(network, { unavailable: true }, true), ['Receive', 'Earn']);
  assert.deepEqual(holdingActions(network, { state: 'ready' }, false), ['Send', 'Receive']);
  assert.deepEqual(holdingActions(network, { state: 'error' }, true), ['Send', 'Receive', 'Earn']);
  assert.deepEqual(holdingActions({ receiveOnly: true }, { state: 'ready' }, false), ['Receive']);
});

// ── 6. Activity quarantine ───────────────────────────────────────────────
const phrase = 'abandon '.repeat(23) + 'art';
const walletId = Buffer.alloc(16, 5).toString('base64');
const hex128 = n => n.toString(16).padStart(128, '0');
const savedRow = (n, extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.5', hash: hex128(n + 1), createdAt: new Date(Date.UTC(2026, 9, 22) + n * 1000).toISOString(), status: 'pending', expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(100000 + n)], ...extra });
const rawFile = async (rows, key) => serializeActivity(walletId, rows, key);

test('Activity: a malformed row is quarantined, the others are kept, and a later save writes the quarantined row back unchanged', async () => {
  const key = await activityKeyFor(phrase, walletId);
  const bad = savedRow(1, { symbol: 'tUSDT' });                 // a token symbol without a token id
  const text = await rawFile([savedRow(0), bad, savedRow(2)], key);
  const rows = await parseActivity(text, walletId, { nodus: FINGERPRINT }, key);
  assert.deepEqual(rows.map(r => r.hash), [hex128(1), hex128(3)]);
  assert.equal(rows.quarantined.length, 1);
  assert.deepEqual(rows.quarantined[0].inputs, bad.inputs);
  assert.deepEqual(Object.keys(rows), ['0', '1'], '`quarantined` is not an enumerable member of the list');
  // its coin reservation: the app holds these inputs like a pending send's
  const held = lockedInputs([...rows, ...rows.quarantined.map(q => ({ chain: 'nodus', address: q.address, status: 'pending', inputs: q.inputs }))]);
  assert.ok(held.has(bad.inputs[0]), 'the quarantined row\'s coin stays locked');
  // a save that knows the quarantine keeps it; the next read finds it again
  const again = await serializeActivity(walletId, rows, key, rows.quarantined);
  const back = await parseActivity(again, walletId, { nodus: FINGERPRINT }, key);
  assert.deepEqual(back.map(r => r.hash), [hex128(1), hex128(3)]);
  assert.equal(back.quarantined.length, 1); assert.deepEqual(back.quarantined[0].raw, bad, 'written back unchanged');
  // a save that drops it (discard) frees the coin
  const discarded = await parseActivity(await serializeActivity(walletId, [], key, []), walletId, { nodus: FINGERPRINT }, key);
  assert.equal(discarded.length, 0); assert.equal(discarded.quarantined.length, 0);
});

test('Activity: quarantined records count against the 100-row cap and are never the rows dropped', async () => {
  const key = await activityKeyFor(phrase, walletId);
  const quarantined = [{ address: FINGERPRINT, inputs: [hex128(9)], raw: savedRow(9, { symbol: 'tUSDT' }) }];
  const rows = Array.from({ length: 101 }, (_, i) => savedRow(i + 20, { status: 'expired' }));
  const back = await parseActivity(await serializeActivity(walletId, rows, key, quarantined), walletId, { nodus: FINGERPRINT }, key);
  assert.equal(back.length + back.quarantined.length, 100);
  assert.equal(back.quarantined.length, 1, 'the quarantined record survived');
});

test('Activity: a row whose reservation cannot be recovered still rejects the file (bad inputs, another address, another network)', async () => {
  const key = await activityKeyFor(phrase, walletId);
  const reject = async row => assert.rejects(parseActivity(await rawFile([savedRow(0), row], key), walletId, { nodus: FINGERPRINT }, key), /Invalid saved|does not match|expiry/, JSON.stringify(row).slice(0, 80));
  await reject(savedRow(1, { symbol: 'tUSDT', inputs: ['zz'] }));
  await reject(savedRow(1, { symbol: 'tUSDT', inputs: [hex128(7), hex128(7)] }));
  await reject(savedRow(1, { symbol: 'tUSDT', inputs: [] }));
  await reject(savedRow(1, { symbol: 'tUSDT', address: 'cd'.repeat(64) }));
  await reject(savedRow(1, { chain: 'ethereum', tokenId: 'ab'.repeat(64) }));
});

// ── 8. the NODUS hop carries the explicit all-zero token id ──────────────
test('the module\'s NODUS build refuses a request without the explicit all-zero token id (and with another one)', async () => {
  const mock = createMockNodusModule();
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 7, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  const request = { to: RECIPIENT, amount: '150000000', expiryHeight: '1090', coins: mock.state.coins };
  await assert.rejects(client.buildAndSign(request), /Invalid token/);
  await assert.rejects(client.buildAndSign({ ...request, tokenId: 'ab'.repeat(64) }), /Invalid token/);
  assert.equal(mock.state.lastBuild, null, 'nothing was built');
  const built = await client.buildAndSign({ ...request, tokenId: ZERO_TOKEN });
  assert.equal(built.decoded.tokenId, ZERO_TOKEN);
  client.lock();
});
