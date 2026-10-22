// BUGS W-24, W-25, W-26 (the wallet side of the MM-Dex verifier findings).
//
// What it proves (against src/adapters/nodus.js and src/activity-storage.js;
// wallet-side rules only):
//   W-24  a quarantined Activity record (unreadable row whose coin reservation
//         is recoverable) keeps the tracking fields that validate (hash,
//         expiryHeight) and its lock is released when (a) none of its inputs
//         is among the wallet's coins any more, or (b) its expiry is known and
//         the chain tip is past it; with an input still unspent and no valid
//         expiry it stays locked; a token record is never released by (a);
//         coinView refuses an unreadable listing instead of reading it as
//         "no coins";
//   W-25  a claim-shaped row (inputs [X], hash X) exempts its input from the
//         coin lock only when it is a real claim of this wallet (NODUS asset,
//         no tokenId, paying the wallet's own address) — a token row or a
//         row paying someone else locks its input like any send;
//   W-26  the faucet poll never sleeps longer than the time left of the whole
//         claim, measures time with a monotonic clock by default, and a wallet
//         closing (signal abort / stopped()) ends the sleep at once, the claim
//         answering 'pending'.
// Requires nothing beyond `npm ci` (no special flags or environment). Leaves
// nothing behind. How it can lie: clock, sleep and fetcher are fakes (the real
// timers are not exercised); app.js reconcileQuarantine (the DOM / tracker
// wiring that calls these pure functions) has no seam here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { activityKeyFor, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { lockedInputs, isClaimRow, quarantineReleasable, coinView, claimTestnetCoins, FAUCET_PENDING_TEXT, FAUCET_POLL_MS, NODUS_TESTNET_CHAIN_ID } from '../src/adapters/nodus.js';
import { FINGERPRINT, RECIPIENT } from './nodus-mock-module.js';

const phrase = 'abandon '.repeat(23) + 'art';
const walletId = Buffer.alloc(16, 5).toString('base64');
const hex128 = n => n.toString(16).padStart(128, '0');
const savedRow = (n, extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.5', hash: hex128(n + 1), createdAt: new Date(Date.UTC(2026, 9, 22) + n * 1000).toISOString(), status: 'pending', expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(100000 + n)], ...extra });
// A saved file holding `rows` exactly as given (malformed ones included).
async function quarantineOf(rows) {
  const key = await activityKeyFor(phrase, walletId);
  // serializeActivity writes `raw` rows back unchanged: use that to plant them
  const text = await serializeActivity(walletId, [], key, rows.map(raw => ({ raw })));
  return (await parseActivity(text, walletId, { nodus: FINGERPRINT }, key)).quarantined;
}
const view = (coins, tip) => ({ coins: new Set(coins), tip });

// ── W-24 ─────────────────────────────────────────────────────────────────
test('W-24: a quarantined record keeps its valid hash and expiry; an invalid hash or expiry is left off', async () => {
  const [a, b] = await quarantineOf([savedRow(1, { symbol: 'tUSDT' }), savedRow(2, { symbol: 'tUSDT', hash: 'zz', expiryHeight: '0x10' })]);
  assert.equal(a.hash, hex128(2)); assert.equal(a.expiryHeight, '1090'); assert.equal(a.tokenRow, false);
  assert.equal(b.hash, undefined); assert.equal(b.expiryHeight, undefined);
});

test('W-24: inputs gone from the coin listing release the lock', async () => {
  const [held] = await quarantineOf([savedRow(1, { symbol: 'tUSDT', expiryHeight: undefined })]);
  assert.equal(held.expiryHeight, undefined);
  const other = hex128(7);
  assert.equal(quarantineReleasable(held, view([other], 500n)), true, 'every input is spent');
});

test('W-24: a past expiry releases the lock even while an input is still listed', async () => {
  const [held] = await quarantineOf([savedRow(1, { symbol: 'tUSDT' })]);   // expiryHeight 1090
  assert.equal(quarantineReleasable(held, view(held.inputs, 1091n)), true);
  assert.equal(quarantineReleasable(held, view(held.inputs, 1090n)), false, 'the tip must be PAST the expiry');
});

test('W-24: an unspent input and no valid expiry stays locked; so does an unusable view', async () => {
  const [held] = await quarantineOf([savedRow(1, { symbol: 'tUSDT', expiryHeight: 'soon' })]);
  assert.equal(held.expiryHeight, undefined);
  assert.equal(quarantineReleasable(held, view(held.inputs, 99999n)), false);
  assert.equal(quarantineReleasable(held, view([], 0n)), false, 'tip 0 is a failed read, not a view');
  assert.equal(quarantineReleasable(held, null), false);
});

test('W-24: a token record is not released because its inputs are not in the NATIVE listing', async () => {
  const [held] = await quarantineOf([savedRow(1, { tokenId: 'nothex', expiryHeight: undefined })]);
  assert.equal(held.tokenRow, true);
  assert.equal(quarantineReleasable(held, view([], 500n)), false);
});

test('W-24: coinView reads balance and listing strictly — a failed read (tip 0, or no coins under a balance) is an error', async () => {
  const client = (list, balance = { total: '0', spendable: '0' }) => ({ state: 'ready', fingerprint: FINGERPRINT, balance: async () => balance, list: async () => list });
  const ok = await coinView({ client: client({ tip: '500', coins: [{ nullifier: hex128(9), amount: '5' }] }, { total: '5', spendable: '5' }), from: FINGERPRINT });
  assert.equal(ok.tip, 500n); assert.ok(ok.coins.has(hex128(9)));
  await assert.rejects(coinView({ client: client({ tip: '0', coins: [] }), from: FINGERPRINT }), /could not be read/);
  await assert.rejects(coinView({ client: client({ tip: '500', coins: [] }, { total: '5', spendable: '5' }), from: FINGERPRINT }), /could not be read/);
  await assert.rejects(coinView({ client: client({ tip: '500', coins: [] }), from: hex128(1) }), /does not match/);
});

// ── W-25 ─────────────────────────────────────────────────────────────────
const X = hex128(31);
const claim = (extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, to: FINGERPRINT, symbol: 'NODUS', amount: '5', hash: X, status: 'pending', inputs: [X], ...extra });

test('W-25: a real claim of this wallet still exempts its (non-)input; a claim-shaped forgery does not', () => {
  assert.equal(isClaimRow(claim()), true);
  assert.deepEqual([...lockedInputs([claim()])], []);
  // pays someone else: a send, whatever its inputs say
  assert.equal(isClaimRow(claim({ to: RECIPIENT })), false);
  assert.deepEqual([...lockedInputs([claim({ to: RECIPIENT })])], [X]);
  // another symbol / no symbol
  assert.equal(isClaimRow(claim({ symbol: 'tUSDT' })), false);
  const bare = claim(); delete bare.symbol;
  assert.equal(isClaimRow(bare), false);
});

test('W-25: a token row shaped inputs:[X] hash:X locks its input', () => {
  const token = claim({ tokenId: hex128(77), symbol: 'tUSDT' });
  assert.equal(isClaimRow(token), false);
  assert.deepEqual([...lockedInputs([token])], [X]);
  // even if it otherwise looks like a native claim
  const sneaky = claim({ tokenId: hex128(77) });
  assert.equal(isClaimRow(sneaky), false);
  assert.deepEqual([...lockedInputs([sneaky])], [X]);
});

// ── W-26 ─────────────────────────────────────────────────────────────────
const testnetClient = { state: 'ready', chainId: NODUS_TESTNET_CHAIN_ID, fingerprint: FINGERPRINT };
const jsonResponse = body => ({ ok: true, json: async () => body });
const planned = state => jsonResponse({ claim_id: 'ab'.repeat(16), state, kind: 'full', message: `state ${state}` });

test('W-26: the sleep requested never exceeds the time left of the whole claim', async () => {
  let clock = 0; const asked = [];
  const sleep = async ms => { asked.push(ms); clock += ms; };
  const claimed = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => planned('submitted'), sleep, now: () => clock, totalMs: 7000, requestMs: 100000 });
  assert.equal(claimed.state, 'pending'); assert.equal(claimed.message, FAUCET_PENDING_TEXT);
  assert.deepEqual(asked, [FAUCET_POLL_MS, FAUCET_POLL_MS, 1000], 'the last wait is clipped to the 1000 ms left');
  assert.ok(asked.every(ms => ms > 0 && ms <= FAUCET_POLL_MS));
});

test('W-26: aborting during the sleep ends the claim promptly as pending', async () => {
  const controller = new AbortController();
  let polls = 0;
  const fetcher = async url => { if (url !== '/faucet/claim') polls++; return planned('submitted'); };
  const never = () => new Promise(() => {});                 // a sleep that never ends by itself
  setTimeout(() => controller.abort(), 20);
  const guard = new Promise((_, reject) => setTimeout(() => reject(new Error('the claim did not end after the abort')), 3000).unref());
  const claimed = await Promise.race([claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: never, signal: controller.signal }), guard]);
  assert.equal(claimed.state, 'pending'); assert.equal(claimed.message, FAUCET_PENDING_TEXT);
  assert.equal(polls, 0, 'no poll was made after the abort');
});

test('W-26: stopped() turning true during the sleep ends it as well', async () => {
  let closed = false;
  const never = () => new Promise(() => {});
  setTimeout(() => { closed = true; }, 20);
  const guard = new Promise((_, reject) => setTimeout(() => reject(new Error('the claim did not end after stopped()')), 3000).unref());
  const claimed = await Promise.race([claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: async () => planned('submitted'), sleep: never, stopped: () => closed }), guard]);
  assert.equal(claimed.state, 'pending');
});
