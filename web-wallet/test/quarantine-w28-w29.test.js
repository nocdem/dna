// BUGS W-28 and W-29 (quarantined NODUS Activity records).
//
// What it proves (src/activity-storage.js, src/app.js refreshQuarantine):
//   W-28  a malformed saved row whose expiryHeight is earlier than its own
//         well-formed fromHeight is quarantined WITHOUT the expiry (so
//         quarantineReleasable can never release it); a coherent expiry is
//         kept; a row without a well-formed fromHeight is judged as before
//         (expiry kept when it is well-formed); `raw` stays the row as read;
//   W-29  reuseQuarantineLocks keeps a lock object across a save when its
//         whole content (address, input set in any order, hash, expiry,
//         token/native) is unchanged, so a release recorded against it
//         survives; any changed field is a new lock (not released); released
//         entries of vanished locks are dropped; two equal records are matched
//         one to one; app.js refreshQuarantine (the real source text, run in a
//         vm with a spy timer) replaces quarantinedRows that way and re-arms
//         the recheck timer, and persistActivity calls it with the saved aside.
// Requires nothing beyond `npm ci`. Leaves nothing behind. How it can lie:
// app.js is run as a source slice with the real helper but stubbed
// NODUS_ASSET / armQuarantineTimer (the DOM wiring and the timer itself have no
// seam here), and the rows are synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { activityKeyFor, serializeActivity, parseActivity, reuseQuarantineLocks, quarantineLockKey } from '../src/activity-storage.js';
import { quarantineReleasable, quarantineLockRows } from '../src/adapters/nodus.js';
import { FINGERPRINT, RECIPIENT } from './nodus-mock-module.js';

const phrase = 'abandon '.repeat(23) + 'art';
const walletId = Buffer.alloc(16, 5).toString('base64');
const hex128 = n => n.toString(16).padStart(128, '0');
const savedRow = (n, extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.5', hash: hex128(n + 1), createdAt: new Date(Date.UTC(2026, 9, 22) + n * 1000).toISOString(), status: 'pending', expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(100000 + n)], ...extra });
async function quarantineOf(rows) {
  const key = await activityKeyFor(phrase, walletId);
  const text = await serializeActivity(walletId, [], key, rows.map(raw => ({ raw })));
  return (await parseActivity(text, walletId, { nodus: FINGERPRINT }, key)).quarantined;
}
// A malformed-but-recoverable row: symbol is not a valid one, so readActivityRow rejects it.
const bad = (n, extra = {}) => savedRow(n, { symbol: 'tUSDT', ...extra });

test('W-28: an expiry earlier than the row\'s own fromHeight is not kept and the lock cannot be released', async () => {
  const [contradiction] = await quarantineOf([bad(1, { fromHeight: '500', expiryHeight: '100' })]);
  assert.equal(contradiction.expiryHeight, undefined);
  assert.equal(contradiction.inputs.length, 1, 'the reservation stays');
  assert.equal(contradiction.raw.expiryHeight, '100', 'raw is written back unchanged');
  assert.equal(quarantineReleasable(contradiction, { tip: 99999n }), false);
});
test('W-28: a coherent expiry is kept; a missing or malformed fromHeight is judged as before', async () => {
  const [coherent, none, malformed, badExpiry] = await quarantineOf([
    bad(1, { fromHeight: '50', expiryHeight: '100' }),
    bad(2, { fromHeight: undefined, expiryHeight: '100' }),
    bad(3, { fromHeight: 'abc', expiryHeight: '100' }),
    bad(4, { fromHeight: '50', expiryHeight: '0x10' })]);
  assert.equal(coherent.expiryHeight, '100');
  assert.equal(none.expiryHeight, '100');
  assert.equal(malformed.expiryHeight, '100');
  assert.equal(badExpiry.expiryHeight, undefined);
});

const lock = (n, extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, status: 'pending', inputs: [hex128(n), hex128(n + 1)], tokenRow: false, hash: hex128(900 + n), expiryHeight: '1090', ...extra });

test('W-29: an unchanged lock keeps its object (and its release) across a save; a changed one is new and locked', () => {
  const a = lock(1), b = lock(10), released = new Set([a]);
  const fresh = [lock(1, { inputs: [hex128(2), hex128(1)] }), lock(10, { expiryHeight: '2000' })];
  const next = reuseQuarantineLocks([a, b], fresh, released);
  assert.equal(next[0], a, 'same content (inputs in another order) reuses the object');
  assert.notEqual(next[1], b, 'a changed expiry is a new reservation');
  assert.deepEqual(quarantineLockRows(next, released), [next[1]], 'only the changed one is locked');
  for (const change of [{ address: 'f'.repeat(128) }, { inputs: [hex128(1)] }, { hash: hex128(5) }, { hash: undefined }, { expiryHeight: undefined }, { tokenRow: true }]) {
    const set = new Set([a]);
    const [row] = reuseQuarantineLocks([a], [{ ...lock(1), ...change }], set);
    assert.notEqual(row, a, `changing ${Object.keys(change)[0]} is a new lock`);
    assert.equal(set.has(row), false);
  }
  assert.notEqual(quarantineLockKey(lock(1)), quarantineLockKey(lock(1, { tokenRow: true })));
});
test('W-29: obsolete released entries are dropped; equal records are matched one to one', () => {
  const a = lock(1), b = lock(1), gone = lock(20);
  const released = new Set([a, gone]);
  const next = reuseQuarantineLocks([a, b, gone], [lock(1), lock(1)], released);
  assert.deepEqual(next, [a, b]);
  assert.deepEqual([...released], [a], 'the released lock of the vanished record is dropped');
  assert.deepEqual(quarantineLockRows(next, released), [b]);
});

const appSource = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
const between = (from, to) => { const start = appSource.indexOf(from); return appSource.slice(start, appSource.indexOf(to, start)); };
test('W-29: app.js refreshQuarantine keeps a released lock released and re-arms the timer', () => {
  const slice = between('const quarantineLocks =', 'const nodusLockRows =');
  assert.match(slice, /function refreshQuarantine/);
  let armed = 0;
  const released = new Set();
  const context = { NODUS_ASSET: { chain: 'nodus' }, reuseQuarantineLocks, releasedQuarantine: released, armQuarantineTimer: () => { armed += 1; } };
  const held = [{ address: FINGERPRINT, inputs: [hex128(1)], tokenRow: false, hash: hex128(7), expiryHeight: '1090' }, { address: FINGERPRINT, inputs: [hex128(2)], tokenRow: false }];
  runInNewContext(`let quarantinedRows = [];${slice};globalThis.refresh = refreshQuarantine; globalThis.rows = () => quarantinedRows;`, context);
  context.refresh(held);
  const first = context.rows();
  released.add(first[0]);
  context.refresh(held);                       // what a save does
  assert.equal(context.rows()[0], first[0], 'the released lock is the same object after the save');
  assert.equal(context.rows()[1], first[1]);
  assert.deepEqual(quarantineLockRows(context.rows(), released), [first[1]]);
  assert.equal(armed, 2, 'the timer is armed after every replacement');
});
test('W-29: persistActivity hands the saved quarantine to refreshQuarantine', () => {
  const body = between('function persistActivity(', '// The last balances, saved encrypted');
  assert.match(body, /refreshQuarantine\(aside\)/);
  assert.doesNotMatch(body, /quarantinedRows = quarantineLocks/);
});
