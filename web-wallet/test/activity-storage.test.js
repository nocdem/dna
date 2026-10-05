// The saved Activity keeps every unresolved row (red-team 2): a pending
// NODUS send or smart-contract reservation holds coins until it resolves,
// so it must survive any number of newer rows; the 100-row cap applies to
// the resolved rows only.
// What it proves:
//   - 101 resolved rows + 1 OLDER pending row: the pending row survives
//     serializeActivity / parseActivity, and the oldest resolved row is the
//     one left out (100 rows in total, the saved order unchanged);
//   - 101 resolved rows only: the newest 100 are kept, the oldest is not;
//   - 101 unresolved rows: refused as "too large", never silently cut to 100
//     (parseActivity reads at most 100 rows);
//   - right after unlock (every parsed row's live status reset to 'pending'):
//     100 rows saved as confirmed plus one new pending row save fine — the
//     new row is kept, the oldest confirmed one left out — because a parsed
//     row's retention follows the status it was SAVED with (savedStatus);
//   - a parsed row saved as pending still counts as unresolved after the
//     re-parse and survives 100 newer resolved rows;
//   - a re-save right after parse writes the confirmed rows as confirmed,
//     not as the reset 'pending' (parse again: savedStatus 'confirmed'),
//     while the visible status stays 'pending' / 'abandoned' as before;
//   - requireSavedForEvm refuses an unsaved wallet in plain words and lets a
//     saved one through.
// Requires nothing beyond `npm ci`. How it can lie: rows are synthetic NODUS
// rows (no network, no tracker); parseActivity re-marks every row 'pending'
// (except 'abandoned'), so rows are identified by their hash and the saved
// status is read from savedStatus, never from the returned status.
import test from 'node:test';
import assert from 'node:assert/strict';
import { activityKeyFor, serializeActivity, parseActivity, requireSavedForEvm } from '../src/activity-storage.js';

const phrase = 'abandon '.repeat(23) + 'art';
const id = Buffer.alloc(16, 5).toString('base64');
const OWN = 'ab'.repeat(64);
const hex128 = n => n.toString(16).padStart(128, '0');
// row n: hash n, created n seconds after a fixed instant, one input of its own
function row(n, status) {
  return {
    chain: 'nodus', address: OWN, to: OWN, symbol: 'NODUS', amount: '1.5', hash: hex128(n + 1),
    createdAt: new Date(Date.UTC(2026, 9, 5) + n * 1000).toISOString(), status,
    expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(100000 + n)]
  };
}
async function roundTrip(rows) {
  const key = await activityKeyFor(phrase, id);
  return parseActivity(await serializeActivity(id, rows, key), id, { nodus: OWN }, key);
}

test('an old pending row survives 101 newer resolved rows; the oldest resolved row is left out', async () => {
  const rows = [row(0, 'pending'), ...Array.from({ length: 101 }, (_, i) => row(i + 1, 'confirmed'))];
  const back = await roundTrip(rows);
  assert.equal(back.length, 100);
  assert.equal(back[0].hash, rows[0].hash, 'the pending row is kept, first as saved');
  assert.deepEqual(back[0].inputs, rows[0].inputs);
  assert.ok(!back.some(r => r.hash === rows[1].hash), 'the oldest resolved row is left out');
  assert.ok(!back.some(r => r.hash === rows[2].hash), 'and the next oldest (99 resolved slots)');
  assert.deepEqual(back.slice(1).map(r => r.hash), rows.slice(3).map(r => r.hash), 'the newest resolved rows, in order');
});

test('the 100-row cap still applies to resolved rows', async () => {
  const rows = Array.from({ length: 101 }, (_, i) => row(i, 'confirmed'));
  const back = await roundTrip(rows);
  assert.deepEqual(back.map(r => r.hash), rows.slice(1).map(r => r.hash));
});

test('a pending row in the middle keeps its place among the kept rows', async () => {
  const rows = Array.from({ length: 150 }, (_, i) => row(i, i === 20 ? 'pending' : 'expired'));
  const back = await roundTrip(rows);
  assert.equal(back.length, 100);
  assert.equal(back[0].hash, rows[20].hash);
  assert.deepEqual(back.slice(1).map(r => r.hash), rows.slice(51).map(r => r.hash));
});

test('more unresolved rows than can be saved are refused, never dropped', async () => {
  const key = await activityKeyFor(phrase, id);
  const rows = Array.from({ length: 101 }, (_, i) => row(i, 'pending'));
  await assert.rejects(serializeActivity(id, rows, key), /Saved activity is too large/);
  // exactly 100 unresolved rows are saved, with every resolved row left out
  const back = await roundTrip([...rows.slice(1), row(500, 'confirmed')]);
  assert.deepEqual(back.map(r => r.hash), rows.slice(1).map(r => r.hash));
});

test('right after unlock: 100 saved confirmed rows + 1 new pending row save; the oldest confirmed row is left out', async () => {
  const saved = Array.from({ length: 100 }, (_, i) => row(i, 'confirmed'));
  const parsed = await roundTrip(saved);
  assert.ok(parsed.every(r => r.status === 'pending' && r.savedStatus === 'confirmed'), 'live status reset, saved status kept');
  const fresh = row(200, 'pending');
  const back = await roundTrip([...parsed, fresh]);
  assert.equal(back.length, 100);
  assert.equal(back[99].hash, fresh.hash, 'the new row is kept, last');
  assert.equal(back[99].savedStatus, 'pending');
  assert.ok(!back.some(r => r.hash === saved[0].hash), 'the oldest confirmed row is left out');
  assert.deepEqual(back.slice(0, 99).map(r => r.hash), saved.slice(1).map(r => r.hash));
  assert.ok(back.slice(0, 99).every(r => r.savedStatus === 'confirmed'));
});

test('a row saved as pending stays unresolved after a re-parse and survives 100 newer resolved rows', async () => {
  const parsed = await roundTrip([row(0, 'pending'), ...Array.from({ length: 99 }, (_, i) => row(i + 1, 'confirmed'))]);
  const back = await roundTrip([...parsed, row(300, 'confirmed')]);
  assert.equal(back.length, 100);
  assert.equal(back[0].hash, row(0).hash);
  assert.equal(back[0].savedStatus, 'pending');
  assert.ok(!back.some(r => r.hash === row(1).hash), 'the oldest confirmed row is left out instead');
});

test('a re-save right after parse keeps the confirmed rows saved as confirmed', async () => {
  const rows = [row(0, 'confirmed'), row(1, 'abandoned'), row(2, 'pending'), row(3, 'expired')];
  const parsed = await roundTrip(rows);
  assert.deepEqual(parsed.map(r => r.status), ['pending', 'abandoned', 'pending', 'pending'], 'the visible status is as before');
  const again = await roundTrip(parsed);
  assert.deepEqual(again.map(r => r.savedStatus), ['confirmed', 'abandoned', 'pending', 'expired']);
  // a parsed row the tracker has re-verified is written with its live status
  const tracked = parsed.map(r => ({ ...r }));
  tracked[2].status = 'confirmed';
  assert.deepEqual((await roundTrip(tracked)).map(r => r.savedStatus), ['confirmed', 'abandoned', 'confirmed', 'expired']);
});

test('requireSavedForEvm: an unsaved wallet is refused in plain words, a saved one passes', () => {
  assert.throws(() => requireSavedForEvm(false), /need this wallet to be saved in this browser first.*Nothing was sent/);
  assert.throws(() => requireSavedForEvm(undefined), /saved in this browser/);
  assert.doesNotThrow(() => requireSavedForEvm(true));
});
