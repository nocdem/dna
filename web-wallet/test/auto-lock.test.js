// Automatic lock choice (web 0.1.89, src/auto-lock.js): the stored value is
// a per-device convenience; anything missing, malformed or unknown gives
// the default (15 minutes), never "never".
import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTO_LOCK_KEY, AUTO_LOCK_CHOICES, AUTO_LOCK_DEFAULT, parseAutoLock, autoLockNote, autoLockBarText, readAutoLock, writeAutoLock } from '../src/auto-lock.js';
import { readFileSync } from 'node:fs';

test('the open wallet\'s bar says the chosen auto-lock time (0.1.104), not a fixed 10 minutes', () => {
  assert.equal(autoLockBarText(15), 'Auto-lock after 15 minutes of inactivity');
  assert.equal(autoLockBarText(60), 'Auto-lock after 1 hour of inactivity');
  assert.equal(autoLockBarText(0), 'Auto-lock off');
  assert.equal(autoLockBarText(AUTO_LOCK_DEFAULT), `Auto-lock after ${AUTO_LOCK_DEFAULT} minutes of inactivity`);
  // Both sites' bar text before the script runs is the default's, and has an id app.js fills.
  for (const file of ['index.html', 'connect-site/index.html']) {
    const html = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    assert.ok(html.includes(`<span id="session-timeout" class="session-timeout">${autoLockBarText(AUTO_LOCK_DEFAULT)}</span>`), file);
  }
});

const memory = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), m }; };

test('auto lock: the default is 15 minutes; only the offered choices are accepted', () => {
  assert.equal(AUTO_LOCK_DEFAULT, 15);
  assert.deepEqual([...AUTO_LOCK_CHOICES], [5, 10, 15, 30, 60, 0]);
  for (const c of AUTO_LOCK_CHOICES) assert.equal(parseAutoLock(String(c)), c);
  for (const bad of [undefined, null, '', ' 5', '5 ', '05', '7', '-1', '1e1', '15.0', '9999', 'never', 5]) assert.equal(parseAutoLock(bad), 15, String(bad));
});

test('auto lock: storage round trip, and a broken storage falls back to the default', () => {
  const s = memory();
  assert.equal(readAutoLock(s), 15, 'nothing stored');
  assert.equal(writeAutoLock(s, 0), true);
  assert.equal(s.m.get(AUTO_LOCK_KEY), '0');
  assert.equal(readAutoLock(s), 0);
  assert.equal(writeAutoLock(s, 7), false, 'not an offered choice');
  assert.equal(readAutoLock(s), 0, 'unchanged');
  s.m.set(AUTO_LOCK_KEY, 'garbage');
  assert.equal(readAutoLock(s), 15);
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.equal(readAutoLock(throwing), 15);
  assert.equal(writeAutoLock(throwing, 30), false);
  assert.equal(readAutoLock(undefined), 15);
});

test('auto lock: the note warns for "never" and names the time otherwise', () => {
  assert.match(autoLockNote(0), /until you press Lock/);
  assert.match(autoLockNote(0), /shared or public device/);
  assert.match(autoLockNote(15), /after 15 minutes without use/);
  assert.match(autoLockNote(60), /after 1 hour without use/);
});
