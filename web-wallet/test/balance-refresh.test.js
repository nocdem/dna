// Automatic balance updates (web 0.1.93, src/balance-refresh.js and
// src/portfolio.js portfolioSnapshot balanceMaxAge).
// What it proves: the choice is 2 / 5 / 10 minutes or off, 5 by default, and
// anything missing, malformed or unknown gives the default; a broken storage
// never throws; while balances are read again every N minutes a balance
// counts until N + 2 minutes old (never less than the 5-minute default), so
// it is not crossed out between two automatic reads, and once older it is out
// of date as before.
// Requires nothing beyond `npm ci`. How it can lie: the timer itself
// (src/portfolio-view.js setAutoRefresh / autoTick, page visibility) runs only
// in a browser and is not exercised here; test/browser-smoke.js checks the
// setting control.
import test from 'node:test';
import assert from 'node:assert/strict';
import { BALANCE_REFRESH_KEY, BALANCE_REFRESH_CHOICES, BALANCE_REFRESH_DEFAULT, parseBalanceRefresh, balanceRefreshNote, readBalanceRefresh, writeBalanceRefresh } from '../src/balance-refresh.js';
import { ASSETS, portfolioSnapshot, BALANCE_MAX_AGE } from '../src/portfolio.js';

const memory = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), m }; };

test('balance refresh: 5 minutes by default; only the offered choices are accepted', () => {
  assert.equal(BALANCE_REFRESH_DEFAULT, 5);
  assert.deepEqual([...BALANCE_REFRESH_CHOICES], [2, 5, 10, 0]);
  for (const c of BALANCE_REFRESH_CHOICES) assert.equal(parseBalanceRefresh(String(c)), c);
  for (const bad of [undefined, null, '', ' 5', '05', '3', '-1', '1e1', '5.0', '99', 'off', 5]) assert.equal(parseBalanceRefresh(bad), 5, String(bad));
});

test('balance refresh: storage round trip, and a broken storage falls back to the default', () => {
  const s = memory();
  assert.equal(readBalanceRefresh(s), 5, 'nothing stored');
  assert.equal(writeBalanceRefresh(s, 0), true);
  assert.equal(s.m.get(BALANCE_REFRESH_KEY), '0');
  assert.equal(readBalanceRefresh(s), 0);
  assert.equal(writeBalanceRefresh(s, 7), false, 'not an offered choice');
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.equal(readBalanceRefresh(throwing), 5);
  assert.equal(writeBalanceRefresh(throwing, 2), false);
  assert.equal(readBalanceRefresh(undefined), 5);
  assert.match(balanceRefreshNote(0), /when you press Refresh/);
  assert.match(balanceRefreshNote(10), /every 10 minutes/);
});

test('portfolio: with automatic reads a balance counts until two minutes past the next read', () => {
  const asset = ASSETS.find(a => a.priceId !== undefined);
  const now = 1_800_000_000_000;
  const balances = { [asset.key]: { state: 'ready', units: 1n, observedAt: now - 9 * 60000 } };
  const row = opts => portfolioSnapshot(balances, {}, now, [asset], {}, opts).rows[0];
  assert.equal(row().state, 'stale', 'default 5 minutes: 9 minutes old is out of date');
  assert.equal(row({ balanceMaxAge: (10 + 2) * 60000 }).state, 'ready', 'every 10 minutes: still counts at 9');
  balances[asset.key].observedAt = now - 13 * 60000;
  assert.equal(row({ balanceMaxAge: (10 + 2) * 60000 }).state, 'stale', 'past 12 minutes: out of date again');
  balances[asset.key].observedAt = now - 4.5 * 60000;
  assert.equal(row({ balanceMaxAge: (2 + 2) * 60000 }).state, 'ready', 'never shorter than the 5-minute default');
  assert.equal(BALANCE_MAX_AGE, 5 * 60000);
});
