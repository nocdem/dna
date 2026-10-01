// src/site-lock.js — the cross-site "not both open" cookie (decision
// 2026-10-01-connect-own-origin.md). Pure parts, plus createSiteLock against
// a fake document / clock / interval (no browser: whether a real browser
// stores the Secure cookie is not covered here).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  COOKIE_NAME, REFRESH_MS, FRESH_MS, cookieDomain, markCookie, clearCookie, parseMarks, isFresh,
  otherSiteOpen, markIsOurs, refusalText, lockedText, createSiteLock
} from '../src/site-lock.js';

const NOW = 1_780_000_000_000;

test('Domain=nodusnetwork.io only on a nodusnetwork.io subdomain', () => {
  assert.equal(cookieDomain('wallet.nodusnetwork.io'), 'nodusnetwork.io');
  assert.equal(cookieDomain('connect.nodusnetwork.io'), 'nodusnetwork.io');
  for (const host of ['localhost', '127.0.0.1', 'nodusnetwork.io', 'evil-nodusnetwork.io', 'nodusnetwork.io.evil.com', '', undefined]) assert.equal(cookieDomain(host), null, String(host));
});

test('the mark cookie carries only the site and the time, with the required attributes', () => {
  assert.equal(markCookie('wallet', NOW, 'wallet.nodusnetwork.io'),
    `nodus_open=wallet.${NOW}; Path=/; Max-Age=15; Secure; SameSite=Strict; Domain=nodusnetwork.io`);
  assert.equal(markCookie('connect', NOW, '127.0.0.1'), `nodus_open=connect.${NOW}; Path=/; Max-Age=15; Secure; SameSite=Strict`);
  assert.equal(clearCookie('connect.nodusnetwork.io'), 'nodus_open=; Path=/; Max-Age=0; Secure; SameSite=Strict; Domain=nodusnetwork.io');
  assert.equal(clearCookie('localhost'), 'nodus_open=; Path=/; Max-Age=0; Secure; SameSite=Strict');
  assert.throws(() => markCookie('other', NOW, 'localhost'), /Unknown site/);
  assert.throws(() => markCookie('wallet', -1, 'localhost'), /Invalid time/);
  assert.throws(() => markCookie('wallet', 1.5, 'localhost'), /Invalid time/);
  assert.equal(COOKIE_NAME, 'nodus_open'); assert.equal(REFRESH_MS, 5000); assert.equal(FRESH_MS, 15000);
});

test('parseMarks reads well-formed marks and ignores everything else', () => {
  assert.deepEqual(parseMarks(`a=1; ${COOKIE_NAME}=wallet.${NOW}; b=2`), [{ site: 'wallet', ms: NOW }]);
  assert.deepEqual(parseMarks(`nodus_open=connect.5;nodus_open=wallet.7`), [{ site: 'connect', ms: 5 }, { site: 'wallet', ms: 7 }]);
  for (const bad of ['', 'nodus_open=', 'nodus_open=wallet', 'nodus_open=wallet.', 'nodus_open=wallet.01', 'nodus_open=wallet.-5',
    'nodus_open=other.5', 'nodus_open=wallet.5x', 'xnodus_open=wallet.5', 'nodus_open=wallet.12345678901234567', undefined, null]) {
    assert.deepEqual(parseMarks(bad), [], String(bad));
  }
});

test('a mark is fresh for less than 15 s, and not when it is far in the future', () => {
  assert.equal(isFresh({ site: 'wallet', ms: NOW }, NOW), true);
  assert.equal(isFresh({ site: 'wallet', ms: NOW - FRESH_MS + 1 }, NOW), true);
  assert.equal(isFresh({ site: 'wallet', ms: NOW - FRESH_MS }, NOW), false);
  assert.equal(isFresh({ site: 'wallet', ms: NOW + 1000 }, NOW), true);
  assert.equal(isFresh({ site: 'wallet', ms: NOW + FRESH_MS }, NOW), false);
  assert.equal(isFresh(null, NOW), false);
});

test('only the OTHER site\'s fresh mark counts', () => {
  assert.equal(otherSiteOpen(`nodus_open=wallet.${NOW}`, 'connect', NOW + 1000), 'wallet');
  assert.equal(otherSiteOpen(`nodus_open=wallet.${NOW}`, 'wallet', NOW + 1000), null);
  assert.equal(otherSiteOpen(`nodus_open=wallet.${NOW}`, 'connect', NOW + FRESH_MS), null);
  assert.equal(otherSiteOpen(`nodus_open=connect.${NOW}`, 'wallet', NOW), 'connect');
  assert.equal(otherSiteOpen('', 'wallet', NOW), null);
  assert.equal(markIsOurs(`nodus_open=connect.${NOW}`, 'connect'), true);
  assert.equal(markIsOurs(`nodus_open=connect.${NOW}`, 'wallet'), false);
  assert.throws(() => otherSiteOpen('', 'x', NOW), /Unknown site/);
});

test('plain words name the other site', () => {
  assert.equal(refusalText('wallet'), 'Your wallet is open on wallet.nodusnetwork.io. Lock it there first.');
  assert.equal(refusalText('connect'), 'Nodus Connect is open on connect.nodusnetwork.io. Lock it there first.');
  assert.match(lockedText('wallet'), /wallet\.nodusnetwork\.io/);
  assert.match(lockedText('connect'), /connect\.nodusnetwork\.io/);
});

// A fake page: document.cookie keeps the last value per name like a browser
// would (Max-Age=0 removes it); intervals run only when the test says so.
function fakePage(hostname = 'connect.nodusnetwork.io') {
  const jar = new Map(), writes = [];
  const doc = {
    get cookie() { return [...jar].map(([k, v]) => `${k}=${v}`).join('; '); },
    set cookie(value) {
      writes.push(value);
      const [pair, ...attrs] = value.split(';');
      const at = pair.indexOf('=');
      const name = pair.slice(0, at), val = pair.slice(at + 1);
      if (attrs.some(a => a.trim() === 'Max-Age=0')) jar.delete(name); else jar.set(name, val);
    }
  };
  let time = NOW, timer = null, nextId = 1;
  return {
    doc, jar, writes, hostname,
    now: () => time, advance(ms) { time += ms; },
    every(fn, ms) { assert.equal(ms, REFRESH_MS); timer = { id: nextId++, fn }; return timer.id; },
    stopEvery(id) { if (timer?.id === id) timer = null; },
    tick() { timer?.fn(); },
    get running() { return timer !== null; }
  };
}

test('createSiteLock: start writes the mark at once and refreshes it every tick', () => {
  const page = fakePage();
  const lock = createSiteLock({ site: 'connect', doc: page.doc, hostname: page.hostname, now: page.now, every: page.every, stopEvery: page.stopEvery });
  assert.equal(lock.otherOpen(), null);
  lock.start();
  assert.equal(page.jar.get(COOKIE_NAME), `connect.${NOW}`);
  assert.match(page.writes[0], /; Domain=nodusnetwork\.io$/);
  page.advance(REFRESH_MS); page.tick();
  assert.equal(page.jar.get(COOKIE_NAME), `connect.${NOW + REFRESH_MS}`);
  assert.equal(lock.running, true);
  lock.stop();
  assert.equal(page.jar.has(COOKIE_NAME), false, 'own mark cleared on stop');
  assert.equal(page.running, false);
});

test('createSiteLock: the other site\'s fresh mark refuses unlock and locks a running page', () => {
  const page = fakePage();
  const seen = [];
  const lock = createSiteLock({ site: 'connect', doc: page.doc, hostname: page.hostname, now: page.now, every: page.every, stopEvery: page.stopEvery, onOther: text => seen.push(text) });
  page.jar.set(COOKIE_NAME, `wallet.${NOW}`);
  assert.equal(lock.otherOpen(), 'Your wallet is open on wallet.nodusnetwork.io. Lock it there first.');
  page.advance(FRESH_MS);
  assert.equal(lock.otherOpen(), null, 'a stale mark does not refuse');
  lock.start();
  assert.equal(page.jar.get(COOKIE_NAME), `connect.${NOW + FRESH_MS}`);
  // The wallet site takes over (its own check passed before our next tick).
  page.jar.set(COOKIE_NAME, `wallet.${NOW + FRESH_MS + 1}`);
  page.advance(REFRESH_MS); page.tick();
  assert.deepEqual(seen, [lockedText('wallet')]);
  assert.equal(lock.running, false);
  assert.equal(page.jar.get(COOKIE_NAME), `wallet.${NOW + FRESH_MS + 1}`, 'the other site\'s mark is never cleared');
  lock.stop();
  assert.equal(page.jar.get(COOKIE_NAME), `wallet.${NOW + FRESH_MS + 1}`);
});

test('createSiteLock: no Domain attribute on localhost, and an unreadable cookie fails open', () => {
  const page = fakePage('127.0.0.1');
  const lock = createSiteLock({ site: 'wallet', doc: page.doc, hostname: page.hostname, now: page.now, every: page.every, stopEvery: page.stopEvery });
  lock.start();
  assert.doesNotMatch(page.writes[0], /Domain=/);
  lock.stop();
  const broken = createSiteLock({ site: 'wallet', doc: { get cookie() { throw new Error('blocked'); }, set cookie(_) { throw new Error('blocked'); } }, hostname: 'localhost', now: page.now, every: page.every, stopEvery: page.stopEvery });
  assert.equal(broken.otherOpen(), null);
  broken.start(); broken.stop();
});
