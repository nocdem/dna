// Browser smoke test of the Nodus Connect site build (vite.connect.config.js,
// decision 2026-10-01-connect-own-origin.md). Run after `npm run build`
// (the wallet build: checked below for the ABSENCE of Messages) and
// `npm run build:connect`; this script serves dist-connect/ itself with
// `vite preview --config vite.connect.config.js` unless CONNECT_URL is set.
//
// What it proves: one unlock opens the wallet dashboard AND gives Messages
// (nav entry, panel, two-pane layout, contacts column) with no second unlock
// screen; the panel's Lock is the wallet's lock; the other site's fresh
// cross-site mark refuses an unlock (src/site-lock.js, through the real page
// wiring); no horizontal scroll at 390 px and 320 px; the wallet build has
// no Messages navigation entry, panel, or Messages UI code.
//
// How it can lie / what it does NOT cover: every node WebSocket is closed
// by the test (no network), so Messages never opens: the contact list stays
// in its "appear here once Messages is open" state and the conversation
// composer (shown only for a selected contact with an agreed salt) is never
// reached. Sending, receiving, requests and profile editing need a live node
// and are not covered here. Whether the browser stores the Secure cookie on
// http://127.0.0.1 is not asserted (the rule fails open); the refusal is
// driven by a cookie the test adds.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { portfolioRead, cellframeRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';

// The wallet build: no Messages navigation, panel or UI code (static check).
const walletHtml = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
for (const marker of ['nav-messages', 'messages-panel', 'nc-root', 'connect-main']) assert.equal(walletHtml.includes(marker), false, `wallet dist/index.html contains ${marker}`);
const walletAssets = new URL('../dist/assets/', import.meta.url);
for (const name of readdirSync(walletAssets).filter(file => file.endsWith('.js') || file.endsWith('.css'))) {
  const text = readFileSync(new URL(name, walletAssets), 'utf8');
  for (const marker of ['nc-send-text', "sender's clock", 'waiting to send', 'Not a contact', 'messenger-sidebar', 'Your ID & profile']) {
    assert.equal(text.includes(marker), false, `wallet dist/assets/${name} contains "${marker}"`);
  }
}
console.log('Wallet build check passed: no Messages navigation entry, panel or Messages UI code in dist/.');

const url = process.env.CONNECT_URL || 'http://127.0.0.1:4192';
const server = process.env.CONNECT_URL ? null : spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--config', 'vite.connect.config.js', '--host', '127.0.0.1', '--port', '4192', '--strictPort'], { stdio: 'pipe' });
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/nodus-addresses.json', import.meta.url)));
let browser;
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ viewport: { width: 1280, height: 960 } });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const errors = [], unexpected = [], sockets = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const req = route.request();
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
    if (!req.url().startsWith(url + '/') || req.method() !== 'GET' || req.postData()) {
      unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
    }
    return route.continue();
  });
  // No node is reachable: every WebSocket is closed at once.
  await page.routeWebSocket(() => true, ws => { sockets.push(ws.url()); ws.close(); });

  await page.goto(url);
  await page.waitForFunction(() => !document.querySelector('#restore').disabled);
  assert.equal(await page.title(), 'Nodus Connect');
  assert.equal(await page.locator('.product-name').innerText(), 'Connect');
  assert.match(await page.locator('.site-address').innerText(), /connect\.nodusnetwork\.io/);

  // The other site's fresh mark refuses the unlock before any key is derived.
  await context.addCookies([{ name: 'nodus_open', value: `wallet.${Date.now()}`, url }]);
  await page.locator('#restore').click(); await pastePhrase(page, vectors[0].phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('wallet.nodusnetwork.io'));
  assert.equal(await page.locator('#wallet-status').innerText(), 'Your wallet is open on wallet.nodusnetwork.io. Lock it there first.');
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await context.clearCookies({ name: 'nodus_open' });

  // ONE unlock: the wallet dashboard opens, and Messages is part of it.
  await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#nc-start').count(), 0, 'no second unlock screen');
  for (const id of ['assets-panel', 'send-form', 'activity-panel', 'device-panel', 'messages-panel']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  const nav = await page.locator('.wallet-navigation a:visible').allInnerTexts();
  assert.ok(nav.includes('Messages'), `navigation: ${nav.join(', ')}`);

  await page.locator('#nav-messages').click();
  await page.locator('.messenger').waitFor({ state: 'visible' });
  assert.equal(await page.locator('.messenger-sidebar').isVisible(), true);
  assert.equal(await page.locator('.contact-list').isVisible(), true);
  assert.equal(await page.locator('.messenger-actions button').count(), 2);
  assert.equal(await page.locator('.requests-row').isVisible(), true);
  // Not open (no node): actions are disabled and the status is shown.
  assert.equal(await page.locator('.messenger-actions button').first().isDisabled(), true);
  assert.equal(await page.locator('.messenger-state').isVisible(), true);
  assert.match(await page.locator('.contact-empty').innerText(), /once Messages is open|Loading your contacts/);
  // The composer exists only inside the conversation view (hidden here).
  assert.equal(await page.locator('#nc-send-text').count(), 1);
  assert.equal(await page.locator('#nc-send-text').isVisible(), false);
  assert.equal(await page.locator('#nc-send-text').getAttribute('maxlength'), '4000');

  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal scroll at ${width}px`);
    assert.equal(await page.locator('.messenger').getAttribute('data-view'), 'state');
    assert.equal(await page.locator('.messenger-state').isVisible(), true);
  }
  await page.setViewportSize({ width: 1280, height: 960 });

  // The panel's Lock is the wallet's lock: one lock closes both.
  await page.locator('#messages-lock').click();
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  assert.match(await page.locator('#wallet-status').innerText(), /Wallet locked/);
  assert.equal(await page.locator('.messenger-state h4').textContent(), 'Messages');
  assert.equal(await page.locator('#nc-own-id').textContent(), '');

  assert.deepEqual(unexpected, []);
  assert.deepEqual(errors, []);
  console.log(`Nodus Connect smoke test passed (${sockets.length} node WebSocket(s) refused by the test): one unlock opens wallet and Messages, cross-site refusal, one lock, no horizontal scroll at 390/320 px.`);
} finally {
  await browser?.close();
  server?.kill();
}
