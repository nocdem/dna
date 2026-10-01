// Browser smoke test of the Nodus Connect site build (vite.connect.config.js,
// decision 2026-10-01-connect-own-origin.md). Run after `npm run build`
// (the wallet build: checked below for the ABSENCE of Messages) and
// `npm run build:connect`; this script serves dist-connect/ itself with
// `vite preview --config vite.connect.config.js` unless CONNECT_URL is set.
//
// What it proves: the page is the app shell (a start screen before unlock;
// after ONE unlock the Home, Chats, Wallet and More screens with a bottom
// bar on a narrow screen and a left rail on a wide one), with no second
// unlock screen; the Wallet screen holds the wallet's sections and the
// "Delete saved wallet" control moves into Device & settings while open and
// back after lock; Chats is Messages (its Chats screen, status shown while
// not open); the Lock in More is the wallet's lock and closes Messages too;
// the other site's fresh cross-site mark refuses an unlock (src/site-lock.js,
// through the real page wiring); no horizontal scroll at 390 px and 320 px;
// the wallet build has no app shell, Messages navigation or Messages UI code.
//
// How it can lie / what it does NOT cover: every node WebSocket is closed
// by the test (no network), so Messages never opens: Chats stays in its
// status state (no chips, no list, no add-contact button) and the
// conversation, contacts and profile screens and the add-contact dialog are
// never reached. Sending, receiving, requests and profile editing need a live
// node and are not covered here. Home's ID stays "Appears when Messages is
// connected". Whether the browser stores the Secure cookie on
// http://127.0.0.1 is not asserted (the rule fails open); the refusal is
// driven by a cookie the test adds.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { startPreview } from './preview-server.js';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { portfolioRead, cellframeRead, ixiosRead, historyRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';

// The wallet build: no app shell, Messages navigation or UI code (static check).
const walletHtml = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
for (const marker of ['app-nav', 'nav-chats', 'tab-chats', 'nc-root', 'connect-main']) assert.equal(walletHtml.includes(marker), false, `wallet dist/index.html contains ${marker}`);
const walletAssets = new URL('../dist/assets/', import.meta.url);
for (const name of readdirSync(walletAssets).filter(file => file.endsWith('.js') || file.endsWith('.css'))) {
  const text = readFileSync(new URL(name, walletAssets), 'utf8');
  for (const marker of ['nc-send-text', "sender's clock", 'waiting to send', 'Not a contact', 'messenger-chats', 'Your ID & profile', 'app-nav-item', 'nc-bar-title']) {
    assert.equal(text.includes(marker), false, `wallet dist/assets/${name} contains "${marker}"`);
  }
}
console.log('Wallet build check passed: no app shell, Messages navigation or Messages UI code in dist/.');

const url = process.env.CONNECT_URL || 'http://127.0.0.1:4192';
const server = process.env.CONNECT_URL ? null : await startPreview(['node_modules/vite/bin/vite.js', 'preview', '--config', 'vite.connect.config.js', '--host', '127.0.0.1', '--port', '4192', '--strictPort'], 4192);
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
    if (await historyRead(route)) return;
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
    // A VITE_ENABLE_IXIOS=true build (the release build) also reads IXIOS.
    if (await ixiosRead(route)) return;
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

  // ONE unlock: the app opens on Home; Messages is its Chats screen.
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'vault-delete-home');
  await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#nc-start').count(), 0, 'no second unlock screen');
  assert.equal(await page.locator('#start-screen').isVisible(), false);
  assert.equal(await page.locator('#tab-home').isVisible(), true);
  assert.deepEqual(await page.locator('.app-nav-item .app-nav-label').allInnerTexts(), ['Home', 'Chats', 'Wallet', 'More']);
  assert.equal(await page.locator('.app-nav-item[aria-current="page"]').getAttribute('data-tab'), 'home');
  // Wide: the four entries are a left rail.
  const rail = await page.locator('.app-nav').boundingBox();
  assert.ok(rail.height > rail.width, `rail ${JSON.stringify(rail)}`);

  // Wallet: the wallet's own sections; deleting the saved wallet sits in Device & settings.
  await page.locator('.app-nav-item[data-tab="wallet"]').click();
  for (const id of ['assets-panel', 'send-form', 'activity-panel', 'device-panel']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  assert.equal(await page.locator('#tab-home').isVisible(), false);
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'device-panel');

  // Chats: Messages, not open (no node) — its status, no list or add button.
  await page.locator('.app-nav-item[data-tab="chats"]').click();
  await page.locator('.messenger').waitFor({ state: 'visible' });
  assert.equal(await page.locator('.messenger-chats').isVisible(), true);
  assert.equal(await page.locator('.messenger-chats .nc-bar-title').innerText(), 'Chats');
  assert.equal(await page.locator('.messenger').getAttribute('data-screen'), 'list');
  assert.equal(await page.locator('.messenger').getAttribute('data-open'), 'false');
  assert.equal(await page.locator('.messenger-state').isVisible(), true);
  assert.equal(await page.locator('.nc-chips').isVisible(), false);
  assert.equal(await page.locator('.nc-fab').isVisible(), false);
  for (const label of ['Contact requests', 'Your ID & profile']) assert.equal(await page.locator(`.messenger-chats .nc-icon-button[title="${label}"]`).isDisabled(), true, label);
  // The composer exists only inside the conversation screen (hidden here).
  assert.equal(await page.locator('#nc-send-text').count(), 1);
  assert.equal(await page.locator('#nc-send-text').isVisible(), false);
  assert.equal(await page.locator('#nc-send-text').getAttribute('maxlength'), '4000');

  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal scroll at ${width}px`);
    assert.equal(await page.locator('.messenger-state').isVisible(), true);
    // Narrow: the four entries are a bottom bar.
    const bar = await page.locator('.app-nav').boundingBox();
    assert.ok(bar.width > bar.height && Math.abs(bar.y + bar.height - 844) < 2, `bottom bar at ${width}px: ${JSON.stringify(bar)}`);
    for (const name of ['home', 'wallet', 'more']) {
      await page.locator(`.app-nav-item[data-tab="${name}"]`).click();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal scroll at ${width}px on ${name}`);
    }
    await page.locator('.app-nav-item[data-tab="chats"]').click();
  }
  await page.setViewportSize({ width: 1280, height: 960 });

  // More: the Lock there is the wallet's lock; one lock closes both.
  await page.locator('.app-nav-item[data-tab="more"]').click();
  for (const id of ['more-profile', 'more-contacts', 'more-requests', 'more-device', 'lock']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  await page.locator('#lock').click();
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  assert.equal(await page.locator('#start-screen').isVisible(), true);
  assert.match(await page.locator('#wallet-status').innerText(), /Wallet locked/);
  assert.equal(await page.locator('.messenger-state h3').textContent(), 'Messages');
  assert.equal(await page.locator('#nc-own-id').textContent(), '');
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'vault-delete-home');

  assert.deepEqual(unexpected, []);
  assert.deepEqual(errors, []);
  console.log(`Nodus Connect smoke test passed (${sockets.length} node WebSocket(s) refused by the test): one unlock opens wallet and Messages, cross-site refusal, one lock, no horizontal scroll at 390/320 px.`);
} finally {
  await browser?.close();
  server?.stop();
}
