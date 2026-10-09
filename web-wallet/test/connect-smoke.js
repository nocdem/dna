// Browser smoke test of the Nodus Connect site build (vite.connect.config.js,
// decision 2026-10-01-connect-own-origin.md). Run after `npm run build`
// (the wallet build: checked below for the ABSENCE of Messages) and
// `npm run build:connect`; this script serves dist-connect/ itself with
// `vite preview --config vite.connect.config.js` unless CONNECT_URL is set.
//
// What it proves: the page is the app shell (a start screen before unlock;
// after ONE unlock the Home, Chats, Wallet and More screens with a bottom
// bar on a narrow screen and a left rail on a wide one), with no second
// unlock screen; the Wallet screen shows Portfolio and Send / Receive only,
// and every other section is a page of its own (src/app.js wallet pages:
// Device & settings from the navigation, Logs from Device & settings,
// Address book from More; the browser's Back, the page's Back control and
// the lock each return to the wallet view, the lock clearing the hash; no
// Smart contracts row in More without the EVM generation); the
// "Delete saved wallet" control moves into Device & settings while open and
// back after lock; Chats is Messages, open LOCALLY with no node (local
// first: the own ID, the empty list and the add button at once, the status
// line connecting / not connected, the contact request's send button
// disabled under the connecting text and saving the profile refused
// offline); the Lock in More is the wallet's lock and
// closes Messages too; Home shows the unavailable chain-name entry offline;
// saving changes the device controls from Save to Change password, and deleting
// the saved copy restores the initial Save controls;
// the other site's fresh cross-site mark refuses an unlock (src/site-lock.js,
// through the real page wiring); no horizontal scroll at 390 px and 320 px;
// the wallet build has no app shell, Messages navigation or Messages UI code.
//
// How it can lie / what it does NOT cover: every node WebSocket is closed
// by the test (no network), so Messages only opens locally: a memory-only
// wallet (typed words, not saved at first; save/delete is checked later) with
// no history, so there is no contact,
// no conversation and no request — the composer's and the requests' offline
// refusals are not reached, and no kept history is shown. Whether the
// failed connection attempt has already been reported is not asserted (the
// status line may still say "Connecting…"). Sending, receiving, requests
// and profile editing need a live node and are not covered here. Groups:
// only the offline part of Chats (the Groups heading, "New group" disabled,
// the hidden group conversation) — no group flow runs without a node. Whether
// the browser stores the Secure cookie on
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
  assert.equal(await page.locator('#home-name-registration').isVisible(), true);
  assert.equal(await page.locator('#home-register-name').innerText(), 'Register a chain name');
  assert.equal(await page.locator('#home-register-name').isDisabled(), true);
  assert.match(await page.locator('#home-name-status').innerText(), /unavailable|Reading your name|Could not read/);
  assert.equal(await page.locator('#quick-name').isVisible(), false);
  assert.deepEqual(await page.locator('.app-nav-item .app-nav-label').allInnerTexts(), ['Home', 'Chats', 'Wallet', 'More']);
  assert.equal(await page.locator('.app-nav-item[aria-current="page"]').getAttribute('data-tab'), 'home');
  // Wide: the four entries are a left rail.
  const rail = await page.locator('.app-nav').boundingBox();
  assert.ok(rail.height > rail.width, `rail ${JSON.stringify(rail)}`);

  // Wallet: the wallet view is Portfolio and Send / Receive only; every
  // other section is its own page (src/app.js wallet pages, 0.1.75), named
  // by the URL hash, with a "Back to wallet" control; deleting the saved
  // wallet sits in Device & settings.
  await page.locator('.app-nav-item[data-tab="wallet"]').click();
  for (const id of ['assets-panel', 'send-form']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  for (const id of ['activity-panel', 'address-book-panel', 'device-panel', 'session-logs', 'stake-panel', 'vault-panel', 'evm-panel']) assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
  assert.equal(await page.locator('#tab-home').isVisible(), false);
  await page.locator('.wallet-navigation a[href="#settings"]').click();
  assert.equal(await page.locator('#device-panel').isVisible(), true);
  assert.equal(await page.locator('#wallet-home').isVisible(), false);
  assert.equal(await page.evaluate(() => location.hash), '#settings');
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'device-title');
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'device-panel');
  // Logs is a page of its own, reached from Device & settings.
  await page.locator('#device-panel a[href="#logs"]').click();
  assert.equal(await page.locator('#session-logs').isVisible(), true);
  assert.equal(await page.locator('#session-logs').evaluate(node => node.open), true);
  assert.equal(await page.locator('#device-panel').isVisible(), false);
  // The browser's Back returns to Device & settings, the page's Back control to the wallet view.
  await page.goBack();
  await page.waitForFunction(() => location.hash === '#settings');
  assert.equal(await page.locator('#device-panel').isVisible(), true);
  assert.equal(await page.locator('#session-logs').evaluate(node => node.open), false);
  await page.locator('#page-settings .page-back').click();
  await page.waitForFunction(() => location.hash === '');
  assert.equal(await page.locator('#wallet-home').isVisible(), true);
  assert.equal(await page.locator('#device-panel').isVisible(), false);
  assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('href')), '#settings');
  // More → Address book opens that page in the Wallet tab.
  await page.locator('.app-nav-item[data-tab="more"]').click();
  assert.equal(await page.locator('#more-contracts').isVisible(), false, 'no Smart contracts row without the EVM generation');
  await page.locator('#more-address-book').click();
  assert.equal(await page.locator('#tab-wallet').isVisible(), true);
  assert.equal(await page.locator('#address-book-panel').isVisible(), true);
  assert.equal(await page.evaluate(() => location.hash), '#address-book');
  await page.locator('#page-address-book .page-back').click();
  await page.waitForFunction(() => location.hash === '');

  // Chats: Messages, open LOCALLY with no node (local first): the own ID,
  // the (empty) list and the add button are there at once; the status line
  // says the network is not connected; every action that sends is refused.
  await page.locator('.app-nav-item[data-tab="chats"]').click();
  await page.locator('.messenger').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('.messenger')?.dataset.open === 'true');
  assert.equal(await page.locator('.messenger-chats').isVisible(), true);
  assert.equal(await page.locator('.messenger-chats .nc-bar-title').innerText(), 'Chats');
  assert.equal(await page.locator('.messenger').getAttribute('data-screen'), 'list');
  assert.equal(await page.locator('.messenger-state').isVisible(), false);
  assert.equal(await page.locator('.nc-chips').isVisible(), true);
  assert.equal(await page.locator('.nc-fab').isVisible(), true);
  assert.equal(await page.locator('#nc-own-id').textContent(), vectors[0].address);
  assert.notEqual(await page.locator('#home-id').textContent(), 'Appears when your wallet is open');
  // The status line: still connecting, or — once the first attempt failed
  // (every WebSocket is closed) — the reason and the retry. How long the
  // attempt takes is not asserted (no wait on it: a timing guess).
  assert.match(await page.locator('.messenger-sync').textContent(), /^(Connecting to the network… Your messages on this device are shown; sending opens once connected\.|Not connected to the network right now; trying again in \d+ seconds\. Your messages on this device are shown\.)$/);
  // Navigation is local and stays enabled.
  for (const label of ['Contact requests', 'Your ID & profile']) assert.equal(await page.locator(`.messenger-chats .nc-icon-button[title="${label}"]`).isDisabled(), false, label);
  // Add contact: the dialog opens; offline its send button waits, disabled,
  // under the connecting text (web 0.1.88, W-04 — it used to refuse every
  // press; a user pressed it 30+ times). Enter cannot submit either: a
  // form whose default button is disabled has no implicit submission.
  await page.locator('.nc-fab').click();
  await page.locator('#nc-add-dialog').waitFor({ state: 'visible' });
  await page.locator('#nc-add-id').fill(vectors[1].address);
  assert.equal(await page.locator('#nc-add-form button[type="submit"]').isDisabled(), true, 'send waits offline');
  assert.equal(await page.locator('#nc-add-form [role="status"]').textContent(), 'Messages is still connecting to the network. You can send the request once it is connected.');
  await page.locator('#nc-add-id').press('Enter');
  assert.equal(await page.locator('#nc-add-form [role="status"]').textContent(), 'Messages is still connecting to the network. You can send the request once it is connected.', 'Enter did not submit');
  await page.locator('#nc-add-form button', { hasText: 'Close' }).click();
  // Your ID & profile: the own ID; saving the profile is refused offline.
  await page.locator('.messenger-chats .nc-icon-button[title="Your ID & profile"]').click();
  assert.equal(await page.locator('.messenger').getAttribute('data-screen'), 'profile');
  assert.equal(await page.locator('#nc-own-id').isVisible(), true);
  await page.locator('#nc-profile-form button[type="submit"]').click();
  assert.equal(await page.locator('#nc-profile-form [role="status"]').textContent(), 'Your profile can be saved once Messages is connected to the network.');
  await page.locator('.messenger-profile .nc-back').click();
  assert.equal(await page.locator('.messenger').getAttribute('data-screen'), 'list');
  // The composer exists only inside the conversation screen (hidden here;
  // no contact, so no conversation offline — its offline Send gate is not
  // reached by this test).
  assert.equal(await page.locator('#nc-send-text').count(), 1);
  assert.equal(await page.locator('#nc-send-text').isVisible(), false);
  assert.equal(await page.locator('#nc-send-text').getAttribute('maxlength'), '4000');
  // Groups (package G3), offline: the Groups part of Chats is there with no
  // group and no invitation (an empty device), "New group" is refused until
  // Messages is connected (the button is disabled), and the group
  // conversation and its composer exist but are hidden. Creating, inviting,
  // joining, sending and reading need a live node and are not covered here.
  assert.equal(await page.locator('.nc-groups').isVisible(), true);
  assert.equal(await page.locator('.nc-groups-head h3').textContent(), 'Groups');
  assert.equal(await page.locator('.nc-groups-head button', { hasText: 'New group' }).isDisabled(), true);
  assert.equal(await page.locator('.nc-groups .contact-row').count(), 0);
  assert.equal(await page.locator('.messenger-group').isVisible(), false);
  assert.equal(await page.locator('#nc-group-text').count(), 1);
  assert.equal(await page.locator('#nc-group-text').isVisible(), false);

  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal scroll at ${width}px`);
    assert.equal(await page.locator('.messenger-chats').isVisible(), true);
    assert.equal(await page.locator('.messenger').getAttribute('data-open'), 'true');
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

  // The Connect copy of the save UI follows the same real storage states.
  await page.locator('.app-nav-item[data-tab="more"]').click();
  await page.locator('#more-device').click();
  await page.locator('#vault-storage-title').click();
  assert.equal(await page.locator('#vault-save').isVisible(), true);
  assert.equal(await page.locator('#vault-change').isVisible(), false);
  assert.equal(await page.locator('#vault-old-password').isVisible(), false);
  assert.equal(await page.locator('#vault-confirm-password').isVisible(), true);
  await page.locator('#vault-password').fill('public-connect-test-password-2026');
  await page.locator('#vault-confirm-password').fill('public-connect-test-password-typo');
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  assert.match(await page.locator('#vault-save-status').innerText(), /passwords do not match/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), null);
  await page.locator('#vault-confirm-password').fill('public-connect-test-password-2026');
  await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-save-status').textContent.includes('Encrypted wallet saved'));
  assert.equal(await page.locator('#vault-storage-title').innerText(), 'Change saved password');
  assert.equal(await page.locator('#vault-save').isVisible(), false);
  assert.equal(await page.locator('#vault-change').isVisible(), true);
  assert.equal(await page.locator('#vault-old-password').isVisible(), true);
  assert.equal(await page.locator('#vault-confirm-label').innerText(), 'Confirm new password');
  assert.equal(await page.locator('#vault-confirm-password').inputValue(), '');
  assert.match(await page.locator('#vault-save-explain').innerText(), /already saved/);
  await page.locator('#vault-delete-details summary').click();
  await page.locator('#vault-delete-confirm').check(); await page.locator('#vault-delete').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('deleted from this device'));
  assert.equal(await page.locator('#vault-storage-title').innerText(), 'Save wallet on this device (optional)');
  assert.equal(await page.locator('#vault-save').isVisible(), true);
  assert.equal(await page.locator('#vault-change').isVisible(), false);
  assert.equal(await page.locator('#vault-old-password').isVisible(), false);
  assert.equal(await page.locator('#vault-confirm-label').innerText(), 'Confirm password');

  // More: the Lock there is the wallet's lock; one lock closes both.
  await page.locator('.app-nav-item[data-tab="more"]').click();
  for (const id of ['more-profile', 'more-contacts', 'more-requests', 'more-device', 'lock']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  await page.locator('#lock').click();
  await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  assert.equal(await page.locator('#start-screen').isVisible(), true);
  assert.match(await page.locator('#wallet-status').innerText(), /Wallet locked/);
  // The lock closes the open page (Device & settings) and clears its hash.
  assert.equal(await page.evaluate(() => location.hash), '');
  assert.equal(await page.locator('#page-settings').evaluate(node => node.hidden), true);
  assert.equal(await page.locator('#wallet-home').evaluate(node => node.hidden), false);
  assert.equal(await page.locator('.messenger-state h3').textContent(), 'Messages');
  assert.equal(await page.locator('#nc-own-id').textContent(), '');
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'vault-delete-home');

  assert.equal(await page.locator('#home-name-registration').isVisible(), false);
  assert.equal(await page.locator('#home-register-name').isDisabled(), true);
  await page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
  await page.locator('#restore').click(); await pastePhrase(page, vectors[0].phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#tab-home').isVisible(), true);
  assert.equal(await page.locator('#home-name-registration').isVisible(), true);
  assert.equal(await page.locator('#home-register-name').isDisabled(), true);
  assert.match(await page.locator('#home-name-status').innerText(), /unavailable|Reading your name|Could not read/);
  await page.locator('.app-nav-item[data-tab="more"]').click(); await page.locator('#lock').click();

  assert.deepEqual(unexpected, []);
  assert.deepEqual(errors, []);
  console.log(`Nodus Connect smoke test passed (${sockets.length} node WebSocket(s) refused by the test): one unlock opens wallet and Messages (locally, offline sends refused), cross-site refusal, offline chain-name entry and lock/reopen reset, save/confirmation/delete controls, no horizontal scroll at 390/320 px.`);
} finally {
  await browser?.close();
  server?.stop();
}
