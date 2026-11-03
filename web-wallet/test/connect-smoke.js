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
// Device & settings offers the automatic lock (15 minutes by default) and the
// automatic balance update (every 5 minutes by default, 0.1.93), each kept
// in this browser;
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
//
// Needs: dist/ (wallet) and dist-connect/ (Connect) built; the preview uses
// 127.0.0.1 port 4192 with --strictPort (browser-portfolio.js uses the same port,
// so do not run both at once; run from web-wallet/); CONNECT_URL replaces the
// server, then nothing is started and whatever answers there is tested, a stale
// build included. Chromium at CHROMIUM_PATH, otherwise Playwright's own.
// Leaves: nothing written; the browser is closed and the server stopped in finally.
// Falsely passes: "the wallet build has no Messages" is a text search of dist/ for
// the marker strings listed in the script, so a Messages part that uses other
// strings is not seen; the provider reads are mocks.
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
// The PQ networks' read hosts the portfolio contacts on open (observed in this script's
// run on 2026-11-03; endpoints in src/pq/*.js and src/ixios/network.js).
const PQ_READ_HOSTS = new Set(['mainnet-api.algonode.cloud', 'mainnet-api.soqu.org', 'mainnet.ckb.dev', 'qtc.events', 'api.xion-mainnet-1.burnt.com', 'quantum-rpc.splendor.org', 'testnet.asentum.com']);
let browser;
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ viewport: { width: 1280, height: 960 } });
  // UI pack 2026-11-03: the Reveal screen's Copy phrase button writes to the clipboard;
  // Home's Send is hidden while the selected network cannot send (checked in the Wallet section).
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  // REVEAL RECOVERY PHRASE in Device & settings on Connect (plan docs/plans/
  // approved/2026-11-03-reveal-phrase.md section 5; src/reveal-phrase.js,
  // src/app.js, src/connect-main.js setTab -> 'wallet-view-closed').
  // Proves: no password before saving, the password after saving (wrong:
  // refused; right: the 24 words); leaving the Wallet tab removes the words
  // and returning does not restore them; a reveal whose result arrives after
  // the tab was left is dropped (the reveal is submitted and the tab changed
  // in ONE synchronous page.evaluate, so the departure always precedes the
  // awaited result); after deleting the saved copy the open wallet reveals with
  // no password (plan section 7); the lock leaves no words. Falsely passes if
  // the words were never shown: each removal check follows a check that the 24
  // words of vectors[0].phrase were on screen, and the dropped-result check
  // also asserts that no decryptVault error text reached the status line.
  const shownWords = () => page.locator('#device-panel input[readonly]').evaluateAll(inputs => inputs.map(input => input.value));
  const revealButton = () => page.locator('#device-panel form:has(#reveal-password) button[type="submit"]');
  const revealNow = async () => { await revealButton().click(); await page.waitForFunction(() => document.querySelectorAll('#device-panel input[readonly]').length === 24); };
  const assertShown = async () => assert.equal((await shownWords()).join(' '), vectors[0].phrase);
  const assertNotShown = async () => assert.deepEqual(await shownWords(), []);
  const errors = [], unexpected = [], sockets = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const req = route.request();
    if (await historyRead(route)) return;
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
    // A VITE_ENABLE_IXIOS=true build (the release build) also reads IXIOS.
    if (await ixiosRead(route)) return;
    // Since 0.1.155 the portfolio reads the PQ networks' balances on open; those
    // reads are refused here (no answer is needed) and must never be a submission.
    if (PQ_READ_HOSTS.has(new URL(req.url()).hostname)) {
      assert.doesNotMatch(req.url() + ' ' + (req.postData() ?? ''), /send_transaction|broadcast|\/tx\/submit|\/txs\b/, 'a PQ read is never a submission');
      return route.abort();
    }
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
  // Send is a page of its own (src/app.js transferPage('send', $('send-form'))): its form is not on the Wallet view (BUGS W-40).
  assert.equal(await page.locator('#assets-panel').isVisible(), true, 'assets-panel');
  assert.equal(await page.locator('#send-form').isVisible(), false, 'send-form');
  for (const id of ['activity-panel', 'address-book-panel', 'device-panel', 'session-logs', 'stake-panel', 'vault-panel', 'evm-panel']) assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
  assert.equal(await page.locator('#tab-home').isVisible(), false);
  // UI pack 2026-11-03: Home's Send follows the selected network's ability to send. No node is
  // reachable here, so NODUS (the default) cannot send: hidden. Ethereum can: shown. Then NODUS again.
  const chooseNetwork = async chain => {
    if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
    const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
    const toggle = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');
    if (await toggle.count() && await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
    await badge.click();
  };
  assert.equal(await page.locator('#home-send').evaluate(node => node.hidden), true, 'Home Send hidden on NODUS without a node');
  await chooseNetwork('ethereum');
  await page.waitForFunction(() => document.querySelector('#home-send').hidden === false);
  await chooseNetwork('nodus');
  await page.waitForFunction(() => document.querySelector('#home-send').hidden === true);
  await page.locator('.wallet-navigation a[href="#settings"]').click();
  assert.equal(await page.locator('#device-panel').isVisible(), true);
  assert.equal(await page.locator('#wallet-home').isVisible(), false);
  assert.equal(await page.evaluate(() => location.hash), '#settings');
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'device-title');
  assert.equal(await page.locator('#vault-delete-details').evaluate(node => node.parentElement.id), 'device-panel');
  // Automatic lock (web 0.1.89): 15 minutes by default; "Never" warns and
  // is kept in this browser; the default comes back after choosing it.
  assert.equal(await page.locator('#auto-lock-minutes').inputValue(), '15');
  assert.match(await page.locator('#auto-lock-note').textContent(), /after 15 minutes without use/);
  await page.locator('#auto-lock-minutes').selectOption('0');
  assert.match(await page.locator('#auto-lock-note').textContent(), /shared or public device/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.autoLockMinutes')), '0');
  await page.locator('#auto-lock-minutes').selectOption('15');
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.autoLockMinutes')), '15');
  // Automatic balance updates (web 0.1.93): every 5 minutes by default; the
  // choice is kept in this browser and the portfolio line says so.
  assert.equal(await page.locator('#balance-refresh-minutes').inputValue(), '5');
  assert.match(await page.locator('#balance-refresh-note').textContent(), /every 5 minutes/);
  await page.locator('#balance-refresh-minutes').selectOption('0');
  assert.match(await page.locator('#balance-refresh-note').textContent(), /when you press Refresh/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.balanceRefreshMinutes')), '0');
  await page.locator('#balance-refresh-minutes').selectOption('5');
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.balanceRefreshMinutes')), '5');
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
  // Since 0.1.145 the row follows the selected network's contracts capability
  // (src/evm/ui.js showPanel; src/connect-main.js syncContractsRow); NODUS is selected.
  assert.equal(await page.locator('#more-contracts').isVisible(), true, 'Smart contracts row follows the NODUS contracts capability');
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
  // Reveal before saving: no password field; the words show, and saving removes them.
  assert.equal(await page.locator('#reveal-password').isVisible(), false);
  await assertNotShown(); await revealNow(); await assertShown();
  // UI pack 2026-11-03: the note, the framed words and the Copy phrase button; the copy reaches the clipboard only.
  assert.match(await page.locator('#device-panel .reveal-note').innerText(), /^Your 24 words control your wallet\. Never send them to anyone/);
  assert.equal(await page.locator('#device-panel .reveal-words').isVisible(), true);
  assert.equal(await page.getByRole('button', { name: 'Copy phrase' }).isVisible(), true);
  await page.getByRole('button', { name: 'Copy phrase' }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), vectors[0].phrase);
  assert.ok(!(await page.locator('#wallet-status').textContent()).includes('abandon'), 'the copied words reached the status line');
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
  // Saving ran updateVaultUI: the words shown before are gone; the password is now asked for.
  await assertNotShown();
  assert.equal(await page.locator('#reveal-password').isVisible(), true);
  await page.locator('#reveal-password').fill('public-connect-test-password-2026'); await revealNow(); await assertShown();
  assert.equal(await page.locator('#reveal-password').inputValue(), '');
  // Leaving the Wallet tab removes the words; returning does not restore them.
  await page.locator('.app-nav-item[data-tab="home"]').click();
  await assertNotShown();
  await page.locator('.app-nav-item[data-tab="wallet"]').click();
  assert.equal(await page.locator('#page-settings').isVisible(), true);
  await assertNotShown();
  // A reveal whose result arrives after the tab was left is dropped: submit and
  // leave in one synchronous call (the result is awaited, so it comes later).
  await page.locator('#reveal-password').fill('public-connect-test-password-2026');
  await page.evaluate(() => {
    document.querySelector('#device-panel form:has(#reveal-password)').requestSubmit();
    document.querySelector('.app-nav-item[data-tab="home"]').click();
  });
  await page.waitForFunction(() => !document.querySelector('#device-panel form:has(#reveal-password) button[type="submit"]').disabled);
  const decryptErrors = ['Incorrect password or damaged saved wallet.', 'Saved wallet is too large or invalid.', 'Invalid saved wallet.', 'Unsupported saved wallet format.', 'Use a local password of 12–1024 characters.'];
  const statusAfterDrop = await page.locator('#wallet-status').textContent();
  for (const text of decryptErrors) assert.equal(statusAfterDrop.includes(text), false, text);
  await assertNotShown();
  await page.locator('.app-nav-item[data-tab="wallet"]').click();
  assert.equal(await page.locator('#page-settings').isVisible(), true);
  await assertNotShown();
  // A wrong password is refused and shows nothing.
  await page.locator('#reveal-password').fill('incorrect-connect-password-2026'); await revealButton().click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Incorrect password or damaged saved wallet.'));
  await assertNotShown(); assert.equal(await page.locator('#reveal-password').inputValue(), '');
  await page.locator('#vault-delete-details summary').click();
  await page.locator('#vault-delete-confirm').check(); await page.locator('#vault-delete').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('deleted from this device'));
  // The open wallet is no longer saved: the words show with no password (plan section 7).
  assert.equal(await page.locator('#reveal-password').isVisible(), false);
  await revealNow(); await assertShown();
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
  await assertNotShown(); // the More tab click already left the Wallet tab; the lock leaves no words either
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
