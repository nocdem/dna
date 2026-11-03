import { portfolioRead, cellframeRead, ixiosRead, historyRead } from './portfolio-routes.js';
import { pastePhrase, readPhrase } from './browser-phrase.js';
import { AUTO_LOCK_KEY } from '../src/auto-lock.js';
import { BALANCE_REFRESH_KEY } from '../src/balance-refresh.js';
import { SHOW_ZERO_KEY } from '../src/zero-balances.js';
import { CHAINS } from '../src/config.js';
// Run after npm run build. Every external request is intercepted.
// Proves, on the web build: wallet create / restore / backup, the Nodus and
// external addresses, the Send and Receive pages and the receive QR (decoded to
// the shown address), signed ETH/ERC20 sends against a mocked node, the wrong-
// network guard, Cellframe balance and error states, activity, saved-wallet
// controls, the settings page, the rail, licence text and the footer version.
// Needs: dist/ built; the script starts `vite preview` itself on 127.0.0.1 port
// 4173 with --strictPort (run from web-wallet/), and preview-server.js refuses a
// port that already answers, so do not start a preview first. WALLET_URL replaces
// the server: nothing is started and whatever answers there is tested. Chromium
// at CHROMIUM_PATH, otherwise Playwright's own. jsqr and fixtures/nodus-addresses.json.
// Leaves: SHOT_DIR/receive-page.png when SHOT_DIR is set; nothing else (fresh
// browser context, closed with the server in finally).
// Falsely passes: every provider and every broadcast is the script's mock; zero
// balances are forced visible by an init script (hiding is checked in
// browser-portfolio.js); the footer version is compared with package.json, so a
// dist built at another version fails, but a stale build of the same version passes.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
// jsQR decodes the receive QR in Node. The page CSP (script-src 'self') blocks
// an injected inline <script>, so the pixels are drawn in the page and decoded here.
const jsQR = createRequire(import.meta.url)('jsqr');
const nodusAddress = JSON.parse(readFileSync(new URL('./fixtures/nodus-addresses.json', import.meta.url))).vectors[0].address;
import { startPreview } from './preview-server.js';
import { setTimeout } from 'node:timers/promises';
const url = process.env.WALLET_URL || 'http://127.0.0.1:4173';
const server = process.env.WALLET_URL ? null : await startPreview(['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4173', '--strictPort'], 4173);
import { chromium } from 'playwright';
import { Transaction, Interface, HDNodeWallet } from 'ethers';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 960 } });
page.setDefaultTimeout(10000);
// This suite works with every asset row, held or not: zero balances shown
// (Device & settings, src/zero-balances.js, 0.1.113 — hidden by default; the
// hiding itself is checked in test/browser-portfolio.js).
await page.addInitScript(key => { try { localStorage.setItem(key, '1'); } catch { /* storage refused */ } }, SHOW_ZERO_KEY);
const errors = [], broadcasts = [], calls = [];
page.on('pageerror', error => errors.push(error.message));
await page.routeWebSocket(() => true, ws => ws.close());
let cellframeBalance = '5', cellframeFail = false, networkId = '0x1', finalized = false;
const historySeen = [];
await page.route('**/*', async route => {
  const req = route.request();
  if (req.url().startsWith(url + '/')) return route.continue();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' } });
  // One received ETH transfer in the account history (Blockscout fixture).
  if (await historyRead(route, { ethereum: address => [{ hash: '0x' + 'ab'.repeat(32), timeStamp: '1790000000', from: '0x' + '12'.repeat(20), to: address, value: '1500000000000000000', isError: '0', txreceipt_status: '1' }], seen: historySeen })) return;
  if (await cellframeRead(route, { balance: cellframeBalance, fail: cellframeFail })) return;
  if (await portfolioRead(route, { ethereum: false })) return;
  if (await ixiosRead(route)) return;
  // New PQ readers are outside this EVM smoke fixture. Model their provider
  // unavailability explicitly, and never forward an unmatched chain request.
  // Compare parsed URLs: the configured endpoint has no trailing slash, the request does.
  if (new URL(req.url()).href !== new URL(CHAINS.ethereum.endpoint).href || req.method() !== 'POST') return route.abort('blockedbyclient');
  const body = req.postDataJSON(); calls.push(body);
  assert.ok(!JSON.stringify(body).includes(phrase));
  const process = call => {
    if (call.method === 'eth_getTransactionReceipt') return { jsonrpc: '2.0', id: call.id, result: finalized ? { transactionHash: call.params[0], blockHash: '0x' + 'a'.repeat(64), blockNumber: '0x1', status: '0x1' } : null };
    const result = { eth_getTransactionReceipt: null, eth_chainId: networkId, eth_getBalance: '0x8ac7230489e80000', eth_call: '0x' + '0'.repeat(64), eth_estimateGas: '0x5208', eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x0', eth_getBlockByNumber: { hash: '0x' + 'a'.repeat(64), parentHash: '0x' + 'b'.repeat(64), number: '0x1', timestamp: '0x65000000', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x5208', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } }[call.method];
    if (call.method === 'eth_sendRawTransaction') { broadcasts.push(Transaction.from(call.params[0])); return { jsonrpc: '2.0', id: call.id, result: Transaction.from(call.params[0]).hash }; }
    assert.notEqual(result, undefined, `Unexpected RPC method ${call.method}`);
    return { jsonrpc: '2.0', id: call.id, result };
  };
  return route.fulfill({ json: Array.isArray(body) ? body.map(process) : process(body) });
});
// A grant is observed by the page before it opens the wallet, so "held" can be
// read once; a release reaches the browser's lock manager asynchronously, so
// "released" is waited for (the 10 s page timeout fails it if it never happens).
const sessionHeld = () => page.evaluate(async () => (await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
const sessionReleased = () => page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
// Wallet pages (src/app.js, 0.1.75; Send and Receive since 0.1.145): everything
// but Portfolio is a page of its own, opened from the wallet's navigation; the
// page's Back control returns to the wallet view.
const WALLET_PAGES = ['send', 'receive', 'earn', 'vaults', 'contracts', 'wallet-activity', 'address-book', 'settings', 'logs'];
// The network chips live in the closed network disclosure (src/app.js:2307);
// #chain itself is hidden. Same steps as the extension layout suite.
const selectNetwork = async chain => {
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
  const toggle = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');
  if (await toggle.count() && await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  await badge.click();
};
const openPage = async name => { await page.locator(`.wallet-navigation a[href="#${name}"]`).click(); await page.locator(`#page-${name}`).waitFor({ state: 'visible' }); };
// Send and Receive pages carry no Back control (src/app.js:2320-2322); the rail's
// Portfolio link ('#') returns to the wallet view from them.
const walletView = async () => { const back = page.locator('.wallet-page:not([hidden]) .page-back'); if (await back.count()) await back.click(); else if (await page.locator('.wallet-page:not([hidden])').count()) await page.locator('.wallet-navigation a[href="#"]').click(); await page.locator('#wallet-home').waitFor({ state: 'visible' }); };
// REVEAL RECOVERY PHRASE in Device & settings (plan docs/plans/approved/
// 2026-11-03-reveal-phrase.md section 5; src/reveal-phrase.js, src/app.js).
// Proves, on the web page: a wallet that is not saved reveals its 24 words with
// no password field; a saved wallet that is open from its saved copy asks for
// the password again (wrong: refused, no words; right: the 24 words); a
// temporary session over a saved copy reveals with no password (orchestrator
// decision, plan section 0 items 5-6); Back, Logs and Lock remove the words;
// the words never reach localStorage, sessionStorage or the session log; the
// reveal ids do not duplicate #phrase-1. The storage-unreadable state is not
// driven here. Leaves nothing behind (storage is checked empty / unchanged).
// Falsely passes if the words were never shown: every "removed" check follows a
// check that exactly the 24 words equal to `phrase` were on screen.
const shownWords = () => page.locator('#device-panel input[readonly]').evaluateAll(inputs => inputs.map(input => input.value));
const revealButton = () => page.locator('#device-panel form:has(#reveal-password) button[type="submit"]');
const revealNow = async () => { await revealButton().click(); await page.waitForFunction(() => document.querySelectorAll('#device-panel input[readonly]').length === 24); };
const assertShown = async () => assert.equal((await shownWords()).join(' '), phrase);
const assertNotShown = async () => assert.deepEqual(await shownWords(), []);
// Serializes the receive QR <svg>, draws it through an <img> (data: URL, allowed
// by img-src) onto a white canvas at 4 px per module, and decodes the pixels
// with jsQR. Returns the decoded text, or undefined when nothing decodes.
async function decodeQr() {
  const image = await page.evaluate(async () => {
    const svg = document.querySelector('#receive-qr svg');
    if (!svg) return null;
    const size = Number(svg.getAttribute('width')) * 4, img = new Image();
    await new Promise((loaded, failed) => { img.onload = loaded; img.onerror = failed; img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(new XMLSerializer().serializeToString(svg)); });
    const canvas = document.createElement('canvas'); canvas.width = size; canvas.height = size;
    const context = canvas.getContext('2d'); context.imageSmoothingEnabled = false;
    context.fillStyle = '#ffffff'; context.fillRect(0, 0, size, size); context.drawImage(img, 0, 0, size, size);
    return { width: size, height: size, data: Array.from(context.getImageData(0, 0, size, size).data) };
  });
  assert.ok(image, 'receive QR is drawn');
  return jsQR(Uint8ClampedArray.from(image.data), image.width, image.height)?.data;
}
const qrEmpty = () => page.locator('#receive-qr').evaluate(node => node.childElementCount === 0);
// The Refresh buttons are hidden while balances update automatically
// (0.1.108); pressed through the page once enabled (a read in flight disables
// them), as a click on the visible button waited for before.
const pressRefresh = id => page.waitForFunction(id => { const b = document.getElementById(id); if (b.disabled) return false; b.click(); return true; }, id);
try {
  await page.goto(url);
  await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  assert.doesNotMatch(await page.locator('body').innerText(), /Check CPUNK|CF-20|Cellframe|CPUNK/);
  await page.locator('#restore').click(); await pastePhrase(page, phrase); await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  // Single-tab rule: an open wallet holds the session lock; one tab alone is never refused.
  assert.equal(await sessionHeld(), true); assert.equal(await page.locator('#session-conflict').isVisible(), false);
  // NODUS leads every list and is the network selected when the page loads: its
  // locally derived address is the receive address, sending is off, no explorer.
  assert.equal(await page.locator('#chain option').first().getAttribute('value'), 'nodus');
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  // Send and Receive are separate pages since 0.1.145 (0b3b0eb0d); the Send
  // heading names the selected network; the QR encodes exactly the shown address.
  assert.equal(await page.locator('#send-title').innerText(), 'Send · Nodus');
  assert.equal(await page.locator('#receive-qr svg').getAttribute('role'), 'img');
  assert.equal(await page.locator('#receive-qr svg').getAttribute('aria-label'), 'QR code for the receive address');
  // 0.1.104 (operator: "auto lock … 10 minutes yazıyor … settings'ten okuması
  // lazım"): the bar says the chosen time and follows a change.
  assert.equal(await page.locator('#session-timeout').innerText(), 'Auto-lock after 15 minutes of inactivity');
  await page.locator('#auto-lock-minutes').evaluate(select => { select.value = '5'; select.dispatchEvent(new Event('change')); });
  assert.equal(await page.locator('#session-timeout').innerText(), 'Auto-lock after 5 minutes of inactivity');
  await page.locator('#auto-lock-minutes').evaluate(select => { select.value = '0'; select.dispatchEvent(new Event('change')); });
  assert.equal(await page.locator('#session-timeout').innerText(), 'Auto-lock off');
  await page.locator('#auto-lock-minutes').evaluate(select => { select.value = '15'; select.dispatchEvent(new Event('change')); });
  await page.evaluate(key => localStorage.removeItem(key), AUTO_LOCK_KEY);   // the choice was kept; this test expects no storage later
  // 0.1.108 (operator: "refresh networks … Ona da gerek yok. Otomatik refresh
  // ediyoruz zaten"): both Refresh buttons are hidden while balances update
  // automatically (the default) and come back when that is turned Off.
  for (const id of ['portfolio-refresh', 'refresh']) assert.equal(await page.locator(`#${id}`).isVisible(), false, `${id} hidden`);
  await page.locator('#balance-refresh-minutes').evaluate(select => { select.value = '0'; select.dispatchEvent(new Event('change')); });
  assert.equal(await page.locator('#portfolio-refresh').isHidden(), false, 'portfolio-refresh back with automatic updates Off');
  // style.css:1012 (0b3b0eb0d): the asset panel's own Refresh stays hidden; the card's is the control.
  assert.equal(await page.locator('#refresh').isHidden(), true, 'asset-panel refresh stays hidden');
  await page.locator('#balance-refresh-minutes').evaluate(select => { select.value = '5'; select.dispatchEvent(new Event('change')); });
  await page.evaluate(key => localStorage.removeItem(key), BALANCE_REFRESH_KEY);
  // Receive is its own page (0.1.145): the QR and address status are checked there.
  await openPage('receive');
  // 0.1.102 (operator: "sol tarafına yapışık … ortalayalım"): centred in its panel
  const qrGap = await page.locator('#receive-qr svg').evaluate(svg => { const s = svg.getBoundingClientRect(), p = svg.parentElement.getBoundingClientRect(); return [s.left - p.left, p.right - s.right]; });
  assert.ok(Math.abs(qrGap[0] - qrGap[1]) <= 2, `QR centred (left ${qrGap[0]}, right ${qrGap[1]})`);
  assert.equal(await decodeQr(), await page.locator('#receive-address').innerText());
  // UI pack 2026-11-03 (operator "2"): "Derived locally…" is gone from the status line; no node is reachable
  // in this script, so the line may still hold a connection-state remainder. It is visible exactly when it has text.
  const nodusStatus = await page.locator('#nodus-address-status').textContent();
  assert.doesNotMatch(nodusStatus, /Derived locally/);
  assert.equal(await page.locator('#nodus-address-status').isVisible(), nodusStatus.trim() !== '');
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  await walletView();
  // UI pack 2026-11-03 (operator "send tusunu kaldir gecsin"): until a node connection is ready (never,
  // here: no node is reachable) NODUS cannot send, so Send is not offered at all; the hidden shortcut
  // button keeps its disabled state for the code paths that read it.
  assert.equal(await page.locator('.wallet-navigation a[href="#send"]').isVisible(), false);
  assert.equal(await page.locator('#quick-send').isDisabled(), true);
  assert.equal(await page.locator('#balances .balance-note, #balances .balance-error').count(), 0, 'no note under any coin');
  assert.equal(await page.locator('#account-explorer').evaluate(node => node.hidden), true);
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), true);
  assert.equal(await page.locator('#activity').textContent(), '');
  // The wallet view is the Portfolio; every other section, Send and Receive
  // included (0.1.145), is a page, not shown until opened.
  assert.equal(await page.locator('#wallet-home').isVisible(), true);
  for (const name of WALLET_PAGES) assert.equal(await page.locator(`#page-${name}`).isVisible(), false, name);
  // Portfolio (0.1.145 network groups; 0.1.153 defaults): every wallet-view
  // opening hides zero and unavailable balances (src/app.js:1116, 2338-2343);
  // the asset panel's Hide zero balances box lists every network. No filters.
  assert.equal(await page.locator('#show-zero-balances').isChecked(), true);
  assert.equal(await page.locator('#portfolio-filters button').count(), 0);
  // 0.1.103: a light, the words in the title / accessible name
  const nodusChip = page.locator('#portfolio-networks .network-health').first();
  assert.equal(await nodusChip.getAttribute('data-chain'), 'nodus');
  assert.equal(await nodusChip.getAttribute('title'), 'Nodus · Nodus not ready');
  assert.equal(await nodusChip.getAttribute('data-health'), 'none');
  const group = chain => page.locator(`#balances .asset-group[data-chain="${chain}"]`);
  const holding = chain => group(chain).locator(`.chain-holding[data-chain="${chain}"]`).first();
  await page.locator('#show-zero-balances').uncheck();
  assert.equal(await page.locator('#show-zero-balances-note').innerText(), 'All networks and their holdings are listed.');
  // SOL must have been READ as 0 first: a row not read yet always stays (it
  // may hold something) — checking before the read answered raced it.
  await page.waitForFunction(() => document.querySelector('.asset-group[data-chain="solana"] .chain-holding .holding-value strong')?.textContent === '0 SOL');
  // Groups follow the portfolio rows: NODUS first, then legacy and PQ networks.
  assert.deepEqual(await page.locator('#balances .asset-group').evaluateAll(nodes => nodes.map(node => node.dataset.chain)),
    ['nodus', 'ethereum', 'bsc', 'solana', 'tron', 'cellframe', 'ixios', 'algorand', 'tidecoin', 'ckb', 'soqucoin', 'qtc', 'xion', 'splendor', 'asentum']);
  const nodusGroup = group('nodus');
  // 0.1.102: icons are built in — inlined (data:) or under a content-hashed
  // name, the only form the sites let browsers cache (an icon fetched again
  // on every redraw blinked out); `data-icon` names the file.
  const nodusIcon = nodusGroup.locator('summary img.coin-icon');
  assert.equal(await nodusIcon.getAttribute('data-icon'), 'nodus.svg');
  assert.match(await nodusIcon.getAttribute('src'), /^data:image\/|\/assets\/[^/]+-[A-Za-z0-9_-]{8}\.(svg|png)$/);
  await nodusGroup.locator('summary').click();
  assert.equal(await nodusGroup.locator('.chain-holding').count(), 1);
  // No node is reachable here: NODUS says so; no amount, no zero, no read state.
  assert.match(await nodusGroup.locator('.chain-holding').innerText(), /Nodus not ready/);
  assert.doesNotMatch(await nodusGroup.innerText(), /Reading|Not read|\b0\.0\b/);
  // Send and Receive are pages (rail), not row buttons.
  assert.equal(await page.locator('#balances .holding-actions').count(), 0);
  await nodusGroup.locator('summary').click();
  // Zero balances (src/portfolio.js groupNetworks): with the box checked, only
  // networks with a displayable nonzero holding stay — SOL read as 0 leaves,
  // Cellframe's 5 CPUNK stays; unchecking brings SOL back.
  await page.locator('#show-zero-balances').check();
  assert.equal(await group('solana').count(), 0);
  assert.equal(await group('cellframe').count(), 1);
  await page.locator('#show-zero-balances').uncheck();
  await group('solana').waitFor();
  // Selecting a holding switches the transfer network and marks the row; the
  // holding control does the same from the keyboard and keeps focus.
  const solGroup = group('solana');
  await solGroup.locator('summary').click();
  await holding('solana').locator('.holding-select').click();
  assert.equal(await page.locator('#chain').inputValue(), 'solana');
  assert.equal(await page.locator('#send-title').innerText(), 'Send · Solana');
  assert.equal(await page.locator('#receive-address').innerText(), '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
  assert.equal(await holding('solana').evaluate(node => node.classList.contains('selected')), true);
  assert.equal(await page.locator('#review-dialog').isVisible(), false);
  await nodusGroup.locator('summary').click();
  await holding('nodus').locator('.holding-select').focus(); await page.keyboard.press('Enter');
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  assert.equal(await page.locator('#send-title').innerText(), 'Send · Nodus');
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  assert.equal(await holding('nodus').evaluate(node => node.classList.contains('selected')), true);
  assert.equal(await holding('solana').evaluate(node => node.classList.contains('selected')), false);
  assert.equal(await holding('nodus').locator('.holding-select').evaluate(el => el === document.activeElement), true, 'selecting does not move focus');
  assert.equal(await decodeQr(), nodusAddress);
  // (The former single-column "panel scrolls into view" check is gone: Send and
  // Receive are separate pages since 0.1.145.)
  await nodusGroup.locator('summary').click(); await solGroup.locator('summary').click();
  assert.equal(await page.locator('#portfolio-scope').count(), 0, 'the scope paragraph is gone (0.1.108)');
  // Device & settings is its own page: it replaces the wallet view, its title
  // takes focus and the URL names it; Back returns to the wallet view where
  // it was, with focus on the link that opened the page; the browser's Back
  // does the same.
  // (The link is clicked in the page: Playwright's own click would first
  // scroll it into view and move the position being checked.)
  await page.evaluate(() => scrollTo(0, 200)); const walletScrolled = await page.evaluate(() => scrollY);
  await page.evaluate(() => document.querySelector('.wallet-navigation a[href="#settings"]').click());
  await page.locator('#page-settings').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#wallet-home').isVisible(), false);
  assert.equal(await page.evaluate(() => location.hash), '#settings');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'device-title');
  assert.match(await page.locator('#wallet-storage-state').innerText(), /Temporary session/);
  await page.locator('#page-settings .page-back').click();
  await page.waitForFunction(() => location.hash === '');
  assert.equal(await page.locator('#wallet-home').isVisible(), true);
  assert.equal(await page.locator('#page-settings').isVisible(), false);
  assert.equal(await page.evaluate(() => scrollY), walletScrolled);
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('href')), '#settings');
  await openPage('wallet-activity');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'activity-title');
  await page.goBack(); await page.waitForFunction(() => location.hash === '');
  assert.equal(await page.locator('#wallet-home').isVisible(), true);
  assert.equal(await page.locator('#page-wallet-activity').isVisible(), false);
  // Logs: a page of its own, linked from Device & settings; open only there.
  await openPage('settings'); await page.locator('#device-panel a[href="#logs"]').click();
  await page.locator('#page-logs').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#session-logs').evaluate(node => node.open), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'logs-title');
  await page.locator('#page-logs .page-back').click(); await page.locator('#wallet-home').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#session-logs').evaluate(node => node.open), false);
  // 0.1.145 capability-driven rail: on Nodus, Earn, Shared vaults and Smart
  // contracts follow chain capability, not the node connection.
  for (const id of ['nav-earn', 'nav-vaults', 'nav-evm']) assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
  await walletView(); await page.evaluate(() => history.replaceState(null, '', location.pathname));
  // Send and Receive are separate rail pages (src/app.js:2324-2329); the page's
  // labelling heading takes focus (pageTitle, src/app.js:2350).
  await selectNetwork('ethereum');
  // The Send link is offered once a network that can send is selected (NODUS cannot, here).
  assert.equal(await page.locator('.wallet-navigation a[href="#send"] .nav-name').innerText(), 'Send');
  assert.equal(await page.locator('.wallet-navigation a[href="#receive"] .nav-name').innerText(), 'Receive');
  await openPage('send');
  assert.equal(await page.locator('#send-title').evaluate(el => el === document.activeElement), true);
  await walletView(); await selectNetwork('nodus');
  await openPage('receive');
  assert.equal(await page.locator('#receive-title').evaluate(el => el === document.activeElement), true);
  // style.css:1009: the rail replaces the former shortcuts (Send, Receive, Earn,
  // Swap); they stay in the DOM for their handlers but are not displayed.
  for (const id of ['quick-send', 'quick-receive', 'quick-earn', 'quick-swap']) assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
  if (process.env.SHOT_DIR) await page.locator('#page-receive').screenshot({ path: `${process.env.SHOT_DIR}/receive-page.png` });
  assert.equal(await page.locator('#page-receive #receive-panel').count(), 1);
  assert.equal(await page.locator('#page-send #send-form').count(), 1);
  for (const width of [320, 390, 820, 1280]) {
    await page.setViewportSize({ width, height: 960 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Dashboard overflow at ${width}px`);
    assert.equal(await page.locator('#receive-qr svg').isVisible(), true, `QR visible at ${width}px`);
  }
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  // Nodus is still the selected network: the shared Copy button copies its address.
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.locator('#copy-address').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), nodusAddress);
  assert.equal(await readPhrase(page), '');
  await selectNetwork('ethereum');
  assert.equal(await page.locator('#receive-address').innerText(), '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
  assert.equal(await page.locator('#nodus-address-status').isVisible(), false);
  // Account history (0.1.42): selecting Ethereum reads Blockscout once (txlist
  // + one tokentx per listed token), and the received transfer is shown with
  // its sender and an explorer link; a second selection within 30 minutes
  // does not read again (the provider limits requests).
  await page.waitForFunction(() => /\+1\.5 ETH/.test(document.querySelector('#history').textContent));
  await openPage('wallet-activity');
  assert.match(await page.locator('#history').innerText(), /from 0x121212…121212/);
  assert.equal(await page.locator('#history a').getAttribute('href'), 'https://etherscan.io/tx/0x' + 'ab'.repeat(32));
  assert.deepEqual(historySeen.filter(s => s.startsWith('ethereum')), ['ethereum:txlist', 'ethereum:tokentx', 'ethereum:tokentx', 'ethereum:tokentx']);
  await walletView();
  await selectNetwork('bsc'); await selectNetwork('ethereum');
  assert.equal(historySeen.filter(s => s.startsWith('ethereum')).length, 4);
  await openPage('wallet-activity');
  assert.match(await page.locator('#history-status').innerText(), /As reported by Blockscout/);
  await page.locator('#history-refresh').click();
  assert.match(await page.locator('#history-status').innerText(), /Try again in a minute/);
  await walletView();
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), false);
  // Cellframe/CPUNK now lives inside the wallet like any other asset: its
  // address is derived automatically (started right after the wallet opened,
  // same as Nodus), and there is no separate panel or manual derive button.
  await selectNetwork('cellframe');
  await page.waitForFunction(() => /^[1-9A-HJ-NP-Za-km-z]{100,110}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#cellframe-address-status').textContent(), '');
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  // The longest address format (100–110 characters) still decodes exactly.
  assert.equal(await decodeQr(), await page.locator('#receive-address').innerText(), 'cellframe QR decodes to the shown address');
  assert.equal(await page.locator('#send-fields').isVisible(), false);
  assert.match(await page.locator('#send-disabled-note').innerText(), /Sending CPUNK is not available/);
  // No network connection settings for Cellframe (0.1.114: one provider).
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), true);
  assert.equal(await page.locator('#account-explorer').evaluate(node => node.hidden), true);
  assert.equal(broadcasts.length, 0);
  for (const [chain, expected] of [['bsc','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'],['solana','3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx'],['tron','TEfhiqsW1SdN44DeHrAWVmbyr8ZbvChrtS'],['ethereum','0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb']]) {
    await selectNetwork(chain); assert.equal(await page.locator('#receive-address').innerText(), expected);
    const selectedName = await page.locator('#chain option:checked').innerText();
    assert.ok((await page.locator('.selected-network-name').allTextContents()).every(name => name === selectedName));
    assert.equal(await page.locator('#send-title').innerText(), `Send · ${selectedName}`);
    assert.equal(await decodeQr(), expected, `${chain} QR decodes to the shown address`);
  }
  // Paket C: RPC provider select — populated per network, TRON has no custom
  // option, and picking "Custom HTTPS endpoint..." reveals the free-text box.
  // Open the settings disclosure first, as a user must: inside a closed
  // <details> Chromium reports option innerText as '' and every control as
  // not visible, so the visibility checks below would pass vacuously. The
  // settings are on the Device & settings page and follow the network
  // selected in the network disclosure on the wallet view.
  const rpcFor = async chain => { await walletView(); await selectNetwork(chain); await openPage('settings'); };
  await openPage('settings');
  await page.locator('#rpc-settings summary').click();
  assert.equal(await page.locator('#rpc-choice').isVisible(), true);
  // One provider (TRON, Solana): no connection settings at all (0.1.114,
  // operator "Tek seçenekli ağlarda gizle").
  await rpcFor('tron');
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), true);
  await rpcFor('bsc');
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), false);
  assert.equal(await page.locator('#rpc-choice option').count(), 9);
  assert.equal(await page.locator('#rpc-choice option').last().innerText(), 'Custom HTTPS endpoint…');
  await rpcFor('solana');
  assert.equal(await page.locator('#rpc-settings').evaluate(node => node.hidden), true);
  await rpcFor('ethereum');
  assert.equal(await page.locator('#rpc-choice option').count(), 5);
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), false);
  await page.selectOption('#rpc-choice', 'custom');
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), true);
  assert.equal(await page.locator('#rpc-endpoint').inputValue(), '');
  await page.selectOption('#rpc-choice', '0');
  assert.equal(await page.locator('#rpc-endpoint').isVisible(), false);
  await walletView();
  // The card's Refresh is the control (style.css:1012 hides the asset panel's).
  await pressRefresh('portfolio-refresh'); await page.waitForFunction(() => document.querySelector('#balances').textContent.includes('10 ETH')); // 0.1.28 display form (was '10.0')
  await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-chain="cellframe"] .holding-value strong'); return strong && strong.textContent.includes('CPUNK'); });
  assert.equal(await page.locator('.asset-group[data-chain="cellframe"] .holding-value small').textContent(), '—'); // closed group: innerText is empty
  await openPage('send');
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); assert.equal(broadcasts.length, 0);
  assert.match(await page.locator('#review-details').innerText(), /0.01/); await page.locator('#cancel-send').click(); assert.equal(broadcasts.length, 0);
  await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 1); assert.equal(broadcasts[0].from, '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'); assert.equal(broadcasts[0].value, 10000000000000000n); assert.equal(broadcasts[0].chainId, 1n);
  // B-1: the first send has no final result yet, so it must be marked abandoned
  // before a second same-network review can open; E-2 also clears the recipient
  // after a successful broadcast, so it is re-filled here too.
  await openPage('wallet-activity');
  await page.locator('#activity').getByRole('button', { name: 'Mark as abandoned' }).click(); await page.locator('#activity').getByRole('button', { name: 'Confirm abandon' }).click(); await page.waitForFunction(() => document.querySelector('#activity').textContent.includes('abandoned'));
  await walletView(); await openPage('send');
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001');
  await page.selectOption('#asset','USDC'); await page.locator('#amount').fill('1.000001'); await page.locator('#review-button').click(); await page.locator('#review-dialog').waitFor({ state: 'visible' }); await page.locator('#confirm-send').click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Broadcast submitted'));
  assert.equal(broadcasts.length, 2); assert.equal(broadcasts[1].to, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'); assert.equal(broadcasts[1].value, 0n);
  const erc = new Interface(['function transfer(address,uint256)']); assert.equal(erc.decodeFunctionData('transfer', broadcasts[1].data)[1], 1000001n);
  assert.match(await page.locator('#activity').innerText(), /pending/);
  finalized = true; await selectNetwork('bsc'); assert.equal(await page.locator('#activity').innerText(), ''); await selectNetwork('ethereum');
  // 0.1.96 (BUGS W-05): a confirmed send leaves "Sent from here" only once
  // the account history SHOWS it; this test's Blockscout lists only an
  // unrelated incoming transfer, so the confirmed send stays here (since
  // 0.1.91 it vanished at confirmation and was in neither list), next to the
  // abandoned first send, and the page does not claim it is listed below.
  const confirmedLeft = () => { const t = document.querySelector('#activity').textContent; return t.includes('abandoned') && !t.includes('pending') && t.includes('confirmed') && document.querySelector('#activity').children.length === 2; };
  await page.waitForFunction(confirmedLeft);
  assert.doesNotMatch(await page.locator('#activity + .activity-empty').innerText(), /listed under Account history/);
  // The Nodus address is unchanged after sends on other networks, and Nodus has no activity.
  await selectNetwork('nodus');
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress); assert.equal(await page.locator('#activity').innerText(), '');
  await selectNetwork('ethereum');
  await page.waitForFunction(confirmedLeft);
  // Selecting NODUS (no Send there) closed the open Send page (UI pack 2026-11-03, item 3): open it again.
  await walletView(); await openPage('send');
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001'); await page.locator('#amount').fill('0.01');
  networkId = '0x38'; await page.locator('#review-button').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('wrong network')); assert.equal(broadcasts.length, 2);
  // A CPUNK read failure is shown on its own row ("Read failed · last read"
  // with the amount read earlier, 0.1.41 — the app's stale-while-revalidate
  // wallet cache), never an inferred zero, and never blocks the rest of the
  // (unrelated) portfolio.
  cellframeFail = true; await pressRefresh('portfolio-refresh');
  // Current wording (src/portfolio-view.js): the time of the last read, and the
  // row says the balance is unavailable and the last read is shown.
  // UI pack 2026-11-03: the "Balance unavailable; showing last read." line under a coin is gone; the failed
  // read is proven by the Cellframe network light turning failed, the older value stays marked "Last read".
  await page.waitForFunction(() => { const row = document.querySelector('.asset-group[data-chain="cellframe"] .chain-holding'); return row && row.querySelector('.holding-value small')?.textContent.startsWith('Last read ') && document.querySelector('#portfolio-networks .network-health[data-chain="cellframe"][data-health="failed"]'); });
  assert.equal(await page.locator('.asset-group[data-chain="cellframe"] .chain-holding .balance-error, .asset-group[data-chain="cellframe"] .chain-holding .balance-note').count(), 0);
  assert.notEqual(await page.locator('.asset-group[data-chain="cellframe"] .holding-value strong').textContent(), '0 CPUNK');
  cellframeFail = false;
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length + sessionStorage.length, SHOW_ZERO_KEY), 0);
  networkId = '0x1';
  await openPage('settings');
  // Reveal 1: temporary session, nothing saved: no password field.
  assert.equal(await page.locator('#reveal-password').isVisible(), false);
  assert.equal(await revealButton().isVisible(), true);
  await assertNotShown();
  await revealNow(); await assertShown();
  assert.equal(await page.locator('#reveal-phrase-1').count(), 1); assert.equal(await page.locator('#phrase-1').count(), 1);
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length + sessionStorage.length, SHOW_ZERO_KEY), 0);
  // UI pack 2026-11-03: note, framed words with centred numbers, Copy phrase (clipboard permission granted above).
  assert.match(await page.locator('#device-panel .reveal-note').innerText(), /^Your 24 words control your wallet\. Never send them to anyone/);
  assert.equal(await page.locator('#device-panel .reveal-words').isVisible(), true);
  const labelOffsets = await page.locator('#device-panel .reveal-words .phrase-cell').evaluateAll(cells => cells.map(cell => {
    const label = cell.querySelector('label').getBoundingClientRect(), input = cell.querySelector('input').getBoundingClientRect();
    return Math.abs((label.top + label.height / 2) - (input.top + input.height / 2));
  }));
  assert.equal(labelOffsets.length, 24); assert.ok(labelOffsets.every(offset => offset <= 1), `number labels off centre: ${labelOffsets}`);
  await page.getByRole('button', { name: 'Copy phrase' }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), phrase);
  const leaked = await page.evaluate(() => JSON.stringify([document.querySelector('#wallet-status').textContent, document.querySelector('#session-log-text').textContent, { ...localStorage }, { ...sessionStorage }]));
  assert.ok(!leaked.includes('abandon abandon'), 'the copied words reached a status line, the log or storage');
  await page.locator('#page-settings .page-back').click(); await page.locator('#wallet-home').waitFor({ state: 'visible' });
  await assertNotShown();
  assert.equal(await page.getByRole('button', { name: 'Copy phrase' }).count(), 0);
  await openPage('settings'); await assertNotShown();
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  assert.equal(await page.locator('#vault-save').isVisible(), true);
  assert.equal(await page.locator('#vault-change').isVisible(), false);
  assert.equal(await page.locator('#vault-old-password').isVisible(), false);
  assert.equal(await page.locator('#vault-confirm-label').innerText(), 'Confirm password');
  await page.locator('#vault-password').fill('public-test-password-123');
  await page.locator('#vault-risk-confirm').check();
  for (const confirmation of ['', 'public-test-password-typo']) {
    await page.locator('#vault-confirm-password').fill(confirmation);
    await page.locator('#vault-save').click();
    assert.match(await page.locator('#vault-save-status').innerText(), /passwords do not match/);
    assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length, SHOW_ZERO_KEY), 0);
    assert.equal(await page.locator('#vault-password').inputValue(), 'public-test-password-123');
    assert.equal(await page.locator('#vault-confirm-password').inputValue(), confirmation);
    assert.equal(await page.evaluate(() => document.activeElement.id), 'vault-confirm-password');
  }
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-confirm-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  assert.equal(await page.locator('#vault-save').isVisible(), false);
  assert.equal(await page.locator('#vault-change').isVisible(), true);
  assert.equal(await page.locator('#vault-old-password').isVisible(), true);
  assert.equal(await page.locator('#vault-storage-title').innerText(), 'Change saved password');
  assert.equal(await page.locator('#vault-confirm-label').innerText(), 'Confirm new password');
  assert.match(await page.locator('#vault-save-explain').innerText(), /already saved/);
  assert.match(await page.locator('#vault-save-status').innerText(), /Encrypted wallet saved/);
  assert.equal(await page.locator('#vault-confirm-password').inputValue(), '');
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage })); assert.ok(!stored.includes(phrase)); assert.ok(!stored.includes('public-test-password-123'));
  // Reveal 2: saved in this session: the password is asked for again; the
  // reveal writes nothing to either storage.
  assert.equal(await page.locator('#reveal-password').isVisible(), true);
  await page.locator('#reveal-password').fill('public-test-password-123'); await revealNow(); await assertShown();
  assert.equal(await page.locator('#reveal-password').inputValue(), '');
  const afterReveal = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  assert.ok(!afterReveal.includes(phrase)); assert.ok(!afterReveal.includes('public-test-password-123'));
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  // 0.1.41: the balances read while the wallet was NOT saved were not written
  // (localStorage was empty above); once saved they are, encrypted (decision
  // 2026-10-02-device-cache-only-when-saved).
  await walletView();
  await pressRefresh('portfolio-refresh');
  await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled);
  await page.waitForFunction(() => localStorage.getItem('nodus.balances.v1') !== null);
  const balancesText = await page.evaluate(() => localStorage.getItem('nodus.balances.v1'));
  assert.deepEqual(Object.keys(JSON.parse(balancesText)).sort(), ['cipher', 'ciphertext', 'id', 'iv', 'version']);
  assert.doesNotMatch(balancesText, /0x[0-9a-fA-F]{40}|ethereum:|"units"/, 'saved balances are not readable without the key');
  // Lock with Nodus selected: its address and status are cleared.
  await selectNetwork('nodus'); assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  assert.equal(await qrEmpty(), false);
  await page.locator('#lock').click(); assert.equal(await page.locator('#receive-address').textContent(), ''); assert.equal(await qrEmpty(), true); assert.equal(await page.locator('#nodus-address-status').textContent(), ''); assert.equal(await page.locator('#cellframe-address-status').innerText(), ''); await sessionReleased();
  // Restoring the words opens a temporary session, not the saved copy.
  await page.locator('#restore').click(); await pastePhrase(page, phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await openPage('settings');
  assert.equal(await page.locator('#vault-storage-title').innerText(), 'Unlock saved wallet to change password');
  assert.match(await page.locator('#vault-save-explain').innerText(), /Lock this temporary session, then unlock the saved wallet/);
  for (const id of ['vault-password', 'vault-confirm-password', 'vault-old-password', 'vault-risk-confirm', 'vault-save', 'vault-change']) assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  // Reveal 3: temporary session over a saved copy: no password field (plan
  // section 0 items 5-6 — the session was opened by typing the words).
  assert.equal(await page.locator('#reveal-password').isVisible(), false);
  await assertNotShown(); await revealNow(); await assertShown();
  await page.locator('#lock').click(); await sessionReleased();
  await assertNotShown();
  await page.locator('#unlock-password').fill('incorrect-password-123'); await page.locator('#unlock-wallet').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Incorrect password'));
  // A failed unlock gives the session lock back.
  await page.waitForFunction(() => !document.querySelector('#unlock-wallet').disabled); await sessionReleased();
  await page.locator('#unlock-password').fill('public-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await sessionHeld(), true); assert.equal(await page.locator('#session-conflict').isVisible(), false);
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  await openPage('settings');
  // Reveal 4: opened from the saved copy: the password is asked for again.
  assert.equal(await page.locator('#reveal-password').isVisible(), true);
  await page.locator('#reveal-password').fill('incorrect-password-123'); await revealButton().click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Incorrect password or damaged saved wallet.'));
  await assertNotShown(); assert.equal(await page.locator('#reveal-password').inputValue(), '');
  await page.locator('#reveal-password').fill('public-test-password-123'); await revealNow(); await assertShown();
  assert.equal(await page.locator('#reveal-password').inputValue(), '');
  // A refused attempt after a shown one leaves nothing on screen.
  await page.evaluate(() => { document.querySelector('#wallet-status').textContent = ''; });
  await page.locator('#reveal-password').fill('incorrect-password-123'); await revealButton().click();
  await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('Incorrect password or damaged saved wallet.'));
  await assertNotShown();
  // A typed but unsent reveal password does not stay behind when Settings is left.
  await page.locator('#reveal-password').fill('typed-not-sent-123');
  await page.locator('#page-settings .page-back').click(); await page.locator('#wallet-home').waitFor({ state: 'visible' });
  await openPage('settings'); assert.equal(await page.locator('#reveal-password').inputValue(), '');
  await page.locator('#reveal-password').fill('public-test-password-123'); await revealNow(); await assertShown();
  const revealedStorage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  assert.ok(!revealedStorage.includes(phrase)); assert.ok(!revealedStorage.includes('public-test-password-123'));
  // Leaving Settings (here: to Logs) removes the words; the log never holds them.
  await page.locator('#device-panel a[href="#logs"]').click(); await page.locator('#page-logs').waitFor({ state: 'visible' });
  await assertNotShown();
  const logText = await page.locator('#session-log-text').textContent();
  assert.ok(!logText.includes(phrase)); assert.ok(!logText.includes('abandon abandon abandon abandon'));
  await page.locator('#page-logs .page-back').click(); await page.locator('#wallet-home').waitFor({ state: 'visible' });
  await openPage('settings'); await assertNotShown();
  await page.locator('#reveal-password').fill('public-test-password-123'); await revealNow(); await assertShown();
  // Lock removes the words and closes the page.
  await page.locator('#lock').click(); await sessionReleased();
  await assertNotShown(); assert.equal(await page.locator('#page-settings').isVisible(), false);
  await page.locator('#unlock-password').fill('public-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  await openPage('settings'); await assertNotShown();
  assert.equal(await page.locator('#vault-save').isVisible(), false);
  assert.equal(await page.locator('#vault-change').isVisible(), true);
  assert.equal(await page.locator('#vault-old-password').isVisible(), true);
  await page.locator('#vault-password').fill('changed-test-password-123'); await page.locator('#vault-confirm-password').fill('changed-test-password-123'); await page.locator('#vault-old-password').fill('public-test-password-123');
  assert.equal(await page.locator('#vault-risk-confirm').isChecked(), false);
  await page.locator('#vault-change').click();
  assert.match(await page.locator('#vault-status').innerText(), /read and accept the risks/);
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  await page.locator('#vault-risk-confirm').check();
  await page.locator('#vault-confirm-password').fill('changed-test-password-typo'); await page.locator('#vault-change').click();
  assert.match(await page.locator('#vault-save-status').innerText(), /passwords do not match/);
  assert.equal(await page.locator('#vault-old-password').inputValue(), 'public-test-password-123');
  assert.equal(await page.locator('#vault-password').inputValue(), 'changed-test-password-123');
  assert.equal(await page.evaluate(() => localStorage.getItem('nodus.wallet.v1')), JSON.parse(stored)['nodus.wallet.v1']);
  await page.locator('#vault-confirm-password').fill('changed-test-password-123'); await page.locator('#vault-change').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Local password changed'));
  assert.match(await page.locator('#vault-save-status').innerText(), /Local password changed/);
  assert.equal(await page.locator('#vault-confirm-password').inputValue(), '');
  assert.equal(await page.locator('#vault-save').isVisible(), false);
  assert.equal(await page.locator('#vault-change').isVisible(), true);
  await page.reload(); await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  await page.locator('#unlock-password').fill('changed-test-password-123'); await page.locator('#unlock-wallet').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  // The reload happened on Device & settings: the pagehide lock kept the
  // hash, so the unlock opens that page again. Its Back control does not step
  // back into the entries of the page before the reload (that would load the
  // page again and lock the wallet): it opens the wallet view in place.
  assert.equal(await page.evaluate(() => location.hash), '#settings');
  assert.equal(await page.locator('#page-settings').isVisible(), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'device-title');
  await walletView();
  assert.equal(await page.locator('#wallet-open').isVisible(), true);
  assert.equal(await page.evaluate(() => location.hash), '');
  await selectNetwork('nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), nodusAddress);
  await selectNetwork('ethereum');
  // reopened from the saved copy: the confirmed send, never shown by the
  // account history, was saved and is back (re-checked to "confirmed")
  await page.waitForFunction(confirmedLeft);
  // 0.1.97: the saved wallet keeps its own identity (encrypted) for the next
  // unlock; deleting the saved wallet removes it too (localStorage empty below)
  await page.waitForFunction(() => { const t = localStorage.getItem('nodus.identity.v1'); return !!t && !t.includes('cellframe') && JSON.parse(t).cipher === 'AES-256-GCM'; });
  await page.getByText('Delete saved wallet from this device', { exact: true }).click(); await page.locator('#vault-delete-confirm').check(); await page.locator('#vault-delete').click();
  // The saved wallet has a readable id, so its Messages history goes in the
  // same step (app.js vault-delete, the 'deleted' outcome).
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('deleted from this device'));
  assert.equal(await page.locator('#vault-status').innerText(), 'Saved wallet, saved activity and message history deleted from this device.');
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length, SHOW_ZERO_KEY), 0);
  await openPage('settings');
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  assert.equal(await page.locator('#vault-save').isVisible(), true);
  assert.equal(await page.locator('#vault-change').isVisible(), false);
  assert.equal(await page.locator('#vault-old-password').isVisible(), false);
  assert.equal(await page.locator('#vault-confirm-label').innerText(), 'Confirm password');
  await page.locator('#vault-password').fill('public-test-password-123'); await page.locator('#vault-confirm-password').fill('public-test-password-123'); await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click(); await page.locator('#lock').click(); assert.equal(await page.locator('#nodus-address-status').textContent(), '');
  await page.waitForFunction(() => !document.querySelector('#vault-save').disabled); assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length, SHOW_ZERO_KEY), 0);
  assert.equal(await page.locator('#vault-confirm-password').inputValue(), '');
  await page.locator('#welcome').waitFor({ state: 'visible' }); assert.equal(await page.locator('#receive-address').innerText(), '');
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length + sessionStorage.length, SHOW_ZERO_KEY), 0);
  await page.locator('#create').click(); const created = await readPhrase(page); assert.equal(created.split(' ').length, 24);
  // 0.1.123: the skip choice is shown, unticked, on the words screen; left
  // unticked the flow is today's: the re-typing step appears, without the choice.
  assert.equal(await page.locator('#skip-verify-row').isVisible(), true); assert.equal(await page.locator('#skip-verify').isChecked(), false);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.equal(await page.locator('#phrase-label').innerText(), 'Re-enter your saved recovery phrase');
  assert.equal(await page.locator('#skip-verify-row').isVisible(), false); assert.equal(await page.locator('#skip-verify-dialog').isVisible(), false);
  // E-4 blocks paste on this verify step by design, so the backup check below
  // types each word into its own box instead of pasting the full phrase.
  const boxes = page.locator('#phrase-grid input');
  for (const [i, word] of phrase.split(' ').entries()) await boxes.nth(i).fill(word);
  await page.locator('#phrase-submit').click(); await page.waitForFunction(() => document.querySelector('#wallet-status').textContent.includes('does not match'));
  for (const [i, word] of created.split(' ').entries()) await boxes.nth(i).fill(word);
  await page.locator('#phrase-submit').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await selectNetwork('nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  await page.locator('#lock').click(); assert.equal(await page.locator('#receive-address').textContent(), ''); assert.equal(await qrEmpty(), true); assert.equal(await page.locator('#nodus-address-status').textContent(), '');
  // 0.1.123 (operator: someone who saved the words, e.g. as a screenshot, may
  // skip typing them again): ticked, the continue button asks first. "Go back"
  // keeps the same words and the tick; "Yes, skip checking" opens the wallet of
  // the shown words without the re-typing step. The choice itself sends nothing
  // and keeps nothing in this browser.
  await page.locator('#welcome').waitFor({ state: 'visible' }); await sessionReleased(); assert.equal(await page.locator('#skip-verify-row').isVisible(), false);
  await page.locator('#create').click(); const skipped = await readPhrase(page); assert.equal(skipped.split(' ').length, 24); assert.notEqual(skipped, created);
  assert.equal(await page.locator('#skip-verify').isChecked(), false);
  const callsBeforeSkip = calls.length;
  await page.locator('#skip-verify').check(); await page.locator('#backup-confirm').check();
  assert.equal(await page.locator('#phrase-submit').innerText(), 'I saved it — open wallet');
  await page.locator('#phrase-submit').click(); await page.locator('#skip-verify-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#skip-verify-title').innerText(), 'Skip checking your recovery words?');
  assert.match(await page.locator('#skip-verify-text').innerText(), /cannot be restored/);
  await page.locator('#skip-verify-back').click(); await page.locator('#skip-verify-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#phrase-form').isVisible(), true); assert.equal(await page.locator('#wallet-open').isVisible(), false);
  assert.equal(await readPhrase(page), skipped); assert.equal(await page.locator('#skip-verify').isChecked(), true);
  assert.notEqual(await page.locator('#phrase-label').innerText(), 'Re-enter your saved recovery phrase');
  assert.equal(calls.length, callsBeforeSkip, 'the skip choice and its dialog make no request');
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length + sessionStorage.length, SHOW_ZERO_KEY), 0);
  await page.locator('#phrase-submit').click(); await page.locator('#skip-verify-dialog').waitFor({ state: 'visible' });
  await page.locator('#skip-verify-yes').click(); await page.locator('#wallet-open').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#phrase-form').isVisible(), false); assert.equal(await page.locator('#skip-verify-dialog').isVisible(), false);
  await selectNetwork('ethereum');
  await page.waitForFunction(() => /^0x[0-9a-fA-F]{40}$/.test(document.querySelector('#receive-address').textContent));
  assert.equal(await page.locator('#receive-address').innerText(), HDNodeWallet.fromPhrase(skipped, undefined, "m/44'/60'/0'/0/0").address);
  await page.locator('#lock').click(); await page.locator('#welcome').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#skip-verify').isChecked(), false);
  assert.equal(await page.evaluate(k => Object.keys(localStorage).filter(x => x !== k).length + sessionStorage.length, SHOW_ZERO_KEY), 0);
  const storedAfterSkip = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage })); assert.ok(!storedAfterSkip.includes(skipped));
  assert.ok(!JSON.stringify(calls).includes(skipped), 'the skipped words never reached a request');
  await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  // Third-party license notices ship at the dist root and are linked from the footer.
  assert.equal(await page.locator('.wallet-footer a[href="/THIRD-PARTY-LICENSES.txt"]').innerText(), 'Licenses');
  const licenses = await fetch(url + '/THIRD-PARTY-LICENSES.txt');
  assert.equal(licenses.status, 200);
  const licenseText = await licenses.text();
  for (const name of ['qrcode-generator', '@noble/hashes', 'ethers']) assert.match(licenseText, new RegExp(`^${name.replace(/[/.]/g, '\\$&')}@\\S+ — `, 'm'), `${name} listed`);
  // No LGPL/GPL package is bundled since 0.1.23 (rpc-websockets left with
  // @solana/web3.js), and the copyright line is taken from qrcode-generator's
  // own source (it ships no license file).
  assert.ok(!licenseText.includes('GNU LESSER GENERAL PUBLIC LICENSE'), 'no LGPL-3.0 text');
  assert.ok(!licenseText.includes('GNU GENERAL PUBLIC LICENSE'), 'no GPL-3.0 text');
  assert.doesNotMatch(licenseText, /^\S+@\S+ — \S*GPL/m, 'no package declares a GPL-family license');
  assert.ok(licenseText.includes('Copyright (c) 2009 Kazuhiko Arase\n(copyright line from dist/qrcode.mjs:5)'), 'qrcode-generator copyright line');
  // The release is shown in the footer (package.json version, vite.config.js define).
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(await page.locator('.wallet-footer .app-version').innerText(), `Version ${version}`);
  assert.deepEqual(errors, []);
  console.log('Browser smoke passed: create/backup/restore, create with the re-typing skipped after the warning (Go back keeps the words, Yes opens the shown words\' wallet, nothing sent or kept),NODUS first and default-selected (receive-only row, no balance shown, no Send), Nodus native address/copy/lock/reopen, 4 external chain addresses, one Send / Receive panel whose heading follows the selected network and whose QR decodes to exactly the shown address (Nodus, Ethereum, BNB Smart Chain, Solana, TRON) and clears on lock, holding-row click/keyboard selection, ETH/ERC20 signed mocked broadcasts, wrong-network guard, automatic Cellframe address derivation + CPUNK balance display/error, send disabled on Cellframe, finalized scoped activity, state-specific save/unlock/change/delete controls, matching password confirmation, phrase-only saved-copy guard, encrypted save/unlock/change/reload/delete, KDF cancellation, temporary storage behavior, mobile layout with the QR shown, third-party license file served. No external request reached a blockchain.');
} catch (error) { console.error('UI status:', await page.locator('#wallet-status').textContent(), 'Cellframe:', await page.locator('#cellframe-address-status').textContent(), 'Page errors:', errors, 'Methods:', calls.map(c => c?.method)); throw error; } finally { await browser.close(); server?.stop(); }
