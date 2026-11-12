import { portfolioRead, cellframeRead, historyRead, PQ_HOST } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
import { PQ_ENTRIES } from '../src/pq/networks.js';
import { BALANCES_KEY } from '../src/vault.js';
// Proves, on a web build made for this script: Ixios (a receive-only wallet network handled
// exactly like Cellframe; the Ixios build switch is gone, every build carries it) is listed and
// selectable (network selector, network badge, its own group in the coin list); its IXIOS row is
// read like the CPUNK row (balance, no USD value, outside the total) after a genesis-block
// identity check (a wrong genesis makes no balance read and keeps only the amount read earlier,
// marked "Last read"); selecting it shows the checksummed receive address and a QR that decodes
// to exactly that address, hides the send fields and shows the Ixios note while Cellframe keeps
// its own; lock clears it; the page never fetches the signing module at runtime (web send stays off) and
// the build has no Ixios markup; every Ixios request goes to the mocked public RPC.
// Public test phrase only; every external request is intercepted (the Ixios RPC included:
// mocked below; the PQ networks' providers are refused, as in test/browser-portfolio.js, and counted
// apart from `unexpected`). Unlike the other browser scripts this one builds its own bundle
// into a temporary directory and previews it with --outDir, so dist/ is left untouched.
// Needs: node_modules/vite (one `vite build` run), jsqr, fixtures/ixios-checksum.json,
// and Chromium (CHROMIUM_PATH, otherwise the one Playwright finds). Preview port
// 4193 on 127.0.0.1 with --strictPort: a busy port makes the script fail, not pass.
// Leaves: nothing; the output directory is removed and the preview is stopped in finally.
// Falsely passes: the Ixios RPC is a mock, so balances prove the page wiring,
// not the live node. The note, send-fields and explorer checks read the elements' `hidden`
// state and text, because the Send page is never displayed for a receive-only network (an
// isVisible() there is false whatever the state); a group read while closed would give empty
// innerText, so the rows are read with textContent after the group has been opened once.
//
// Second part (Ixios test network, plan docs/plans/approved/2026-11-12-ixios-testnet.md 9.4), run after the part
// above on fresh browser contexts, once on this web build and once on a Connect build (vite.connect.config.js, built
// into its own temporary directory and previewed with --outDir on port 4194, --strictPort, so a busy port fails):
// the "Network environment" chooser offers Mainnet and Testnet for Ixios and starts on Mainnet; choosing Testnet
// makes only ixios_ calls to nx-rpc.ixoflow.io (block 1's parentHash = the test genesis, then ixios_getBalance for
// the same checksummed address), shows the stage "Testnet", keeps the Ixios note, keeps the send fields hidden and
// makes no call to the main node; a wrong genesis (Ethereum's, and the main Ixios genesis) makes no balance call;
// back to Mainnet gives today's eth_ calls and no test call; choosing Testnet, selecting another chain (Ethereum) and
// then Ixios again shows Mainnet (chooser and stage) with only eth_ calls to the main node; with a SAVED wallet (the password flow of
// test/browser-smoke.js), a balance read on Testnet before locking is not shown after unlocking, not even as
// "Last read" while the main node fails its genesis check, and the reopened wallet is on Mainnet. Both nodes are
// mocks answering by URL; the test node answers every other method (any eth_ name included) with -32601 as the real
// one does, and every request it sees is recorded.
// Leaves: nothing; each part runs in its own browser context whose storage (the saved wallet included) goes with
// the context, and the Connect output directory is removed in finally.
// Falsely passes: CORS is not exercised (the sites cannot read either live node today, plan 2.6), the RPCs are mocks
// (wiring only), the saved-balance check depends on a write of the kept balances to be observed (a counter on
// localStorage.setItem for that key, then 300 ms without a new write); a slower write than that could be missed and the
// check would then pass without having looked. The Connect run proves the shared src/app.js chooser on that build, not
// Connect's own shell.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { startPreview } from './preview-server.js';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';
// Decodes the receive QR in Node (the page CSP blocks an injected inline script);
// same procedure as test/browser-smoke.js decodeQr().
const jsQR = createRequire(import.meta.url)('jsqr');
async function decodeQr(page) {
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
const app = fileURLToPath(new URL('..', import.meta.url));
const vite = join(app, 'node_modules/vite/bin/vite.js');
const { Phrase: phrase, Checksummed: expected } = JSON.parse(readFileSync(new URL('./fixtures/ixios-checksum.json', import.meta.url))).vectors[0];
assert.equal(phrase, Array(23).fill('abandon').concat('art').join(' '));
// Web wallet 0.1.18, Package R3 item 3, verbatim (the Cellframe-style note).
const IXIOS_NOTE = 'Send IXIOS from the extension.';
const IXIOS_RPC = 'https://ixios-rpc.innova.limited';
// Ixios mainnet genesis block hash (ixiosSpark params/config.go:27) and, for
// the wrong-network case, Ethereum mainnet's: both chains report chain id 1.
const IXIOS_GENESIS = '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f';
const ETHEREUM_GENESIS = '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
// The PQ networks' priced assets (src/pq/prices.js PQ_PRICE_IDS) join the hero's priced-only count and their
// providers are refused here, so the status counts them as unavailable balances (test/browser-portfolio.js missingStatus).
const PQ_MISSING = PQ_ENTRIES.filter(({ asset }) => asset.priceId !== undefined).length;
const missingStatus = new RegExp(`^${PQ_MISSING} balances and 0 prices unavailable or out of date\\.`);
// Mocked IXIOS holding: 1234.567 IXIOS (18 decimals).
const IXIOS_BALANCE = '0x' + (1234567n * 10n ** 15n).toString(16);
const dirs = [], servers = [];
let browser, ixiosGenesis = IXIOS_GENESIS;
// Every JSON-RPC call answered by the Ixios mock, in arrival order.
const ixiosCalls = [];

function build() {
  const outDir = mkdtempSync(join(tmpdir(), 'nodus-wallet-ixios-')); dirs.push(outDir);
  const result = spawnSync(process.execPath, [vite, 'build', '--outDir', outDir, '--emptyOutDir'], { cwd: app, encoding: 'utf8' });
  assert.equal(result.status, 0, `vite build failed:\n${result.stdout}\n${result.stderr}`);
  return outDir;
}
// Every emitted file, not only assets/: the signing module must not ship in
// the web build (this release displays the address; it never signs).
function inspect(outDir) {
  const files = readdirSync(outDir, { recursive: true }).map(String);
  const js = files.filter(file => file.endsWith('.js'));
  return {
    ixiosJs: js.filter(file => /ixios/i.test(file) || /ixios/i.test(readFileSync(join(outDir, file), 'utf8'))),
    ixiosHtml: files.filter(file => file.endsWith('.html') && /ixios/i.test(readFileSync(join(outDir, file), 'utf8'))),
    signWasm: files.filter(file => /mldsa87-sign/.test(file)),
    // mldsa87-verify (src/pq/ixios verify path) ships too; the released 0.1.160 build has the same three files.
    keygenWasm: files.filter(file => /mldsa87-[^/]+\.wasm$/.test(file) && !/mldsa87-(sign|verify)/.test(file)),
  };
}
async function serve(outDir, port) {
  const server = await startPreview([vite, 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort', '--outDir', outDir], port, { cwd: app });
  servers.push(server);
  return server.url;
}
// Any request whose host names Ixios (the public RPC ixios-rpc.innova.limited,
// the test network's nx-rpc.ixoflow.io, or any other Ixios endpoint). Only the mocked RPCs may be requested.
const ixiosHost = requestUrl => /ixios|innova\.limited|ixoflow\.io/i.test(new URL(requestUrl).hostname);
// The Ixios RPC mock: genesis block 0 (network identity) and eth_getBalance.
async function ixiosRead(route) {
  const req = route.request();
  if (new URL(req.url()).origin !== new URL(IXIOS_RPC).origin) return false;
  assert.equal(req.method(), 'POST');
  const call = req.postDataJSON();
  ixiosCalls.push({ method: call.method, params: call.params });
  let result;
  if (call.method === 'eth_getBlockByNumber') result = { number: '0x1', parentHash: ixiosGenesis };
  else if (call.method === 'eth_getBalance') result = IXIOS_BALANCE;
  else { await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, error: { code: -32601, message: 'Fixture: method not mocked' } } }); return true; }
  await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, result } });
  return true;
}
async function openWallet(url) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 960 } }); page.setDefaultTimeout(20000);
  const unexpected = [], errors = [], wasm = [], ixiosRequests = [], pqRefused = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { if (ixiosHost(req.url())) ixiosRequests.push(req.url()); });
  await page.route('**/*', async route => {
    const req = route.request();
    if (await ixiosRead(route)) return;
    if (await historyRead(route)) return;
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
    if (PQ_HOST.test(new URL(req.url()).hostname)) { pqRefused.push(req.url()); return route.abort('blockedbyclient'); }
    if (!req.url().startsWith(url + '/') || req.method() !== 'GET' || req.postData()) {
      unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
    }
    if (new URL(req.url()).pathname.endsWith('.wasm')) wasm.push(new URL(req.url()).pathname + new URL(req.url()).search);
    return route.continue();
  });
  await page.goto(url);
  await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  await page.locator('#restore').click(); await pastePhrase(page, phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  // The Nodus address proves the wallet finished opening. Nodus is the network selected on page load, so it is the receive address.
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#receive-address').textContent));
  const nodusAddress = await page.locator('#receive-address').innerText();
  // Hide zero balances is checked on every wallet opening (src/app.js resetAssetView); unchecked, every
  // network's group is listed, held or not.
  assert.equal(await page.locator('#show-zero-balances').isChecked(), true);
  await page.locator('#show-zero-balances').uncheck();
  return { page, unexpected, errors, wasm, ixiosRequests, pqRefused, nodusAddress };
}
// The network list lives in the closed network disclosure, the PQ and Legacy groups collapsed
// (src/app.js #wallet-network, src/portfolio-view.js groupedNetworkControls).
async function openNetworks(page) { if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click(); }
async function expandGroupOf(page, badge) {
  const groupToggle = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');
  if (await groupToggle.count() && await groupToggle.getAttribute('aria-expanded') !== 'true') await groupToggle.click();
}
async function badgeOf(page, name) {
  await openNetworks(page);
  const badge = page.locator('#portfolio-networks .network-health', { hasText: name });
  await expandGroupOf(page, badge);
  return badge;
}
// Chooses the transfer network as a user does: its badge in the network disclosure.
async function selectNetwork(page, chain) {
  await openNetworks(page);
  const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
  await expandGroupOf(page, badge); await badge.click();
}
const rail = (page, href) => page.locator(`.wallet-navigation a[href="#${href}"]`);
async function openPage(page, name) { await rail(page, name).click(); await page.locator(`#page-${name}`).waitFor({ state: 'visible' }); }
// The rail's Portfolio link leaves a Send / Receive page.
async function walletView(page) {
  if (await page.locator('.wallet-page:not([hidden])').count()) await rail(page, '').click();
  await page.locator('#wallet-home').waitFor({ state: 'visible' });
}
async function portfolioDone(page) {
  await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled && document.querySelector('#portfolio-updated').textContent.startsWith('Last refresh:'));
}
// The Ixios address (and so its balance read) arrives after the automatic
// refresh has settled, as Cellframe's does; wait for its row to leave "Reading…".
async function ixiosSettled(page) {
  await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-chain="ixios"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; });
}

// ---- Second part: the Ixios test network (see the header) ----
const TEST_RPC = 'https://nx-rpc.ixoflow.io';
// Block 1's parentHash on the live test node, docs/research-evidence/2026-11-12-ixios-testnet-rpc/probes.txt:52.
const TEST_GENESIS = '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe';
// Mocked holdings, different from each other on purpose: 7654.321 IXIOS on the test node, 1234.567 IXIOS on the main node.
const TEST_BALANCE = '0x' + (7654321n * 10n ** 15n).toString(16), TEST_BALANCE_TEXT = '7,654.321 IXIOS', MAIN_BALANCE_TEXT = '1,234.567 IXIOS';
const WALLET_PASSWORD = 'public-test-password-123';
let testGenesis = TEST_GENESIS;
// Every JSON-RPC call answered by the test node mock, in arrival order.
const testCalls = [];
async function testnetRead(route) {
  const req = route.request();
  if (new URL(req.url()).origin !== new URL(TEST_RPC).origin) return false;
  assert.equal(req.method(), 'POST');
  const call = req.postDataJSON();
  testCalls.push({ method: call.method, params: call.params });
  let result;
  if (call.method === 'ixios_getBlockByNumber') result = { number: '0x1', parentHash: testGenesis };
  else if (call.method === 'ixios_getBalance') result = TEST_BALANCE;
  else { await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, error: { code: -32601, message: `Fixture: the method ${call.method} does not exist/is not available` } } }); return true; }
  await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, result } });
  return true;
}
function buildConnect() {
  const outDir = mkdtempSync(join(tmpdir(), 'nodus-connect-ixios-')); dirs.push(outDir);
  const result = spawnSync(process.execPath, [vite, 'build', '--config', 'vite.connect.config.js', '--outDir', outDir, '--emptyOutDir'], { cwd: app, encoding: 'utf8' });
  assert.equal(result.status, 0, `vite build (Connect) failed:\n${result.stdout}\n${result.stderr}`);
  return outDir;
}
async function serveConnect(outDir, port) {
  const server = await startPreview([vite, 'preview', '--config', 'vite.connect.config.js', '--host', '127.0.0.1', '--port', String(port), '--strictPort', '--outDir', outDir], port, { cwd: app });
  servers.push(server);
  return server.url;
}
// A fresh context and page of the web build or of the Connect build, wallet opened from the public test phrase. The main
// and test nodes are mocked by URL; the PQ providers are refused; every other request is recorded as unexpected. A counter on
// localStorage.setItem for the kept balances lets the saved-balance check see when a write has happened.
async function openSite(url, connect) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 960 } });
  const page = await context.newPage(); page.setDefaultTimeout(20000);
  const unexpected = [], errors = [], ixiosRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { if (ixiosHost(req.url())) ixiosRequests.push(req.url()); });
  await page.addInitScript(key => {
    const set = Storage.prototype.setItem; window.__balanceWrites = 0;
    Storage.prototype.setItem = function (name, value) { if (name === key) window.__balanceWrites++; return set.call(this, name, value); };
  }, BALANCES_KEY);
  await page.route('**/*', async route => {
    const req = route.request();
    if (await ixiosRead(route)) return;
    if (await testnetRead(route)) return;
    if (await historyRead(route)) return;
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
    if (PQ_HOST.test(new URL(req.url()).hostname)) return route.abort('blockedbyclient');
    if (!req.url().startsWith(url + '/') || req.method() !== 'GET' || req.postData()) {
      unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
    }
    return route.continue();
  });
  // Connect talks to Nodus nodes over WebSockets: none is reachable here (as in test/connect-smoke.js).
  if (connect) await page.routeWebSocket(() => true, ws => ws.close());
  await page.goto(url);
  await page.waitForFunction(() => { const button = document.querySelector('#restore'); return button && !button.disabled && typeof button.onclick === 'function'; });
  await page.locator('#restore').click(); await pastePhrase(page, phrase);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  return { context, page, unexpected, errors, ixiosRequests };
}
// Connect opens on its Home tab; the wallet is the Wallet tab.
async function toWalletTab(page, connect) { if (connect) await page.locator('.app-nav-item[data-tab="wallet"]').click(); }
async function chooseEnvironment(page, id) {
  await openNetworks(page);
  if (!await page.locator('#wallet-environment').evaluate(node => node.open)) await page.locator('#wallet-environment > summary').click();
  await page.locator(`#wallet-environment button[data-environment="${id}"]`).click();
}
const environments = page => page.locator('#wallet-environment button[data-environment]').evaluateAll(buttons => buttons.map(button => [button.dataset.environment, button.textContent]));
const stageLabels = page => page.locator('.selected-network-stage').evaluateAll(nodes => [...new Set(nodes.map(node => node.textContent))]);
const waitHolding = (page, text) => page.waitForFunction(expected => document.querySelector('.asset-group[data-chain="ixios"] .holding-value strong')?.textContent === expected, text);
async function refreshNow(page) {
  await walletView(page);
  await page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; }); await portfolioDone(page);
}
const sessionReleased = page => page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nodus.wallet.session'));
async function saveWallet(page) {
  await openPage(page, 'settings');
  await page.getByText('Save wallet on this device (optional)', { exact: true }).click();
  await page.locator('#vault-password').fill(WALLET_PASSWORD); await page.locator('#vault-confirm-password').fill(WALLET_PASSWORD);
  await page.locator('#vault-risk-confirm').check(); await page.locator('#vault-save').click();
  await page.waitForFunction(() => document.querySelector('#vault-status').textContent.includes('Encrypted wallet saved'));
  await walletView(page);
}
async function lockWallet(page, connect) {
  if (connect) await page.locator('.app-nav-item[data-tab="more"]').click();
  await page.locator('#lock').click();
  await page.locator('#wallet-open').waitFor({ state: 'hidden' }); await sessionReleased(page);
}
async function unlockWallet(page, connect) {
  await page.locator('#unlock-password').fill(WALLET_PASSWORD); await page.locator('#unlock-wallet').click();
  await page.locator('#wallet-open').waitFor({ state: 'visible' });
  await toWalletTab(page, connect);
  // Every opening hides zero balances again (src/app.js resetAssetView): the Ixios group is listed only if unchecked.
  await page.locator('#show-zero-balances').uncheck();
}
// No new write of the kept balances for 300 ms (see the header: this is how the saved-balance check knows the write it
// is about to look at has happened).
const writesSettled = page => page.waitForFunction(() => { const now = window.__balanceWrites, settled = window.__seenWrites === now; window.__seenWrites = now; return settled; }, undefined, { polling: 300 });
async function siteChecks(url, connect) {
  const label = connect ? 'Connect' : 'web', site = await openSite(url, connect), page = site.page, mainOrigin = new URL(IXIOS_RPC).origin, testOrigin = new URL(TEST_RPC).origin;
  try {
    await toWalletTab(page, connect);
    await page.locator('#show-zero-balances').uncheck();
    await waitHolding(page, MAIN_BALANCE_TEXT);
    assert.deepEqual(testCalls, [], `${label}: no test node request while the wallet is on Mainnet`);
    // The chooser: Mainnet and Testnet, starting on Mainnet; Ixios keeps its own address line (no PQ status or note).
    await selectNetwork(page, 'ixios');
    assert.deepEqual(await environments(page), [['mainnet', 'Mainnet'], ['testnet', 'Testnet']], `${label}: chooser options`);
    assert.equal(await page.locator('#pq-network-environment').inputValue(), 'mainnet');
    assert.match(await page.locator('#wallet-environment summary').textContent(), /Environment · Mainnet/);
    assert.equal(await page.locator('#wallet-environment').evaluate(node => node.hidden), false);
    assert.equal(await page.locator('#pq-address-status').evaluate(node => node.hidden), true);
    assert.equal(await page.locator('#pq-recovery-note').evaluate(node => node.hidden), true);
    assert.deepEqual(await stageLabels(page), ['Mainnet']);
    // Testnet: only ixios_ calls to the test node, and none to the main node.
    ixiosCalls.length = 0; testCalls.length = 0;
    let mark = site.ixiosRequests.length;
    await chooseEnvironment(page, 'testnet');
    await waitHolding(page, TEST_BALANCE_TEXT);
    assert.deepEqual(testCalls, [{ method: 'ixios_getBlockByNumber', params: ['0x1', false] }, { method: 'ixios_getBalance', params: [expected, 'latest'] }], `${label}: test node calls`);
    assert.deepEqual(ixiosCalls, [], `${label}: no main node call on Testnet`);
    let fresh = site.ixiosRequests.slice(mark);
    assert.ok(fresh.length > 0 && fresh.every(requestUrl => new URL(requestUrl).origin === testOrigin), fresh.join());
    assert.deepEqual(await stageLabels(page), ['Testnet']);
    assert.equal(await page.locator('#pq-network-environment').inputValue(), 'testnet');
    assert.match(await page.locator('#wallet-environment summary').textContent(), /Environment · Testnet/);
    assert.equal(await page.locator('#send-fields').evaluate(node => node.hidden), true);
    assert.equal(await page.locator('#send-disabled-note').evaluate(node => node.hidden), false);
    assert.equal(await page.locator('#send-disabled-note').textContent(), IXIOS_NOTE);
    // A wrong genesis on the test entry (Ethereum's, and the main Ixios one): no balance call.
    for (const wrong of [ETHEREUM_GENESIS, IXIOS_GENESIS]) {
      testCalls.length = 0; testGenesis = wrong;
      await refreshNow(page);
      assert.deepEqual(testCalls, [{ method: 'ixios_getBlockByNumber', params: ['0x1', false] }], `${label}: no ixios_getBalance after the wrong genesis ${wrong}`);
    }
    testGenesis = TEST_GENESIS;
    // Back to Mainnet: today's eth_ calls, nothing for the test node.
    ixiosCalls.length = 0; testCalls.length = 0; mark = site.ixiosRequests.length;
    await chooseEnvironment(page, 'mainnet');
    await waitHolding(page, MAIN_BALANCE_TEXT);
    assert.deepEqual(ixiosCalls, [{ method: 'eth_getBlockByNumber', params: ['0x1', false] }, { method: 'eth_getBalance', params: [expected, 'latest'] }], `${label}: main node calls`);
    assert.deepEqual(testCalls, [], `${label}: no test node call on Mainnet`);
    fresh = site.ixiosRequests.slice(mark);
    assert.ok(fresh.length > 0 && fresh.every(requestUrl => new URL(requestUrl).origin === mainOrigin), fresh.join());
    assert.deepEqual(await stageLabels(page), ['Mainnet']);
    // Choosing Testnet, leaving Ixios for another chain and coming back selects Ixios on Mainnet again, as for the PQ chains.
    await chooseEnvironment(page, 'testnet');
    await waitHolding(page, TEST_BALANCE_TEXT);
    await selectNetwork(page, 'ethereum');
    assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
    ixiosCalls.length = 0; testCalls.length = 0; mark = site.ixiosRequests.length;
    await selectNetwork(page, 'ixios');
    assert.equal(await page.locator('#chain').inputValue(), 'ixios');
    await waitHolding(page, MAIN_BALANCE_TEXT);
    assert.equal(await page.locator('#pq-network-environment').inputValue(), 'mainnet', `${label}: Ixios selected again is on Mainnet`);
    assert.match(await page.locator('#wallet-environment summary').textContent(), /Environment · Mainnet/);
    assert.deepEqual(await stageLabels(page), ['Mainnet']);
    assert.deepEqual(ixiosCalls, [{ method: 'eth_getBlockByNumber', params: ['0x1', false] }, { method: 'eth_getBalance', params: [expected, 'latest'] }], `${label}: main node calls after selecting Ixios again`);
    assert.deepEqual(testCalls, [], `${label}: no test node call after selecting Ixios again`);
    fresh = site.ixiosRequests.slice(mark);
    assert.ok(fresh.length > 0 && fresh.every(requestUrl => new URL(requestUrl).origin === mainOrigin), fresh.join());
    // Saved wallet: a test balance read before locking is neither kept nor shown after unlocking.
    await saveWallet(page);
    await page.waitForFunction(() => window.__balanceWrites > 0);
    await writesSettled(page);
    const writesBefore = await page.evaluate(() => window.__balanceWrites);
    await chooseEnvironment(page, 'testnet');
    await waitHolding(page, TEST_BALANCE_TEXT);
    await page.waitForFunction(before => window.__balanceWrites > before, writesBefore);
    await writesSettled(page);
    await lockWallet(page, connect);
    // The main node now fails its genesis check, so any kept Ixios balance would be shown as "Last read".
    ixiosGenesis = ETHEREUM_GENESIS; ixiosCalls.length = 0; testCalls.length = 0;
    await unlockWallet(page, connect);
    await ixiosSettled(page);
    const reopened = await page.locator('.asset-group[data-chain="ixios"]').textContent();
    assert.doesNotMatch(reopened, /7,654\.321/, `${label}: the test balance is not shown after unlocking`);
    assert.doesNotMatch(reopened, /Last read/, `${label}: nothing is kept for Ixios after a Testnet read`);
    assert.deepEqual(testCalls, [], `${label}: no test node call after unlocking`);
    assert.ok(ixiosCalls.length > 0 && ixiosCalls.every(call => call.method.startsWith('eth_')), `${label}: the reopened wallet reads the main node`);
    ixiosGenesis = IXIOS_GENESIS;
    await selectNetwork(page, 'ixios');
    assert.equal(await page.locator('#pq-network-environment').inputValue(), 'mainnet', `${label}: reopened on Mainnet`);
    assert.match(await page.locator('#wallet-environment summary').textContent(), /Environment · Mainnet/);
    assert.deepEqual(await stageLabels(page), ['Mainnet']);
    assert.ok(site.ixiosRequests.every(requestUrl => [mainOrigin, testOrigin].includes(new URL(requestUrl).origin)), site.ixiosRequests.join());
    assert.deepEqual(site.unexpected, [], `${label}: unexpected requests`); assert.deepEqual(site.errors, [], `${label}: page errors`);
  } finally { await site.context.close(); }
}

try {
  const outDir = build();
  const files = inspect(outDir);
  assert.ok(files.ixiosJs.length > 0, 'the build must contain the Ixios code');
  // The old top-of-page panel is gone: Ixios is created only by JavaScript.
  assert.deepEqual(files.ixiosHtml, []);
  // The signing module ships in the build (src/pq/ixios/transaction.js imports src/pq/sign.js); the released 0.1.160
  // web and Connect builds already carry it (deployment0160 SHA256SUMS: dist/assets/mldsa87-sign-Dd8Y3xVG.wasm).
  // Web send stays off (decisions/2026-09-23-ixios-send-mainnet-first.md "Değişiklik 2"); the page never fetches it (below).
  assert.equal(files.signWasm.length, 1);
  assert.equal(files.keygenWasm.length, 1, 'Ixios reuses the Nodus keygen module, not a new one');
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });

  const on = await openWallet(await serve(outDir, 4193));
  const page = on.page;
  assert.equal(await page.locator('#ixios-address-panel').count(), 0, 'no separate top panel');
  // Network selector: Nodus first, Ixios after the sendable chains and Cellframe.
  // Today's screen (reason: the list is grouped, PQ group first, and includes the eight PQ networks since 0.1.155; src/network-groups.js, src/app.js extraNetworks order).
  assert.deepEqual(await page.locator('#chain option').evaluateAll(options => options.map(o => o.value)),
    ['nodus', 'cellframe', 'ixios', 'algorand', 'tidecoin', 'ckb', 'soqucoin', 'qtc', 'xion', 'splendor', 'asentum', 'ethereum', 'bsc', 'solana', 'tron']);
  assert.equal(await page.locator('#chain option[value="ixios"]').textContent(), 'Ixios');
  // The scope paragraph is gone (0.1.108, operator: "Gerek yok onlar artık").
  assert.equal(await page.locator('#portfolio-scope').count(), 0);
  // Portfolio: health badge, and an IXIOS row read like the CPUNK row. There are no network filters (0.1.145,
  // commit 0b3b0eb0d; src/portfolio-view.js: `$('portfolio-filters').hidden = true`, the group list lists every network).
  assert.equal(await page.locator('#portfolio-filters button').count(), 0, 'no network filters (0.1.145)');
  // The badge is in the closed network disclosure, the PQ group collapsed: opened as a user would (badgeOf).
  const badge = await badgeOf(page, 'Ixios');
  // 0.1.102: built-in icon (data: or content-hashed); data-icon names the file
  assert.equal(await badge.locator('img.coin-icon').getAttribute('data-icon'), 'ixios.png');
  assert.match(await badge.locator('img.coin-icon').getAttribute('src'), /^data:image\/|\/assets\/[^/]+-[A-Za-z0-9_-]{8}\.png$/);
  await portfolioDone(page); await ixiosSettled(page);
  assert.equal(await badge.getAttribute('title'), 'Ixios · Balances read');
  assert.equal(await badge.getAttribute('data-health'), 'current', 'green light (0.1.103)');
  // Network identity (block 1's parentHash = genesis hash) is checked before the
  // balance is read, and the balance is read for the derived, checksummed address.
  assert.deepEqual(ixiosCalls, [
    { method: 'eth_getBlockByNumber', params: ['0x1', false] },
    { method: 'eth_getBalance', params: [expected, 'latest'] },
  ]);
  // One group per network (0.1.145): data-symbol / data-chain is the chain id, the IXIOS row is the row of "ixios"
  // (src/portfolio-view.js render). The coin list shows the groups of held networks, or of every network with Hide
  // zero balances unchecked (openWallet unchecks it).
  const row = page.locator('.asset-group[data-chain="ixios"]');
  assert.equal(await row.count(), 1);
  assert.equal(await row.locator('summary img.coin-icon').getAttribute('data-icon'), 'ixios.png');
  assert.equal(await row.locator('summary .network-heading-select').innerText(), 'Ixios');
  // The old per-asset summary ("IXIOS · Ixios" subtitle, .asset-value) is gone with the grouped list (0.1.145,
  // commit 0b3b0eb0d removed .asset-name / .asset-value from src/portfolio-view.js); the amount is on the holding row.
  assert.equal(await row.locator('.asset-name, .asset-value').count(), 0);
  // Shown like the CPUNK row: the balance, and no USD value. A closed group has no innerText: it is opened by its chevron first.
  const cpunk = page.locator('.asset-group[data-chain="cellframe"]');
  await row.locator('summary .asset-chevron').click();
  assert.equal(await row.locator('.chain-holding img.coin-icon').getAttribute('data-icon'), 'ixios.png');
  assert.equal(await row.locator('.holding-value strong').innerText(), '1,234.567 IXIOS'); // 0.1.28 display form
  assert.equal(await row.locator('.holding-value small').innerText(), '—');
  assert.equal(await row.locator('.holding-value small').textContent(), await cpunk.locator('.holding-value small').textContent(), 'no USD value, like CPUNK');
  // Row buttons are gone (0.1.145, commit 0b3b0eb0d; test/browser-portfolio.js: "Send and Receive are rail pages, not row
  // buttons"): the row only selects its network and asset, the rail offers Receive and, for a receive-only network, no Send.
  assert.equal(await page.locator('#balances .holding-actions').count(), 0, 'Send and Receive are rail pages, not row buttons');
  // Outside the USD total: the priced networks only (price fixture $2,
  // zero holdings), although IXIOS holds a non-zero balance. The PQ networks' providers are refused here, and
  // their priced assets count as unavailable balances (as in test/browser-portfolio.js).
  // With the refused PQ reads the priced set is incomplete and its known total is zero, so no total is shown
  // (src/portfolio.js:133: a total only when the set is complete or above zero).
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  // The PQ addresses arrive after the refresh settled; their refused reads leave the status on the count above.
  await page.waitForFunction(source => new RegExp(source).test(document.querySelector('#portfolio-status').textContent), missingStatus.source);
  assert.match(await page.locator('#portfolio-status').innerText(), missingStatus);
  assert.doesNotMatch(await page.locator('body').innerText(), /not active/i);
  // Selecting the IXIOS row (a 'choose' selection, src/app.js selectAsset) selects the Ixios network: the rail offers Receive, not Send.
  await row.locator('.holding-select').click();
  assert.equal(await page.locator('#chain').inputValue(), 'ixios');
  assert.equal(await rail(page, 'send').isVisible(), false, 'IXIOS: no Send');
  assert.equal(await rail(page, 'receive').isVisible(), true, 'IXIOS: Receive');
  await openPage(page, 'receive');
  // Checksummed address, send fields hidden, Ixios note. The Send page is never displayed for a receive-only network,
  // so the state is read from `hidden` (src/app.js: send-fields hidden = receiveOnly, send-disabled-note hidden = !receiveOnly).
  await page.waitForFunction(address => document.querySelector('#receive-address').textContent === address, expected);
  assert.equal(await page.locator('#send-fields').evaluate(node => node.hidden), true);
  assert.equal(await page.locator('#send-disabled-note').evaluate(node => node.hidden), false);
  assert.equal(await page.locator('#send-disabled-note').textContent(), IXIOS_NOTE);
  // UI pack 2026-11-03 (operator "2"): the "Derived locally…" status line is gone; the empty line takes no space.
  assert.equal(await page.locator('#ixios-address-status').isVisible(), false);
  assert.equal(await page.locator('#ixios-address-status').textContent(), '');
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  // (#account-explorer sits on the Activity page since 0.1.75: its own
  // `hidden` says whether the network has an explorer.)
  assert.equal(await page.locator('#account-explorer').evaluate(node => node.hidden), true);
  assert.match(await page.locator('#receive-title').innerText(), /Receive on Ixios/);
  // "Send / Receive · " became "Send · " (src/app.js: send-title firstChild text; test/browser-smoke.js 'Send · Solana').
  assert.equal(await page.locator('#send-title').textContent(), 'Send · Ixios');
  // The QR encodes exactly the checksummed Ixios address shown.
  assert.equal(await page.locator('#receive-address').innerText(), expected);
  assert.equal(await decodeQr(page), expected);
  assert.match(on.nodusAddress, /^[0-9a-f]{128}$/);
  assert.notEqual(on.nodusAddress.slice(-96), expected.slice(2).toLowerCase(), 'Ixios key must differ from the Nodus identity');
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.locator('#copy-address').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expected);
  // Cellframe keeps its own note; switching back to Ixios restores the Ixios one.
  // #chain is hidden since 0.1.145 (src/app.js `$('chain').hidden = true`): the network is chosen by its badge in the network disclosure.
  await selectNetwork(page, 'cellframe');
  assert.equal(await page.locator('#chain').inputValue(), 'cellframe');
  assert.equal(await page.locator('#send-disabled-note').textContent(), 'Sending CPUNK is not available in this release. You can receive to the address above.');
  assert.equal(await page.locator('#ixios-address-status').isVisible(), false);
  await selectNetwork(page, 'ethereum');
  assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
  assert.equal(await page.locator('#send-fields').evaluate(node => node.hidden), false); assert.equal(await page.locator('#send-disabled-note').evaluate(node => node.hidden), true);
  await selectNetwork(page, 'ixios');
  assert.equal(await page.locator('#chain').inputValue(), 'ixios');
  assert.equal(await page.locator('#receive-address').innerText(), expected);
  assert.equal(await page.locator('#send-disabled-note').textContent(), IXIOS_NOTE);
  // Wrong network (an RPC whose genesis is Ethereum's, same chain id 1): the
  // balance is never read; the row keeps the amount read earlier from the
  // right network, marked "Read failed · last read" (0.1.41, the app's
  // stale-while-revalidate wallet cache) — never an amount from the wrong
  // network, never a zero.
  await walletView(page);
  ixiosCalls.length = 0; ixiosGenesis = ETHEREUM_GENESIS;
  // Refresh is hidden while balances update automatically (0.1.108): it is
  // pressed through the page once enabled (a read in flight disables it).
  await page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; }); await portfolioDone(page);
  assert.deepEqual(ixiosCalls, [{ method: 'eth_getBlockByNumber', params: ['0x1', false] }], 'no eth_getBalance after a wrong genesis');
  assert.equal(await row.locator('.holding-value strong').textContent(), '1,234.567 IXIOS');
  // The row says "Last read <time>" under the amount (the "Read failed" wording is gone, UI pack 2026-11-03;
  // src/portfolio-view.js: keptAt -> `Last read ${readTime}`), and the network's badge says it too.
  assert.match(await row.locator('.holding-value small').textContent(), /^Last read \d{1,2}:\d{2}/);
  assert.match(await badge.getAttribute('title'), /^Ixios · Last read /);
  assert.equal(await badge.getAttribute('data-health'), 'failed', 'red light: the last read failed (0.1.103)');
  assert.equal(await page.locator('#portfolio-total').innerText(), '—'); // same rule as above (src/portfolio.js:133)
  // The right network again: the balance comes back.
  ixiosCalls.length = 0; ixiosGenesis = IXIOS_GENESIS;
  await page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; }); await portfolioDone(page);
  assert.deepEqual(ixiosCalls.map(call => call.method), ['eth_getBlockByNumber', 'eth_getBalance']);
  assert.equal(await row.locator('.holding-value strong').textContent(), '1,234.567 IXIOS');
  assert.doesNotMatch(await row.locator('.holding-value small').textContent(), /Last read/);
  assert.equal(await badge.getAttribute('title'), 'Ixios · Balances read');
  assert.equal(await badge.getAttribute('data-health'), 'current');
  assert.doesNotMatch(await page.locator('body').innerText(), /not active/i);
  // The Cellframe derivation also fetches legacy-dilithium-*.wasm on open; what matters
  // here is that the keygen module was loaded and the signing module never was.
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm$/.test(path)), 'Nodus keygen request (no query)');
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm\?ixios$/.test(path)), 'Ixios keygen request is tagged ?ixios');
  assert.ok(on.wasm.every(path => !/mldsa87-sign/.test(path)));
  await page.locator('#lock').click();
  assert.equal(await page.locator('#receive-address').textContent(), '');
  assert.equal(await page.locator('#receive-qr').evaluate(node => node.childElementCount), 0);
  assert.equal(await page.locator('#ixios-address-status').textContent(), '');
  assert.equal(await page.locator('#balances').textContent(), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  // Every Ixios-host request went to the configured public RPC (and was mocked).
  assert.ok(on.ixiosRequests.length > 0);
  assert.ok(on.ixiosRequests.every(requestUrl => new URL(requestUrl).origin === new URL(IXIOS_RPC).origin), on.ixiosRequests.join());
  assert.deepEqual(on.unexpected, []); assert.deepEqual(on.errors, []);
  // Second part (header): the Ixios test network on this web build, then on a Connect build.
  const webUrl = servers[0].url;
  await siteChecks(webUrl, false);
  await siteChecks(await serveConnect(buildConnect(), 4194), true);
  console.log('Ixios test network browser checks passed on the web build and on the Connect build: the Network environment chooser offers Mainnet and Testnet and starts on Mainnet; Testnet makes only ixios_ calls to nx-rpc.ixoflow.io after the test genesis check, shows the stage "Testnet" and the unchanged note with the send fields hidden, makes no balance call after a wrong genesis and no call to the main node; back to Mainnet gives the eth_ calls and none to the test node; a saved wallet locked after a Testnet read shows no Testnet balance (and no "Last read") when reopened, and reopens on Mainnet.');
  console.log('Ixios browser checks passed: the build lists Ixios in the network selector, network badges and coin list (IXIOS row: no row buttons, receive only through the rail, balance read like CPUNK after a genesis-block identity check, outside the USD total; a wrong genesis makes no balance read and keeps only the amount read earlier from the right network, marked "Last read"); selecting it shows the checksummed receive address (its QR decodes to exactly that address; lock clears the QR), hides the send fields and shows the Ixios note while Cellframe keeps its own; Ixios requests go only to the configured RPC; lock clears it; loads only the keygen module (?ixios). The build ships neither mldsa87-sign.wasm nor Ixios markup; no unmocked external requests or storage.');
} finally {
  await browser?.close();
  for (const server of servers) server.stop();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
