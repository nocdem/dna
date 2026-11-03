import { portfolioRead, cellframeRead, historyRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
// Ixios as a receive-only wallet network handled exactly like Cellframe (the
// Ixios build switch is gone: every build carries Ixios). Public test
// phrase only; every external request is intercepted (the Ixios RPC included:
// mocked below). Unlike the other browser scripts this one builds its own bundle
// into a temporary directory and previews it with --outDir, so dist/ is left untouched.
// Needs: node_modules/vite (one `vite build` run), jsqr, fixtures/ixios-checksum.json,
// and Chromium (CHROMIUM_PATH, otherwise the one Playwright finds). Preview port
// 4193 on 127.0.0.1 with --strictPort: a busy port makes the script fail, not pass.
// Leaves: nothing; the output directory is removed and the preview is stopped in finally.
// Falsely passes: the Ixios RPC is a mock, so balances prove the page wiring,
// not the live node.
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
// or any other Ixios endpoint). Only the mocked RPC may be requested.
const ixiosHost = requestUrl => /ixios|innova\.limited/i.test(new URL(requestUrl).hostname);
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
  // Every asset row, held or not (zero balances hidden by default since 0.1.113).
  await page.addInitScript(() => { try { localStorage.setItem('nodus.showZeroBalances', '1'); } catch { /* storage refused */ } });
  const unexpected = [], errors = [], wasm = [], ixiosRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { if (ixiosHost(req.url())) ixiosRequests.push(req.url()); });
  await page.route('**/*', async route => {
    const req = route.request();
    if (await ixiosRead(route)) return;
    if (await historyRead(route)) return;
    if (await cellframeRead(route)) return;
    if (await portfolioRead(route)) return;
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
  return { page, unexpected, errors, wasm, ixiosRequests, nodusAddress };
}
async function portfolioDone(page) {
  await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled && document.querySelector('#portfolio-updated').textContent.startsWith('Last refresh:'));
}
// The Ixios address (and so its balance read) arrives after the automatic
// refresh has settled, as Cellframe's does; wait for its row to leave "Reading…".
async function ixiosSettled(page) {
  await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-symbol="IXIOS"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; });
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
  // Portfolio: filter, health badge, and an IXIOS row read like the CPUNK row.
  assert.equal(await page.locator('.network-filter[data-chain="ixios"]').innerText(), 'Ixios');
  const badge = page.locator('#portfolio-networks .network-health', { hasText: 'Ixios' });
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
  const row = page.locator('.asset-group[data-symbol="IXIOS"]');
  assert.equal(await row.count(), 1);
  assert.equal(await row.locator('summary img.coin-icon').getAttribute('data-icon'), 'ixios.png');
  assert.equal(await row.locator('.asset-name small').innerText(), 'IXIOS · Ixios');
  assert.equal(await page.locator('.asset-group[data-symbol="ETH"] .asset-name small').innerText(), 'Ethereum · Ethereum', 'shared subtitle format unchanged for other coins');
  // Shown like the CPUNK row: the balance, and no USD value.
  const cpunk = page.locator('.asset-group[data-symbol="CPUNK"]');
  assert.equal(await row.locator('.asset-value strong').innerText(), '1,234.567'); // 0.1.28 display form
  assert.equal(await row.locator('.asset-value small').innerText(), '—');
  assert.equal(await row.locator('.asset-value small').innerText(), await cpunk.locator('.asset-value small').innerText());
  await row.locator('summary').click();
  assert.equal(await row.locator('.holding-value strong').innerText(), '1,234.567 IXIOS');
  assert.equal(await row.locator('.holding-value small').innerText(), '—');
  assert.deepEqual(await row.locator('.holding-actions button').allTextContents(), ['Receive']);
  // Outside the USD total: the priced four networks only (price fixture $2,
  // zero holdings), although IXIOS holds a non-zero balance.
  assert.equal(await page.locator('#portfolio-total').innerText(), '$0.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /All supported asset balances/);
  assert.doesNotMatch(await page.locator('body').innerText(), /not active/i);
  await page.locator('.network-filter[data-chain="ixios"]').click();
  assert.deepEqual(await page.locator('.asset-group').evaluateAll(groups => groups.map(g => g.dataset.symbol)), ['IXIOS']);
  await page.locator('.network-filter[data-chain="all"]').click();
  // Receive action selects the Ixios network: checksummed address, send fields hidden, Ixios note.
  await page.getByRole('button', { name: 'Receive IXIOS on Ixios', exact: true }).click();
  assert.equal(await page.locator('#chain').inputValue(), 'ixios');
  await page.waitForFunction(address => document.querySelector('#receive-address').textContent === address, expected);
  assert.equal(await page.locator('#send-fields').isVisible(), false);
  assert.equal(await page.locator('#send-disabled-note').isVisible(), true);
  assert.equal(await page.locator('#send-disabled-note').innerText(), IXIOS_NOTE);
  // UI pack 2026-11-03 (operator "2"): the "Derived locally…" status line is gone; the empty line takes no space.
  assert.equal(await page.locator('#ixios-address-status').isVisible(), false);
  assert.equal(await page.locator('#ixios-address-status').textContent(), '');
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  // (#account-explorer sits on the Activity page since 0.1.75: its own
  // `hidden` says whether the network has an explorer.)
  assert.equal(await page.locator('#account-explorer').evaluate(node => node.hidden), true);
  assert.match(await page.locator('#receive-title').innerText(), /Receive on Ixios/);
  assert.equal(await page.locator('#send-title').innerText(), 'Send / Receive · Ixios');
  // The QR encodes exactly the checksummed Ixios address shown.
  assert.equal(await page.locator('#receive-address').innerText(), expected);
  assert.equal(await decodeQr(page), expected);
  assert.match(on.nodusAddress, /^[0-9a-f]{128}$/);
  assert.notEqual(on.nodusAddress.slice(-96), expected.slice(2).toLowerCase(), 'Ixios key must differ from the Nodus identity');
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.locator('#copy-address').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expected);
  // Cellframe keeps its own note; switching back to Ixios restores the Ixios one.
  await page.selectOption('#chain', 'cellframe');
  assert.equal(await page.locator('#send-disabled-note').innerText(), 'Sending CPUNK is not available in this release. You can receive to the address above.');
  assert.equal(await page.locator('#ixios-address-status').isVisible(), false);
  await page.selectOption('#chain', 'ethereum');
  assert.equal(await page.locator('#send-fields').isVisible(), true); assert.equal(await page.locator('#send-disabled-note').isVisible(), false);
  await page.selectOption('#chain', 'ixios');
  assert.equal(await page.locator('#receive-address').innerText(), expected);
  assert.equal(await page.locator('#send-disabled-note').innerText(), IXIOS_NOTE);
  // Wrong network (an RPC whose genesis is Ethereum's, same chain id 1): the
  // balance is never read; the row keeps the amount read earlier from the
  // right network, marked "Read failed · last read" (0.1.41, the app's
  // stale-while-revalidate wallet cache) — never an amount from the wrong
  // network, never a zero.
  ixiosCalls.length = 0; ixiosGenesis = ETHEREUM_GENESIS;
  // Refresh is hidden while balances update automatically (0.1.108): it is
  // pressed through the page once enabled (a read in flight disables it).
  await page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; }); await portfolioDone(page);
  assert.deepEqual(ixiosCalls, [{ method: 'eth_getBlockByNumber', params: ['0x1', false] }], 'no eth_getBalance after a wrong genesis');
  assert.equal(await row.locator('.holding-value strong').innerText(), '1,234.567 IXIOS');
  assert.match(await row.locator('.holding-value small').innerText(), /^Read failed · last read /);
  assert.equal(await row.locator('.asset-value small').innerText(), 'Last read');
  assert.match(await badge.getAttribute('title'), /^Ixios · Last read /);
  assert.equal(await badge.getAttribute('data-health'), 'failed', 'red light: the last read failed (0.1.103)');
  assert.equal(await page.locator('#portfolio-total').innerText(), '$0.00');
  // The right network again: the balance comes back.
  ixiosCalls.length = 0; ixiosGenesis = IXIOS_GENESIS;
  await page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; }); await portfolioDone(page);
  assert.deepEqual(ixiosCalls.map(call => call.method), ['eth_getBlockByNumber', 'eth_getBalance']);
  assert.equal(await row.locator('.holding-value strong').innerText(), '1,234.567 IXIOS');
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
  assert.equal(await page.evaluate(() => Object.keys(localStorage).filter(x => x !== 'nodus.showZeroBalances').length + sessionStorage.length), 0);
  // Every Ixios-host request went to the configured public RPC (and was mocked).
  assert.ok(on.ixiosRequests.length > 0);
  assert.ok(on.ixiosRequests.every(requestUrl => new URL(requestUrl).origin === new URL(IXIOS_RPC).origin), on.ixiosRequests.join());
  assert.deepEqual(on.unexpected, []); assert.deepEqual(on.errors, []);
  console.log('Ixios browser checks passed: the build lists Ixios in the network selector, portfolio filters, badges and assets (IXIOS row: Receive only, balance read like CPUNK after a genesis-block identity check, outside the USD total; a wrong genesis makes no balance read and keeps only the amount read earlier from the right network, marked "Read failed · last read"); selecting it shows the checksummed receive address (its QR decodes to exactly that address; lock clears the QR), hides the send fields and shows the Ixios note while Cellframe keeps its own; Ixios requests go only to the configured RPC; lock clears it; loads only the keygen module (?ixios). The build ships neither mldsa87-sign.wasm nor Ixios markup; no unmocked external requests or storage.');
} finally {
  await browser?.close();
  for (const server of servers) server.stop();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
