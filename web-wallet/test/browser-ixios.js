import { portfolioRead, cellframeRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
// Ixios as a receive-only, not-active wallet network, both sides of
// VITE_ENABLE_IXIOS. Public test phrase only; every external request is
// intercepted. Unlike the other browser scripts this one builds its own two
// bundles (flag on, flag off) into temporary directories and previews each with
// --outDir, so dist/ is left untouched.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
const app = fileURLToPath(new URL('..', import.meta.url));
const vite = join(app, 'node_modules/vite/bin/vite.js');
const { Phrase: phrase, Checksummed: expected } = JSON.parse(readFileSync(new URL('./fixtures/ixios-checksum.json', import.meta.url))).vectors[0];
assert.equal(phrase, Array(23).fill('abandon').concat('art').join(' '));
// Spec 2026-09-23-wallet-0.1.16-ixios-spec.md, Paket R2 item 3, verbatim.
const IXIOS_NOTE = 'Do not send IXIOS to this address yet. The Ixios network has not switched on quantum-safe addresses; funds sent here before it does may be lost. Sending and receiving will be enabled in a later release.';
const dirs = [], servers = [];
let browser;

function build(enabled) {
  const outDir = mkdtempSync(join(tmpdir(), `nodus-wallet-ixios-${enabled ? 'on' : 'off'}-`)); dirs.push(outDir);
  // The disabled build leaves the variable unset, exactly like a default production build.
  const env = { ...process.env }; delete env.VITE_ENABLE_IXIOS;
  if (enabled) env.VITE_ENABLE_IXIOS = 'true';
  const result = spawnSync(process.execPath, [vite, 'build', '--outDir', outDir, '--emptyOutDir'], { cwd: app, encoding: 'utf8', env });
  assert.equal(result.status, 0, `vite build failed:\n${result.stdout}\n${result.stderr}`);
  return outDir;
}
// Every emitted file, not only assets/: the signing module must not ship in
// either build (this release displays the address; it never signs).
function inspect(outDir) {
  const files = readdirSync(outDir, { recursive: true }).map(String);
  const js = files.filter(file => file.endsWith('.js'));
  return {
    ixiosJs: js.filter(file => /ixios/i.test(file) || /ixios/i.test(readFileSync(join(outDir, file), 'utf8'))),
    ixiosHtml: files.filter(file => file.endsWith('.html') && /ixios/i.test(readFileSync(join(outDir, file), 'utf8'))),
    signWasm: files.filter(file => /mldsa87-sign/.test(file)),
    keygenWasm: files.filter(file => /mldsa87-[^/]+\.wasm$/.test(file) && !/mldsa87-sign/.test(file)),
  };
}
async function serve(outDir, port) {
  const url = `http://127.0.0.1:${port}`;
  servers.push(spawn(process.execPath, [vite, 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort', '--outDir', outDir], { cwd: app, stdio: 'pipe' }));
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
  return url;
}
// Any request whose host names Ixios (the public RPC ixios-rpc.innova.limited,
// or any other Ixios endpoint): the network is not active, so none may be made.
const ixiosHost = requestUrl => /ixios|innova\.limited/i.test(new URL(requestUrl).hostname);
async function openWallet(url) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 960 } }); page.setDefaultTimeout(20000);
  const unexpected = [], errors = [], wasm = [], ixiosRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { if (ixiosHost(req.url())) ixiosRequests.push(req.url()); });
  await page.route('**/*', async route => {
    const req = route.request();
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
  // The Nodus address is independent of the flag and proves the wallet finished opening.
  await page.waitForFunction(() => /^[0-9a-f]{128}$/.test(document.querySelector('#nodus-address').textContent));
  return { page, unexpected, errors, wasm, ixiosRequests };
}
async function portfolioDone(page) {
  await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled && document.querySelector('#portfolio-updated').textContent.startsWith('Last refresh:'));
}

try {
  const enabledDir = build(true), disabledDir = build(false);
  const enabledFiles = inspect(enabledDir), disabledFiles = inspect(disabledDir);
  // Non-vacuous: the enabled bundle does carry Ixios code, so the empty result below means something.
  assert.ok(enabledFiles.ixiosJs.length > 0, 'enabled build must contain the Ixios code');
  assert.deepEqual(disabledFiles.ixiosJs, [], 'disabled build must contain no JavaScript mentioning Ixios');
  // The old top-of-page panel is gone: Ixios is created only by the flag-on JavaScript.
  assert.deepEqual(enabledFiles.ixiosHtml, []); assert.deepEqual(disabledFiles.ixiosHtml, []);
  assert.deepEqual(enabledFiles.signWasm, []); assert.deepEqual(disabledFiles.signWasm, []);
  assert.equal(enabledFiles.keygenWasm.length, 1); assert.equal(disabledFiles.keygenWasm.length, 1);
  assert.deepEqual(enabledFiles.keygenWasm, disabledFiles.keygenWasm, 'Ixios reuses the Nodus keygen module, not a new one');
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });

  const on = await openWallet(await serve(enabledDir, 4193));
  const page = on.page;
  assert.equal(await page.locator('#ixios-address-panel').count(), 0, 'no separate top panel');
  // Network selector: Ixios after the sendable chains and Cellframe.
  assert.deepEqual(await page.locator('#chain option').evaluateAll(options => options.map(o => o.value)), ['ethereum', 'bsc', 'solana', 'tron', 'cellframe', 'ixios']);
  assert.equal(await page.locator('#chain option[value="ixios"]').textContent(), 'Ixios');
  assert.match(await page.locator('#portfolio-scope').innerText(), /Ixios/);
  assert.match(await page.locator('#portfolio-scope').innerText(), /not active yet/);
  // Portfolio: filter, health badge, and an IXIOS row that is never read.
  assert.equal(await page.locator('.network-filter[data-chain="ixios"]').innerText(), 'Ixios');
  const badge = page.locator('#portfolio-networks .network-health', { hasText: 'Ixios' });
  assert.equal(await badge.innerText(), 'Ixios · Not active yet');
  assert.ok((await badge.locator('img.coin-icon').getAttribute('src')).endsWith('/assets/coins/ixios.png'));
  await portfolioDone(page);
  const row = page.locator('.asset-group[data-symbol="IXIOS"]');
  assert.equal(await row.count(), 1);
  assert.ok((await row.locator('summary img.coin-icon').getAttribute('src')).endsWith('/assets/coins/ixios.png'));
  assert.equal(await row.locator('.asset-name small').innerText(), 'IXIOS · Ixios');
  assert.equal(await page.locator('.asset-group[data-symbol="ETH"] .asset-name small').innerText(), 'Ethereum · Ethereum', 'shared subtitle format unchanged for other coins');
  assert.equal(await row.locator('.asset-value strong').innerText(), '—');
  assert.equal(await row.locator('.asset-value small').innerText(), 'Not active yet');
  await row.locator('summary').click();
  assert.equal(await row.locator('.holding-value strong').innerText(), '—');
  assert.equal(await row.locator('.holding-value small').innerText(), 'Not active yet');
  assert.deepEqual(await row.locator('.holding-actions button').allTextContents(), ['Receive']);
  assert.doesNotMatch(await page.locator('#balances').innerText(), /\d\s*IXIOS/, 'never a numeric IXIOS balance');
  // The USD total is the priced four networks only (price fixture $2, zero holdings).
  assert.equal(await page.locator('#portfolio-total').innerText(), '$0.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /All supported asset balances/);
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
  assert.equal(await page.locator('#ixios-address-status').isVisible(), true);
  assert.match(await page.locator('#ixios-address-status').innerText(), /Derived locally/);
  assert.equal(await page.locator('#cellframe-address-status').isVisible(), false);
  assert.equal(await page.locator('#account-explorer').isVisible(), false);
  assert.match(await page.locator('#receive-title').innerText(), /Receive on Ixios/);
  assert.notEqual((await page.locator('#nodus-address').innerText()).slice(-96), expected.slice(2).toLowerCase(), 'Ixios key must differ from the Nodus identity');
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
  // Another full refresh still reads nothing from Ixios.
  await page.locator('#portfolio-refresh').click(); await portfolioDone(page);
  assert.equal(await row.locator('.asset-value small').innerText(), 'Not active yet');
  // The Cellframe derivation also fetches legacy-dilithium-*.wasm on open; what matters
  // here is that the keygen module was loaded and the signing module never was.
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm$/.test(path)), 'Nodus keygen request (no query)');
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm\?ixios$/.test(path)), 'Ixios keygen request is tagged ?ixios');
  assert.ok(on.wasm.every(path => !/mldsa87-sign/.test(path)));
  await page.locator('#lock').click();
  assert.equal(await page.locator('#receive-address').textContent(), '');
  assert.equal(await page.locator('#ixios-address-status').textContent(), '');
  assert.equal(await page.locator('#balances').textContent(), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(on.ixiosRequests, [], 'no request to any Ixios host');
  assert.deepEqual(on.unexpected, []); assert.deepEqual(on.errors, []);

  const off = await openWallet(await serve(disabledDir, 4194));
  await portfolioDone(off.page);
  assert.equal(await off.page.locator('#chain option[value="ixios"]').count(), 0);
  assert.deepEqual((await off.page.locator('#chain option').evaluateAll(options => options.map(o => `${o.value} ${o.textContent}`))).filter(text => /ixios/i.test(text)), []);
  assert.equal(await off.page.locator('.asset-group[data-symbol="IXIOS"]').count(), 0);
  assert.equal(await off.page.locator('.network-filter[data-chain="ixios"]').count(), 0);
  assert.doesNotMatch(await off.page.locator('#portfolio-networks').innerText(), /ixios/i);
  assert.doesNotMatch(await off.page.locator('#portfolio-scope').innerText(), /ixios/i);
  assert.equal(await off.page.locator('#ixios-address-status').count(), 0);
  assert.doesNotMatch(await off.page.locator('body').innerText(), /ixios/i);
  assert.ok(off.wasm.every(path => !/mldsa87-sign/.test(path)));
  assert.ok(off.wasm.every(path => !/\?ixios$/.test(path)), 'flag-off build makes no Ixios keygen request');
  await off.page.locator('#lock').click();
  assert.equal(await off.page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(off.ixiosRequests, []);
  assert.deepEqual(off.unexpected, []); assert.deepEqual(off.errors, []);
  console.log('Ixios browser checks passed: flag-on build lists Ixios in the network selector, portfolio filters, badges and assets (IXIOS row: Receive only, "Not active yet", never a balance, outside the USD total); selecting it shows the checksummed receive address, hides the send fields and shows the Ixios note while Cellframe keeps its own; no request to any Ixios host; lock clears it; loads only the keygen module (?ixios). Flag-off build shows no Ixios anywhere and ships no Ixios JavaScript; neither build ships mldsa87-sign.wasm or Ixios markup; no unmocked external requests or storage.');
} finally {
  await browser?.close();
  for (const server of servers) server.kill();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
