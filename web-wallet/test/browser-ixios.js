import { portfolioRead, cellframeRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
// Ixios receive-only address, both sides of VITE_ENABLE_IXIOS. Public test phrase
// only; every external request is intercepted. Unlike the other browser scripts
// this one builds its own two bundles (flag on, flag off) into temporary
// directories and previews each with --outDir, so dist/ is left untouched.
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
async function openWallet(url) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 960 } }); page.setDefaultTimeout(20000);
  const unexpected = [], errors = [], wasm = [];
  page.on('pageerror', error => errors.push(error.message));
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
  return { page, unexpected, errors, wasm };
}

try {
  const enabledDir = build(true), disabledDir = build(false);
  const enabledFiles = inspect(enabledDir), disabledFiles = inspect(disabledDir);
  // Non-vacuous: the enabled bundle does carry Ixios code, so the empty result below means something.
  assert.ok(enabledFiles.ixiosJs.length > 0, 'enabled build must contain the Ixios chunk');
  assert.deepEqual(disabledFiles.ixiosJs, [], 'disabled build must contain no JavaScript mentioning Ixios');
  assert.deepEqual(enabledFiles.signWasm, []); assert.deepEqual(disabledFiles.signWasm, []);
  assert.equal(enabledFiles.keygenWasm.length, 1); assert.equal(disabledFiles.keygenWasm.length, 1);
  assert.deepEqual(enabledFiles.keygenWasm, disabledFiles.keygenWasm, 'Ixios reuses the Nodus keygen module, not a new one');
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });

  const on = await openWallet(await serve(enabledDir, 4193));
  const panel = on.page.locator('#ixios-address-panel');
  assert.equal(await panel.isVisible(), true);
  await on.page.waitForFunction(address => document.querySelector('#ixios-address').textContent === address, expected);
  assert.match(await panel.innerText(), /Your Ixios address/);
  assert.match(await panel.locator('.pill').innerText(), /Ixios · not active yet/);
  assert.match(await panel.innerText(), /Do not send IXIOS to this address yet/);
  assert.doesNotMatch(await panel.innerText(), /testnet|mainnet/i);
  assert.equal(await on.page.locator('#copy-ixios-address').isDisabled(), false);
  assert.match(await on.page.locator('#ixios-status').innerText(), /Derived locally/);
  assert.notEqual((await on.page.locator('#nodus-address').innerText()).slice(-96), expected.slice(2).toLowerCase(), 'Ixios key must differ from the Nodus identity');
  await on.page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await on.page.locator('#copy-ixios-address').click();
  assert.equal(await on.page.evaluate(() => navigator.clipboard.readText()), expected);
  // Not a network, not a portfolio asset, not a send target.
  assert.deepEqual((await on.page.locator('#chain option').evaluateAll(options => options.map(o => `${o.value} ${o.textContent}`))).filter(text => /ixios/i.test(text)), []);
  assert.doesNotMatch(await on.page.locator('#balances').innerText(), /ixios/i);
  assert.doesNotMatch(await on.page.locator('#portfolio-networks').innerText(), /ixios/i);
  // The Cellframe derivation also fetches legacy-dilithium-*.wasm on open; what matters
  // here is that the keygen module was loaded and the signing module never was.
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm$/.test(path)), 'Nodus keygen request (no query)');
  assert.ok(on.wasm.some(path => /\/assets\/mldsa87-[^/?]+\.wasm\?ixios$/.test(path)), 'Ixios keygen request is tagged ?ixios');
  assert.ok(on.wasm.every(path => !/mldsa87-sign/.test(path)));
  await on.page.locator('#lock').click();
  assert.equal(await on.page.locator('#ixios-address').innerText(), '');
  assert.equal(await on.page.locator('#ixios-status').innerText(), '');
  assert.equal(await on.page.locator('#copy-ixios-address').isDisabled(), true);
  assert.equal(await on.page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(on.unexpected, []); assert.deepEqual(on.errors, []);

  const off = await openWallet(await serve(disabledDir, 4194));
  assert.equal(await off.page.locator('#ixios-address-panel').isVisible(), false);
  assert.equal(await off.page.locator('#ixios-address').textContent(), '');
  assert.ok(off.wasm.every(path => !/mldsa87-sign/.test(path)));
  assert.ok(off.wasm.every(path => !/\?ixios$/.test(path)), 'flag-off build makes no Ixios keygen request');
  assert.equal(await off.page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(off.unexpected, []); assert.deepEqual(off.errors, []);
  console.log('Ixios browser checks passed: flag-on build shows the checksummed receive-only address for the public fixture phrase, copies it, keeps it out of networks/portfolio/send, clears it on lock and loads only the keygen module; flag-off build hides the panel and ships no Ixios JavaScript; neither build ships mldsa87-sign.wasm; no unmocked external requests or storage.');
} finally {
  await browser?.close();
  for (const server of servers) server.kill();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
