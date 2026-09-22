import { portfolioRead, cellframeRead } from './portfolio-routes.js';
import { pastePhrase, readPhrase } from './browser-phrase.js';
// Production assets, public test phrases, and no external network requests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
const url = process.env.WALLET_URL || 'http://127.0.0.1:4190';
const server = process.env.WALLET_URL ? null : spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4190', '--strictPort'], { stdio: 'pipe' });
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/nodus-addresses.json', import.meta.url)));
const wasm = readFileSync(new URL('../src/nodus/mldsa87.wasm', import.meta.url));
let browser;
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  for (const mode of ['delayed', 'failed']) {
    const startup = await browser.newPage();
    const requested = Promise.withResolvers(), release = Promise.withResolvers();
    const external = [], startupErrors = [];
    startup.on('pageerror', error => startupErrors.push(error.message));
    await startup.route('**/*', async route => {
      const req = route.request();
      if (!req.url().startsWith(url + '/') || req.method() !== 'GET' || req.postData()) {
        external.push(req.url()); return route.abort();
      }
      if (/\/assets\/app-[^/]+\.js$/.test(new URL(req.url()).pathname)) {
        requested.resolve(); await release.promise;
        if (mode === 'failed') return route.fulfill({ status: 503, body: 'Unavailable' });
      }
      return route.continue();
    });
    try {
      await startup.goto(url, { waitUntil: 'commit' }); await requested.promise;
      for (const id of ['create', 'restore', 'unlock-wallet']) assert.equal(await startup.locator(`#${id}`).isDisabled(), true);
      assert.match(await startup.locator('#wallet-boot-status').innerText(), /Loading wallet/);
      release.resolve();
      if (mode === 'delayed') {
        await startup.waitForFunction(() => !document.querySelector('#restore').disabled);
        assert.equal(await startup.locator('#wallet-boot-status').isVisible(), false);
        await startup.locator('#restore').click();
        await startup.locator('#phrase-form').waitFor({ state: 'visible' });
        await startup.locator('#phrase-cancel').click();
      } else {
        await startup.waitForFunction(() => document.querySelector('#wallet-boot-status').textContent.includes('could not load'));
        for (const id of ['create', 'restore', 'unlock-wallet']) assert.equal(await startup.locator(`#${id}`).isDisabled(), true);
      }
      assert.equal(await startup.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(external, []); assert.deepEqual(startupErrors, []);
    } finally { release.resolve(); await startup.close(); }
  }
  console.log('Startup checks passed: entry controls wait for initialization; delayed loading recovers and failed loading gives a visible error without enabling controls.');
  const page = await browser.newPage(); page.setDefaultTimeout(10000);
  const seen = Promise.withResolvers(), release = Promise.withResolvers(), completed = Promise.withResolvers();
  let wasmRequests = 0, failLoad = false;
  const unexpected = [], errors = [], cellframeRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const req = route.request();
    // The wallet now derives its Cellframe/CPUNK address and reads its balance
    // automatically alongside the Nodus address on every restore below.
    // cellframeRead() validates the request shape (method, body fields, and
    // the address by format, same as portfolioRead's Solana/EVM checks) before
    // fulfilling it, so a malformed or secret-carrying request here fails this
    // test rather than being silently accepted.
    if (await cellframeRead(route)) { cellframeRequests.push(req.url()); return; }
    if (await portfolioRead(route)) return;
    if (!req.url().startsWith(url + '/') || req.method() !== 'GET' || req.postData()) {
      unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
    }
    if (/\/mldsa87-[^/]+\.wasm$/.test(req.url())) {
      wasmRequests++;
      if (wasmRequests === 1) {
        seen.resolve(); await release.promise;
        try { await route.fulfill({ contentType: 'application/wasm', body: wasm }); }
        finally { completed.resolve(); }
        return;
      }
      if (failLoad) return route.fulfill({ status: 503, body: 'Unavailable' });
    }
    return route.continue();
  });
  await page.goto(url);
  await page.waitForFunction(() => typeof document.querySelector('#restore').onclick === 'function');
  await page.locator('#restore').click();
  for (const width of [320, 390, 1280]) {
    await page.locator('#phrase-cancel').click();
    await page.setViewportSize({ width, height: 844 });
    await page.locator('#restore').click();
    const warning = await page.locator('#recovery-warning').boundingBox();
    assert.ok(warning.y >= 0 && warning.y + warning.height <= 844, `Recovery warning must be visible on entry at ${width}px`);
    assert.equal(await page.locator('#phrase-grid').evaluate(grid => grid.contains(document.activeElement)), false);
  }
  const phraseInput = page.locator('#phrase-1'), suggestions = page.locator('#phrase-suggestions-1');
  assert.equal(await page.locator('#phrase-grid input').count(), 24);
  assert.deepEqual(await page.locator('#phrase-grid label').allTextContents(), Array.from({ length: 24 }, (_, i) => `${i + 1}.`));
  await phraseInput.fill('a');
  const aWords = await suggestions.locator('button').allTextContents();
  assert.ok(aWords.length > 1 && aWords.every(word => word.startsWith('a')));
  await phraseInput.fill('ab');
  const abWords = await suggestions.locator('button').allTextContents();
  assert.ok(abWords.length > 1 && abWords.every(word => word.startsWith('ab')));
  await phraseInput.press('ArrowDown'); await phraseInput.press('Enter');
  assert.equal(await phraseInput.inputValue(), 'abandon');
  assert.equal(await page.locator('#phrase-2').evaluate(input => input === document.activeElement), true);
  await page.locator('#phrase-2').fill('ability'); await phraseInput.fill('ab');
  await suggestions.getByRole('option', { name: 'about', exact: true }).click();
  assert.equal(await phraseInput.inputValue(), 'about');
  assert.equal(await page.locator('#phrase-2').inputValue(), 'ability');
  // Full paste from a middle box replaces every numbered position.
  await pastePhrase(page, vectors[0].phrase.toUpperCase().split(' ').join(' \n\t'), 13);
  assert.equal(await readPhrase(page), vectors[0].phrase);
  await pastePhrase(page, vectors[0].phrase + ' extra', 7);
  assert.equal(await readPhrase(page), vectors[0].phrase);
  assert.match(await page.locator('#phrase-error').innerText(), /Too many/);
  await pastePhrase(page, 'ability able about', 24);
  assert.equal(await readPhrase(page), vectors[0].phrase);
  await pastePhrase(page, 'ability able', 12);
  assert.equal(await page.locator('#phrase-11').inputValue(), 'abandon');
  assert.equal(await page.locator('#phrase-12').inputValue(), 'ability');
  assert.equal(await page.locator('#phrase-13').inputValue(), 'able');
  assert.equal(await page.locator('#phrase-14').inputValue(), 'abandon');
  await pastePhrase(page, vectors[0].phrase);
  await page.locator('#phrase-12').fill('');
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.match(await page.locator('#wallet-status').innerText(), /24-word/);
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await page.locator('#phrase-cancel').click();
  assert.equal(await readPhrase(page), '');
  assert.deepEqual(await page.locator('.phrase-suggestions').allTextContents(), Array(24).fill(''));
  // Exercise a real browser clipboard paste with the public fixture only.
  await page.locator('#restore').click();
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.evaluate(text => navigator.clipboard.writeText(text), vectors[0].phrase);
  await page.locator('#phrase-9').focus(); await page.keyboard.press('Control+V');
  assert.equal(await readPhrase(page), vectors[0].phrase);
  await page.locator('#phrase-24').fill('abandon');
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.match(await page.locator('#wallet-status').innerText(), /invalid/);
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await page.locator('#phrase-cancel').click();
  await page.locator('#restore').click();
  await pastePhrase(page, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.match(await page.locator('#wallet-status').innerText(), /24-word/);
  await page.locator('#phrase-cancel').click();
  await page.locator('#create').click();
  const generated = await readPhrase(page);
  assert.equal(generated.split(' ').length, 24);
  assert.equal(await page.locator('#phrase-grid input').evaluateAll(inputs => inputs.every(input => input.readOnly)), true);
  await pastePhrase(page, vectors[0].phrase, 5);
  assert.equal(await readPhrase(page), generated);
  await page.setViewportSize({ width: 320, height: 740 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.equal(await readPhrase(page), '');
  assert.equal(await page.locator('#phrase-grid input').evaluateAll(inputs => inputs.every(input => !input.readOnly)), true);
  await page.locator('#phrase-cancel').click();
  await page.setViewportSize({ width: 1280, height: 960 });
  async function restore(phrase) {
    await page.locator('#restore').click(); await pastePhrase(page, phrase);
    await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
    await page.locator('#wallet-open').waitFor({ state: 'visible' });
  }
  await restore(vectors[0].phrase); await seen.promise;
  await page.locator('#lock').click();
  assert.equal(await page.locator('#nodus-address').innerText(), '');
  assert.equal(await page.locator('#copy-nodus-address').isDisabled(), true);
  await restore(vectors[1].phrase);
  await page.waitForFunction(address => document.querySelector('#nodus-address').textContent === address, vectors[1].address);
  release.resolve(); await completed.promise;
  assert.equal(await page.locator('#nodus-address').innerText(), vectors[1].address);
  await page.selectOption('#chain', 'solana');
  assert.equal(await page.locator('#nodus-address').innerText(), vectors[1].address);
  await page.locator('#lock').click(); failLoad = true;
  await restore(vectors[0].phrase);
  await page.waitForFunction(() => document.querySelector('#nodus-status').textContent.includes('unavailable'));
  assert.equal(await page.locator('#nodus-address').innerText(), '');
  assert.equal(await page.locator('#copy-nodus-address').isDisabled(), true);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(wasmRequests, 3);
  // No request other than the mocked, shape-checked Cellframe balance reads
  // reached an external origin: every entry actually observed here is that
  // exact endpoint (the exact count is not asserted — each restore's
  // derive-then-read chain races the lock() calls above by design, so how
  // many complete before being aborted is not deterministic; only that none
  // of them was ever anything else, and that the wiring fired at least once).
  assert.ok(cellframeRequests.length >= 1, 'expected at least one automatic Cellframe balance read to be observed and mocked');
  assert.ok(cellframeRequests.every(u => u === 'https://rpc.cellframe.net/connect'));
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  console.log('Nodus browser checks passed: 24 numbered boxes, read-only generation, full/partial/overflow and real clipboard paste, blank-word/checksum rejection, mobile layout, local a/ab suggestions and keyboard/click completion; late derivation cannot replace a reopened wallet; lock clears address; external-chain switch preserves native identity; failed module load shows unavailable; automatic Cellframe balance reads are mocked and shape-checked; no other unmocked external requests or storage.');
} finally { await browser?.close(); server?.kill(); }
