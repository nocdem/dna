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
  const page = await browser.newPage(); page.setDefaultTimeout(10000);
  const seen = Promise.withResolvers(), release = Promise.withResolvers(), completed = Promise.withResolvers();
  let wasmRequests = 0, failLoad = false;
  const unexpected = [], errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const req = route.request();
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
  const phraseInput = page.locator('#phrase'), suggestions = page.locator('#phrase-suggestions');
  await phraseInput.fill('a');
  assert.ok((await suggestions.locator('button').allTextContents()).every(word => word.startsWith('a')));
  await phraseInput.fill('ab');
  const abWords = await suggestions.locator('button').allTextContents();
  assert.ok(abWords.length > 1); assert.ok(abWords.every(word => word.startsWith('ab')));
  await phraseInput.press('ArrowDown'); await phraseInput.press('Enter');
  assert.equal(await phraseInput.inputValue(), 'abandon ');
  await phraseInput.fill('ab ability');
  await phraseInput.evaluate(input => { input.setSelectionRange(2, 2); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await suggestions.getByRole('option', { name: 'about', exact: true }).click();
  assert.equal(await phraseInput.inputValue(), 'about ability');
  await phraseInput.fill('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
  assert.match(await page.locator('#wallet-status').innerText(), /24-word/);
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  await page.locator('#phrase-cancel').click();
  assert.equal(await phraseInput.inputValue(), '');
  assert.equal(await suggestions.innerText(), '');
  async function restore(phrase) {
    await page.locator('#restore').click(); await page.locator('#phrase').fill(phrase);
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
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  console.log('Nodus browser checks passed: 24-word-only restore, local a/ab suggestions, keyboard/click completion, editing a word preserves its neighbors; late derivation cannot replace a reopened wallet; lock clears address; external-chain switch preserves native identity; failed module load shows unavailable; no external requests or storage.');
} finally { await browser?.close(); server?.kill(); }
