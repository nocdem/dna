// Public fixtures only. Every external request is intercepted; no transaction is sent.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { ASSETS, PRICE_URL } from '../src/portfolio.js';
import { priceFixture, portfolioRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
const url = process.env.WALLET_URL || 'http://127.0.0.1:4192';
const server = process.env.WALLET_URL ? null : spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4192', '--strictPort'], { stdio: 'pipe' });
const phrase = Array(23).fill('abandon').concat('art').join(' ');
const holdings = Object.fromEntries(ASSETS.map(a => [a.key, String(10n ** BigInt(a.decimals))]));
let browser, priceMode = 'valid', failures = [], wrongNetwork, gate, requested, completed;
const unexpected = [], errors = [], reads = new Set();
try {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url)).ok) break; } catch {} await delay(50); }
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } }); page.setDefaultTimeout(20000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const req = route.request();
    if (req.url().startsWith(url + '/') && req.method() === 'GET' && !req.postData()) return route.continue();
    assert.ok(!req.url().includes(phrase) && !req.postData()?.includes(phrase));
    if (req.url() === PRICE_URL) {
      assert.equal(req.method(), 'GET'); assert.equal(req.postData(), null);
      const mode = priceMode;
      if (mode === 'late') {
        requested.resolve(); await gate.promise;
        try { await route.fulfill({ json: priceFixture(999) }); } finally { completed.resolve(); }
        return;
      }
      return mode === 'failed' ? route.fulfill({ status: 503, body: 'Unavailable' })
        : route.fulfill({ json: priceFixture(2, Math.floor(Date.now() / 1000) - (mode === 'stale' ? 901 : 0)) });
    }
    if (await portfolioRead(route, { holdings, failures, wrongNetwork })) { reads.add(new URL(req.url()).origin); return; }
    unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
  });
  await page.goto(url);
  async function restore() {
    await page.locator('#restore').click(); await pastePhrase(page, phrase);
    await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
    await page.locator('#wallet-open').waitFor({ state: 'visible' });
  }
  async function done() { await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled && document.querySelector('#portfolio-updated').textContent.startsWith('Last refresh:')); }
  async function refresh() { await page.locator('#portfolio-refresh').click(); await done(); }
  await restore(); await done();
  assert.equal(reads.size, 4); assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /All supported asset balances/);
  const usdt = page.locator('.asset-group[data-symbol="USDT"]');
  assert.equal(await page.locator('.asset-group').count(), 8);
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '4.0');
  await usdt.locator('summary').click(); assert.equal(await usdt.locator('.chain-holding').count(), 4);
  assert.equal(await usdt.locator('.holding-value strong').allTextContents().then(a => a.every(v => v === '1.0 USDT')), true);
  await page.locator('#portfolio-hide').click(); assert.equal(await page.locator('#portfolio-total').innerText(), '••••');
  assert.ok((await page.locator('.asset-value, .holding-value').allTextContents()).every(v => /^•+$/.test(v)));
  await page.locator('#portfolio-hide').click();
  if (process.env.SCREENSHOT_DIR) mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewportSize({ width, height: 1050 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Portfolio overflow at ${width}px`);
    if (process.env.SCREENSHOT_DIR && [1440, 390].includes(width)) {
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/portfolio-${width}.png`, fullPage: true });
    }
  }
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.locator('.network-filter[data-chain="solana"]').click();
  assert.equal(await page.locator('.asset-group').count(), 3);
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '1.0');
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00'); // Hero always spans all networks.
  await page.getByRole('button', { name: 'Receive USDT on Solana', exact: true }).click();
  assert.equal(await page.locator('#chain').inputValue(), 'solana'); assert.equal(await page.locator('#asset').inputValue(), 'USDT');
  assert.equal(await page.locator('#receive-address').innerText(), '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
  await page.locator('.network-filter[data-chain="bsc"]').click();
  await page.getByRole('button', { name: 'Send USDT on BNB Smart Chain', exact: true }).click();
  assert.equal(await page.locator('#chain').inputValue(), 'bsc'); assert.equal(await page.locator('#asset').inputValue(), 'USDT');
  assert.equal(await page.locator('#review-dialog').isVisible(), false);
  await page.locator('.network-filter[data-chain="all"]').click();
  failures = ['ethereum:USDT']; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$26.00');
  assert.match(await page.locator('#portfolio-label').innerText(), /incomplete/);
  assert.match(await usdt.innerText(), /Balance unavailable/);
  failures = []; wrongNetwork = 'bsc'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$22.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /3 balances/);
  wrongNetwork = undefined;
  for (const mode of ['failed', 'stale']) {
    priceMode = mode; await refresh();
    assert.equal(await page.locator('#portfolio-total').innerText(), '—');
    assert.match(await page.locator('#portfolio-status').innerText(), /14 prices unavailable/);
    assert.equal(await usdt.locator('.asset-value strong').innerText(), '4.0');
  }
  priceMode = 'late'; gate = Promise.withResolvers(); requested = Promise.withResolvers(); completed = Promise.withResolvers();
  await page.locator('#portfolio-refresh').click(); await requested.promise;
  await usdt.locator('summary').focus(); gate.resolve(); await completed.promise; await done();
  assert.equal(await usdt.locator('summary').evaluate(node => document.activeElement === node), true);
  priceMode = 'valid'; await refresh();
  await page.clock.setFixedTime(new Date(Date.now() + 301000));
  await page.locator('#portfolio-hide').click(); await page.locator('#portfolio-hide').click();
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  assert.match(await page.locator('#portfolio-status').innerText(), /14 balances/);
  await page.clock.setFixedTime(new Date());
  priceMode = 'late'; gate = Promise.withResolvers(); requested = Promise.withResolvers(); completed = Promise.withResolvers();
  await page.locator('#portfolio-refresh').click(); await requested.promise;
  await page.locator('#lock').click(); gate.resolve(); await completed.promise;
  assert.equal(await page.locator('#portfolio-total').textContent(), '—');
  assert.equal(await page.locator('#wallet-open').isVisible(), false);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  priceMode = 'valid'; await restore(); await done();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  await page.locator('#lock').click();
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  console.log('Portfolio browser checks passed: automatic four-network reads; exact grouped holdings/total; filters; hide; per-network send/receive; 320–1440px layout; partial RPC failure; wrong network; failed/stale quotes; balance expiry; lock cancels late replies; reopening refreshes; no persistence or unmocked external requests.');
} finally { gate?.resolve(); await browser?.close(); server?.kill(); }
