// Shared by the normal *.test.js suite and the standalone orchestrator check.
// Uses CHROMIUM_PATH or /usr/bin/chromium and a loopback Vite server.
// No flags/live RPC/wallet artifacts. Per-chain fixture replies differ; using
// the same rows for every method could falsely pass routing and USD checks.
// This checks real DOM/controller behavior, including retaining entered send
// fields while a price-only refresh changes the total. Builder does not run it.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'vite';
import { chromium } from 'playwright';
import config from '../../../vite.extension.config.js';

export async function withPortfolioPage(check) {
  // As in ui-layout.test.js:208, isolate Vite's cache for parallel test files
  // and for worktrees whose node_modules is a read-only shared symlink.
  const cache = await mkdtemp(join(tmpdir(), 'nodus-functions-vite-'));
  let server, browser;
  try {
    server = await createServer({ ...config, configFile: false, cacheDir: cache, server: { host: '127.0.0.1', port: 0, hmr: false } });
    await server.listen();
    browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium' });
    const page = await browser.newPage();
    await page.clock.install({ time: 100000 });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await check(page, `http://127.0.0.1:${server.httpServer.address().port}`);
    assert.deepEqual(errors, []);
  } finally {
    try { await browser?.close(); }
    finally { try { await server?.close(); } finally { await rm(cache, { recursive: true, force: true }); } }
  }
}

export async function selectFixtureNetwork(page, chain) {
  await page.locator('.wallet-navigation a[href="#"]').click();
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
  const group = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]');
  const toggle = group.locator('.network-group-toggle');
  if (await toggle.count() && await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  await badge.click();
}

export async function checkPortfolioFlows(page, origin) {
  await page.goto(`${origin}/test/fixtures/functions.html`);
  await page.waitForFunction(() => window.fixture?.ready);
  assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
  const calls = await page.evaluate(() => window.fixture.calls.map(([method, args]) => [method, args]));
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'getIxiosBalance', 'getSolanaBalances', 'getTronBalances', 'getPrices']) assert.ok(calls.some(call => call[0] === method));
  assert.ok(calls.some(([method, args]) => method === 'getEvmBalances' && args[0] === 'ethereum'));
  assert.ok(calls.some(([method, args]) => method === 'getEvmBalances' && args[0] === 'bsc'));
  assert.equal(await page.locator('#assets-panel').isVisible(), true);
  assert.equal(await page.locator('#portfolio-filters').isHidden(), true);
  await page.locator('#portfolio-hide').click(); assert.equal(await page.locator('#portfolio-total').textContent(), '••••');
  await page.locator('#portfolio-hide').click();
  await selectFixtureNetwork(page, 'solana');
  await page.locator('.wallet-navigation a[href="#send"]').click();
  assert.equal(await page.locator('#receive-address').textContent(), '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
  assert.deepEqual(await page.locator('#asset option').allTextContents(), ['SOL']);
  await page.locator('#recipient').fill('public fixture recipient'); await page.locator('#amount').fill('1.234');
  await page.locator('#page-send .page-back').click();
  await page.locator('.wallet-navigation a[href="#settings"]').click();
  await page.locator('#balance-refresh-minutes').selectOption('0');
  await page.locator('#page-settings .page-back').click();
  await page.evaluate(() => { window.fixture.price('300000000'); window.fixture.hold(); document.getElementById('portfolio-refresh').click(); });
  assert.equal(await page.locator('#portfolio-refresh').isDisabled(), true);
  await page.evaluate(() => window.fixture.release());
  await page.waitForFunction(() => document.getElementById('portfolio-total').textContent === '$3.00');
  assert.equal(await page.locator('#recipient').inputValue(), 'public fixture recipient'); assert.equal(await page.locator('#amount').inputValue(), '1.234');
  await selectFixtureNetwork(page, 'ixios');
  const ixios = page.locator('.asset-group[data-chain="ixios"]');
  if (!await ixios.evaluate(node => node.open)) await ixios.locator('summary').click();
  assert.match(await ixios.locator('.holding-value strong').textContent(), /^8 IXIOS$/);
  assert.equal(await page.locator('#chain').inputValue(), 'ixios');
  assert.equal(await page.locator('.wallet-navigation a[href="#send"]').isVisible(), true);
  // Check the actual image bytes load; a balance/address-only implementation
  // could falsely pass with a missing shared icon-map entry.
  await page.waitForFunction(() => { const images = [...document.querySelectorAll('img[data-icon="ixios.png"]')]; return images.length > 0 && images.every(image => image.complete && image.naturalWidth > 0); });
  // A failed background derivation is final for this unlock, unlike the web
  // page's pending derivation. It must not leave an unpriced row loading after
  // all reads settle, on manual or automatic refresh. No live RPC/artifacts;
  // an always-present fixture address would falsely pass this regression.
  await page.goto(`${origin}/test/fixtures/functions.html?ixios-unavailable`);
  await page.waitForFunction(() => window.fixture?.ready);
  const assertSettled = async () => {
    await page.waitForFunction(() => document.getElementById('portfolio-label').textContent !== 'Updating portfolio');
    assert.equal(await page.locator('#portfolio-label').textContent(), 'Known value · incomplete');
    assert.equal(await page.locator('#portfolio-status').isVisible(), false);
    assert.equal(await page.locator('.network-health[data-chain="ixios"]').getAttribute('data-reading'), 'false');
    assert.equal(await page.locator('#portfolio-refresh').isDisabled(), false);
    assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
    assert.equal(await page.evaluate(() => window.fixture.calls.some(([method]) => method === 'getIxiosBalance')), false);
  };
  await assertSettled();
  await page.evaluate(() => window.fixture.screen.loadBalances(true));
  await assertSettled();
  const beforeAuto = await page.evaluate(() => window.fixture.calls.filter(([method]) => method === 'getPrices').length);
  await page.evaluate(() => { const choice = document.getElementById('balance-refresh-minutes'); choice.value = '5'; choice.onchange(); });
  await page.clock.runFor(5 * 60000);
  await page.waitForFunction(count => window.fixture.calls.filter(([method]) => method === 'getPrices').length > count, beforeAuto);
  await assertSettled();
  // Reopening with a derived address must restore the existing balance reader.
  await page.goto(`${origin}/test/fixtures/functions.html`);
  await page.waitForFunction(() => window.fixture?.ready);
  assert.equal(await page.evaluate(() => window.fixture.calls.some(([method]) => method === 'getIxiosBalance')), true);
  // Public capability transitions exercise the existing page gates, including
  // updates on an already mounted screen. These fakes cannot prove the live
  // worker supplies the flags; nodus-background.test.js covers that boundary.
  await page.evaluate(() => {
    Object.assign(window.fixture.state.nodus, { stakeable: true, nameable: true, registrable: true, vaultable: true });
    window.fixture.screen.update();
  });
  await page.locator('#wallet-register-name:visible').waitFor();
  assert.equal(await page.locator('#quick-name').isVisible(), false);
  assert.equal(await page.locator('#quick-earn').isEnabled(), true);
  assert.equal(await page.locator('#nav-earn').isVisible(), true);
  await page.locator('#nav-vaults:visible').waitFor();
  await page.locator('#nav-earn').click();
  assert.equal(await page.locator('#page-earn').isVisible(), true);
  await page.locator('#page-earn .page-back').click();
  await page.locator('#nav-vaults').click();
  assert.equal(await page.locator('#page-vaults').isVisible(), true);
  await page.locator('#page-vaults .page-back').click();
  await page.evaluate(() => {
    Object.assign(window.fixture.state.nodus, { state: 'connecting', stakeable: false, nameable: false, registrable: false, vaultable: false });
    window.fixture.screen.update();
  });
  assert.equal(await page.locator('#quick-earn').isEnabled(), false);
  // Navigation reflects chain capabilities; the unavailable action stays disabled.
  assert.equal(await page.locator('#nav-earn').isVisible(), true);
  assert.equal(await page.locator('#quick-name').isVisible(), false);
}

export async function checkPortfolioStatus(page, origin) {
  await page.goto(`${origin}/test/fixtures/functions.html`);
  await page.waitForFunction(() => window.fixture?.ready);
  // The operator removed the duplicate connection text; updates must still
  // preserve the lock icon and the portfolio's per-network status controls.
  for (const state of ['idle', 'locked', 'error', 'unknown', 'identifying', 'identified', 'connecting', 'ready']) {
    await page.evaluate(value => { window.fixture.state.nodus.state = value; window.fixture.screen.update(); }, state);
    assert.equal(await page.locator('#net-status, #net-status-text').count(), 0);
    assert.equal(await page.locator('#portfolio-status').isVisible(), false);
    assert.equal(await page.locator('#lock').isVisible(), true);
    assert.equal(await page.locator('.network-health[data-chain="nodus"]').count(), 1);
  }
  for (const minutes of [5, 10, 15, 30, 60, 0]) {
    await page.evaluate(value => { window.fixture.state.preferences.autoLockTimeLimit = value; window.fixture.screen.update(); }, minutes);
    assert.equal(await page.locator('.wallet-session, #session-timeout').count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Lock wallet', exact: true }).count(), 1);
    assert.equal(await page.locator('#auto-lock-minutes').inputValue(), String(minutes));
    assert.match(await page.locator('#auto-lock-note').textContent(), minutes === 0 ? /Auto-lock is off/u
      : new RegExp(`The wallet locks after ${minutes === 60 ? '1 hour' : `${minutes} minutes`} without use`, 'u'));
  }
}
