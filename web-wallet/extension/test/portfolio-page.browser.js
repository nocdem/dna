// Standalone orchestrator check: node extension/test/portfolio-page.browser.js.
// Requires installed Playwright Chromium; starts only a loopback Vite server.
// No flags/live RPC/wallet artifacts. Per-chain fixture replies differ; using
// the same rows for every method could falsely pass routing and USD checks.
// This checks real DOM/controller behavior, including retaining entered send
// fields while a price-only refresh changes the total. Builder does not run it.
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import { chromium } from 'playwright';
import config from '../../vite.extension.config.js';
const server = await createServer({ ...config, configFile: false, server: { host: '127.0.0.1', port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium' });
try {
  const page = await browser.newPage();
  await page.clock.install({ time: 100000 });
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/test/fixtures/functions.html`);
  await page.waitForFunction(() => window.fixture?.ready);
  assert.equal(await page.locator('#portfolio-total').textContent(), '$2.00');
  const calls = await page.evaluate(() => window.fixture.calls.map(([method, args]) => [method, args]));
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'getIxiosBalance', 'getSolanaBalances', 'getTronBalances', 'getPrices']) assert.ok(calls.some(call => call[0] === method));
  assert.ok(calls.some(([method, args]) => method === 'getEvmBalances' && args[0] === 'ethereum'));
  assert.ok(calls.some(([method, args]) => method === 'getEvmBalances' && args[0] === 'bsc'));
  await page.locator('#portfolio-filters button[data-chain="ethereum"]').click();
  assert.equal(await page.locator('#balances .chain-holding').evaluateAll(rows => rows.every(row => row.dataset.chain === 'ethereum')), true);
  await page.locator('#portfolio-hide').click(); assert.equal(await page.locator('#portfolio-total').textContent(), '••••');
  await page.locator('#portfolio-hide').click();
  await page.locator('#chain').selectOption('solana');
  assert.equal(await page.locator('#receive-address').textContent(), '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
  assert.deepEqual(await page.locator('#asset option').allTextContents(), ['SOL']);
  await page.locator('#recipient').fill('public fixture recipient'); await page.locator('#amount').fill('1.234');
  await page.locator('.device-logs-link a').evaluate(link => link.closest('.wallet-page').hidden = false);
  await page.locator('#balance-refresh-minutes').selectOption('0', { force: true });
  await page.evaluate(() => { window.fixture.price('300000000'); window.fixture.hold(); document.getElementById('portfolio-refresh').click(); });
  assert.equal(await page.locator('#portfolio-refresh').isDisabled(), true);
  await page.evaluate(() => window.fixture.release());
  await page.waitForFunction(() => document.getElementById('portfolio-total').textContent === '$3.00');
  assert.equal(await page.locator('#recipient').inputValue(), 'public fixture recipient'); assert.equal(await page.locator('#amount').inputValue(), '1.234');
  await page.locator('#portfolio-filters button[data-chain="ixios"]').click();
  assert.equal(await page.locator('.asset-group[data-symbol="IXIOS"] .asset-value strong').textContent(), '8');
  assert.deepEqual(await page.locator('.chain-holding[data-chain="ixios"] .holding-actions button').allTextContents(), ['Receive']);
  for (const [state, text] of [['ready', 'Connected to the Nodus network'], ['connecting', 'Connecting to the Nodus network…'], ['identified', 'Connecting to the Nodus network…'], ['error', 'Not connected to the Nodus network. Lock and reopen your wallet to retry.']]) {
    await page.evaluate(value => { window.fixture.state.nodus.state = value; window.fixture.screen.update(); }, state);
    assert.equal(await page.locator('#net-status-text').textContent(), text);
  }
  for (const [minutes, text] of [[5, 'Auto-lock after 5 minutes of inactivity'], [10, 'Auto-lock after 10 minutes of inactivity'], [15, 'Auto-lock after 15 minutes of inactivity'], [30, 'Auto-lock after 30 minutes of inactivity'], [60, 'Auto-lock after 1 hour of inactivity'], [0, 'Auto-lock off']]) {
    await page.evaluate(value => { window.fixture.state.preferences.autoLockTimeLimit = value; window.fixture.screen.update(); }, minutes);
    assert.equal(await page.locator('#session-timeout').textContent(), text);
  }
  // Check the actual image bytes load; a balance/address-only implementation
  // could falsely pass with a missing shared icon-map entry.
  await page.waitForFunction(() => { const images = [...document.querySelectorAll('img[data-icon="ixios.png"]')]; return images.length > 0 && images.every(image => image.complete && image.naturalWidth > 0); });
  // A failed background derivation is final for this unlock, unlike the web
  // page's pending derivation. It must not leave an unpriced row loading after
  // all reads settle, on manual or automatic refresh. No live RPC/artifacts;
  // an always-present fixture address would falsely pass this regression.
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/test/fixtures/functions.html?ixios-unavailable`);
  await page.waitForFunction(() => window.fixture?.ready);
  const assertSettled = async () => {
    assert.equal(await page.locator('#portfolio-label').textContent(), 'Known value · incomplete');
    assert.doesNotMatch(await page.locator('#portfolio-status').textContent(), /Reading all networks/);
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
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/test/fixtures/functions.html`);
  await page.waitForFunction(() => window.fixture?.ready);
  assert.equal(await page.evaluate(() => window.fixture.calls.some(([method]) => method === 'getIxiosBalance')), true);
  // Public capability transitions exercise the existing page gates, including
  // updates on an already mounted screen. These fakes cannot prove the live
  // worker supplies the flags; nodus-background.test.js covers that boundary.
  await page.evaluate(() => {
    Object.assign(window.fixture.state.nodus, { stakeable: true, nameable: true, registrable: true, vaultable: true });
    window.fixture.screen.update();
  });
  await page.locator('#quick-name:visible').waitFor();
  assert.equal(await page.locator('#quick-earn').isEnabled(), true);
  assert.equal(await page.locator('#nav-earn').isVisible(), true);
  await page.locator('#nav-vaults:visible').waitFor();
  await page.locator('#quick-earn').click();
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
  assert.equal(await page.locator('#nav-earn').isVisible(), false);
  assert.equal(await page.locator('#quick-name').isVisible(), false);
  assert.deepEqual(errors, []);
} finally { await browser.close(); await server.close(); }
