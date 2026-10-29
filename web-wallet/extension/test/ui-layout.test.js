import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { ASSETS, PRICE_MAX_AGE, chainBalances, portfolioSnapshot, usdText } from '../../src/portfolio.js';

// Node >=22.14; Chromium at CHROMIUM_PATH or /usr/bin/chromium. No build or
// compile flags. SHOT_DIR optionally keeps review screenshots; otherwise no
// artifacts remain. Browser, HTTP server and Vite close in finally, even on failure.
// Vite aliases/defines are copied from vite.extension.config.js:24-29; mirror
// later changes there. The version define comes from the same package.json.
// Proves mounted-page geometry, names, price wiring and approval/form regressions.
// Can falsely pass visually: geometry is not aesthetic approval. A normal page
// cannot prove extension font loading (package-smoke.test.js does). Fake state
// and quotes cannot prove live background/chain/feed compatibility. Notification
// viewports are not measurements of a real window's inner size: no vertical fit.
const walletRoot = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(import.meta.url);
const { version } = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
const button = (page, name) => page.getByRole('button', { name, exact: true });
async function priceCount(page) { return page.evaluate(() => window.layout.calls.filter(call => call.method === 'getPrices').length); }
async function waitHome(page) {
  await page.waitForFunction(() => document.querySelectorAll('.extension-holding strong').length === 16 && document.getElementById('portfolio-total')?.textContent.startsWith('$'));
  await page.locator('#screen:not([inert])').waitFor();
}
async function assertNavigation(page, current) {
  const values = await page.locator('#wallet-navigation button').evaluateAll(nodes => nodes.map(node => ({ text: node.textContent, current: node.getAttribute('aria-current'), top: node.getBoundingClientRect().top })));
  assert.deepEqual(values.map(node => node.text), ['Home', 'Connected sites', 'Settings', 'Lock']);
  for (const node of values) assert.equal(node.current, node.text === current ? 'page' : null);
  if (page.viewportSize().width === 400) assert.ok(values.every(node => Math.abs(node.top - values[0].top) < 1), 'Navigation stays on one row');
}
async function assertHome(page, popup) {
  await waitHome(page); await page.evaluate(() => scrollTo(0, 0));
  await assertNavigation(page, 'Home');
  const geometry = await page.evaluate(() => {
    const rect = node => { const box = node.getBoundingClientRect(); return { top: box.top, bottom: box.bottom, right: box.right }; };
    const articles = [...document.querySelectorAll('article.extension-network')];
    return { portfolio: rect(document.querySelector('section.portfolio-card')), cards: articles.map(article => ({
      box: rect(article), head: rect(article.querySelector('.extension-network-head')), icon: rect(article.querySelector('img')),
      title: rect(article.querySelector('h2')), address: rect(article.querySelector('code')),
      values: [...article.querySelectorAll('.extension-holding strong')].map(rect),
      buttons: [...article.querySelectorAll('button')].map(node => ({ text: node.textContent, ...rect(node) })),
    })) };
  });
  assert.equal(geometry.cards.length, 6);
  if (popup) assert.ok(geometry.portfolio.bottom <= 600, `Portfolio bottom ${geometry.portfolio.bottom} exceeds popup`);
  for (const card of geometry.cards) {
    for (const item of [card.icon, card.title, card.address]) {
      assert.ok(item.top >= card.head.top && item.bottom <= card.head.bottom, 'Identity remains inside its header');
      assert.ok(item.top < card.icon.bottom && item.bottom > card.icon.top, 'Icon overlaps name/address vertically');
    }
    for (const value of card.values) assert.ok(card.box.right - value.right <= 17.1 && value.right <= card.box.right, 'Holding amount is right aligned within row padding');
    const send = card.buttons.find(node => node.text === 'Send'), receive = card.buttons.find(node => node.text === 'Receive');
    if (send) assert.ok(Math.abs(send.top - receive.top) < 1, 'Send and Receive share a row');
  }
  assert.equal(await button(page, 'Send').count(), geometry.cards.filter(card => card.buttons.some(node => node.text === 'Send')).length);
  assert.equal(await button(page, 'Receive').count(), 6);
  const styles = await page.evaluate(() => ({
    font: getComputedStyle(document.body).fontFamily,
    cards: [...document.querySelectorAll('article.extension-network')].map(node => getComputedStyle(node).borderRadius),
    portfolioRadius: getComputedStyle(document.querySelector('section.portfolio-card')).borderRadius,
    portfolioBackground: getComputedStyle(document.querySelector('section.portfolio-card')).backgroundImage,
    totalSize: parseFloat(getComputedStyle(document.getElementById('portfolio-total')).fontSize),
    send: getComputedStyle(document.querySelector('.extension-send')).backgroundColor,
  }));
  assert.match(styles.font, /^Inter(?:,|$)/u); assert.deepEqual(styles.cards, Array(6).fill('10px'));
  assert.equal(styles.portfolioRadius, '16px'); assert.notEqual(styles.portfolioBackground, 'none');
  assert.ok(styles.totalSize >= 32); assert.equal(styles.send, 'rgb(213, 249, 152)');
  const fixture = await page.evaluate(() => ({ balances: window.layout.balances, times: window.layout.balanceTimes, quotes: window.layout.quotes, now: Date.now() }));
  const balances = Object.assign({}, ...Object.entries(fixture.balances).map(([chain, rows]) => chainBalances(chain, rows, fixture.times[chain])));
  const quotes = Object.fromEntries(Object.entries(fixture.quotes).map(([key, quote]) => [key, { ...quote, units: BigInt(quote.units) }]));
  const snap = portfolioSnapshot(balances, quotes, fixture.now, ASSETS);
  assert.equal(await page.locator('#portfolio-total').textContent(), usdText(snap.total, snap.positive));
}

test('mounted extension screens follow the web-wallet layout and preserve price/approval state', { timeout: 120_000 }, async () => {
  let vite, server, browser, cache;
  const blocked = [], errors = [];
  try {
    const { createServer: createViteServer } = await import('vite');
    cache = await mkdtemp(join(tmpdir(), 'nodus-layout-vite-'));
    vite = await createViteServer({ configFile: false, root: walletRoot, cacheDir: cache, server: { middlewareMode: true, hmr: false },
      resolve: { alias: [
        { find: /^buffer\/?$/u, replacement: require.resolve('buffer/') },
        { find: /^events\/?$/u, replacement: require.resolve('events/') },
        { find: /^process\/?$/u, replacement: require.resolve('process/browser.js') },
      ] }, define: { __APP_VERSION__: JSON.stringify(version), 'process.env.IN_TEST': 'false', global: 'globalThis' } });
    server = createServer(vite.middlewares);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const origin = `http://127.0.0.1:${server.address().port}`;
    const { chromium } = await import('playwright');
    browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium' });
    if (process.env.SHOT_DIR) await mkdir(process.env.SHOT_DIR, { recursive: true });
    for (const [kind, width, height] of [['popup', 400, 600], ['fullscreen', 1100, 900], ['fullscreen', 360, 900], ['notification', 400, 620], ['notification', 360, 620]]) {
      const context = await browser.newContext({ viewport: { width, height } });
      try {
        const page = await context.newPage(); page.setDefaultTimeout(15_000);
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', route => {
          const url = new URL(route.request().url());
          if (url.origin === origin) return route.continue();
          blocked.push(url.href); return route.abort('blockedbyclient');
        });
        // Fix the page's clock before any fixture quote or balance answer.
        await page.clock.install({ time: new Date() });
        await page.clock.setFixedTime(new Date());
        const open = async stage => {
          await page.goto(`${origin}/extension/test/fixtures/layout.html?page=${kind}&stage=${stage}`);
          await page.waitForFunction(() => Boolean(window.layout));
          await page.evaluate(() => document.fonts.ready);
        };
        const capture = async name => {
          await page.evaluate(() => scrollTo(0, 0));
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${kind} ${width}: ${name} horizontal overflow`);
          if (process.env.SHOT_DIR) await page.screenshot({ path: join(process.env.SHOT_DIR, `${kind}-${width}-${name}.png`), fullPage: true });
        };
        if (kind === 'notification') {
          await open('connect'); await page.getByRole('heading', { name: 'Connect to site', exact: true }).waitFor();
          assert.equal(await page.locator('.extension-origin').textContent(), 'https://connect-request.example');
          await capture('connect-request');
          await open('signature'); await page.getByRole('heading', { name: 'Nodus signature request', exact: true }).waitFor();
          assert.ok((await page.locator('pre').allTextContents()).some(text => text.includes('<img src=x onerror=alert(1)>') && text.endsWith('ab'.repeat(100))));
          await capture('nodus-signature');
          continue;
        }
        await open('welcome'); await page.getByRole('heading', { name: 'Your Nodus wallet', exact: true }).waitFor();
        assert.equal(await priceCount(page), 0); await capture('welcome');
        await open('unlock'); await page.getByRole('heading', { name: 'Unlock your wallet', exact: true }).waitFor();
        assert.equal(await priceCount(page), 0); await capture('unlock');
        await page.getByLabel('Password', { exact: true }).fill('public-fixture-password'); await button(page, 'Unlock').click();
        await assertHome(page, kind === 'popup'); assert.equal(await priceCount(page), 1); await capture('home');
        await button(page, 'Refresh balances').click(); await waitHome(page); assert.equal(await priceCount(page), 2);
        const nodus = page.locator('article.extension-network').filter({ has: page.getByRole('heading', { name: 'Nodus · Testnet', exact: true }) });
        await nodus.getByRole('button', { name: 'Receive', exact: true }).click();
        await page.getByRole('heading', { name: 'Receive on Nodus', exact: true }).waitFor(); await assertNavigation(page, undefined); await capture('receive');
        await button(page, 'Home').click(); await waitHome(page);
        const ethereum = page.locator('article.extension-network').filter({ has: page.getByRole('heading', { name: 'Ethereum', exact: true }) });
        await ethereum.getByRole('button', { name: 'Send', exact: true }).click();
        await page.locator('#evm-send-to').fill('0x' + '34'.repeat(20)); await page.locator('#evm-send-amount').fill('0.125');
        await assertNavigation(page, undefined); await capture('send');
        const before = await page.evaluate(() => window.layout.calls.filter(call => call.method === 'getState').length);
        // Keep node identity inside the page too: equal values alone could miss
        // a redraw followed by accidental restoration from a fixture.
        await page.evaluate(() => { window.typedNodes = [document.getElementById('evm-send-to'), document.getElementById('evm-send-amount')]; });
        await page.clock.setFixedTime(new Date(await page.evaluate(() => Date.now()) + PRICE_MAX_AGE + 1));
        await page.locator('#evm-send-amount').dispatchEvent('input');
        await page.waitForFunction(count => window.layout.calls.filter(call => call.method === 'getState').length > count, before);
        await page.evaluate(async () => { await window.layout.refresh(); });
        assert.equal(await page.locator('#evm-send-to').inputValue(), '0x' + '34'.repeat(20));
        assert.equal(await page.locator('#evm-send-amount').inputValue(), '0.125');
        assert.equal(await page.evaluate(() => window.typedNodes[0] === document.getElementById('evm-send-to') && window.typedNodes[1] === document.getElementById('evm-send-amount')), true);
        await button(page, 'Review transfer').click(); await button(page, 'Confirm send').waitFor(); await capture('send-review');
        await button(page, 'Cancel').click(); await button(page, 'Refresh balances').click(); await waitHome(page);
        await nodus.getByRole('button', { name: 'History', exact: true }).click();
        await page.getByRole('heading', { name: 'Nodus history', exact: true }).waitFor();
        await page.locator('.activity-row').first().waitFor(); await capture('history');
        await button(page, 'Settings').click(); await page.locator('#auto-lock-minutes').waitFor(); await assertNavigation(page, 'Settings'); await capture('settings');
        await button(page, 'Connected sites').click(); await assertNavigation(page, 'Connected sites');
        assert.equal(await button(page, 'Disconnect').count(), 2); await capture('sites');
      } finally { await context.close(); }
    }
    // A whole-chain failure must not strand the page on an already approved
    // request. Assert both distinct messages and both actual request ids.
    const page = await browser.newPage({ viewport: { width: 400, height: 620 } });
    try {
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', route => {
        if (new URL(route.request().url()).origin === origin) return route.continue();
        blocked.push(route.request().url()); return route.abort('blockedbyclient');
      });
      await page.goto(`${origin}/extension/test/fixtures/layout.html?page=notification&stage=approvals&failed=ethereum`);
      await page.waitForFunction(() => window.layout?.calls.some(call => call.method === 'getEvmBalances' && call.params[0] === 'ethereum'));
      await page.getByText('First queued message', { exact: true }).waitFor(); await button(page, 'Approve').click();
      await page.getByText('Second queued message', { exact: true }).waitFor();
      assert.deepEqual(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'resolvePendingApproval').map(call => call.params)), [['first', true]]);
      await button(page, 'Approve').click(); await page.waitForFunction(() => Object.keys(window.layout.state.pendingApprovals).length === 0);
      assert.deepEqual(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'resolvePendingApproval').map(call => call.params)), [['first', true], ['second', true]]);
      assert.equal(await page.locator('#wallet-status').textContent(), '');
    } finally { await page.close(); }
    assert.deepEqual(errors, [], 'The actual mounted app must load and run without page errors');
    assert.deepEqual(blocked, [], 'Layout fixtures must make no outside request');
  } finally {
    try { await browser?.close(); }
    finally {
      try { if (server?.listening) await new Promise((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); }); }
      finally { try { await vite?.close(); } finally { if (cache) await rm(cache, { recursive: true, force: true }); } }
    }
  }
});
