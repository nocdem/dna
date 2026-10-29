import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { ASSETS, PRICE_MAX_AGE, chainBalances, portfolioSnapshot, usdText, displayAmount } from '../../src/portfolio.js';

// Node >=22.14; Chromium at CHROMIUM_PATH or /usr/bin/chromium. No build or
// compile flags. SHOT_DIR optionally keeps review screenshots; otherwise no
// artifacts remain. Browser, HTTP server and Vite close in finally, even on failure.
// Vite aliases/defines are copied from vite.extension.config.js; mirror
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
// Populated pending-send fixtures must leave no block, rows, empty text or
// actions in popup/full-page Activity. Account assertions stay below.
async function assertAccountHistoryOnly(page) {
  const panel = page.locator('#activity-panel');
  assert.equal(await panel.locator('.page-block').count(), 1);
  assert.equal(await panel.getByRole('heading', { name: 'Account history', exact: true }).count(), 1);
  assert.equal(await panel.locator('#activity, .activity-empty').count(), 0);
  assert.doesNotMatch(await panel.textContent(), /Sent from here|Sends made in this wallet|No sends recorded here|Awaiting confirmation\.|Mark as abandoned|Confirm abandon|Try again/u);
  assert.equal(await page.evaluate(() => window.layout.calls.some(call => ['getChainLocalHistory', 'abandonActivity', 'resubmitNodusSend'].includes(call.method))), false);
}
async function waitHome(page) {
  await page.waitForFunction(() => document.querySelectorAll('.network-health[data-health="current"]').length === 7 && document.getElementById('portfolio-total')?.textContent.startsWith('$'));
  await page.locator('#screen:not([inert])').waitFor();
}
async function assertNavigation(page, current = null) {
  // index.html:34 and style.css:882-885: ordered tiles, two columns at 400px.
  // Pages replace wallet-home (src/app.js:2134-2144); links have no aria-current.
  const links = page.locator('.wallet-navigation a');
  const values = await links.evaluateAll(nodes => nodes.map(node => ({
    text: node.querySelector('.nav-name').textContent, href: node.getAttribute('href'),
    hidden: node.hidden, box: node.getBoundingClientRect().toJSON(),
  })));
  assert.deepEqual(values.map(node => [node.text, node.href]), [
    ['Portfolio', '#assets-panel'], ['Send / Receive', '#send-form'],
    ['Earn', '#earn'], ['Shared vaults', '#vaults'], ['Smart contracts', '#contracts'],
    ['Activity', '#wallet-activity'], ['Address book', '#address-book'], ['Device & settings', '#settings'],
    ['Connected sites', '#sites'],
  ]);
  const available = values.filter(node => !node.hidden);
  assert.deepEqual(available.filter(node => !['#earn', '#vaults', '#contracts'].includes(node.href)).map(node => node.text),
    ['Portfolio', 'Send / Receive', 'Activity', 'Address book', 'Device & settings', 'Connected sites']);
  assert.deepEqual(await page.locator('.wallet-page:visible').evaluateAll(nodes => nodes.map(node => node.id)), current ? [`page-${current}`] : []);
  assert.equal(await page.locator('#wallet-home').isVisible(), current === null);
  assert.equal(await page.locator('.wallet-navigation a:visible').count(), current ? 0 : available.length);
  if (current) {
    const title = current === 'wallet-activity' ? 'Activity' : current === 'sites' ? 'Connected sites' : 'Device & settings';
    const heading = page.locator(`#page-${current}`).getByRole('heading', { name: title, exact: true });
    await heading.waitFor();
    assert.equal(await heading.evaluate(node => document.activeElement === node), true);
    assert.equal(await page.evaluate(() => location.hash), `#${current}`);
  } else if (page.viewportSize().width <= 760) {
    for (let index = 0; index < available.length; index += 2) {
      const left = available[index].box, right = available[index + 1]?.box;
      assert.ok(left.width > 0, 'Navigation tiles must have measurable width');
      assert.ok(Math.abs(left.left - available[0].box.left) < 1, 'Left navigation column stays aligned');
      if (right) {
        assert.ok(right.width > 0, 'Navigation tiles must have measurable width');
        assert.ok(Math.abs(left.top - right.top) < 1, 'Each pair of navigation tiles shares a row');
        assert.ok(left.right < right.left, 'Navigation columns must not overlap');
        assert.ok(Math.abs(right.left - available[1].box.left) < 1, 'Right navigation column stays aligned');
      }
      if (index) assert.ok(left.top > available[index - 2].box.bottom, 'Navigation rows must not overlap');
    }
  }
}
async function assertAssetLayout(page) {
  // portfolio-view.js:168-204; style.css:452-480. Closed details have no row
  // geometry: expand only for measurement and restore every original open state.
  const groups = await page.evaluate(() => {
    const details = [...document.querySelectorAll('.asset-group')], opened = details.map(node => node.open);
    const rect = node => node.getBoundingClientRect().toJSON();
    const identity = node => ({
      box: rect(node), icon: rect(node.querySelector('.coin-icon')),
      name: rect(node.querySelector('.asset-name, span:not(.coin-icon)')),
    });
    try {
      for (const node of details) node.open = true;
      return details.map(node => ({
        symbol: node.dataset.symbol, radius: getComputedStyle(node).borderRadius,
        summary: { ...identity(node.querySelector('.asset-summary')),
          labels: [...node.querySelectorAll('.asset-name strong, .asset-name small')].map(rect) },
        rows: [...node.querySelectorAll('.chain-holding')].map(row => ({
          chain: row.dataset.chain, box: rect(row), padding: parseFloat(getComputedStyle(row).paddingRight),
          identity: identity(row.querySelector('.holding-network')),
          current: row.querySelector('.holding-select').getAttribute('aria-current'),
          value: { ...rect(row.querySelector('.holding-value')), align: getComputedStyle(row.querySelector('.holding-value')).textAlign },
          amounts: [...row.querySelectorAll('.holding-value strong, .holding-value small')].map(rect),
          actions: [...row.querySelectorAll('.holding-actions button')].map(button => ({ text: button.textContent, ...rect(button) })),
        })),
      }));
    } finally { details.forEach((node, index) => { node.open = opened[index]; }); }
  });
  // All fixture balances are positive. One row per asset/network: seventeen
  // holdings in eleven asset groups; Cellframe and Ixios offer Receive only.
  // portfolio.js:153-171 sorts native groups by network name after stablecoins.
  assert.deepEqual(groups.map(group => [group.symbol, group.rows.map(row => row.chain)]), [
    ['NODUS', ['nodus']], ['USDT', ['ethereum', 'bsc', 'solana', 'tron']],
    ['USDC', ['ethereum', 'bsc', 'solana', 'tron']], ['DAI', ['ethereum']], ['USDD', ['tron']],
    ['BNB', ['bsc']], ['CPUNK', ['cellframe']], ['ETH', ['ethereum']], ['IXIOS', ['ixios']], ['SOL', ['solana']], ['TRX', ['tron']],
  ]);
  const contained = (item, box, message) => {
    assert.ok(item.width > 0 && item.height > 0, `${message}: must be measurable`);
    assert.ok(item.top >= box.top - 1 && item.bottom <= box.bottom + 1 && item.left >= box.left - 1 && item.right <= box.right + 1, message);
  };
  const alignedIdentity = (identity, label) => {
    contained(identity.icon, identity.box, `${label}: icon stays inside its header`);
    contained(identity.name, identity.box, `${label}: name stays inside its header`);
    assert.ok(identity.name.top < identity.icon.bottom && identity.name.bottom > identity.icon.top, `${label}: icon and name overlap vertically`);
    assert.ok(Math.abs((identity.icon.top + identity.icon.bottom) / 2 - (identity.name.top + identity.name.bottom) / 2) < 1, `${label}: icon and name are vertically centered`);
    assert.ok(identity.icon.right <= identity.name.left, `${label}: icon and name must not overlap horizontally`);
  };
  for (const group of groups) {
    assert.equal(group.radius, '10px', group.symbol);
    alignedIdentity(group.summary, group.symbol);
    for (const label of group.summary.labels) contained(label, group.summary.box, `${group.symbol}: symbol and caption stay inside the summary`);
    for (const row of group.rows) {
      const label = `${group.symbol} on ${row.chain}`;
      alignedIdentity(row.identity, label);
      assert.equal(row.current, row.chain === 'nodus' ? 'true' : null, `${label}: selected network marker`);
      assert.equal(row.value.align, 'right', label);
      assert.ok(Math.abs(row.box.right - row.padding - row.value.right) < 1, `${label}: holding value ends at the row's right padding`);
      for (const amount of row.amounts) {
        contained(amount, row.box, `${label}: amount stays inside its row`);
        assert.ok(Math.abs(amount.right - row.value.right) < 1, `${label}: amount and price share the right edge`);
      }
      assert.deepEqual(row.actions.map(action => action.text), ['cellframe', 'ixios'].includes(row.chain) ? ['Receive'] : ['Send', 'Receive'], label);
      for (const action of row.actions) contained(action, row.box, `${label}: action stays inside its row`);
      if (!['cellframe', 'ixios'].includes(row.chain)) assert.ok(Math.abs(row.actions[0].top - row.actions[1].top) < 1, `${label}: Send and Receive share a row`);
    }
  }
  assert.equal(await page.locator('.chain-holding').count(), 17);
  assert.equal(await page.locator('.holding-actions button[aria-label^="Send "]').count(), 15);
  assert.equal(await page.locator('.holding-actions button[aria-label^="Receive "]').count(), 17);
  assert.equal(await page.locator('.transfer-buttons #quick-send').count(), 1);
  assert.equal(await page.locator('.transfer-buttons #quick-receive').count(), 1);
}
async function assertHome(page, popup) {
  await waitHome(page); await page.evaluate(() => scrollTo(0, 0));
  await assertNavigation(page);
  assert.equal(await page.getByRole('heading', { name: 'Your wallet', exact: true }).count(), 0);
  assert.equal(await page.locator('.wallet-card > .section-head .eyebrow').count(), 0);
  assert.equal(await page.locator('#wallet-heading img').count(), 0);
  assert.equal(await page.locator('.site-header .wordmark img').count(), 1);
  assert.equal(await page.getByText('Wallet open in this browser', { exact: true }).count(), 0);
  assert.equal(await button(page, 'Lock wallet').isVisible(), true);
  assert.deepEqual(await page.locator('.wallet-navigation a:visible .nav-name').allTextContents(),
    ['Portfolio', 'Send / Receive', 'Smart contracts', 'Activity', 'Address book', 'Device & settings', 'Connected sites']);
  assert.equal(await page.locator('.extension-network').count(), 0);
  assert.equal(await page.locator('.network-health').count(), 7);
  assert.equal(await page.locator('.network-filter').count(), 8);
  const networks = ['Nodus', 'Ethereum', 'BNB Smart Chain', 'Solana', 'TRON', 'Cellframe', 'Ixios'];
  assert.deepEqual(await page.locator('.network-health > span:not(.health-light)').allTextContents(), networks);
  assert.deepEqual(await page.locator('#chain option').allTextContents(), networks);
  await page.waitForFunction(() => {
    const icons = [...document.querySelectorAll('img[data-icon="ixios.png"]')];
    return icons.length > 0 && icons.every(icon => icon.complete && icon.naturalWidth > 0);
  });
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  assert.deepEqual(await page.locator('.selected-network-name').allTextContents(), Array(5).fill('Nodus'));
  assert.deepEqual(await page.locator('.selected-network-stage').allTextContents(), Array(4).fill('Testnet'));
  assert.deepEqual(await page.locator('#asset option').allTextContents(), ['NODUS']);
  assert.equal(await page.locator('#asset').inputValue(), '0'.repeat(128));
  assert.equal(await page.locator('#receive-address').textContent(), 'ab'.repeat(64));
  assert.equal(await page.locator('#receive-qr svg[aria-label="QR code for the receive address"]').count(), 1);
  assert.equal(await page.locator('#net-status, #net-status-text').count(), 0);
  assert.equal(await page.locator('.asset-group[data-symbol="NODUS"] .asset-value strong').textContent(), '12.34');
  assert.equal(await page.locator('.asset-group[data-symbol="NODUS"] .holding-value strong').textContent(), '12.34 NODUS');
  assert.match(await page.locator('#portfolio-status').textContent(), /asset balances are included|balances and .* prices unavailable/u);
  const methods = await page.evaluate(() => window.layout.calls.map(call => call.method));
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'getEvmBalances', 'getSolanaBalances', 'getTronBalances', 'getPrices']) {
    assert.ok(methods.includes(method), `Opening the wallet must request ${method} over the trusted client`);
  }
  assert.equal(await page.locator('.asset-group[data-symbol="USDT"] .chain-holding').count(), 4);
  assert.equal(await page.locator('#send-form #receive-panel').count(), 1);
  await assertAssetLayout(page);
  const actions = await page.locator('#quick-send, #quick-receive, #quick-earn, #quick-swap').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().toJSON()));
  for (const action of actions) {
    assert.ok(action.width > 0 && action.height > 0, 'Each transfer shortcut is measurable');
    assert.ok(Math.abs(action.width - actions[0].width) < 1, 'Send, Receive, Earn and Swap have equal width');
    assert.ok(Math.abs(action.height - actions[0].height) < 1, 'Send, Receive, Earn and Swap have equal height');
  }
  const styles = await page.evaluate(() => ({
    font: getComputedStyle(document.body).fontFamily,
    portfolioRadius: getComputedStyle(document.querySelector('.portfolio-card')).borderRadius,
    portfolioBackground: getComputedStyle(document.querySelector('.portfolio-card')).backgroundImage,
    totalSize: parseFloat(getComputedStyle(document.getElementById('portfolio-total')).fontSize),
    send: getComputedStyle(document.getElementById('quick-send')).backgroundColor,
    sendTop: document.getElementById('quick-send').getBoundingClientRect().top,
    receiveTop: document.getElementById('quick-receive').getBoundingClientRect().top,
    shell: document.querySelector('.wallet-card').getBoundingClientRect().toJSON(),
    sourceTop: document.querySelector('.price-source').getBoundingClientRect().top,
    lastAssetBottom: [...document.querySelectorAll('.asset-group')].at(-1).getBoundingClientRect().bottom,
  }));
  assert.match(styles.font, /^Inter(?:,|$)/u);
  assert.equal(styles.portfolioRadius, '16px'); assert.notEqual(styles.portfolioBackground, 'none');
  assert.ok(styles.totalSize >= 32);
  assert.equal(styles.send, 'rgb(213, 249, 152)');
  assert.ok(Math.abs(styles.sendTop - styles.receiveTop) < 1, 'Transfer Send and Receive share a row');
  if (popup) { assert.equal(styles.shell.left, 20); assert.equal(styles.shell.right, 380); }
  assert.ok(styles.sourceTop >= styles.lastAssetBottom);
  const fixture = await page.evaluate(() => ({ balances: window.layout.balances, times: window.layout.balanceTimes, quotes: window.layout.quotes, now: Date.now() }));
  const balances = Object.assign({}, ...Object.entries(fixture.balances).map(([chain, rows]) => chainBalances(chain, rows, fixture.times[chain])));
  const quotes = Object.fromEntries(Object.entries(fixture.quotes).map(([key, quote]) => [key, { ...quote, units: BigInt(quote.units) }]));
  const snap = portfolioSnapshot(balances, quotes, fixture.now, ASSETS);
  assert.equal(await page.locator('#portfolio-total').textContent(), usdText(snap.total, snap.positive));
}

async function assertHistoryLayout(page) {
  const rows = await page.locator('#history .activity-row').evaluateAll(nodes => nodes.map(node => {
    const box = item => item.getBoundingClientRect().toJSON();
    return { row: box(node), main: box(node.querySelector('.activity-main')), side: box(node.querySelector('.activity-side')),
      footer: box(node.querySelector('.activity-footer')),
      content: [...node.querySelectorAll('strong, small, time, .status-badge, .activity-id, a')].map(box) };
  }));
  for (const { row, main, side, footer, content } of rows) {
    for (const item of [main, side, footer, ...content]) {
      if (!item.height) continue; // a boundary row legitimately has no footer
      assert.ok(item.left >= row.left - 1 && item.right <= row.right + 1 && item.top >= row.top - 1 && item.bottom <= row.bottom + 1, 'Account history content stays inside its row');
    }
    assert.ok(main.right <= side.left + 1 || main.bottom <= side.top + 1, 'History description and status do not overlap');
    if (footer.height) assert.ok(footer.top >= Math.max(main.bottom, side.bottom) - 1, 'Transaction details sit below the row summary');
  }
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
      ] }, define: { __APP_VERSION__: JSON.stringify(version), 'process.env.IN_TEST': 'false', global: 'globalThis', 'import.meta.env.VITE_ENABLE_IXIOS': '"true"' } });
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
        const open = async (stage, name) => {
          const params = new URLSearchParams({ page: kind, stage });
          if (name !== undefined) params.set('name', name);
          await page.goto(`${origin}/extension/test/fixtures/layout.html?${params}`);
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
        await open('home'); await assertHome(page, kind === 'popup');
        // No flags/live data. The public fixture holds every initial balance
        // and quote read. Measuring only after waitHome would miss the jump.
        await page.goto(`${origin}/extension/test/fixtures/layout.html?page=${kind}&stage=home&hold`);
        await page.waitForFunction(() => window.layout && document.getElementById('portfolio-label')?.textContent === 'Updating portfolio');
        await page.evaluate(() => document.fonts.ready);
        const loading = await page.locator('.portfolio-card').boundingBox();
        const refreshTop = await page.locator('#portfolio-refresh').evaluate(node => node.getBoundingClientRect().top);
        await page.evaluate(() => window.layout.releaseReads()); await waitHome(page);
        assert.equal(await page.locator('#portfolio-label').textContent(), 'Estimated portfolio value');
        const settled = await page.locator('.portfolio-card').boundingBox();
        assert.ok(Math.abs(loading.height - settled.height) < 1, `${kind} ${width}: portfolio height stays fixed after loading`);
        assert.ok(Math.abs(refreshTop - await page.locator('#portfolio-refresh').evaluate(node => node.getBoundingClientRect().top)) < 1, 'Refresh action stays in place');
        // Both approved greeting states on popup/full-page layouts. A trusted
        // name reply drives the heading; the registration prompt reaches the
        // existing Nodus form even from another network and a separate page.
        await open('home', 'publicname');
        await page.getByRole('heading', { name: 'Welcome back, publicname', exact: true }).waitFor();
        assert.equal(await page.locator('#wallet-register-name').isVisible(), false);
        assert.equal(await page.locator('.site-header .wordmark').textContent(), 'nodus');
        assert.equal(await page.locator('.site-header .product-name').textContent(), 'Wallet');
        assert.equal(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'getOwnName').length), 1);
        await open('home', 'none');
        await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
        await page.locator('#chain').selectOption('ethereum');
        await page.locator('.wallet-navigation a[href="#settings"]').click();
        await button(page, 'Register your on-chain name').click();
        assert.equal(await page.locator('#wallet-home').isVisible(), true);
        assert.equal(await page.locator('#chain').inputValue(), 'nodus');
        assert.equal(await page.locator('#name-block').isVisible(), true);
        assert.equal(await page.locator('#name-input').evaluate(node => document.activeElement === node), true);
        assert.equal(await page.evaluate(() => window.layout.calls.some(call => call.method === 'prepareName')), false);
        await open('welcome'); await page.locator('#welcome:visible').waitFor();
        assert.equal(await priceCount(page), 0); await capture('welcome');
        await open('unlock'); await page.locator('#unlock-form:visible').waitFor();
        assert.equal(await priceCount(page), 0); await capture('unlock');
        await page.getByLabel('Local wallet password', { exact: true }).fill('public-fixture-password');
        await page.locator('#unlock-wallet').click();
        await assertHome(page, kind === 'popup'); assert.equal(await priceCount(page), 1); await capture('home');
        const visibleTotal = await page.locator('#portfolio-total').textContent();
        const eye = page.locator('#portfolio-hide');
        assert.equal(await button(page, 'Hide balances').count(), 1);
        const visibleEye = await eye.evaluate(node => ({ size: getComputedStyle(node).fontSize, border: getComputedStyle(node).borderWidth,
          background: getComputedStyle(node).backgroundColor, icon: getComputedStyle(node, '::before').maskImage }));
        assert.equal(visibleEye.size, '0px'); assert.equal(visibleEye.border, '0px');
        assert.equal(visibleEye.background, 'rgba(0, 0, 0, 0)'); assert.notEqual(visibleEye.icon, 'none');
        await eye.focus(); await page.keyboard.press('Enter');
        assert.equal(await page.locator('#portfolio-total').textContent(), '••••');
        assert.equal(await page.locator('#portfolio-hide').getAttribute('aria-pressed'), 'true');
        assert.equal(await button(page, 'Show balances').count(), 1);
        assert.notEqual(await eye.evaluate(node => getComputedStyle(node, '::before').maskImage), visibleEye.icon);
        for (const value of await page.locator('.asset-value strong, .asset-value small, .holding-value strong, .holding-value small').allTextContents()) {
          assert.equal(value, '••••');
        }
        await page.keyboard.press('Space');
        assert.equal(await page.locator('#portfolio-total').textContent(), visibleTotal);
        assert.equal(await page.locator('.asset-group[data-symbol="NODUS"] .asset-value strong').textContent(), '12.34');
        await page.locator('#portfolio-refresh').click(); await waitHome(page); assert.equal(await priceCount(page), 2);
        await page.locator('#quick-receive').click();
        assert.equal(await page.locator('#receive-address').textContent(), 'ab'.repeat(64));
        await assertNavigation(page);
        assert.equal(await page.locator('#receive-title').evaluate(node => document.activeElement === node), true);
        await capture('receive');
        await page.locator('#chain').selectOption('ethereum');
        await page.locator('#quick-send').click();
        await page.locator('#recipient').fill('0x' + '34'.repeat(20)); await page.locator('#amount').fill('0.125');
        await assertNavigation(page);
        await capture('send');
        const before = await page.evaluate(() => window.layout.calls.filter(call => call.method === 'getState').length);
        await page.evaluate(() => { window.typedNodes = [document.getElementById('recipient'), document.getElementById('amount')]; });
        await page.clock.setFixedTime(new Date(await page.evaluate(() => Date.now()) + PRICE_MAX_AGE + 1));
        await page.clock.runFor(30000); // the shared controller's render tick
        await page.locator('#amount').dispatchEvent('input');
        await page.waitForFunction(count => window.layout.calls.filter(call => call.method === 'getState').length > count, before);
        await page.evaluate(async () => { await window.layout.refresh(); });
        assert.equal(await page.locator('#recipient').inputValue(), '0x' + '34'.repeat(20));
        assert.equal(await page.locator('#amount').inputValue(), '0.125');
        assert.equal(await page.evaluate(() => window.typedNodes[0] === document.getElementById('recipient') && window.typedNodes[1] === document.getElementById('amount')), true);
        await page.clock.pauseAt(await page.evaluate(() => Date.now()));
        await page.locator('#review-button').click(); await page.locator('#review-dialog[open]').waitFor();
        assert.deepEqual(await page.evaluate(() => window.layout.calls.find(call => call.method === 'prepareEvmSend').params),
          [{ to: '0x' + '34'.repeat(20), amount: '0.125', chain: 'ethereum', symbol: 'ETH' }]);
        assert.equal(await page.locator('#confirm-send').isDisabled(), true);
        await capture('send-review');
        await page.clock.runFor(600);
        assert.equal(await page.locator('#confirm-send').isDisabled(), false);
        await page.locator('#cancel-send').click();
        assert.deepEqual(await page.evaluate(() => window.layout.calls.find(call => call.method === 'cancelEvmSend').params), ['layout-review']);
        await page.locator('#review-button').click(); await page.locator('#review-dialog[open]').waitFor();
        await page.clock.runFor(600); await page.locator('#confirm-send').click();
        await page.waitForFunction(() => !document.getElementById('review-dialog').open);
        assert.deepEqual(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'confirmEvmSend').map(call => call.params)), [['layout-review']]);
        await page.locator('#portfolio-refresh').click(); await waitHome(page);
        await page.locator('#chain').selectOption('nodus');
        await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
        await assertNavigation(page, 'wallet-activity');
        assert.equal(await page.locator('#activity-panel .page-chip').textContent(), 'Nodus · Testnet');
        await page.locator('#history .activity-row').first().waitFor();
        assert.equal(await page.locator('#history-status').textContent(), 'Fixture account history');
        assert.ok((await page.locator('#history').textContent()).includes('Received NODUS'));
        await assertAccountHistoryOnly(page);
        const nodusRow = page.locator('#history .activity-row').first();
        assert.equal(await nodusRow.locator('.activity-main strong').textContent(), '+2');
        assert.equal(await nodusRow.locator('.activity-main small').textContent(), 'Received NODUS · Public fixture transfer');
        assert.equal(await nodusRow.locator('.activity-side [data-status="confirmed"]').count(), 1);
        assert.equal(await nodusRow.locator('time[datetime]').count(), 1);
        assert.equal(await nodusRow.locator('.activity-footer .activity-id').textContent(), `Network record ID ${'cd'.repeat(64)}`);
        assert.equal(await page.locator('#history .activity-row').nth(1).locator('.activity-main strong').textContent(), 'Witness update');
        assert.equal(await page.locator('#history .activity-row').nth(1).locator('time').count(), 0);
        await assertHistoryLayout(page);
        await capture('history');
        // Ethereum, Solana, TRON and Cellframe share this renderer. Real
        // network rows retain their explorer routing; no peer/hash is HTML.
        for (const chain of ['ethereum', 'solana', 'tron', 'cellframe']) {
          await page.locator('#page-wallet-activity .page-back').click();
          await page.locator('#chain').selectOption(chain);
          await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
          const symbol = chain === 'ethereum' ? 'ETH' : chain === 'solana' ? 'SOL' : chain === 'tron' ? 'TRX' : 'CPUNK';
          await page.waitForFunction(amount => document.querySelector('#history .activity-main strong')?.textContent === amount, `+${displayAmount('1234567.123456789')} ${symbol}`);
          const peer = await page.evaluate(value => window.layout.state.addresses[value === 'cellframe' ? 'cpunk' : value], chain);
          assert.equal(await page.locator('#history .activity-main small').textContent(), `from ${peer.slice(0, 8)}…${peer.slice(-6)}`);
          assert.equal(await page.locator('#history .activity-side .status-badge[data-status="confirmed"]').count(), 1);
          assert.equal(await page.locator('#history .activity-side time[datetime]').count(), 1);
          await assertAccountHistoryOnly(page);
          await assertHistoryLayout(page);
          await capture(`history-${chain}`);
        }
        await page.locator('#page-wallet-activity .page-back').click();
        await page.locator('#chain').selectOption('bsc');
        await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
        await page.waitForFunction(() => document.querySelector('#history-status')?.textContent === 'Account history for BNB Smart Chain is not read here. Use the account explorer.');
        assert.equal(await page.locator('#history .activity-row').count(), 0);
        await assertAccountHistoryOnly(page);
        await page.locator('#page-wallet-activity .page-back').click();
        await page.locator('#chain').selectOption('ixios');
        await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
        assert.equal(await page.locator('#history-status').textContent(), '');
        assert.equal(await page.locator('#history .activity-row').count(), 0);
        await assertAccountHistoryOnly(page);
        await page.locator('#page-wallet-activity .page-back').click();
        await page.locator('#chain').selectOption('nodus'); await waitHome(page);
        await assertNavigation(page);
        await page.locator('.wallet-navigation a[href="#settings"]').click();
        await assertNavigation(page, 'settings'); await capture('settings');
        assert.equal(await page.locator('#balance-refresh-minutes').isDisabled(), false);
        assert.equal(await page.locator('#address-book-save').isDisabled(), false);
        await page.locator('#page-settings .page-back').click();
        await page.locator('.wallet-navigation a[href="#sites"]').click(); await assertNavigation(page, 'sites');
        assert.deepEqual(await page.locator('#page-sites .extension-site h2').allTextContents(), ['https://evm-site.example', 'https://nodus-site.example']);
        for (const site of await page.locator('#page-sites .extension-site').all()) {
          assert.equal(await site.getByRole('button', { name: 'Disconnect', exact: true }).isVisible(), true);
        }
        assert.equal(await button(page, 'Disconnect').count(), 2); await capture('sites');
        await page.locator('#page-sites .page-back').click(); await page.locator('.wallet-navigation a[href="#settings"]').click();
        await page.locator('#auto-lock-minutes').selectOption('15');
        await page.waitForFunction(() => window.layout.state.preferences.autoLockTimeLimit === 15);
        assert.match(await page.locator('#session-timeout').textContent(), /15 minutes/);
        await page.locator('#rpc-settings').evaluate(node => { node.open = true; });
        await page.locator('#network-solana').selectOption('devnet');
        await page.waitForFunction(() => window.layout.state.networks.solana === 'devnet');
        await page.locator('#page-settings .page-back').click();
        await page.locator('#chain').selectOption('solana');
        assert.deepEqual(await page.locator('#asset option').allTextContents(), ['SOL']);
        assert.equal(await page.locator('.asset-group[data-symbol="SOL"] .asset-value small').textContent(), '—');
        await page.locator('.wallet-navigation a[href="#settings"]').click();
        await page.locator('#reveal-password').fill('fresh-password');
        await button(page, 'Reveal phrase').click();
        assert.equal(await page.locator('#device-panel .phrase-grid input[readonly]').count(), 24);
        await page.locator('#lock').click();
        await page.locator('#unlock-form:visible').waitFor();
        assert.equal(await page.locator('input[readonly]').count(), 0);
        assert.equal(await page.locator('#wallet-heading').isVisible(), false);
        await capture('locked');
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
