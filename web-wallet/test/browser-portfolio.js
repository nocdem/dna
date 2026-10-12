// Public fixtures only. Every external request is intercepted; no transaction is sent.
import assert from 'node:assert/strict';
import { startPreview } from './preview-server.js';
import { mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { ASSETS, PRICE_URL } from '../src/portfolio.js';
import { CHAINS } from '../src/config.js';
import { priceFixture, portfolioRead, cellframeRead, historyRead } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
import { IXIOS_NETWORK } from '../src/ixios/network.js';
// A VITE_ENABLE_IXIOS=true dist also reads the IXIOS balance (like CPUNK); its
// own behaviour is covered by test/browser-ixios.js. Ixios mainnet genesis
// (ixiosSpark params/config.go:27); 1 IXIOS held.
const IXIOS_GENESIS = '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f';
async function ixiosRead(route) {
  const req = route.request();
  if (new URL(req.url()).origin !== new URL(IXIOS_NETWORK.endpoint).origin) return false;
  assert.equal(req.method(), 'POST');
  const call = req.postDataJSON();
  let result;
  if (call.method === 'eth_getBlockByNumber') { assert.deepEqual(call.params, ['0x1', false]); result = { number: '0x1', parentHash: IXIOS_GENESIS }; }
  else if (call.method === 'eth_getBalance') { assert.match(call.params[0], /^0x[0-9a-fA-F]{96}$/); assert.equal(call.params[1], 'latest'); result = '0x' + (10n ** 18n).toString(16); }
  else return false;
  await route.fulfill({ json: { jsonrpc: '2.0', id: call.id, result } });
  return true;
}
const url =process.env.WALLET_URL || 'http://127.0.0.1:4192';
const server = process.env.WALLET_URL ? null : await startPreview(['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '4192', '--strictPort'], 4192);
const phrase = Array(23).fill('abandon').concat('art').join(' ');
const holdings = Object.fromEntries(ASSETS.map(a => [a.key, String(10n ** BigInt(a.decimals))]));
let browser, priceMode = 'valid', failures = [], wrongNetwork, gate, requested, completed, cellframeFail = false;
// Holds Ethereum's balance read while set (0.1.103): a "Reading" badge is
// checked while that read is really in flight, not raced against it.
let ethHold, ethHeld;
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
    const hold = ethHold;
    if (hold && req.url().startsWith(CHAINS.ethereum.endpoint)) { ethHeld.resolve(); await hold.promise; }
    if (await historyRead(route)) return;
    if (await cellframeRead(route, { balance: '10', fail: cellframeFail })) { reads.add(new URL(req.url()).origin); return; }
    if (await portfolioRead(route, { holdings, failures, wrongNetwork })) { reads.add(new URL(req.url()).origin); return; }
    if (await ixiosRead(route)) { reads.add(new URL(req.url()).origin); return; }
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
  // Cellframe's address (and so its balance read) arrives asynchronously, after
  // the other four networks' automatic refresh has already settled; wait for
  // its row to leave the "Reading…" placeholder before asserting on it.
  async function cpunkSettled() { await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-symbol="CPUNK"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; }); }
  // Same for the IXIOS row, when the dist was built with VITE_ENABLE_IXIOS=true.
  async function ixiosSettled() { await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-symbol="IXIOS"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; }); }
  const cpunk = page.locator('.asset-group[data-symbol="CPUNK"]');
  await restore(); await done(); await cpunkSettled();
  const ixiosShown = await page.locator('#chain option[value="ixios"]').count() === 1;
  if (ixiosShown) await ixiosSettled();
  assert.equal(reads.size, ixiosShown ? 6 : 5); assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /All supported asset balances/);
  // Coin icons: CPUNK's own file in the asset summary, the Cellframe network's
  // own logo (not the CPUNK asset icon) on its network badge, ETH unaffected,
  // and every rendered coin-icon actually decodes from the served file (a
  // missing/404'd icon still reports `complete: true, naturalWidth: 0`).
  // 0.1.102: built-in icons (data: or content-hashed, cacheable); data-icon names the file
  const cacheable = /^data:image\/|\/assets\/[^/]+-[A-Za-z0-9_-]{8}\.(svg|png)$/;
  for (const [img, file] of [
    [cpunk.locator('summary img.coin-icon'), 'cpunk.png'],
    [page.locator('#portfolio-networks .network-health', { hasText: 'Cellframe' }).locator('img.coin-icon'), 'cellframe.svg'],
    [page.locator('#portfolio-networks .network-health', { hasText: 'Ethereum' }).locator('img.coin-icon'), 'eth.svg']
  ]) {
    assert.equal(await img.getAttribute('data-icon'), file);
    assert.match(await img.getAttribute('src'), cacheable);
  }
  await page.waitForFunction(() => [...document.querySelectorAll('img.coin-icon')].every(i => i.complete));
  const iconState = await page.evaluate(() => [...document.querySelectorAll('img.coin-icon')].map(i => ({ src: i.getAttribute('src'), naturalWidth: i.naturalWidth })));
  assert.ok(iconState.length > 0);
  assert.ok(iconState.every(i => !!i.src && i.naturalWidth > 0), JSON.stringify(iconState.filter(i => !i.src || i.naturalWidth === 0)));
  // CPUNK: shown alongside the priced assets, but with no USD value and no
  // effect on the total, and receive-only (no Send button).
  assert.equal(await cpunk.locator('.asset-value small').innerText(), '—');
  await cpunk.locator('summary').click();
  // 0.1.28 display form (displayAmount): no trailing ".0"; exact value in title.
  assert.equal(await cpunk.locator('.holding-value strong').innerText(), '10 CPUNK');
  assert.equal(await cpunk.locator('.holding-value strong').getAttribute('title'), '10.0 CPUNK');
  assert.equal(await cpunk.locator('.holding-value small').innerText(), '—');
  assert.deepEqual(await cpunk.locator('.holding-actions button').allTextContents(), ['Receive']);
  await cpunk.locator('summary').click();
  const usdt = page.locator('.asset-group[data-symbol="USDT"]');
  // A VITE_ENABLE_IXIOS=true dist adds one IXIOS group (by its network name, 0.1.102), shown like CPUNK:
  // a read balance, no USD value. The default build has none. The NODUS group
  // (first, never read — 0.1.21) is counted in both.
  assert.equal(await page.locator('.asset-group').count(), ixiosShown ? 11 : 10);
  if (ixiosShown) {
    const ixios = page.locator('.asset-group[data-symbol="IXIOS"]');
    // 0.1.102: after the stablecoins, coins by network name — Ixios between Ethereum and Solana
    const symbols = await page.locator('.asset-group').evaluateAll(groups => groups.map(g => g.dataset.symbol));
    assert.deepEqual(symbols.slice(symbols.indexOf('ETH'), symbols.indexOf('ETH') + 3), ['ETH', 'IXIOS', 'SOL']);
    assert.equal(await ixios.locator('.asset-value strong').innerText(), '1');
    assert.equal(await ixios.locator('.asset-value small').innerText(), '—');
    await ixios.locator('summary').click();
    assert.equal(await ixios.locator('.holding-value strong').innerText(), '1 IXIOS');
    assert.equal(await ixios.locator('.holding-value small').innerText(), '—');
    assert.deepEqual(await ixios.locator('.holding-actions button').allTextContents(), ['Receive']);
    await ixios.locator('summary').click();
  }
  assert.doesNotMatch(await page.locator('#portfolio-networks').innerText(), /Not active yet/);
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '4');
  await usdt.locator('summary').click(); assert.equal(await usdt.locator('.chain-holding').count(), 4);
  assert.equal(await usdt.locator('.holding-value strong').allTextContents().then(a => a.every(v => v === '1 USDT')), true);
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
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '1');
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
  // A failed read keeps the last balance read, marked as such (0.1.41, the
  // app's stale-while-revalidate wallet cache), never a zero.
  assert.match(await usdt.innerText(), /Read failed · last read/);
  failures = []; wrongNetwork = 'bsc'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$22.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /3 balances/);
  wrongNetwork = undefined;
  // A CPUNK read failure never becomes an inferred zero, never joins the
  // priced-only "X balances unavailable" hero count, and does not stop the
  // portfolio from being reported complete.
  await cpunk.locator('summary').click();
  cellframeFail = true; await refresh(); await cpunkSettled();
  assert.match(await cpunk.innerText(), /Read failed · last read/);
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  assert.match(await page.locator('#portfolio-status').innerText(), /All supported asset balances/);
  cellframeFail = false; await refresh(); await cpunkSettled();
  assert.match(await cpunk.innerText(), /\b10 CPUNK/);
  await cpunk.locator('summary').click();
  // 0.1.102: a Refresh whose price read fails keeps the prices shown — they
  // still expire by their own age (PRICE_MAX_AGE), as after an automatic read;
  // prices that arrive out of date are dropped at once.
  priceMode = 'failed'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  priceMode = 'stale'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  assert.match(await page.locator('#portfolio-status').innerText(), /14 prices unavailable/);
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '4');
  priceMode = 'valid'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  priceMode = 'late'; gate = Promise.withResolvers(); requested = Promise.withResolvers(); completed = Promise.withResolvers();
  ethHold = Promise.withResolvers(); ethHeld = Promise.withResolvers();
  await page.locator('#portfolio-refresh').click(); await requested.promise; await ethHeld.promise;
  // 0.1.102 (operator: "refresh ettiği anda hepsi boş oluyor"): while Refresh
  // reads, what was shown stays — the amount and the total — and the
  // network badges say "Reading".
  assert.equal(await usdt.locator('.asset-value strong').innerText(), '4');
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  const ethBadge = page.locator('#portfolio-networks .network-health', { hasText: 'Ethereum' });
  assert.equal(await ethBadge.getAttribute('title'), 'Ethereum · Reading');
  assert.equal(await ethBadge.getAttribute('data-reading'), 'true', 'the light pulses while reading (0.1.103)');
  assert.equal(await ethBadge.getAttribute('data-health'), 'current', 'and keeps its colour: the shown balances are current');
  const release = ethHold; ethHold = undefined; release.resolve();
  await usdt.locator('summary').focus(); gate.resolve(); await completed.promise; await done();
  // 0.1.106 (operator: "tam ortalamak … sağa dayalı"): every badge's light is
  // its last item, right of the name, centred top to bottom — wide and narrow.
  for (const width of [1440, 360]) {
    await page.setViewportSize({ width, height: 1050 });
    const marks = await page.locator('#portfolio-networks .network-health').evaluateAll(badges => badges.map(b => {
      const light = b.lastElementChild, name = light.previousElementSibling;
      const l = light.getBoundingClientRect(), n = name.getBoundingClientRect(), r = b.getBoundingClientRect();
      const pad = parseFloat(getComputedStyle(b).paddingRight) + parseFloat(getComputedStyle(b).borderRightWidth);
      return { last: light.classList.contains('health-light'), right: l.left >= n.right, edge: Math.abs(r.right - pad - l.right) <= 1, centred: Math.abs((l.top + l.bottom) / 2 - (r.top + r.bottom) / 2) <= 1 };
    }));
    assert.ok(marks.length > 0 && marks.every(m => m.last && m.right && m.edge && m.centred), `badge lights at ${width}px: ${JSON.stringify(marks)}`);
    if (process.env.BADGE_SHOT_DIR) await page.locator('#portfolio-networks').screenshot({ path: `${process.env.BADGE_SHOT_DIR}/badges-${width}.png` });
  }
  await page.setViewportSize({ width: 1440, height: 1050 });
  assert.equal(await usdt.locator('summary').evaluate(node => document.activeElement === node), true);
  // 0.1.107 (operator: "clickable yap … Ethereum'a bastı … send receive …
  // network seçebilirsin"): a badge chooses its network for Send / Receive,
  // marks itself, and works from the keyboard too.
  const badgeOf = name => page.locator('#portfolio-networks .network-health', { hasText: name });
  await badgeOf('Ethereum').click();
  assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
  assert.equal(await badgeOf('Ethereum').getAttribute('aria-pressed'), 'true');
  assert.equal(await page.locator('#portfolio-networks .network-health[aria-pressed="true"]').count(), 1);
  assert.match(await page.locator('#receive-title').innerText(), /Ethereum/);
  await badgeOf('Solana').focus(); await page.keyboard.press('Enter');
  assert.equal(await page.locator('#chain').inputValue(), 'solana');
  assert.equal(await badgeOf('Solana').getAttribute('aria-pressed'), 'true');
  assert.equal(await badgeOf('Ethereum').getAttribute('aria-pressed'), 'false');
  priceMode = 'valid'; await refresh();
  // A balance counts until two minutes past its next automatic read (0.1.93:
  // every 5 minutes by default, src/balance-refresh.js) — 7 minutes, not the
  // bare BALANCE_MAX_AGE of 5 this check used before (it was never updated).
  await page.clock.setFixedTime(new Date(Date.now() + 421000));
  await page.locator('#portfolio-hide').click(); await page.locator('#portfolio-hide').click();
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  assert.equal(await page.locator('#portfolio-networks .network-health', { hasText: 'Ethereum' }).getAttribute('data-health'), 'old', 'amber light once out of date (0.1.103)');
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
  console.log('Portfolio browser checks passed: automatic four-network reads; exact grouped holdings/total; filters; hide; per-network send/receive; 320–1440px layout; partial RPC failure; wrong network; failed/stale quotes; balance expiry; lock cancels late replies; reopening refreshes; no persistence or unmocked external requests; CPUNK/Cellframe/ETH coin icons resolve to their own files and decode.');
} finally { gate?.resolve(); await browser?.close(); server?.stop(); }
