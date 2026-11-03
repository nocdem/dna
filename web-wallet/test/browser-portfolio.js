// Public fixtures only. Every external request is intercepted; no transaction is sent.
// Proves, on the web build: the portfolio's network groups and holdings (one group per
// network, one row per asset; src/portfolio-view.js), exact total and status, Hide zero
// balances, failed / stale quotes and balances (a failed read keeps the last amount with
// its read time, never a zero), Refresh keeping what is shown, network badges choosing the
// transfer network (the box and the rail follow what the network can do), the badge lights,
// a click / Enter / Space on a network's name selecting it and toggling its group
// (UI pack 2026-11-03), lock cancelling late replies, reopening refreshing, coin icons, and that
// Ixios is always listed and read (no build switch; plan 2026-11-03-pq-native section 5.2). Falsely
// passes if the Ixios RPC mock answers a request the page should not make (the mock is the only answer).
// Needs the built page (dist, served by vite preview on 127.0.0.1 port 4192 with
// --strictPort; run from web-wallet/) and Chromium (CHROMIUM_PATH, otherwise
// Playwright's own). WALLET_URL replaces the server: nothing is started and
// whatever answers there is tested, including a stale build.
// Leaves: only screenshots, and only when SCREENSHOT_DIR (portfolio-1440/390.png),
// BADGE_SHOT_DIR (badges-<width>.png) or SHOT_DIR (box-*.png) is set; the browser
// is closed and the server stopped in finally. The PQ
// networks' providers are outside this fixture: their reads are refused, as in
// test/browser-security.js, and counted apart from `unexpected`.
// False passes: a group already open before the first name click (the test closes it
// first and asserts it); text read from a closed group (textContent is used there,
// innerText only on open groups, which is empty for a closed one).
import assert from 'node:assert/strict';
import { startPreview } from './preview-server.js';
import { mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { ASSETS, PRICE_URL } from '../src/portfolio.js';
import { CHAINS } from '../src/config.js';
import { priceFixture, portfolioRead, cellframeRead, historyRead, PQ_HOST } from './portfolio-routes.js';
import { pastePhrase } from './browser-phrase.js';
import { IXIOS_NETWORK } from '../src/pq/ixios/network.js';
import { PQ_ENTRIES } from '../src/pq/networks.js';
// Every build also reads the IXIOS balance (like CPUNK); its
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
const unexpected = [], errors = [], reads = new Set(), pqRefused = [];
// The PQ networks' read providers (src/pq/*.js); the portfolio contacts them on open since 0.1.155.
// Their priced assets (src/pq/prices.js PQ_PRICE_IDS) join the hero's priced-only count since 0.1.155
// (src/portfolio.js), so each refused read is one of the "X balances ... unavailable" there.
const PQ_MISSING = PQ_ENTRIES.filter(({ asset }) => asset.priceId !== undefined).length;
const missingStatus = legacy => new RegExp(`^${legacy + PQ_MISSING} balances and 0 prices unavailable or out of date\\.`);
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
    if (PQ_HOST.test(new URL(req.url()).hostname)) { pqRefused.push(req.url()); return route.abort('blockedbyclient'); }
    unexpected.push({ url: req.url(), method: req.method() }); return route.abort();
  });
  await page.goto(url);
  async function restore() {
    await page.locator('#restore').click(); await pastePhrase(page, phrase);
    await page.locator('#backup-confirm').check(); await page.locator('#phrase-submit').click();
    await page.locator('#wallet-open').waitFor({ state: 'visible' });
  }
  async function done() { await page.waitForFunction(() => !document.querySelector('#portfolio-refresh').disabled && document.querySelector('#portfolio-updated').textContent.startsWith('Last refresh:')); }
  // The Refresh button is hidden while balances update automatically (0.1.108,
  // the default); the test still drives reads through its handler.
  // Pressed once it is enabled (a read in flight disables it), as a click on
  // the visible button waited for before.
  const pressRefresh = () => page.waitForFunction(() => { const b = document.getElementById('portfolio-refresh'); if (b.disabled) return false; b.click(); return true; });
  async function refresh() { await pressRefresh(); await done(); }
  // Cellframe's address (and so its balance read) arrives asynchronously, after
  // the other four networks' automatic refresh has already settled; wait for
  // its row to leave the "Reading…" placeholder before asserting on it.
  // One group per network (0.1.145): data-symbol / data-chain is the chain id, CPUNK is the row of "cellframe".
  // While the row reads (or has no balance) the group is left out by Hide zero balances, so the wait is for it to appear.
  async function cpunkSettled() { await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-chain="cellframe"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; }); }
  // Same for the IXIOS row.
  async function ixiosSettled() { await page.waitForFunction(() => { const strong = document.querySelector('.asset-group[data-chain="ixios"] .holding-value strong'); return strong && strong.textContent !== 'Reading…'; }); }
  const cpunk = page.locator('.asset-group[data-chain="cellframe"]');
  const group = chain => page.locator(`#balances .asset-group[data-chain="${chain}"]`);
  // A group opens and closes at its chevron (a click on the name also selects the network).
  const toggle = node => node.locator('summary .asset-chevron').click();
  // The holding row of one asset on one network, and every row of one asset.
  const holdingRow = (chain, symbol) => group(chain).locator('.chain-holding').filter({ has: page.locator(`button[aria-label="Select ${symbol} on ${CHAINS[chain]?.name ?? chain}"]`) });
  const usdtRows = page.locator('#balances .chain-holding').filter({ has: page.locator('button[aria-label^="Select USDT on "]') });
  const usdtAmounts = () => usdtRows.locator('.holding-value strong').allTextContents();
  // The network list lives in the closed network disclosure, the PQ and Legacy groups collapsed (src/app.js:2381, src/portfolio-view.js groupedNetworkControls).
  const openNetworks = async () => { if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click(); };
  const badgeOf = async name => {
    await openNetworks();
    const badge = page.locator('#portfolio-networks .network-health', { hasText: name });
    const groupToggle = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');
    if (await groupToggle.count() && await groupToggle.getAttribute('aria-expanded') !== 'true') await groupToggle.click();
    return badge;
  };
  const expandAllNetworks = async () => { await openNetworks(); for (const button of await page.locator('.network-group-toggle').all()) if (await button.getAttribute('aria-expanded') !== 'true') await button.click(); };
  const rail = href => page.locator(`.wallet-navigation a[href="#${href}"]`);
  await restore(); await done(); await cpunkSettled();
  assert.equal(await page.locator('#chain option[value="ixios"]').count(), 1, 'Ixios is always listed (no build switch)');
  await ixiosSettled();
  assert.equal(reads.size, 6); assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  assert.match(await page.locator('#portfolio-status').innerText(), missingStatus(0));
  // Coin icons: CPUNK's own file on its holding row, the Cellframe network's
  // own logo (not the CPUNK asset icon) on its group summary and network badge,
  // ETH unaffected, and every rendered coin-icon actually decodes from the served
  // file (a missing/404'd icon still reports `complete: true, naturalWidth: 0`).
  // 0.1.102: built-in icons (data: or content-hashed, cacheable); data-icon names the file
  const cacheable = /^data:image\/|\/assets\/[^/]+-[A-Za-z0-9_-]{8}\.(svg|png)$/;
  for (const [img, file] of [
    [cpunk.locator('.chain-holding img.coin-icon'), 'cpunk.png'],
    [cpunk.locator('summary img.coin-icon'), 'cellframe.svg'],
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
  // effect on the total, and receive-only (no Send; no row button at all, 0.1.145).
  await toggle(cpunk);
  // 0.1.28 display form (displayAmount): no trailing ".0"; exact value in title.
  assert.equal(await cpunk.locator('.holding-value strong').innerText(), '10 CPUNK');
  assert.equal(await cpunk.locator('.holding-value strong').getAttribute('title'), '10.0 CPUNK');
  assert.equal(await cpunk.locator('.holding-value small').innerText(), '—');
  assert.equal(await page.locator('#balances .holding-actions').count(), 0, 'Send and Receive are rail pages, not row buttons');
  await cpunk.locator('.holding-select').click();
  assert.equal(await page.locator('#chain').inputValue(), 'cellframe');
  assert.equal(await rail('send').isVisible(), false, 'CPUNK: no Send');
  assert.equal(await rail('receive').isVisible(), true, 'CPUNK: Receive');
  await toggle(cpunk);
  // Hide zero balances (0.1.151, src/portfolio.js groupNetworks): checked on every wallet opening, only networks
  // with a displayable nonzero holding are listed — the held networks, in network order; NODUS (never read),
  // the PQ networks (their providers are refused here) and everything else without a balance are left out.
  // The IXIOS group follows Cellframe, shown like CPUNK: a read balance, no USD value.
  assert.equal(await page.locator('#show-zero-balances').isChecked(), true);
  assert.deepEqual(await page.locator('#balances .asset-group').evaluateAll(nodes => nodes.map(node => node.dataset.chain)),
    ['ethereum', 'bsc', 'solana', 'tron', 'cellframe', 'ixios']);
  assert.equal(await page.locator('#portfolio-filters button').count(), 0, 'no network filters (0.1.145)');
  {
    const ixios = group('ixios');
    await toggle(ixios);
    assert.equal(await ixios.locator('.holding-value strong').innerText(), '1 IXIOS');
    assert.equal(await ixios.locator('.holding-value small').innerText(), '—');
    await toggle(ixios);
  }
  // Unchecked, every network is listed; NODUS (never read here) and the PQ networks join the held ones.
  await page.locator('#show-zero-balances').uncheck();
  assert.ok(await page.locator('#balances .asset-group').count() > 6);
  for (const chain of ['nodus', 'algorand']) assert.equal(await group(chain).count(), 1, `${chain} listed with zero balances shown`);
  await page.locator('#show-zero-balances').check();
  assert.equal(await group('nodus').count(), 0);
  assert.doesNotMatch(await page.locator('#portfolio-networks').textContent(), /Not active yet/);
  // USDT is a row of each of four networks, one USDT held on each (the old per-asset total of 4 is the sum of the rows).
  assert.equal(await usdtRows.count(), 4);
  assert.deepEqual(await usdtAmounts(), ['1 USDT', '1 USDT', '1 USDT', '1 USDT']);
  await page.locator('#portfolio-hide').click(); assert.equal(await page.locator('#portfolio-total').innerText(), '••••');
  assert.ok((await page.locator('.holding-value').allTextContents()).every(v => /^•+$/.test(v)));
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
  // There are no network filters (0.1.145): a holding row chooses its network and asset for Send / Receive,
  // and the hero total always spans all networks.
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  const solanaGroup = group('solana'); await toggle(solanaGroup);
  await page.getByRole('button', { name: 'Select USDT on Solana', exact: true }).click();
  assert.equal(await page.locator('#chain').inputValue(), 'solana'); assert.equal(await page.locator('#asset').inputValue(), 'USDT');
  assert.equal(await page.locator('#receive-address').textContent(), '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx');
  await toggle(solanaGroup);
  const bscGroup = group('bsc'); await toggle(bscGroup);
  await page.getByRole('button', { name: 'Select USDT on BNB Smart Chain', exact: true }).click();
  assert.equal(await page.locator('#chain').inputValue(), 'bsc'); assert.equal(await page.locator('#asset').inputValue(), 'USDT');
  assert.equal(await page.locator('#review-dialog').isVisible(), false);
  await toggle(bscGroup);
  failures = ['ethereum:USDT']; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$26.00');
  assert.match(await page.locator('#portfolio-label').innerText(), /incomplete/);
  // A failed read keeps the last balance read, marked as such (0.1.41, the
  // app's stale-while-revalidate wallet cache), never a zero: the row shows the
  // last amount and "Last read <time>" under it (the "Read failed" wording is
  // gone, UI pack 2026-11-03), and the network's badge says it too.
  assert.equal(await holdingRow('ethereum', 'USDT').locator('.holding-value strong').textContent(), '1 USDT');
  assert.match(await holdingRow('ethereum', 'USDT').locator('.holding-value small').textContent(), /^Last read \d{1,2}:\d{2}/);
  assert.match(await (await badgeOf('Ethereum')).getAttribute('title'), /^Ethereum · Last read \d{1,2}:\d{2}/);
  failures = []; wrongNetwork = 'bsc'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$22.00');
  assert.match(await page.locator('#portfolio-status').innerText(), missingStatus(3));
  wrongNetwork = undefined;
  // A CPUNK read failure never becomes an inferred zero, never joins the
  // priced-only "X balances unavailable" hero count, and does not stop the
  // portfolio from being reported complete.
  // The row keeps the last amount with "Last read <time>" (no "Read failed" wording, UI pack 2026-11-03).
  await toggle(cpunk);
  cellframeFail = true; await refresh(); await cpunkSettled();
  assert.match(await cpunk.innerText(), /\b10 CPUNK/);
  assert.doesNotMatch(await cpunk.innerText(), /(^|\s)0 CPUNK/);
  assert.match(await cpunk.locator('.holding-value small').innerText(), /^Last read \d{1,2}:\d{2}/);
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  assert.match(await page.locator('#portfolio-status').innerText(), missingStatus(0));
  cellframeFail = false; await refresh(); await cpunkSettled();
  assert.match(await cpunk.innerText(), /\b10 CPUNK/);
  assert.doesNotMatch(await cpunk.innerText(), /Last read/);
  await toggle(cpunk);
  // 0.1.102: a Refresh whose price read fails keeps the prices shown — they
  // still expire by their own age (PRICE_MAX_AGE), as after an automatic read;
  // prices that arrive out of date are dropped at once.
  priceMode = 'failed'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  priceMode = 'stale'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  assert.match(await page.locator('#portfolio-status').innerText(), /14 prices unavailable/);
  assert.deepEqual(await usdtAmounts(), ['1 USDT', '1 USDT', '1 USDT', '1 USDT']);
  priceMode = 'valid'; await refresh();
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  // Every network badge visible for the badge checks below (their focus must not be moved after the focus check).
  await expandAllNetworks();
  priceMode = 'late'; gate = Promise.withResolvers(); requested = Promise.withResolvers(); completed = Promise.withResolvers();
  ethHold = Promise.withResolvers(); ethHeld = Promise.withResolvers();
  await pressRefresh(); await requested.promise; await ethHeld.promise;
  // 0.1.102 (operator: "refresh ettiği anda hepsi boş oluyor"): while Refresh
  // reads, what was shown stays — the amount and the total — and the
  // network badges say "Reading".
  assert.deepEqual(await usdtAmounts(), ['1 USDT', '1 USDT', '1 USDT', '1 USDT']);
  assert.equal(await page.locator('#portfolio-total').innerText(), '$28.00');
  const ethBadge = page.locator('#portfolio-networks .network-health', { hasText: 'Ethereum' });
  assert.equal(await ethBadge.getAttribute('title'), 'Ethereum · Reading');
  assert.equal(await ethBadge.getAttribute('data-reading'), 'true', 'the light pulses while reading (0.1.103)');
  assert.equal(await ethBadge.getAttribute('data-health'), 'current', 'and keeps its colour: the shown balances are current');
  const release = ethHold; ethHold = undefined; release.resolve();
  const ethereumSummary = group('ethereum').locator('summary');
  await ethereumSummary.focus(); gate.resolve(); await completed.promise; await done();
  // 0.1.106 (operator: "tam ortalamak … sağa dayalı"): every badge's light is
  // its last item, right of the name, centred top to bottom — wide and narrow.
  // 0.1.108 (operator: "yeşili kaldıralım. Sadece sarı ve kırmızı"): a
  // current or not-yet-read network shows no light; amber and red do.
  const lightShown = await page.locator('#portfolio-networks .network-health').evaluateAll(badges => badges.map(b => [b.dataset.health, getComputedStyle(b.lastElementChild).display !== 'none']));
  assert.ok(lightShown.length > 0 && lightShown.every(([health, shown]) => shown === (health === 'old' || health === 'failed')), JSON.stringify(lightShown));
  // The position is measured with every badge shown as amber for the moment
  // (a layout check; the next redraw restores the real states).
  const realHealth = await page.locator('#portfolio-networks .network-health').evaluateAll(badges => badges.map(b => { const h = b.dataset.health; b.dataset.health = 'old'; return h; }));
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
  await page.locator('#portfolio-networks .network-health').evaluateAll((badges, real) => badges.forEach((b, i) => { b.dataset.health = real[i]; }), realHealth);
  await page.setViewportSize({ width: 1440, height: 1050 });
  assert.equal(await ethereumSummary.evaluate(node => document.activeElement === node), true, 'a redraw keeps keyboard focus on the group');
  // 0.1.107 (operator: "clickable yap … Ethereum'a bastı … send receive …
  // network seçebilirsin"): a badge chooses its network for Send / Receive,
  // marks itself, and works from the keyboard too.
  // The badges are in the network disclosure with every group expanded (expandAllNetworks above).
  await openNetworks();
  const badge = name => page.locator('#portfolio-networks .network-health', { hasText: name });
  await badge('Ethereum').click();
  assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
  assert.equal(await badge('Ethereum').getAttribute('aria-pressed'), 'true');
  assert.equal(await page.locator('#portfolio-networks .network-health[aria-pressed="true"]').count(), 1);
  // Receive is its own page, not shown: its title is read as text.
  assert.match(await page.locator('#receive-title').textContent(), /Ethereum/);
  await badge('Solana').focus(); await page.keyboard.press('Enter');
  assert.equal(await page.locator('#chain').inputValue(), 'solana');
  assert.equal(await badge('Solana').getAttribute('aria-pressed'), 'true');
  assert.equal(await badge('Ethereum').getAttribute('aria-pressed'), 'false');
  // 0.1.108 (operator: "QR kodunu oraya gönderiyorsun … istemiyorum … network
  // nodus yazıyor. Onun değişmesini istiyorum … Cellframe'e geldi. Send kapalı.
  // Sadece receive … Swap yok … Earn yok … Ethereum … send receive açık"):
  // a badge changes only the TRANSFER NETWORK box — nothing scrolls, even
  // on a narrow screen — and what the network can do follows. The box's own
  // buttons are hidden since 0.1.145 (test/browser-smoke.js:297); what they
  // showed is now the rail: Send / Receive / Earn links offered per network
  // (src/app.js showTransferActions). The hidden Swap shortcut keeps its state.
  const box = page.locator('.transfer-actions');
  const offered = async () => ({ send: await rail('send').isVisible(), receive: await rail('receive').isVisible(), earn: await page.locator('#nav-earn').isVisible() });
  const swap = () => page.locator('#quick-swap').evaluate(button => ({ hidden: button.hidden, disabled: button.disabled }));
  // The badge is scrolled into view first, so a scroll seen after the click is the click's own.
  // "Nothing scrolls" is checked as: the click makes no scroll call (scrollIntoView, scrollTo,
  // scroll, scrollBy, or a focus without preventScroll) and the badge stays on screen. scrollY
  // itself is not compared: on a single-column width the rail sits above the badges and loses
  // the Nodus-only links (Earn, Vaults, Contracts) when another network is chosen, and the
  // browser's scroll anchoring then moves scrollY by that height (measured at 390 px: 135 px)
  // without any call from the page.
  await page.evaluate(() => {
    if (window.__scrollCalls) return;
    window.__scrollCalls = [];
    const wrap = (owner, key, record = () => true) => { const original = owner[key]; owner[key] = function (...args) { if (record(args)) window.__scrollCalls.push(key); return original.apply(this, args); }; };
    for (const key of ['scrollTo', 'scroll', 'scrollBy']) { wrap(window, key); wrap(Element.prototype, key); }
    wrap(Element.prototype, 'scrollIntoView');
    wrap(HTMLElement.prototype, 'focus', args => !args[0]?.preventScroll);
  });
  const pick = async name => { const target = badge(name); await target.scrollIntoViewIfNeeded(); await page.evaluate(() => { window.__scrollCalls.length = 0; }); await target.click(); return target; };
  const stayed = async (target, width) => {
    assert.deepEqual(await page.evaluate(() => window.__scrollCalls), [], `nothing scrolls at ${width}px`);
    const { top, bottom } = await target.evaluate(node => node.getBoundingClientRect());
    assert.ok(top >= 0 && bottom <= await page.evaluate(() => innerHeight), `the badge stays on screen at ${width}px`);
  };
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await stayed(await pick('Ethereum'), width);
    assert.equal(await box.locator('.selected-network-name').innerText(), 'Ethereum');
    assert.deepEqual(await offered(), { send: true, receive: true, earn: false }, 'Ethereum: Send and Receive');
    assert.equal((await swap()).hidden, true, 'Ethereum: no Swap (src/app.js quick-swap only on Nodus)');
    if (process.env.SHOT_DIR && width === 1440) await box.screenshot({ path: `${process.env.SHOT_DIR}/box-ethereum.png` });
    await stayed(await pick('Cellframe'), width);
    assert.equal(await box.locator('.selected-network-name').innerText(), 'Cellframe');
    assert.deepEqual(await offered(), { send: false, receive: true, earn: false }, 'Cellframe: receive only');
    assert.equal((await swap()).hidden, true, 'Cellframe: no Swap');
    assert.match(await page.locator('#quick-send').getAttribute('title'), /./, 'a disabled Send says why');
    if (process.env.SHOT_DIR && width === 1440) await box.screenshot({ path: `${process.env.SHOT_DIR}/box-cellframe.png` });
    await stayed(await pick('Nodus'), width);
    assert.equal(await box.locator('.selected-network-name').innerText(), 'Nodus');
    assert.equal((await offered()).earn, true, 'Nodus: Earn there');
    assert.deepEqual(await swap(), { hidden: false, disabled: true }, 'Nodus: Swap there, not yet usable');
    if (process.env.SHOT_DIR && width === 1440) await box.screenshot({ path: `${process.env.SHOT_DIR}/box-nodus.png` });
  }
  // UI pack 2026-11-03 (operator: "ustune basilinca yapmali"): a click on the network NAME selects the
  // network and opens or closes its group; the keyboard does the same. False pass: a group already open
  // before the first click, so it is closed first.
  {
    const ethereumGroup = page.locator('.network-assets[data-chain="ethereum"]');
    const ethereumName = page.getByRole('button', { name: 'Select Ethereum network', exact: true });
    const isOpen = () => ethereumGroup.evaluate(node => node.open);
    if (await isOpen()) await ethereumGroup.locator('summary .asset-chevron').click();
    assert.equal(await isOpen(), false, 'the group starts closed');
    await ethereumName.click();
    assert.equal(await page.locator('#chain').inputValue(), 'ethereum'); assert.equal(await isOpen(), true, 'a click on the name opens the group');
    await ethereumName.click();
    assert.equal(await page.locator('#chain').inputValue(), 'ethereum'); assert.equal(await isOpen(), false, 'a second click closes it');
    await ethereumName.focus(); await page.keyboard.press('Enter');
    assert.equal(await isOpen(), true, 'Enter on the name opens the group');
    await page.keyboard.press('Space');
    assert.equal(await isOpen(), false, 'Space on the name closes it');
    assert.equal(await page.locator('#chain').inputValue(), 'ethereum');
    await badge('Nodus').click();
  }
  await page.setViewportSize({ width: 1440, height: 1050 });
  priceMode = 'valid'; await refresh();
  // A balance counts until two minutes past its next automatic read (0.1.93:
  // every 5 minutes by default, src/balance-refresh.js) — 7 minutes, not the
  // bare BALANCE_MAX_AGE of 5 this check used before (it was never updated).
  await page.clock.setFixedTime(new Date(Date.now() + 421000));
  await page.locator('#portfolio-hide').click(); await page.locator('#portfolio-hide').click();
  assert.equal(await page.locator('#portfolio-total').innerText(), '—');
  assert.equal(await page.locator('#portfolio-networks .network-health', { hasText: 'Ethereum' }).getAttribute('data-health'), 'old', 'amber light once out of date (0.1.103)');
  assert.match(await page.locator('#portfolio-status').innerText(), missingStatus(14));
  await page.clock.setFixedTime(new Date());
  priceMode = 'late'; gate = Promise.withResolvers(); requested = Promise.withResolvers(); completed = Promise.withResolvers();
  await pressRefresh(); await requested.promise;
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
