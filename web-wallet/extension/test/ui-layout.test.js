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
import { assertNetworkGroups } from '../../test/browser-network-groups.js';

// Node >=22.14; Chromium at CHROMIUM_PATH or /usr/bin/chromium. No build or
// compile flags. SHOT_DIR optionally keeps review screenshots; otherwise no
// artifacts remain. Browser, HTTP server and Vite close in finally, even on failure.
// Vite aliases/defines are copied from vite.extension.config.js; mirror
// later changes there. The version define comes from the same package.json.
// Proves mounted-page geometry, including label text below the eye and lock,
// the 0.1.145 navigation rail beside every page, separate Send and Receive
// pages, network-grouped holdings, names, price wiring and approval/form
// regressions. With PQ addresses set, the page's public-only PQ readers are
// aborted by the route and their origins are checked against a fixed list.
// UI pack 2026-11-03 additions: the bottom bar (Connect, Wallet, Settings;
// current view, no top switch, one lock control, Settings page and Back, the
// unread badge from the fixture's `?unread` open Connect snapshot, messenger
// above the bar), the Reveal screen's frame / centred numbers / Copy phrase
// button, and (below) the other UI-pack screen checks. The badge check falsely
// passes only if the snapshot were not "open"; it asserts the positive count 2.
// Can falsely pass visually: geometry is not aesthetic approval. A normal page
// cannot prove extension font loading (package-smoke.test.js does). Fake state
// and quotes cannot prove live background/chain/feed compatibility. Notification
// viewports are not measurements of a real window's inner size: no vertical fit.
// The chat row is opened by a held mouse press (W-42); the fixture's client answers in microtasks, so a
// re-read that redrew the list on the press removes the row at once; the real worker answers later, inside
// the hold. Without the release-time re-read (extension/src/ui/app.js) this step times out on the screen wait.
// The wide-tab shell edges (1100 px) are fixed numbers measured on 14dc02b9f and this branch.
const walletRoot = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(import.meta.url);
const { version } = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

// Sizing at bed273dcf (0.1.136): src/style.css:530-533,886 and
// extension/src/ui/extension.css:18-20,35. Restore those declarations on the
// same mounted card so the comparison uses identical fonts, text and width.
// Comparing only the two new states would falsely pass an unchanged large card.
async function portfolioHeight0136(page) {
  // Restore the status and label-first order only for the historical measure.
  await page.locator('.portfolio-card').evaluate(card => {
    const heading = card.querySelector('.portfolio-heading');
    heading.prepend(card.querySelector('#portfolio-label'));
    heading.after(card.querySelector('.portfolio-amount'));
    card.querySelector('#portfolio-status').hidden = false;
  });
  const baseline = await page.addStyleTag({ content: `
    .extension-page .portfolio-card { padding: 28px 28px 24px; }
    .extension-page .portfolio-heading { grid-template-columns: minmax(0, 1fr) 32px; }
    .extension-page .portfolio-heading #lock { display: none; }
    .extension-page #portfolio-label { display: flex; align-items: center; min-height: 3.4em; margin: 0; font-size: 10px; }
    .extension-page .portfolio-amount { margin: 20px 0 6px; }
    .extension-page #portfolio-status { min-height: 3.4em; margin: 6px 0 18px; }
    @media (max-width: 760px) {
      .extension-page .portfolio-card { padding: 20px 18px 18px; }
      .extension-page #portfolio-label { font-size: 9px; }
      .extension-page #portfolio-status { min-height: 6.8em; }
    }
  ` });
  try { return (await page.locator('.portfolio-card').boundingBox()).height; }
  finally {
    await page.locator('.portfolio-card').evaluate(card => {
      const heading = card.querySelector('.portfolio-heading');
      heading.prepend(card.querySelector('.portfolio-amount'));
      heading.after(card.querySelector('#portfolio-label'));
      card.querySelector('#portfolio-status').hidden = true;
    });
    await baseline.evaluate(node => node.remove());
  }
}

async function assertPortfolioLayout(page) {
  assert.equal(await page.locator('#quick-name').isVisible(), false);
  const layout = await page.evaluate(() => {
    const card = document.querySelector('.portfolio-card'), heading = card.querySelector('.portfolio-heading');
    const reference = document.createElement('p'); reference.className = 'eyebrow';
    heading.append(reference);
    const previousLabelSize = parseFloat(getComputedStyle(reference).fontSize); reference.remove();
    const amount = document.getElementById('portfolio-total'), label = document.getElementById('portfolio-label');
    // Measure the text: the paragraph spans the card even when left-aligned.
    const labelText = document.createRange(); labelText.selectNodeContents(label);
    const greeting = document.getElementById('wallet-heading').getBoundingClientRect(), box = card.getBoundingClientRect();
    return { amount: amount.getBoundingClientRect().toJSON(), label: labelText.getBoundingClientRect().toJSON(),
      eye: document.getElementById('portfolio-hide').getBoundingClientRect().toJSON(),
      lock: document.getElementById('lock').getBoundingClientRect().toJSON(),
      amountFirst: Boolean(amount.compareDocumentPosition(label) & Node.DOCUMENT_POSITION_FOLLOWING),
      labelSize: parseFloat(getComputedStyle(label).fontSize), previousLabelSize,
      upperGap: box.top - greeting.bottom,
      // wallet-screen.js:44,49 (0b3b0eb0d): the network disclosure follows the card.
      lowerGap: document.getElementById('wallet-network').getBoundingClientRect().top - box.bottom };
  });
  assert.equal(layout.amountFirst, true, 'The amount precedes its label in reading order');
  assert.ok(layout.amount.bottom <= layout.label.top, 'The amount sits above its label');
  for (const control of [layout.eye, layout.lock]) {
    assert.ok(layout.label.top >= control.bottom, 'The label text sits below both the eye and lock');
    assert.ok(layout.label.left < control.right && layout.label.right > control.left, 'The label text sits beneath each icon horizontally');
  }
  assert.ok(Math.abs(layout.label.right - layout.lock.right) < 1, 'The label text aligns with the right edge of the lock');
  assert.ok(layout.labelSize < layout.previousLabelSize, 'The label is smaller than the previous portfolio eyebrow');
  assert.ok(layout.upperGap > 0 && layout.lowerGap > 0, 'The greeting, card and network chips have space between them');
  assert.ok(Math.abs(layout.upperGap - layout.lowerGap) < 1, 'Welcome to card and card to network disclosure have equal gaps');
  assert.ok(Math.abs(layout.lowerGap - 18) < 1, 'Both portfolio gaps are 18px (operator 2026-11-02: "ikiside 18")');
}

const button = (page, name) => page.getByRole('button', { name, exact: true });
// UI pack 2026-11-03: Settings is a button of the bottom bar (connect.js); the rail has no gear.
// Connect's accessible name gains ", N new" with unread messages, hence the prefix match.
const bottomBar = (page, name) => page.locator(`#extension-bottom-bar button[aria-label^="${name}"]`);
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
// The network chips live in the closed disclosure beside the card, on Send and
// on Receive (wallet-screen.js:44,199-202); groups collapse their chips. Same
// steps as fixtures/portfolio-page-checks.js selectFixtureNetwork, on any page.
async function selectNetwork(page, chain) {
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  const badge = page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);
  const toggle = badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');
  if (await toggle.count() && await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  await badge.click();
}
// 0.1.155 (5eb8dc724): the environment is chosen with buttons in the compact
// disclosure inside the network disclosure (wallet-screen.js:149-161).
async function selectEnvironment(page, id) {
  if (!await page.locator('#wallet-network').evaluate(node => node.open)) await page.locator('#wallet-network > summary').click();
  if (!await page.locator('#wallet-environment').evaluate(node => node.open)) await page.locator('#wallet-environment > summary').click();
  await page.locator(`#wallet-environment button[data-environment="${id}"]`).click();
}
async function assertNavigation(page, current = null) {
  // index.html:34 sets the link order.
  // wallet-screen.js:57-63 (0.1.145, 0b3b0eb0d): Portfolio returns home ('#'),
  // Send and Receive are separate pages. Pages replace wallet-home
  // (wallet-screen.js:194-212); links have no aria-current.
  const links = page.locator('.wallet-navigation a');
  const values = await links.evaluateAll(nodes => nodes.map(node => ({
    text: node.querySelector('.nav-name').textContent, href: node.getAttribute('href'),
    hidden: node.hidden, box: node.getBoundingClientRect().toJSON(),
  })));
  assert.deepEqual(values.map(node => [node.text, node.href]), [
    ['Portfolio', '#'], ['Send', '#send'], ['Receive', '#receive'],
    ['Earn', '#earn'], ['Shared vaults', '#vaults'], ['Smart contracts', '#contracts'],
    ['Activity', '#wallet-activity'], ['Address book', '#address-book'],
    ['Connected sites', '#sites'],
  ]);
  const available = values.filter(node => !node.hidden);
  assert.deepEqual(available.filter(node => !['#earn', '#vaults', '#contracts'].includes(node.href)).map(node => node.text),
    ['Portfolio', 'Send', 'Receive', 'Activity', 'Address book', 'Connected sites']);
  assert.deepEqual(await page.locator('.wallet-page:visible').evaluateAll(nodes => nodes.map(node => node.id)), current ? [`page-${current}`] : []);
  assert.equal(await page.locator('#wallet-home').isVisible(), current === null);
  assert.equal(await page.locator('#wallet-heading').isVisible(), current === null);
  // style.css:999-1005 and :1019-1022 (0b3b0eb0d): one compact rail stays beside
  // the home screen and every wallet page; names are visually hidden labels.
  assert.equal(await page.locator('.wallet-navigation a:visible').count(), available.length);
  if (current) {
    const title = current === 'send' ? /^Send · /u : current === 'receive' ? /^Receive on /u
      : current === 'wallet-activity' ? 'Activity' : current === 'sites' ? 'Connected sites' : 'Device & settings';
    const heading = page.locator(`#page-${current}`).getByRole('heading', { name: title, exact: true });
    await heading.waitFor();
    assert.equal(await heading.evaluate(node => document.activeElement === node), true);
    assert.equal(await page.evaluate(() => location.hash), `#${current}`);
    const back = page.locator(`#page-${current} > .page-back`);
    assert.equal(await back.isVisible(), true);
    assert.match(await back.textContent(), /Back to wallet/u);
    assert.ok((await back.boundingBox()).y < (await heading.boundingBox()).y, 'Back appears above the page heading');
  }
  const content = await page.locator(current ? `#page-${current}` : '#wallet-home').evaluate(node => node.getBoundingClientRect().toJSON());
  for (const [index, link] of available.entries()) {
    assert.ok(link.box.width > 0 && link.box.height > 0, `${link.text}: rail link must be measurable`);
    assert.ok(Math.abs(link.box.left - available[0].box.left) < 1, `${link.text}: rail links share one column`);
    assert.ok(Math.abs(link.box.width - available[0].box.width) < 1, `${link.text}: rail links have equal widths`);
    if (index) assert.ok(link.box.top >= available[index - 1].box.bottom, `${link.text}: rail links stack without overlap`);
    assert.ok(link.box.right <= content.left, `${link.text}: the rail stays beside the ${current ?? 'home'} content`);
  }
}
async function assertAssetLayout(page) {
  // 0.1.145 (0b3b0eb0d): holdings are grouped by network on the home screen
  // (portfolio-view.js:211-214, portfolio.js groupNetworks); no Portfolio page.
  // Closed details have no row geometry: expand only for measurement and
  // restore every original open state.
  assert.equal(await page.locator('#assets-panel').isVisible(), true);
  const groups = await page.evaluate(() => {
    const details = [...document.querySelectorAll('.asset-group')], opened = details.map(node => node.open);
    const rect = node => node.getBoundingClientRect().toJSON();
    try {
      for (const node of details) node.open = true;
      return details.map(node => ({
        chain: node.dataset.chain, radius: getComputedStyle(node).borderRadius,
        summary: { box: rect(node.querySelector('.asset-summary')), icon: rect(node.querySelector('.asset-summary > .coin-icon')),
          name: rect(node.querySelector('.asset-summary > .network-heading-select')) },
        rows: [...node.querySelectorAll('.chain-holding')].map(row => ({
          chain: row.dataset.chain, symbol: row.querySelector('.holding-network span:not(.coin-icon)').textContent,
          selected: row.classList.contains('selected'), box: rect(row), padding: parseFloat(getComputedStyle(row).paddingRight),
          identity: { box: rect(row.querySelector('.holding-network')), icon: rect(row.querySelector('.holding-network .coin-icon')),
            name: rect(row.querySelector('.holding-network span:not(.coin-icon)')) },
          value: { ...rect(row.querySelector('.holding-value')), align: getComputedStyle(row.querySelector('.holding-value')).textAlign },
          amounts: [...row.querySelectorAll('.holding-value strong, .holding-value small')].map(rect),
          actions: row.querySelectorAll('.holding-actions button').length,
        })),
      }));
    } finally { details.forEach((node, index) => { node.open = opened[index]; }); }
  });
  // Hide zero balances is on by default (portfolio-view.js:129): networks whose
  // balance is unavailable or zero leave no group. Order follows snapshot rows.
  assert.deepEqual(groups.map(group => [group.chain, group.rows.map(row => row.symbol)]), [
    ['nodus', ['NODUS']], ['ethereum', ['ETH', 'USDT', 'USDC', 'DAI']], ['bsc', ['BNB', 'USDT', 'USDC']],
    ['solana', ['SOL', 'USDT', 'USDC']], ['tron', ['TRX', 'USDT', 'USDC', 'USDD']], ['cellframe', ['CPUNK']], ['ixios', ['IXIOS']],
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
    assert.equal(group.radius, '10px', group.chain);
    alignedIdentity(group.summary, group.chain); // operator 2026-11-02: "hizala"
    for (const row of group.rows) {
      const label = `${row.symbol} on ${group.chain}`;
      assert.equal(row.chain, group.chain, label);
      alignedIdentity(row.identity, label);
      assert.equal(row.selected, group.chain === 'nodus', `${label}: selected network marker`);
      assert.equal(row.value.align, 'right', label);
      // style.css:1024 (<=560px): .holding-value is display: contents, so its
      // amount and price are measured as the row's own grid items there.
      const valueRight = row.value.width ? row.value.right : Math.max(...row.amounts.map(amount => amount.right));
      assert.ok(Math.abs(row.box.right - row.padding - valueRight) < 1, `${label}: holding value ends at the row's right padding`);
      for (const amount of row.amounts) {
        contained(amount, row.box, `${label}: amount stays inside its row`);
        assert.ok(Math.abs(amount.right - valueRight) < 1, `${label}: amount and price share the right edge`);
      }
      // Send and Receive are pages reached from the rail or the shortcuts.
      assert.equal(row.actions, 0, `${label}: rows carry no transfer buttons`);
    }
  }
  assert.equal(await page.locator('.chain-holding').count(), 17);
  assert.equal(await page.locator('.transfer-buttons #quick-send').count(), 1);
  assert.equal(await page.locator('.transfer-buttons #quick-receive').count(), 1);
  assert.equal(await page.locator('#send-form').isVisible(), false);
  assert.ok(await page.locator('.price-source').evaluate(node => node.getBoundingClientRect().top >= [...document.querySelectorAll('.asset-group')].at(-1).getBoundingClientRect().bottom));
}
async function assertHome(page, popup) {
  await waitHome(page); await page.evaluate(() => scrollTo(0, 0));
  await assertNavigation(page);
  await assertPortfolioLayout(page);
  assert.equal(await page.getByRole('heading', { name: 'Your wallet', exact: true }).count(), 0);
  assert.equal(await page.locator('.wallet-card > .section-head .eyebrow').count(), 0);
  assert.equal(await page.locator('#wallet-heading img').count(), 0);
  assert.equal(await page.locator('.site-header .wordmark img').count(), 1);
  assert.equal(await page.getByText('Wallet open in this browser', { exact: true }).count(), 0);
  assert.equal(await button(page, 'Lock wallet').isVisible(), true);
  assert.equal((await button(page, 'Lock wallet').textContent()).trim(), '');
  assert.equal(await page.locator('#lock > svg.app-icon[aria-hidden="true"]').count(), 1);
  assert.equal(await page.locator('.wallet-session, #session-timeout').count(), 0);
  assert.equal(await page.locator('.portfolio-heading > #portfolio-hide + #lock').count(), 1);
  const lockStyle = await page.locator('#lock').evaluate(node => ({ border: getComputedStyle(node).borderWidth,
    background: getComputedStyle(node).backgroundColor, icon: node.querySelector('svg').getBoundingClientRect().toJSON() }));
  assert.equal(lockStyle.border, '0px'); assert.equal(lockStyle.background, 'rgba(0, 0, 0, 0)');
  assert.ok(lockStyle.icon.width > 0 && lockStyle.icon.height > 0, 'The lock icon is measurable');
  const controls = await page.locator('#portfolio-hide, #lock').evaluateAll(nodes => nodes.map(node => {
    const style = getComputedStyle(node);
    return { box: node.getBoundingClientRect().toJSON(), color: style.color,
      background: style.backgroundColor, padding: style.padding, border: style.borderWidth };
  }));
  const [eye, lock] = controls;
  assert.equal(lock.color, eye.color); assert.equal(lock.background, eye.background);
  assert.equal(lock.padding, eye.padding); assert.equal(lock.border, eye.border);
  assert.equal(lock.box.width, eye.box.width); assert.equal(lock.box.height, eye.box.height);
  assert.ok(Math.abs(lock.box.top - eye.box.top) < 1, 'The lock and eye share a row');
  assert.ok(lock.box.left >= eye.box.right && lock.box.left - eye.box.right <= 12, 'The lock sits beside the eye');
  // wallet-screen.js:249 and capabilities.js: Nodus pages follow chain capability.
  assert.deepEqual(await page.locator('.wallet-navigation a:visible .nav-name').allTextContents(),
    ['Portfolio', 'Send', 'Receive', 'Earn', 'Shared vaults', 'Smart contracts', 'Activity', 'Address book', 'Connected sites']);
  assert.equal(await page.locator('.extension-network').count(), 0);
  assert.equal(await page.locator('.network-health').count(), 15);
  // portfolio-view.js:477-479: the portfolio always shows every network; no filter buttons.
  assert.equal(await page.locator('.network-filter').count(), 0);
  assert.equal(await page.locator('#portfolio-filters').isHidden(), true);
  const networks = ['Nodus', 'Cellframe', 'Ixios', 'Algorand', 'Tidecoin', 'Nervos CKB',
    'Soqucoin', 'QTC', 'Verona / XION', 'Splendor', 'Asentum', 'Ethereum', 'BNB Smart Chain', 'Solana', 'TRON'];
  assert.deepEqual(await page.locator('.network-health > span:not(.health-light):not(.coin-icon)').allTextContents(), networks);
  assert.deepEqual(await page.locator('#chain option').allTextContents(), networks);
  await assertNetworkGroups(page, { addressBookIxios: true });
  await page.waitForFunction(() => {
    const icons = [...document.querySelectorAll('img[data-icon="ixios.png"]')];
    return icons.length > 0 && icons.every(icon => icon.complete && icon.naturalWidth > 0);
  });
  assert.equal(await page.locator('#chain').inputValue(), 'nodus');
  assert.deepEqual(await page.locator('.selected-network-name').allTextContents(), Array(6).fill('Nodus'));
  assert.deepEqual(await page.locator('.selected-network-stage').allTextContents(), Array(5).fill('Testnet'));
  assert.deepEqual(await page.locator('#asset option').allTextContents(), ['NODUS']);
  assert.equal(await page.locator('#asset').inputValue(), '0'.repeat(128));
  assert.equal(await page.locator('#receive-address').textContent(), 'ab'.repeat(64));
  assert.equal(await page.locator('#receive-qr svg[aria-label="QR code for the receive address"]').count(), 1);
  assert.equal(await page.locator('#net-status, #net-status-text').count(), 0);
  assert.equal(await page.locator('.asset-group[data-chain="nodus"] .holding-value strong').textContent(), '12.34 NODUS');
  assert.equal(await page.locator('#portfolio-status').isVisible(), false);
  assert.equal(await page.locator('#assets-panel').isVisible(), true);
  assert.equal(await page.locator('#send-form').isVisible(), false);
  const methods = await page.evaluate(() => window.layout.calls.map(call => call.method));
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'getEvmBalances', 'getSolanaBalances', 'getTronBalances', 'getPrices']) {
    assert.ok(methods.includes(method), `Opening the wallet must request ${method} over the trusted client`);
  }
  assert.equal(await page.locator('.asset-group[data-chain="ethereum"] .chain-holding').count(), 4);
  assert.equal(await page.locator('#page-receive #receive-panel').count(), 1);
  await assertAssetLayout(page);
  // style.css:1009 (0b3b0eb0d): the rail replaces the home shortcuts, which
  // stay in the DOM for their handlers but are not displayed.
  assert.equal(await page.locator('.transfer-actions .transfer-buttons').evaluate(node => getComputedStyle(node).display), 'none');
  for (const id of ['quick-send', 'quick-receive', 'quick-earn', 'quick-swap']) assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
  for (const chip of await page.locator('.network-health').all()) {
    const centers = await chip.evaluate(node => {
      const center = item => { const box = item.getBoundingClientRect(); return box.top + box.height / 2; };
      return { chip: center(node), content: [...node.querySelectorAll('.coin-icon, span:not(.health-light)')].map(center) };
    });
    for (const center of centers.content) assert.ok(Math.abs(center - centers.chip) < 1, 'Network icon and name are vertically centered in the chip');
  }
  const styles = await page.evaluate(() => ({
    font: getComputedStyle(document.body).fontFamily,
    portfolioRadius: getComputedStyle(document.querySelector('.portfolio-card')).borderRadius,
    portfolioBackground: getComputedStyle(document.querySelector('.portfolio-card')).backgroundImage,
    totalSize: parseFloat(getComputedStyle(document.getElementById('portfolio-total')).fontSize),
    shell: document.querySelector('.wallet-card').getBoundingClientRect().toJSON(),
  }));
  assert.match(styles.font, /^Inter(?:,|$)/u);
  assert.equal(styles.portfolioRadius, '16px'); assert.notEqual(styles.portfolioBackground, 'none');
  // 32px+ total; at <=380px the extension uses 27px so USD stays on its line (operator 2026-11-03).
  assert.ok(page.viewportSize().width <= 380 ? styles.totalSize === 27 : styles.totalSize >= 32, `total font ${styles.totalSize}px at ${page.viewportSize().width}px`);
  // UI pack 2026-11-03 (operator "2" = wide-a.png): the open wallet at <=760 px loses its outer frame and the
  // assets panel is padded 14 px; the full browser tab on a wide screen keeps today's frame.
  if (popup) { assert.equal(styles.shell.left, 10); assert.equal(styles.shell.right, 390); }
  const frame = await page.evaluate(() => { const card = getComputedStyle(document.querySelector('.wallet-card')), panel = getComputedStyle(document.querySelector('#assets-panel')); return { border: card.borderTopWidth, padding: card.paddingTop, panel: panel.paddingTop }; });
  if (page.viewportSize().width <= 760) {
    assert.deepEqual(frame, { border: '0px', padding: '0px', panel: '14px' }, `frame at ${page.viewportSize().width}px`);
    if (popup) {
      // Rows were 232 px wide in the popup; they are wider without the frame.
      const rowWidth = await page.evaluate(() => { const group = document.querySelector('.asset-group'), was = group.open; group.open = true; try { return document.querySelector('.asset-group .chain-holding').getBoundingClientRect().width; } finally { group.open = was; } });
      assert.ok(rowWidth > 232, `popup row width ${rowWidth}`);
    }
  } else {
    // Shell edges at the full 1100 px tab, measured on 14dc02b9f (before the UI pack) and on this branch:
    // left 56, right 1044, width 988 on both (only its top moved up, 173 -> 115, with the top Connect toggle gone).
    if (page.viewportSize().width === 1100) assert.deepEqual({ left: styles.shell.left, right: styles.shell.right, width: styles.shell.width }, { left: 56, right: 1044, width: 988 }, 'the wide full tab keeps its shell geometry');
    assert.equal(frame.border, '1px', 'a wide full tab keeps its frame'); assert.ok(['18px', '24px'].includes(frame.panel), `wide tab panel padding ${frame.panel} is today's (src/style.css:249 24 px, :403 18 px)`);
  }
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
        // Real reference-page wiring, public fake background, no live keys or
        // RPC. Visibility alone cannot prove native keyboard activation locks.
        for (const key of ['click', 'Enter', 'Space']) {
          const lock = button(page, 'Lock wallet');
          if (key === 'click') await lock.click();
          else {
            await button(page, 'Hide balances').focus(); await page.keyboard.press('Tab');
            assert.equal(await lock.evaluate(node => document.activeElement === node), true);
            await page.keyboard.press(key);
          }
          await page.locator('#unlock-form:visible').waitFor();
          // UI pack 2026-11-03: only the OPEN wallet loses its frame; the locked screen keeps the card border.
          assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('.wallet-card')).borderTopWidth), '1px');
          assert.equal(await page.locator('#extension-bottom-bar').count(), 0, 'no bottom bar on the locked screen');
          assert.equal(await page.evaluate(() => window.layout.state.isUnlocked), false);
          assert.equal(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'setLocked').length), 1);
          assert.equal(await page.locator('#lock').isVisible(), false);
          await open('home'); await waitHome(page);
        }
        // UI pack 2026-11-03: the bottom bar. Order, current view, no top switch, one lock control,
        // Settings and Back, no horizontal overflow, no badge without unread messages.
        assert.deepEqual(await page.locator('#extension-bottom-bar button').evaluateAll(nodes => nodes.map(node => node.getAttribute('aria-label'))), ['Connect', 'Wallet', 'Settings']);
        assert.equal(await bottomBar(page, 'Wallet').getAttribute('aria-current'), 'page');
        assert.equal(await page.locator('#extension-bottom-bar [aria-current="page"]').count(), 1);
        assert.equal(await page.locator('.wallet-connect-switch, #wallet-connect-switch').count(), 0);
        assert.equal(await page.getByRole('button', { name: 'Lock wallet' }).count(), 1);
        assert.equal(await page.locator('.extension-bottom-badge').isVisible(), false);
        // UI pack 2026-11-03: a click, Enter and Space on a network's name select it and toggle its group.
        {
          const group = page.locator('.network-assets[data-chain="ethereum"]');
          const name = page.getByRole('button', { name: 'Select Ethereum network', exact: true });
          const isOpen = () => group.evaluate(node => node.open);
          if (await isOpen()) await group.locator('summary .asset-chevron').click();
          assert.equal(await isOpen(), false, 'the group starts closed');
          await name.click();
          assert.equal(await page.locator('#chain').inputValue(), 'ethereum'); assert.equal(await isOpen(), true);
          await name.click();
          assert.equal(await page.locator('#chain').inputValue(), 'ethereum'); assert.equal(await isOpen(), false);
          await name.focus(); await page.keyboard.press('Enter'); assert.equal(await isOpen(), true);
          await page.keyboard.press('Space'); assert.equal(await isOpen(), false);
          await selectNetwork(page, 'nodus');
        }
        await bottomBar(page, 'Settings').click();
        await page.locator('#page-settings').waitFor({ state: 'visible' });
        assert.equal(await bottomBar(page, 'Settings').getAttribute('aria-current'), 'page');
        assert.equal(await bottomBar(page, 'Wallet').getAttribute('aria-current'), null);
        await capture('bottom-bar-settings');
        await page.locator('#page-settings .page-back').click();
        assert.equal(await bottomBar(page, 'Wallet').getAttribute('aria-current'), 'page');
        await capture('bottom-bar-wallet');
        // The badge reads the unread count of the fixture's open Connect snapshot (2), only off the Connect view.
        await page.goto(`${origin}/extension/test/fixtures/layout.html?page=${kind}&stage=home&unread`);
        await page.waitForFunction(() => Boolean(window.layout));
        await page.locator('.extension-bottom-badge:visible').waitFor();
        assert.equal(await page.locator('.extension-bottom-badge').textContent(), '2');
        assert.equal(await bottomBar(page, 'Connect').getAttribute('aria-label'), 'Connect, 2 new');
        await bottomBar(page, 'Connect').click();
        await page.locator('#extension-connect').waitFor({ state: 'visible' });
        assert.equal(await bottomBar(page, 'Connect').getAttribute('aria-current'), 'page');
        assert.equal(await page.locator('.extension-bottom-badge').isVisible(), false);
        await capture('bottom-bar-connect');
        const bottoms = await page.evaluate(() => ({ messenger: document.querySelector('#extension-connect .messenger').getBoundingClientRect().bottom, bar: document.querySelector('#extension-bottom-bar').getBoundingClientRect().top }));
        assert.ok(bottoms.messenger <= bottoms.bar + 0.5, `${kind} ${width}: messenger bottom ${bottoms.messenger} reaches the bar top ${bottoms.bar}`);
        // Chat "Send NODUS" follows the wallet's NODUS send state (UI pack 2026-11-03, connect.js nodusSendable),
        // seen in the fixture contact's open conversation: ready shows it, not ready hides it, ready shows it again.
        // The conversation is opened by a mouse press held 100 ms (W-42: a re-read on the press redrew the chat
        // list before the release and the click was lost; the screen stayed on the list).
        await page.locator('#extension-connect .contact-list .contact-row').first().click({ delay: 100 });
        await page.waitForFunction(() => document.querySelector('#extension-connect .messenger').dataset.screen === 'conversation');
        const pay = page.locator('#extension-connect .conversation-pay');
        await pay.waitFor({ state: 'visible' });
        await page.evaluate(async () => { window.layout.state.nodus.state = 'connecting'; await window.layout.refresh(); });
        await pay.waitFor({ state: 'hidden' });
        await page.evaluate(async () => { window.layout.state.nodus.state = 'ready'; await window.layout.refresh(); });
        await pay.waitFor({ state: 'visible' });
        await open('home'); await waitHome(page);
        // No flags/live data. The public fixture holds every initial balance
        // and quote read. Measuring only after waitHome would miss the jump.
        await page.goto(`${origin}/extension/test/fixtures/layout.html?page=${kind}&stage=home&hold`);
        await page.waitForFunction(() => window.layout && document.getElementById('portfolio-label')?.textContent === 'Updating portfolio');
        assert.equal(await page.locator('#portfolio-status').isVisible(), false);
        await page.evaluate(() => document.fonts.ready);
        const loading = await page.locator('.portfolio-card').boundingBox();
        await assertPortfolioLayout(page);
        assert.ok(loading.height < await portfolioHeight0136(page) - 1, `${kind} ${width}: loading card is smaller than 0.1.136`);
        const refreshTop = await page.locator('#portfolio-refresh').evaluate(node => node.getBoundingClientRect().top);
        await page.evaluate(() => window.layout.releaseReads()); await waitHome(page);
        assert.equal(await page.locator('#portfolio-status').isVisible(), false);
        // The fixture has no selected-environment PQ addresses: those networks are
        // balanceUnavailable (wallet-screen.js:194-196), so the known value is incomplete.
        assert.equal(await page.locator('#portfolio-label').textContent(), 'Known value · incomplete');
        const settled = await page.locator('.portfolio-card').boundingBox();
        await assertPortfolioLayout(page);
        assert.ok(settled.height < await portfolioHeight0136(page) - 1, `${kind} ${width}: settled card is smaller than 0.1.136`);
        assert.ok(Math.abs(loading.height - settled.height) < 1, `${kind} ${width}: portfolio height stays fixed after loading`);
        assert.ok(Math.abs(refreshTop - await page.locator('#portfolio-refresh').evaluate(node => node.getBoundingClientRect().top)) < 1, 'Refresh action stays in place');
        // operator 2026-11-03 ("12'den 6 piksele indir"): amount and currency share one line.
        const [total, currency] = await page.locator('#portfolio-total, .portfolio-currency').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().toJSON()));
        assert.ok(currency.top >= total.top - 1 && currency.bottom <= total.bottom + 1 && currency.left > total.right, `${kind} ${width}: USD stays on the amount's line`);
        // Public fixture replies, no live reads. Compare the generic, named
        // (including long text) and registration states at each viewport. This
        // pins row height and portfolio position; name-block-ui.test.js pins
        // the pending read. Geometry alone cannot approve visual appearance.
        assert.equal(await page.getByRole('heading', { name: 'Welcome back', exact: true }).isVisible(), true);
        const greeting = await page.locator('#wallet-heading').boundingBox();
        const portfolioTop = (await page.locator('.portfolio-card').boundingBox()).y;
        const assertGreetingPosition = async () => {
          const row = await page.locator('#wallet-heading').boundingBox();
          assert.ok(Math.abs(row.y - greeting.y) < 1, `${kind} ${width}: greeting stays in place`);
          assert.ok(Math.abs(row.height - greeting.height) < 1, `${kind} ${width}: greeting row height stays fixed`);
          assert.ok(Math.abs((await page.locator('.portfolio-card').boundingBox()).y - portfolioTop) < 1, `${kind} ${width}: greeting does not move the portfolio`);
          await assertPortfolioLayout(page);
        };
        for (const name of ['publicname', 'publicnamepublicnamepublicname']) {
          await open('home', name); await waitHome(page);
          await page.getByRole('heading', { name: `Welcome back, ${name}`, exact: true }).waitFor();
          assert.equal(await page.locator('#wallet-register-name').isVisible(), false);
          await assertGreetingPosition(); await capture(`greeting-${name}`);
          assert.equal(await page.locator('.site-header .wordmark').textContent(), 'nodus');
          assert.equal(await page.locator('.site-header .product-name').textContent(), 'Connect');
          assert.equal(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'getOwnName').length), 1);
        }
        await open('home', 'none');
        await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
        await button(page, 'Register your on-chain name').waitFor(); await waitHome(page);
        await assertGreetingPosition();
        const title = await page.locator('#wallet-title').boundingBox();
        const register = await page.locator('#wallet-register-name').boundingBox();
        assert.ok(title.x + title.width <= register.x, 'Registration sits to the right of the greeting');
        assert.ok(Math.abs(title.y + title.height / 2 - register.y - register.height / 2) < 1, 'Greeting and registration share a row');
        assert.ok(Math.abs(register.x + register.width - greeting.x - greeting.width) < 1, 'Registration aligns with the right edge');
        assert.equal(await page.locator('#wallet-register-name').evaluate(node => node.scrollHeight <= node.clientHeight), true, 'Registration text fits inside the button');
        await capture('greeting-registration');
        // Greeting and registration belong to home. A name/state refresh on a
        // separate page must not restore them; returning home keeps the form.
        await selectNetwork(page, 'ethereum');
        await bottomBar(page, 'Settings').click();
        assert.equal(await page.locator('#wallet-heading').isVisible(), false);
        await page.evaluate(async () => {
          window.layout.state.nodus.connection = 'public-refresh'; await window.layout.refresh();
        });
        assert.equal(await page.locator('#wallet-heading').isVisible(), false);
        await page.locator('#page-settings .page-back').click();
        await button(page, 'Register your on-chain name').click();
        assert.equal(await page.locator('#wallet-home').isVisible(), false);
        // wallet-screen.js:419-420: registration opens Nodus Receive with the name block.
        assert.equal(await page.locator('#page-receive').isVisible(), true);
        assert.equal(await page.locator('#chain').inputValue(), 'nodus');
        assert.equal(await page.locator('#name-block').isVisible(), true);
        assert.equal(await page.locator('#name-input').evaluate(node => document.activeElement === node), true);
        assert.equal(await page.evaluate(() => window.layout.calls.some(call => call.method === 'prepareName')), false);
        // Parent regression: rejected persistence must redraw a coherent
        // environment/address/QR; same-value selection must preserve them.
        // Public independent native oracle addresses; no signing or network.
        if(kind==='popup') {
          const pqStart = blocked.length;
          await open('home');await waitHome(page);
          const pq=JSON.parse(readFileSync(new URL('../../test/fixtures/pq-receive.json',import.meta.url))).vectors[0].addresses;
          await page.evaluate(async pq=>{window.layout.state.pqAddresses=pq;await window.layout.refresh();},pq);
          await page.locator('.wallet-navigation a[href="#receive"]').click();await selectNetwork(page,'qtc');
          await selectEnvironment(page,'mainnet');
          assert.equal(await page.locator('#receive-address').textContent(),pq.qtc.mainnet);
          for(const failure of ['before','after']) {
            await page.evaluate(failure=>{window.layout.state.failNetworkWrites=failure;},failure);
            await selectEnvironment(page,'testnet');
            await page.waitForFunction(()=>!document.querySelector('#screen').inert&&document.querySelector('#wallet-status').textContent.includes('Public fixture network persistence failure'));
            const network=failure==='before'?'mainnet':'testnet';
            assert.equal(await page.locator('#pq-network-environment').inputValue(),network);
            assert.equal(await page.locator('#receive-address').textContent(),pq.qtc[network]);
            assert.equal(await page.locator('#receive-qr svg').count(),1);
            assert.equal(await page.locator('#copy-address').isDisabled(),false);
          }
          // With PQ addresses the page's public-only readers (wallet-page.js:17-28)
          // call their own endpoints directly; the route above aborts them, so
          // those rows stay unavailable. Only these public read origins may appear.
          const pqOrigins = new Set(['https://mainnet-api.algonode.cloud', 'https://mainnet-api.soqu.org', 'https://qtc.events',
            'https://testnet.qtc.events', 'https://api.xion-mainnet-1.burnt.com', 'https://quantum-rpc.splendor.org',
            'https://testnet.asentum.com', 'https://mainnet.ckb.dev']); // src/pq/{algorand,soqucoin,qtc,xion,ckb}.js, splendor-history.js, asentum-transfer.js
          for (const url of blocked.splice(pqStart)) assert.ok(pqOrigins.has(new URL(url).origin), `Unexpected outside request ${url}`);
        }
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
        assert.equal(await page.locator('.asset-group[data-chain="nodus"] .holding-value strong').textContent(), '12.34 NODUS');
        await page.locator('#portfolio-refresh').click(); await waitHome(page); assert.equal(await priceCount(page), 2);
        await page.locator('.wallet-navigation a[href="#receive"]').click();
        assert.equal(await page.locator('#receive-address').textContent(), 'ab'.repeat(64));
        await assertNavigation(page, 'receive');
        await capture('receive');
        await page.locator('#page-receive .page-back').click();
        await selectNetwork(page, 'ethereum');
        await page.locator('.wallet-navigation a[href="#send"]').click();
        // Check navigation focus before filling fields, which moves focus to
        // the input. Typing must not mask a missing heading focus on entry.
        await assertNavigation(page, 'send');
        await page.locator('#recipient').fill('0x' + '34'.repeat(20)); await page.locator('#amount').fill('0.125');
        assert.equal(await page.locator('#amount').evaluate(node => document.activeElement === node), true, 'Filling the amount keeps focus in the input');
        await capture('send');
        const before = await page.evaluate(() => window.layout.calls.filter(call => call.method === 'getState').length);
        await page.evaluate(() => { window.typedNodes = [document.getElementById('recipient'), document.getElementById('amount')]; });
        await page.locator('#page-send .page-back').click();
        await page.locator('.wallet-navigation a[href="#"]').click();
        await assertNavigation(page);
        await page.locator('.wallet-navigation a[href="#send"]').click();
        await assertNavigation(page, 'send');
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
        await page.locator('#page-send .page-back').click();
        await page.locator('#portfolio-refresh').click(); await waitHome(page);
        await selectNetwork(page, 'nodus');
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
        // Pin the mounted record link as well as its renderer: the footer
        // must use this row's network record, with TRON's link text/attributes.
        const nodusLink = nodusRow.locator('.activity-footer a');
        assert.equal(await nodusLink.textContent(), 'View transaction');
        assert.equal(await nodusLink.getAttribute('href'), `https://scan.nodusnetwork.io/tx.html?hash=${'cd'.repeat(64)}&lang=en`);
        assert.equal(await nodusLink.getAttribute('target'), '_blank');
        assert.equal(await nodusLink.getAttribute('rel'), 'noopener noreferrer');
        assert.equal(await nodusRow.locator('.activity-id').count(), 0);
        assert.equal(await page.locator('#history .activity-row').nth(1).locator('.activity-main strong').textContent(), 'Witness update');
        assert.equal(await page.locator('#history .activity-row').nth(1).locator('time').count(), 0);
        assert.equal(await page.locator('#history .activity-row').nth(1).locator('.activity-footer a').count(), 0);
        await assertHistoryLayout(page);
        await capture('history');
        // Ethereum, Solana, TRON and Cellframe share this renderer. Real
        // network rows retain their explorer routing; no peer/hash is HTML.
        for (const chain of ['ethereum', 'solana', 'tron', 'cellframe']) {
          await page.locator('#page-wallet-activity .page-back').click();
          await selectNetwork(page, chain);
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
        await selectNetwork(page, 'bsc');
        // wallet-screen.js:249 (0b3b0eb0d): without history capability the
        // Activity page is not offered at all.
        assert.equal(await page.locator('.wallet-navigation a[href="#wallet-activity"]').isHidden(), true);
        await selectNetwork(page, 'ixios');
        await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();
        assert.equal(await page.locator('#history-status').textContent(), '');
        assert.equal(await page.locator('#history .activity-row').count(), 0);
        await assertAccountHistoryOnly(page);
        await page.locator('#page-wallet-activity .page-back').click();
        await selectNetwork(page, 'nodus'); await waitHome(page);
        await assertNavigation(page);
        await bottomBar(page, 'Settings').click();
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
        await page.locator('#page-sites .page-back').click(); await bottomBar(page, 'Settings').click();
        await page.locator('#auto-lock-minutes').selectOption('15');
        await page.waitForFunction(() => window.layout.state.preferences.autoLockTimeLimit === 15);
        assert.match(await page.locator('#auto-lock-note').textContent(), /locks after 15 minutes/);
        assert.equal(await page.locator('#session-timeout').count(), 0);
        await page.locator('#rpc-settings').evaluate(node => { node.open = true; });
        await page.locator('#network-solana').selectOption('devnet');
        await page.waitForFunction(() => window.layout.state.networks.solana === 'devnet');
        await page.locator('#page-settings .page-back').click();
        await selectNetwork(page, 'solana');
        assert.deepEqual(await page.locator('#asset option').allTextContents(), ['SOL']);
        assert.equal(await page.locator('.asset-group[data-chain="solana"] .chain-holding').first().locator('.holding-value small').textContent(), '—');
        await bottomBar(page, 'Settings').click();
        await page.locator('#reveal-password').fill('fresh-password');
        await button(page, 'Reveal phrase').click();
        assert.equal(await page.locator('#device-panel .phrase-grid input[readonly]').count(), 24);
        // UI pack 2026-11-03: framed words, centred numbers, Copy phrase button; all gone after Back.
        assert.equal(await page.locator('#device-panel .reveal-words').isVisible(), true);
        assert.equal(await page.locator('#device-panel .reveal-words input[readonly]').count(), 24);
        const labelOffsets = await page.locator('#device-panel .reveal-words .phrase-cell').evaluateAll(cells => cells.map(cell => {
          const label = cell.querySelector('label').getBoundingClientRect(), input = cell.querySelector('input').getBoundingClientRect();
          return Math.abs((label.top + label.height / 2) - (input.top + input.height / 2));
        }));
        assert.ok(labelOffsets.every(offset => offset <= 1), `number labels off centre: ${labelOffsets}`);
        assert.equal(await button(page, 'Copy phrase').isVisible(), true);
        await page.locator('#page-settings .page-back').click();
        assert.equal(await page.locator('input[readonly]').count(), 0);
        assert.equal(await button(page, 'Copy phrase').count(), 0);
        await page.locator('#lock').click();
        await page.locator('#unlock-form:visible').waitFor();
        assert.equal(await page.evaluate(() => window.layout.state.isUnlocked), false);
        assert.equal(await page.evaluate(() => window.layout.calls.filter(call => call.method === 'setLocked').length), 1);
        assert.equal(await page.locator('input[readonly]').count(), 0);
        assert.equal(await page.locator('#wallet-heading').isVisible(), true);
        assert.equal(await page.locator('#wallet-title').textContent(), 'Welcome back');
        assert.equal(await page.locator('#wallet-register-name').isVisible(), false);
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
