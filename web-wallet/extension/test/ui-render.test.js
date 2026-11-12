// Proves the extension's page renderers and the mounted wallet page: home,
// receive QR, connect, sites, settings, reveal phrase, import, create, send,
// approvals and balances, plus one Chromium check of the status bar wording,
// RPC provider choices and welcome text. It also proves that an approval arriving
// at an open popup replaces the open-wallet screen from the background
// notification alone, and that only the approval window closes itself once no
// approval is left (the closer is a counter or fake browser here).
// Needs: Node >=22.14 for the in-memory tests. The Chromium test also needs
// CHROMIUM_PATH or /usr/bin/chromium and a loopback Vite server (through
// portfolio-page-checks.js). No flags, network, wallet artifacts or ports
// chosen here.
// Leaves: nothing on disk except the temporary Vite cache that
// portfolio-page-checks.js removes. In-memory tests swap globalThis.document
// and restore it afterwards; document.getElementById is replaced on the
// file's own fake document only.
// Falsely passes: the fake Node class answers only the selectors these tests
// use, so it does not prove real DOM behaviour; timers are mocked; the
// provider loop in the Chromium test asserts nothing for a chain whose
// rpcOptions is empty.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderHome, renderReceive, renderConnect, renderSites, renderSettings } from '../src/ui/views.js';
import { mountWalletPage } from '../src/ui/app.js';
import { closeApprovalWindow, approvalWindowOptions } from '../src/ui/close-window.js';
import { Caip25EndowmentPermissionName, getCaip25PermissionFromLegacyPermissions, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { netLevelFor, netStatusView } from '../../src/net-status.js';
import { autoLockBarText } from '../../src/auto-lock.js';
import { CHAINS } from '../../src/config.js';

// A: every public connection state and every persisted auto-lock choice uses
// the web-wallet bar wording. No flags/network/artifacts. This pure mapping
// does not prove DOM wiring; the mounted-page test below checks that separately.
test('open-wallet status uses web-wallet network and auto-lock text', () => {
  for (const state of ['idle', 'locked', 'error', 'unknown']) assert.equal(netStatusView(netLevelFor(state)).text, 'Not connected to the Nodus network. Lock and reopen your wallet to retry.');
  for (const state of ['identifying', 'identified', 'connecting']) assert.equal(netStatusView(netLevelFor(state)).text, 'Connecting to the Nodus network…');
  assert.equal(netStatusView(netLevelFor('ready')).text, 'Connected to the Nodus network');
  for (const minutes of [5, 10, 15, 30, 60, 0]) assert.equal(autoLockBarText(minutes), minutes === 0 ? 'Auto-lock off' : `Auto-lock after ${minutes === 60 ? '1 hour' : `${minutes} minutes`} of inactivity`);
});

// Connection updates preserve the lock icon; auto-lock reaches its settings;
// listed provider selections and the welcome paragraph retain reference text.
// Public state only, loopback Vite, Chromium; no live RPC/wallet artifacts.
test('mounted status, provider choices and welcome text follow the reference', { timeout: 60_000 }, async () => {
  const { withPortfolioPage, checkPortfolioStatus, selectFixtureNetwork } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await checkPortfolioStatus(page, origin);
    // Endpoint state deliberately uses URL.href, including a trailing slash.
    // The real background's listed/typed restart is covered in evm-site.test.js.
    for (const chain of ['ethereum', 'bsc']) {
      for (const provider of CHAINS[chain].rpcOptions) {
        await selectFixtureNetwork(page, chain);
        // functions.html has no bottom bar and the rail has no Settings link (UI pack): the #settings hash opens the page.
        await page.evaluate(() => { window.location.hash = '#settings'; });
        await page.locator('#page-settings').waitFor({ state: 'visible' });
        if (!await page.locator('#rpc-settings').evaluate(details => details.open)) await page.locator('#rpc-settings > summary').click();
        await page.locator('#rpc-choice').selectOption(provider.url); await page.locator('#save-rpc').click();
        await page.locator('#page-settings .page-back').click();
        await selectFixtureNetwork(page, 'solana'); await selectFixtureNetwork(page, chain);
        await page.evaluate(() => { window.location.hash = '#settings'; });
        await page.locator('#page-settings').waitFor({ state: 'visible' });
        assert.equal(await page.locator('#rpc-choice').inputValue(), provider.url);
        assert.equal(await page.locator('#rpc-endpoint').isHidden(), true);
        await page.locator('#page-settings .page-back').click();
      }
    }
    // The markup is checked verbatim elsewhere; check the mounted welcome
    // paragraph too so a runtime replacement cannot silently change it.
    await page.goto(`${origin}/test/fixtures/layout.html?stage=welcome`);
    // A fresh profile shows the data notice first; its button opens the start screen (plan section 2.7).
    await page.locator('#privacy-agree:visible').click();
    await page.waitForFunction(() => window.layout);
    assert.equal(await page.locator('#welcome > p').first().textContent(), 'Create a new wallet or restore your 24 recovery words. Open it in this tab, or choose to save an encrypted copy on your device.');
  });
});

// Node >=22.14, no flags/network/storage writes; the minimal document and public addresses below are in-memory fixtures.
class Node extends EventTarget {
  constructor(tag) { super(); this.tagName = tag; this.children = []; this.attributes = {}; this.value = ''; this.checked = false; this.hidden = false; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.text = ''; this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  querySelectorAll(selector) {
    return descendants(this, node => selector === 'input' ? node.tagName === 'input' : selector === 'input[type="password"]' ? node.tagName === 'input' && node.type === 'password' : selector === '.phrase-grid' ? node.className === 'phrase-grid' : selector === '[role="option"]' ? node.attributes.role === 'option' : false);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  focus() { document.activeElement = this; }
}
const document = Object.assign(new EventTarget(), { createElement: tag => new Node(tag), createElementNS: (_ns, tag) => new Node(tag) });
function descendants(node, predicate) { return node.children.flatMap(child => [...(predicate(child) ? [child] : []), ...descendants(child, predicate)]); }
function button(root, text) { return descendants(root, node => node.tagName === 'button' && node.textContent === text)[0]; }
const account = '0xf278cf59f82edcf871d630f28ecc8056f25c1cdb';
function pending() {
  return { id: 'request', origin: 'https://site.example', requestData: { origin: 'https://site.example', permissions: getCaip25PermissionFromLegacyPermissions() } };
}

// Proves six address rows/receive actions use background data without dummy amounts; counting rows alone misses duplicated addresses.
test('home renders the six networks using only returned addresses', () => {
  const root = new Node('main'), selected = [], addresses = { nodus: 'public-nodus', ethereum: account, bsc: account, solana: 'public-solana', tron: 'public-tron', cpunk: 'public-cpunk' };
  renderHome(document, root, { addresses }, key => selected.push(key));
  assert.equal(descendants(root, node => node.tagName === 'article').length, 6);
  assert.deepEqual(descendants(root, node => node.tagName === 'code').map(node => node.textContent), [addresses.nodus, account, account, addresses.solana, addresses.tron, addresses.cpunk]);
  for (const control of descendants(root, node => node.tagName === 'button')) control.onclick();
  assert.deepEqual(selected, ['nodus', 'ethereum', 'bsc', 'solana', 'tron', 'cellframe']);
  assert.doesNotMatch(root.textContent, /\$|0\.00/i);
});

// Pin the asset/amount association and the reference's truncated display:
// exact units remain available on hover, while failed reads stay explicit.
test('network rows label their assets and retain exact amounts behind the web-wallet display', () => {
  const root = new Node('main');
  renderHome(document, root, { addresses: { ethereum: account }, evmBalances: { ethereum: [
    { symbol: 'ETH', balance: '1234.123456789' }, { symbol: 'USDC', error: 'Balance unavailable' },
  ] } }, () => {});
  const rows = descendants(root, node => node.className === 'chain-holding extension-holding');
  assert.deepEqual(rows.map(row => row.children.map(node => node.textContent)), [
    ['ETH', '1,234.123456 ETH'], ['USDC', 'USDC: Balance unavailable'],
  ]);
  assert.equal(rows[0].children[1].title, '1234.123456789 ETH');
  assert.equal(rows[1].children[1].className, 'field-error');
});

// Proves receive passes exactly the displayed address to the imported QR renderer; a nonempty SVG alone could encode a different address or URI.
test('receive QR is identical to the address shown to the user', t => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document'); globalThis.document = document;
  t.after(() => { if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
  const one = new Node('main'), two = new Node('main');
  renderReceive(document, one, 'ethereum', { ethereum: account }, () => {});
  renderReceive(document, two, 'ethereum', { ethereum: `${account}0` }, () => {});
  assert.equal(descendants(one, node => node.tagName === 'code')[0].textContent, account);
  const paths = root => descendants(descendants(root, node => node.className === 'receive-qr')[0], node => node.tagName === 'path').map(node => node.attributes.d);
  assert.equal(paths(one).length, 1); assert.notDeepEqual(paths(one), paths(two));
});

// Proves approval reads current account/network checkboxes and rejection targets this request; a click-only test could miss granting unchecked networks.
test('connect screen submits only selected accounts and networks', async () => {
  const root = new Node('main'), approved = [], rejected = [], request = pending();
  renderConnect(document, root, { accounts: [account] }, request, {
    approve: (...args) => approved.push(args), reject: value => rejected.push(value),
  });
  const inputs = descendants(root, node => node.tagName === 'input');
  assert.equal(inputs.length, 3); inputs[2].checked = false;
  await button(root, 'Connect').onclick();
  assert.deepEqual(approved, [[request, [account], ['0x1']]]);
  await button(root, 'Reject').onclick(); assert.deepEqual(rejected, [request]);
  assert.ok(root.textContent.includes(request.origin));
});

// Proves the visible site origin is sent to revocation and only granted sites are listed; a fixed revoke fixture could hide the wrong-origin action.
test('connected sites render grants and revoke their actual origins', async () => {
  const root = new Node('main'), revoked = [], permissions = pending().requestData.permissions;
  permissions[Caip25EndowmentPermissionName].caveats[0].value = setEthAccounts(permissions[Caip25EndowmentPermissionName].caveats[0].value, [account]);
  renderSites(document, root, { subjects: { 'https://site.example': { permissions } } }, origin => revoked.push(origin));
  assert.ok(root.textContent.includes(account)); await button(root, 'Disconnect').onclick();
  assert.deepEqual(revoked, ['https://site.example']);
  renderSites(document, root, { subjects: {} }, () => assert.fail('No revoked control should remain.'));
  assert.match(root.textContent, /no connected sites/i);
  // A connected-sites record that could not be opened is reported on this page (plan section 2.6).
  renderSites(document, root, { subjects: {}, connectedSitesError: 'Saved connected sites could not be read (x).' }, () => {});
  assert.match(root.textContent, /Saved connected sites could not be read/);
});

// Proves settings use the six web-wallet choices and password re-entry, clearing the input before export; inspecting labels alone could miss a cached-password export.
test('settings persist selected minutes and authenticate phrase reveal', async () => {
  const root = new Node('main'), changed = [], passwords = [];
  renderSettings(document, root, { preferences: { autoLockTimeLimit: 15 } }, {
    setAutoLock: minutes => changed.push(minutes), reveal: password => passwords.push(password),
  });
  const select = descendants(root, node => node.tagName === 'select')[0];
  assert.deepEqual(select.children.map(option => option.value), ['5', '10', '15', '30', '60', '0']);
  select.value = '0'; await select.onchange(); assert.deepEqual(changed, [0]);
  const input = descendants(root, node => node.tagName === 'input' && node.type === 'password')[0];
  input.value = 'freshly-entered-password';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(passwords, ['freshly-entered-password']); assert.equal(input.value, '');
  assert.doesNotMatch(root.textContent, /closing.*always locks/i);
});

async function pageFixture(t, initialized = true, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document'); globalThis.document = document;
  const root = new Node('section'), navigation = new Node('nav'), status = new Node('p');
  document.getElementById = id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id];
  const clipboardWrites = [];
  const window = Object.assign(new EventTarget(), { navigator: { clipboard: { async writeText(text) { clipboardWrites.push(text); } } } });
  const calls = [], phrase = 'abandon '.repeat(23) + 'art';
  const state = { isInitialized: initialized, isUnlocked: initialized, accounts: [account], addresses: { ethereum: account }, subjects: {}, pendingApprovals: {}, preferences: { autoLockTimeLimit: 15 } };
  let notification;
  const client = { onNotification: listener => { notification = listener; return () => { notification = undefined; }; }, onDisconnect: () => () => {}, close() {}, async request(method, params = []) {
    calls.push({ method, params: structuredClone(params) });
    if (method === 'getState') return structuredClone(state);
    if (method === 'getSeedPhrase') return [...new TextEncoder().encode(phrase)];
    if (method === 'acceptPrivacyNotice') state.privacyConsent = true;
    if (method === 'createNewVaultAndRestore') state.isInitialized = true;
    if (method === 'submitPasswordOrEncryptionKey') state.isUnlocked = true;
    if (method === 'prepareEvmSend') return { id: 'public-review', ...params[0], fee: 'Up to 0.001 ETH' };
    if (method === 'confirmEvmSend') return 'public-transaction-hash';
    if (method === 'getEvmBalances') return [{ symbol: params[0] === 'ethereum' ? 'ETH' : 'BNB', balance: '12.34' }];
    return null;
  } };
  const page = await mountWalletPage({ document, window, client, ...options });
  t.after(() => { page.dispose(); if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
  return { root, navigation, status, calls, state, page, phrase, clipboardWrites, notify: (method = 'messengerSubscription') => notification?.({ method }) };
}

// Proves the data notice (plan docs/plans/2026-11-03-chrome-web-store-plan.md section 2.7) replaces every other screen
// while the background reports no consent: its text and policy link, one button and no create/import control; the
// button sends acceptPrivacyNotice and the next screen follows. Fake document and client: it does not prove the real
// stylesheet or the background gate (privacy-consent.test.js and package-smoke.test.js do).
test('the data notice shows first with one button and agreeing opens the start screen', async t => {
  const { root, calls, state, page } = await pageFixture(t, false);
  assert.ok(button(root, 'Create wallet'), 'without the consent flag the start screen shows (older fake background)');
  state.privacyConsent = false; await page.refresh();
  assert.match(root.textContent, /Before you start: what this extension does with your data/);
  assert.match(root.textContent, /never sends the phrase, the password or your private keys to a server/);
  assert.match(root.textContent, /No analytics, no tracking, no advertising\./);
  assert.deepEqual(descendants(root, node => node.tagName === 'button').map(node => node.textContent), ['Agree and continue']);
  assert.deepEqual(descendants(root, node => node.tagName === 'a').map(node => node.href), ['https://connect.nodusnetwork.io/privacy.html']);
  assert.equal(button(root, 'Create wallet'), undefined); assert.equal(button(root, 'Import phrase'), undefined);
  await button(root, 'Agree and continue').onclick();
  assert.ok(calls.some(call => call.method === 'acceptPrivacyNotice'));
  assert.equal(button(root, 'Agree and continue'), undefined);
  assert.ok(button(root, 'Create wallet'));
});

test('home session shows the actual background auto-lock preference', async t => {
  const { navigation, state, page } = await pageFixture(t);
  assert.match(navigation.textContent, /Auto-lock after 15 minutes of inactivity/);
  state.preferences.autoLockTimeLimit = 0; await page.refresh();
  assert.match(navigation.textContent, /Auto-lock off/);
  assert.doesNotMatch(navigation.textContent, /15 minutes/);
});

// Proves the mounted page keeps authenticated words visible until expiry and removes them on lock; testing renderSettings alone would miss the action wrapper clearing or retaining secrets.
test('mounted reveal survives its response and is cleared on background lock', async t => {
  const { root, navigation, calls, state, page, phrase, clipboardWrites } = await pageFixture(t);
  button(root, 'Settings').onclick();
  const password = root.querySelectorAll('input[type="password"]')[0]; password.value = 'fresh-password';
  document.dispatchEvent(new Event('input'));
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(calls.find(call => call.method === 'getSeedPhrase').params, ['fresh-password']);
  assert.equal(root.querySelectorAll('input').filter(input => input.readOnly).map(input => input.value).join(' '), phrase);
  // UI pack 2026-11-03: Copy phrase writes the shown words to the clipboard on click only.
  assert.deepEqual(clipboardWrites, []);
  await button(root, 'Copy phrase').onclick();
  assert.deepEqual(clipboardWrites, [phrase]);
  state.isUnlocked = false; await page.refresh();
  assert.equal(root.querySelectorAll('input').some(input => input.value), false); assert.match(root.textContent, /unlock your wallet/i);
  assert.equal(button(root, 'Copy phrase'), undefined);
});

// Proves the ten-minute recovery timeout remains active with auto-lock disabled; a default fifteen-minute wallet timer could otherwise hide missing secret cleanup.
test('mounted reveal clears after ten idle minutes even when auto-lock is never', async t => {
  const { root, navigation, state } = await pageFixture(t); state.preferences.autoLockTimeLimit = 0;
  button(root, 'Settings').onclick(); root.querySelectorAll('input[type="password"]')[0].value = 'fresh-password';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.ok(button(root, 'Copy phrase'));
  t.mock.timers.tick(10 * 60_000);
  assert.equal(root.querySelectorAll('input').some(input => input.value), false);
  assert.equal(button(root, 'Copy phrase'), undefined);
});

// Proves the lifecycle adapter's import form reaches save/unlock with 24 words,
// clears inputs and restores the session controls plus portfolio (index.html:31).
// This uses the lifecycle's fallback renderer; ui-layout.test.js covers the
// production reference entry and its name-based greeting.
test('mounted import form saves through the trusted API and renders home', async t => {
  const { root, navigation, calls, phrase } = await pageFixture(t, false);
  button(root, 'Import phrase').onclick();
  const words = root.querySelectorAll('input').filter(input => input.type === 'text');
  phrase.split(' ').forEach((word, index) => { words[index].value = word; });
  for (const input of root.querySelectorAll('input[type="password"]')) input.value = 'public-test-password-123';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.ok(calls.some(call => call.method === 'createNewVaultAndRestore')); assert.ok(calls.some(call => call.method === 'submitPasswordOrEncryptionKey'));
  assert.ok(button(navigation, 'Lock'));
  assert.equal(descendants(root, node => node.id === 'portfolio-label')[0].textContent, 'Estimated portfolio value');
  assert.deepEqual(descendants(root, node => ['portfolio-total', 'portfolio-label'].includes(node.id)).map(node => node.id),
    ['portfolio-total', 'portfolio-label']);
  assert.equal(root.querySelectorAll('input').length, 0);
});

// Proves create replaces the displayed backup with writable empty verification fields and password entry; a logical confirmBackup test would miss a renderer that stays on the backup screen.
test('mounted create advances from generated backup to re-entry', async t => {
  const { root } = await pageFixture(t, false); button(root, 'Create wallet').onclick();
  assert.equal(root.querySelectorAll('input').filter(input => input.readOnly && input.value).length, 24);
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.equal(root.querySelectorAll('input').filter(input => input.type === 'text' && !input.readOnly && !input.value).length, 24);
  assert.equal(root.querySelectorAll('input[type="password"]').length, 2);
  assert.match(root.textContent, /pasting is disabled/i);
});

// Proves a live pending permission replaces an already-open home page; controller notification tests alone would miss the renderer ignoring an unchanged route.
test('mounted page presents incoming permission requests', async t => {
  const { root, state, page, notify } = await pageFixture(t);
  state.pendingApprovals.request = pending(); notify(); await page.refresh();
  assert.ok(button(root, 'Connect')); assert.ok(button(root, 'Reject')); assert.match(root.textContent, /site\.example/);
});

const settle = async predicate => {
  for (let turn = 0; turn < 100; turn++) { if (predicate()) return; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail('Expected page update did not arrive.');
};

// Proves the open toolbar popup (the open-wallet screen is mounted) shows an approval that arrives afterwards from the
// background notification alone, with no explicit refresh and no click: the open-wallet screen is disposed and the approval
// screen replaces it. A test that calls page.refresh() itself (as the one above does) would hide a missing notification wiring.
test('an approval arriving while the open-wallet screen is shown replaces it on the background notification', async t => {
  let disposed = 0;
  const renderOpenWallet = ({ root }) => { root.replaceChildren(new Node('div')); return { update() {}, dispose() { disposed++; } }; };
  const { root, state, notify } = await pageFixture(t, true, { renderOpenWallet });
  assert.equal(button(root, 'Connect'), undefined);
  state.pendingApprovals.request = pending(); notify();
  await settle(() => button(root, 'Connect'));
  assert.ok(button(root, 'Reject')); assert.equal(disposed, 1); assert.match(root.textContent, /site\.example/);
});

// Fake open-wallet screen: records the options of every mount and the showConnect() calls it receives.
function openWalletRecorder() {
  const mounts = [], record = { mounts, shown: 0, disposed: 0 };
  record.renderOpenWallet = options => {
    mounts.push({ startConnect: options.startConnect });
    options.root.replaceChildren(new Node('div'));
    return { update() {}, dispose() { record.disposed++; }, showConnect() { record.shown++; } };
  };
  return record;
}
const lockAndUnlock = async (state, page) => {
  state.isUnlocked = false; await page.refresh();
  state.isUnlocked = true; await page.refresh();
};

// Proves the one-shot start-on-Connect flag of the page: a `showConnect` controller notification that arrives while the page is
// LOCKED (the stopped-worker case: the tab shows the unlock form) makes the next open-wallet mount start on Connect
// (`startConnect: true`, only after the unlock); a later lock and unlock mounts the wallet as before (`false`). The unlock
// form is asserted before the notification, so a fixture that never locks cannot pass. A fake open-wallet screen: it does
// not prove the real Connect screen (ui-layout.test.js does).
test('showConnect while locked starts the next open-wallet mount on Connect, once', async t => {
  const screen = openWalletRecorder(), { root, state, notify, page } = await pageFixture(t, true, { renderOpenWallet: screen.renderOpenWallet });
  assert.deepEqual(screen.mounts, [{ startConnect: false }]);
  state.isUnlocked = false; await page.refresh(); assert.match(root.textContent, /unlock your wallet/i);
  notify('showConnect'); for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(screen.mounts.length, 1, 'nothing is mounted while locked');
  state.isUnlocked = true; await page.refresh();
  assert.deepEqual(screen.mounts, [{ startConnect: false }, { startConnect: true }]);
  await lockAndUnlock(state, page);
  assert.deepEqual(screen.mounts.at(-1), { startConnect: false }, 'the flag was consumed by the first mount');
});

// Proves a `showConnect` notification reaching a page whose wallet-and-Connect screen is mounted calls its showConnect()
// once and does not mount it again.
test('showConnect with the open-wallet screen mounted calls showConnect without a new mount', async t => {
  const screen = openWalletRecorder(), { notify } = await pageFixture(t, true, { renderOpenWallet: screen.renderOpenWallet });
  assert.equal(screen.mounts.length, 1); assert.equal(screen.shown, 0);
  notify('showConnect'); await settle(() => screen.shown === 1);
  assert.equal(screen.shown, 1); assert.equal(screen.mounts.length, 1); assert.equal(screen.disposed, 0);
});

// Proves the address query `?view=connect` makes the FIRST mount start on Connect (`window.location.search` is read by the
// page), and that this is one-shot: after a lock and unlock the wallet mounts as before. A page without the query mounts
// with `startConnect: false` (first test).
test('the address query view=connect makes the first mount start on Connect, once', async t => {
  const screen = openWalletRecorder();
  const window = Object.assign(new EventTarget(), { location: { search: '?view=connect' }, navigator: {} });
  const { state, page } = await pageFixture(t, true, { renderOpenWallet: screen.renderOpenWallet, window });
  assert.deepEqual(screen.mounts, [{ startConnect: true }]);
  await lockAndUnlock(state, page);
  assert.deepEqual(screen.mounts.at(-1), { startConnect: false });
});

// Proves the approval window does not close while the recovery-phrase step is open, even with nothing pending, and
// closes once, after the step is left. The wallet is uninitialized so the start screen is shown while an approval is
// pending; the import form is then opened, the approval goes away, and only the completed import ends the step.
test('the approval window does not close during the recovery-phrase step', async t => {
  let closed = 0;
  const { root, state, notify, phrase } = await pageFixture(t, false, { closeWhenNothingPending: () => { closed++; } });
  await settle(() => closed === 1);
  state.pendingApprovals.request = pending(); notify();
  for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
  button(root, 'Import phrase').onclick();
  state.pendingApprovals = {}; notify();
  for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, 1, 'no close request while the phrase step is open');
  const words = root.querySelectorAll('input').filter(input => input.type === 'text');
  phrase.split(' ').forEach((word, index) => { words[index].value = word; });
  for (const input of root.querySelectorAll('input[type="password"]')) input.value = 'public-test-password-123';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  await settle(() => closed === 2);
  for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, 2, 'exactly one close request after the step is left');
});

// Proves the approval window closes itself once the last approval is gone, once per empty spell, and again after a new
// approval has come and gone; and that a page mounted without the close option (toolbar popup, full page) never asks.
// The closer is a counter: the real window closing is in close-window checks below and the Chromium measurement.
test('the approval window asks to close when no approval is left, and other pages never do', async t => {
  let closed = 0;
  const { root, state, notify } = await pageFixture(t, true, { closeWhenNothingPending: () => { closed++; } });
  await settle(() => closed === 1);
  state.pendingApprovals.request = pending(); notify();
  await settle(() => button(root, 'Connect')); assert.equal(closed, 1);
  state.pendingApprovals = {}; notify();
  await settle(() => closed === 2 && !button(root, 'Connect'));
  state.preferences.autoLockTimeLimit = 5; notify();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(closed, 2);
});

// Proves only notification.html is given the closer, so the toolbar popup and the full page can never close themselves.
test('only the approval window page receives the closer', () => {
  let received;
  const close = options => { received = options; };
  assert.deepEqual(Object.keys(approvalWindowOptions('/notification.html', close)), ['closeWhenNothingPending']);
  const client = {}; approvalWindowOptions('/notification.html', close).closeWhenNothingPending(client);
  assert.equal(received.client, client, 'the closer gets the page\'s trusted client to tell the background');
  assert.deepEqual(approvalWindowOptions('/popup.html', close), {});
  assert.deepEqual(approvalWindowOptions('/home.html', close), {});
  assert.deepEqual(approvalWindowOptions(undefined, close), {});
});

// Proves the window closer: it closes a popup window (window.close, then the tab removal), leaves a normal browser
// window or tab alone, and still tries when the window type cannot be read. Fake browser and window objects only.
test('closeApprovalWindow closes only a popup window', async () => {
  const run = async windowsGetCurrent => {
    const log = [];
    const client = { async request(method) { log.push(method); } };
    const browser = { windows: { getCurrent: windowsGetCurrent }, tabs: { async getCurrent() { return { id: 7 }; }, async remove(id) { log.push(`remove ${id}`); } } };
    const result = await closeApprovalWindow({ client, browser, window: { close() { log.push('close'); } } });
    return { result, log };
  };
  const closed = ['markNotificationPopupAsAutomaticallyClosed', 'close', 'remove 7'];
  assert.deepEqual(await run(async () => ({ type: 'popup' })), { result: true, log: closed });
  assert.deepEqual(await run(async () => ({ type: 'normal' })), { result: false, log: [] });
  assert.deepEqual(await run(async () => { throw new Error('unreadable'); }), { result: true, log: closed });
});

// Proves the background is told the close is automatic before window.close() runs (the order is what keeps the removal
// from being read as the user closing the window), that nothing is sent to the background after the close attempts (a
// later message could reach it before the removal), and that a failing mark stops the close. Fakes record one shared log,
// so a call made in the wrong order or after the close shows in the list.
test('closeApprovalWindow marks the close as automatic first and sends nothing after the close', async () => {
  const log = [];
  const client = { async request(method) { log.push(method); } };
  const browser = { windows: { async getCurrent() { return { type: 'popup' }; } }, tabs: { async getCurrent() { return { id: 7 }; }, async remove() { log.push('remove'); } } };
  await closeApprovalWindow({ client, browser, window: { close() { log.push('close'); } } });
  assert.deepEqual(log, ['markNotificationPopupAsAutomaticallyClosed', 'close', 'remove']);
  // A background that cannot take the mark stops the close: nothing is closed.
  const failing = [];
  const refusing = { async request(method) { failing.push(method); throw new Error('background gone'); } };
  await assert.rejects(closeApprovalWindow({ client: refusing, browser, window: { close() { failing.push('close'); } } }), /background gone/u);
  assert.deepEqual(failing, ['markNotificationPopupAsAutomaticallyClosed']);
});

// Proves activity reconciles another window's lock without erasing password entry on the locked screen; directly refreshing in the assertion would bypass the event wiring.
test('mounted activity observes background lock and preserves unlock entry', async t => {
  const { root, navigation, state, calls } = await pageFixture(t);
  button(root, 'Settings').onclick(); state.isUnlocked = false;
  // W-42: a press re-reads the background only once released (a redraw between press and release lost the click).
  const reads = () => calls.filter(call => call.method === 'getState').length, beforePress = reads();
  document.dispatchEvent(new Event('pointerdown')); await new Promise(resolve => setImmediate(resolve));
  assert.equal(reads(), beforePress, 'a press alone does not re-read');
  document.dispatchEvent(new Event('pointerup')); t.mock.timers.tick(0); await new Promise(resolve => setImmediate(resolve)); // setTimeout is mocked (pageFixture)
  assert.match(root.textContent, /unlock your wallet/i);
  const password = root.querySelectorAll('input[type="password"]')[0]; password.value = 'typed-password';
  const previousReads = calls.filter(call => call.method === 'getState').length;
  document.dispatchEvent(new Event('input')); await new Promise(resolve => setImmediate(resolve));
  assert.equal(password.value, 'typed-password');
  assert.equal(calls.filter(call => call.method === 'getState').length, previousReads);
});

// Proves the mounted approval routes to EVM controls and the trusted id; isolated render tests miss app routing.
test('mounted page answers incoming EVM signature approvals', async t => {
  const { root, state, calls, page } = await pageFixture(t);
  state.pendingApprovals.signing = { id: 'public-signature', type: 'personal_sign', origin: 'https://site.example',
    requestData: { account, chain: 'ethereum', text: 'public signing message' } };
  await page.refresh(); assert.match(root.textContent, /public signing message/);
  await button(root, 'Approve').onclick();
  assert.deepEqual(calls.find(call => call.method === 'resolvePendingApproval').params, ['public-signature', true]);
});

// Proves Ethereum's mounted send prepares and confirms its review with Nodus also on home; selecting the first Send no longer identifies Ethereum.
test('mounted EVM send reaches prepare, review and confirm', async t => {
  const { root, calls } = await pageFixture(t);
  const ethereum = descendants(root, node => node.tagName === 'article').find(row => descendants(row, node => node.tagName === 'h2' && node.textContent === 'Ethereum').length === 1);
  const send = button(ethereum, 'Send'); assert.equal(send.disabled, false); send.onclick();
  const inputs = root.querySelectorAll('input'); inputs[0].value = account; inputs[1].value = '0.01';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.match(root.textContent, /Up to 0\.001 ETH/); await button(root, 'Confirm send').onclick();
  assert.deepEqual(calls.find(call => call.method === 'prepareEvmSend').params, [{ chain: 'ethereum', symbol: 'ETH', to: account, amount: '0.01' }]);
  assert.deepEqual(calls.find(call => call.method === 'confirmEvmSend').params, ['public-review']);
  assert.match(root.textContent, /your assets/i);
});

// Proves home actually requests both chains and renders returned rows; renderer-only tests could pass without background reads.
test('mounted home loads EVM balances through the trusted API', async t => {
  const { root, state, page, calls } = await pageFixture(t);
  state.evm = { selectedChain: 'ethereum', endpoints: {} }; await page.refresh();
  await new Promise(resolve => setImmediate(resolve));
  assert.match(root.textContent, /12\.34 ETH/); assert.match(root.textContent, /12\.34 BNB/);
  assert.deepEqual(calls.filter(call => call.method === 'getEvmBalances').map(call => call.params), [['ethereum'], ['bsc']]);
});
