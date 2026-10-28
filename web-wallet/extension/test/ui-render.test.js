import test from 'node:test';
import assert from 'node:assert/strict';
import { renderHome, renderReceive, renderConnect, renderSites, renderSettings } from '../src/ui/views.js';
import { mountWalletPage } from '../src/ui/app.js';
import { Caip25EndowmentPermissionName, getCaip25PermissionFromLegacyPermissions, setEthAccounts } from '@metamask/chain-agnostic-permission';

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

// Proves receive passes exactly the displayed address to the imported QR renderer; a nonempty SVG alone could encode a different address or URI.
test('receive QR is identical to the address shown to the user', t => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document'); globalThis.document = document;
  t.after(() => { if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
  const one = new Node('main'), two = new Node('main');
  renderReceive(document, one, 'ethereum', { ethereum: account }, () => {});
  renderReceive(document, two, 'ethereum', { ethereum: `${account}0` }, () => {});
  assert.equal(descendants(one, node => node.tagName === 'code')[0].textContent, account);
  const paths = root => descendants(root, node => node.tagName === 'path').map(node => node.attributes.d);
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

async function pageFixture(t, initialized = true) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document'); globalThis.document = document;
  const root = new Node('section'), navigation = new Node('nav'), status = new Node('p');
  document.getElementById = id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id];
  const window = Object.assign(new EventTarget(), { navigator: { clipboard: { async writeText() {} } } });
  const calls = [], phrase = 'abandon '.repeat(23) + 'art';
  const state = { isInitialized: initialized, isUnlocked: initialized, accounts: [account], addresses: { ethereum: account }, subjects: {}, pendingApprovals: {}, preferences: { autoLockTimeLimit: 15 } };
  let notification;
  const client = { onNotification: listener => { notification = listener; return () => { notification = undefined; }; }, onDisconnect: () => () => {}, close() {}, async request(method, params = []) {
    calls.push({ method, params: structuredClone(params) });
    if (method === 'getState') return structuredClone(state);
    if (method === 'getSeedPhrase') return [...new TextEncoder().encode(phrase)];
    if (method === 'createNewVaultAndRestore') state.isInitialized = true;
    if (method === 'submitPasswordOrEncryptionKey') state.isUnlocked = true;
    if (method === 'prepareEvmSend') return { id: 'public-review', ...params[0], fee: 'Up to 0.001 ETH' };
    if (method === 'confirmEvmSend') return 'public-transaction-hash';
    if (method === 'getEvmBalances') return [{ symbol: params[0] === 'ethereum' ? 'ETH' : 'BNB', balance: '12.34' }];
    return null;
  } };
  const page = await mountWalletPage({ document, window, client });
  t.after(() => { page.dispose(); if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
  return { root, navigation, status, calls, state, page, phrase, notify: () => notification?.({ method: 'messengerSubscription' }) };
}

// Proves the mounted page keeps authenticated words visible until expiry and removes them on lock; testing renderSettings alone would miss the action wrapper clearing or retaining secrets.
test('mounted reveal survives its response and is cleared on background lock', async t => {
  const { root, navigation, calls, state, page, phrase } = await pageFixture(t);
  button(navigation, 'Settings').onclick();
  const password = root.querySelectorAll('input[type="password"]')[0]; password.value = 'fresh-password';
  document.dispatchEvent(new Event('input'));
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(calls.find(call => call.method === 'getSeedPhrase').params, ['fresh-password']);
  assert.equal(root.querySelectorAll('input').filter(input => input.readOnly).map(input => input.value).join(' '), phrase);
  state.isUnlocked = false; await page.refresh();
  assert.equal(root.querySelectorAll('input').some(input => input.value), false); assert.match(root.textContent, /unlock your wallet/i);
});

// Proves the ten-minute recovery timeout remains active with auto-lock disabled; a default fifteen-minute wallet timer could otherwise hide missing secret cleanup.
test('mounted reveal clears after ten idle minutes even when auto-lock is never', async t => {
  const { root, navigation, state } = await pageFixture(t); state.preferences.autoLockTimeLimit = 0;
  button(navigation, 'Settings').onclick(); root.querySelectorAll('input[type="password"]')[0].value = 'fresh-password';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  t.mock.timers.tick(10 * 60_000);
  assert.equal(root.querySelectorAll('input').some(input => input.value), false);
});

// Proves the actual import form reaches save and unlock with 24 entered words; controller-only tests would miss missing form submission or password plumbing.
test('mounted import form saves through the trusted API and renders home', async t => {
  const { root, calls, phrase } = await pageFixture(t, false);
  button(root, 'Import phrase').onclick();
  const words = root.querySelectorAll('input').filter(input => input.type === 'text');
  phrase.split(' ').forEach((word, index) => { words[index].value = word; });
  for (const input of root.querySelectorAll('input[type="password"]')) input.value = 'public-test-password-123';
  await descendants(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.ok(calls.some(call => call.method === 'createNewVaultAndRestore')); assert.ok(calls.some(call => call.method === 'submitPasswordOrEncryptionKey'));
  assert.match(root.textContent, /your wallet/i); assert.equal(root.querySelectorAll('input').length, 0);
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

// Proves activity reconciles another window's lock without erasing password entry on the locked screen; directly refreshing in the assertion would bypass the event wiring.
test('mounted activity observes background lock and preserves unlock entry', async t => {
  const { root, navigation, state, calls } = await pageFixture(t);
  button(navigation, 'Settings').onclick(); state.isUnlocked = false;
  document.dispatchEvent(new Event('pointerdown')); await new Promise(resolve => setImmediate(resolve));
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
  assert.match(root.textContent, /your wallet/i);
});

// Proves home actually requests both chains and renders returned rows; renderer-only tests could pass without background reads.
test('mounted home loads EVM balances through the trusted API', async t => {
  const { root, state, page, calls } = await pageFixture(t);
  state.evm = { selectedChain: 'ethereum', endpoints: {} }; await page.refresh();
  await new Promise(resolve => setImmediate(resolve));
  assert.match(root.textContent, /12\.34 ETH/); assert.match(root.textContent, /12\.34 BNB/);
  assert.deepEqual(calls.filter(call => call.method === 'getEvmBalances').map(call => call.params), [['ethereum'], ['bsc']]);
});
