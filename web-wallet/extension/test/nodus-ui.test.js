import test from 'node:test';
import assert from 'node:assert/strict';
import { renderNodusSend, renderNodusHistory, renderNodusContracts } from '../src/ui/nodus-screens.js';
import { renderHome, renderSettings } from '../src/ui/views.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { NODUS_TOKEN_ID } from '../../src/nodus/network.js';
import { mountWalletPage } from '../src/ui/app.js';

// Minimal DOM fixture: records displayed text and invokes actual renderer handlers.
class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this.text = ''; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); }
  querySelectorAll(selector) { return find(this, node => node.tagName === 'input' && (selector === 'input' || node.type === 'password')); }
  querySelector() { return null; }
}
const document = { createElement: tag => new Node(tag), createElementNS: (_ns, tag) => new Node(tag) };
const find = (root, predicate) => [...(predicate(root) ? [root] : []), ...root.children.flatMap(child => find(child, predicate))];
const button = (root, text) => find(root, node => node.tagName === 'button' && node.textContent === text)[0];
const address = 'ab'.repeat(64);

// Pins real address/balance display and receive-only CPUNK alongside Nodus Send and History controls.
test('home displays Nodus and CPUNK values returned by the background', () => {
  const root = new Node('main'), sent = [], history = [];
  renderHome(document, root, { addresses: { nodus: address, cpunk: 'public-cpunk-address' }, nodus: { state: 'ready' },
    nodusBalances: [{ symbol: 'NODUS', balance: '12.34' }], cpunkBalance: { balance: '0.75' } }, () => {}, chain => sent.push(chain), () => {}, () => history.push('nodus'));
  assert.ok(root.textContent.includes(address)); assert.ok(root.textContent.includes('12.34 NODUS')); assert.ok(root.textContent.includes('0.75 CPUNK'));
  const rows = find(root, node => node.tagName === 'article');
  assert.equal(find(rows.at(-1), node => node.tagName === 'button' && node.textContent === 'Send').length, 0);
  button(rows[0], 'Send').onclick(); button(rows[0], 'History').onclick();
  assert.deepEqual(sent, ['nodus']); assert.deepEqual(history, ['nodus']);
});

// Pins the native/token form identity and renders every module-decoded review row as text before confirming its id.
test('Nodus send uses explicit token identity and the decoded web-wallet review', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), prepared = [], confirmed = [];
  const actions = { prepare: fields => prepared.push(fields), confirm: id => confirmed.push(id), cancel() {} };
  renderNodusSend(document, root, { account: address, tokens: [] }, actions);
  const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = address; inputs[1].value = '1';
  await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(prepared, [{ to: address, amount: '1', tokenId: NODUS_TOKEN_ID }]);
  const expiresAt = Date.now() + 60000;
  const stop = renderNodusSend(document, root, { account: address, review: { id: '7', expiresAt, review: [['To', address], ['Network fee', '0.1 NODUS'], ['Valid until block', '100'], ['Name check', '<img src=x>']] } }, actions);
  t.after(stop);
  for (const text of [address, '0.1 NODUS', '100', '<img src=x>']) assert.ok(root.textContent.includes(text));
  assert.equal(find(root, node => node.tagName === 'img').length, 0);
  assert.ok(root.textContent.includes('Review expires')); assert.ok(root.textContent.includes(new Date(expiresAt).toLocaleTimeString()));
  assert.equal(button(root, 'Confirm send').disabled, true);
  await button(root, 'Confirm send').onclick(); assert.deepEqual(confirmed, []);
  t.mock.timers.tick(599); assert.equal(button(root, 'Confirm send').disabled, true);
  t.mock.timers.tick(1); assert.equal(button(root, 'Confirm send').disabled, false);
  await button(root, 'Confirm send').onclick(); assert.deepEqual(confirmed, ['7']);
});

// Pins src/evm/ui.js showReview: decoded rows only and immediate confirmation, with both controls disabled while sending.
test('contract reviews confirm immediately without a transfer expiry row', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), confirmed = [], cancelled = [], expiresAt = Date.now() + 60000;
  renderNodusContracts(document, root, { review: { id: 'contract-review', expiresAt, review: [['Amount', '1 NODUS']] } },
    { confirm: id => confirmed.push(id), cancel: () => cancelled.push(true) });
  assert.ok(root.textContent.includes('1 NODUS')); assert.equal(root.textContent.includes('Review expires'), false);
  assert.equal(root.textContent.includes(new Date(expiresAt).toLocaleTimeString()), false);
  const confirm = button(root, 'Confirm & send'); assert.equal(confirm.disabled, false);
  await confirm.onclick(); assert.deepEqual(confirmed, ['contract-review']);
  assert.equal(confirm.disabled, true); assert.equal(button(root, 'Cancel').disabled, true);
  t.mock.timers.tick(600); assert.equal(confirm.disabled, true);
  await confirm.onclick(); assert.deepEqual(confirmed, ['contract-review']); assert.deepEqual(cancelled, []);
});

// Proves recovery is visible in settings for either unreadable files or quarantined rows and invokes explicit discard.
test('settings offer discard only when saved activity needs recovery', () => {
  const root = new Node('main'), discarded = [];
  for (const nodus of [{ activityError: 'Saved activity authentication failed.' }, { quarantinedCount: 1 }, {}]) {
    renderSettings(document, root, { preferences: { autoLockTimeLimit: 15 }, nodus }, { discardActivity: () => discarded.push('discard') });
    const discard = button(root, 'Discard unreadable history');
    if (nodus.activityError || nodus.quarantinedCount) {
      assert.ok(root.textContent.includes('Check the explorer')); discard.onclick();
    } else assert.equal(discard, undefined);
  }
  assert.deepEqual(discarded, ['discard', 'discard']);
});

// Pins history status, local pending sends and explicit retry controls without hiding a node read error.
test('history shows node provenance, read failures and pending local sends', () => {
  const root = new Node('main'), retried = [];
  renderNodusHistory(document, root, { rows: [{ title: 'Received', sign: '+', amount: '1 NODUS', detail: 'from public peer', height: '9' }],
    status: 'Newest entries as reported by one Nodus node.', local: [{ hash: address, amount: '2', symbol: 'NODUS', status: 'pending', note: 'Network busy.', canResubmit: true }] },
  { refresh() {}, resubmit: hash => retried.push(hash) });
  assert.ok(root.textContent.includes('one Nodus node')); assert.ok(root.textContent.includes('Received')); assert.ok(root.textContent.includes('Network busy.'));
  button(root, 'Try again').onclick(); assert.deepEqual(retried, [address]);
  renderNodusHistory(document, root, { rows: [], local: [], error: 'fixture node unavailable' }, { refresh() {}, resubmit() {} });
  assert.ok(root.textContent.includes('fixture node unavailable'));
});

// Pins contract forms to the web-wallet bridge/ABI actions and displays returned results without interpreting contract data as markup.
test('smart-contract forms route bridge and contract requests with their original arguments', async () => {
  const root = new Node('main'), prepared = [], reads = [];
  renderNodusContracts(document, root, { account: address, readable: true, buildable: true, result: '<img src=x>' },
    { prepare: fields => prepared.push(fields), read: fields => reads.push(fields), confirm() {}, cancel() {} });
  assert.ok(root.textContent.includes('<img src=x>')); assert.equal(find(root, node => node.tagName === 'img').length, 0);
  button(root, 'Read account').onclick(); assert.deepEqual(reads, [{ action: 'account' }]);
  const bridge = find(root, node => node.tagName === 'form')[0];
  const inputs = find(bridge, node => node.tagName === 'input'); inputs[0].value = '1';
  await bridge.onsubmit({ preventDefault() {} }); assert.equal(prepared[0].action, 'deposit'); assert.equal(prepared[0].amount, '1');
  const contract = find(root, node => node.tagName === 'form')[1];
  await contract.onsubmit({ preventDefault() {} }); assert.equal(reads[1].action, 'read'); assert.equal(reads[1].args, '[]');
});

// Pins trusted request wiring and clears late Nodus/CPUNK reads when the background reports lock.
test('wallet UI routes Nodus requests and discards balances from a locked session', async () => {
  let state = { isUnlocked: true, addresses: { nodus: address }, nodus: { state: 'ready' } }, release;
  const calls = [], client = { async request(method, params = []) {
    calls.push([method, params]);
    if (method === 'getState') return state;
    if (method === 'getNodusBalances') return new Promise(resolve => { release = resolve; });
    if (method === 'getCpunkBalance') return { balance: '1' };
    if (method === 'getNodusHistory') return { rows: [], local: [], status: 'one Nodus node' };
    return method === 'prepareNodusSend' ? { id: '9' } : 'public-result';
  } };
  const ui = createWalletUi(client); await ui.refresh();
  const loading = ui.loadNodusBalances();
  state = { isUnlocked: false, addresses: {} }; await ui.refresh(); release([{ symbol: 'NODUS', balance: '3' }]); await loading;
  assert.equal(ui.state.nodusBalances, null); assert.equal(ui.state.cpunkBalance, null);
  await ui.prepareNodusSend({ to: address, amount: '1', tokenId: NODUS_TOKEN_ID });
  await ui.confirmNodusSend('9'); await ui.cancelNodusSend('9'); await ui.resubmitNodusSend(address);
  await ui.readNodusContract({ action: 'account' }); await ui.prepareNodusContract({ action: 'deposit', amount: '1' });
  await ui.discardNodusActivity();
  state = { isUnlocked: true, addresses: { nodus: address } }; await ui.refresh(); await ui.loadNodusHistory();
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'prepareNodusSend', 'confirmNodusSend', 'cancelNodusSend', 'getNodusHistory', 'resubmitNodusSend', 'readNodusContract', 'prepareNodusContract', 'discardNodusActivity']) assert.ok(calls.some(([name]) => name === method));
});

// Pins mounted app navigation from returned balances through Nodus prepare/confirm/cancel and account history.
test('the mounted wallet routes Nodus screens through the trusted background methods', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p'), calls = [];
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses: { nodus: address }, nodus: { state: 'ready', tokens: [] },
    preferences: { autoLockTimeLimit: 15 }, pendingApprovals: {} };
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method, params = []) {
    calls.push([method, params]);
    if (method === 'getState') return structuredClone(state);
    if (method === 'getNodusBalances') return [{ symbol: 'NODUS', balance: '3.0' }];
    if (method === 'getCpunkBalance') return { balance: '0.25' };
    if (method === 'prepareNodusSend') return { id: 'mounted-review', expiresAt: Date.now() + 60000, review: [['To', address], ['Network fee', '0.1 NODUS']] };
    if (method === 'confirmNodusSend') return address;
    if (method === 'getNodusHistory') return { rows: [], local: [], status: 'Newest entries as reported by one Nodus node.' };
    return null;
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  await new Promise(resolve => setImmediate(resolve));
  // src/portfolio-view.js:193-194: trim display zeroes, retain the exact amount on hover.
  const amounts = find(root, node => node.tagName === 'strong' && node.title === '3.0 NODUS');
  assert.equal(amounts.length, 1); assert.equal(amounts[0].textContent, '3 NODUS');
  async function prepare() {
    button(root, 'Send').onclick();
    const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = address; inputs[1].value = '1';
    await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    assert.ok(root.textContent.includes('0.1 NODUS'));
  }
  await prepare(); button(root, 'Cancel').onclick();
  assert.ok(calls.some(([method, params]) => method === 'cancelNodusSend' && params[0] === 'mounted-review'));
  await prepare(); assert.equal(button(root, 'Confirm send').disabled, true);
  t.mock.timers.tick(600); await button(root, 'Confirm send').onclick();
  assert.ok(calls.some(([method, params]) => method === 'confirmNodusSend' && params[0] === 'mounted-review'));
  await button(root, 'History').onclick();
  assert.ok(root.textContent.includes('one Nodus node'));
  assert.equal(calls.some(([method]) => method === 'prepareEvmSend'), false);
});

// Pins contract errors to src/evm/ui.js: keep the decoded review, display the exact message and offer Close without the transfer note.
test('mounted contract confirm errors keep the review with its message and Close button', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p'), calls = [];
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses: { nodus: address }, nodus: { state: 'ready', tokens: [], evmBuildable: true, evmReadable: true },
    preferences: { autoLockTimeLimit: 0 }, pendingApprovals: {} };
  let tracked = true;
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method, params = []) {
    calls.push([method, params]);
    if (method === 'getState') return structuredClone(state);
    if (method === 'getNodusBalances') return []; if (method === 'getCpunkBalance') return { balance: '1' };
    if (method === 'prepareNodusContract') return { id: 'failed-contract', expiresAt: Date.now() + 60000, review: [['Amount', '1 NODUS']] };
    if (method === 'confirmNodusSend') throw Object.assign(new Error('fixture contract failure'), { data: { activityTracked: tracked } });
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  for (const hasRecord of [true, false]) {
    tracked = hasRecord; button(root, 'Smart contracts').onclick();
    await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    assert.equal(root.textContent.includes('Review expires'), false);
    assert.equal(button(root, 'Confirm & send').disabled, false);
    await button(root, 'Confirm & send').onclick();
    assert.ok(root.textContent.includes('1 NODUS'));
    assert.ok(find(root, node => node.tagName === 'p' && node.textContent === 'fixture contract failure').length);
    assert.equal(`${root.textContent}${status.textContent}`.includes('tracked in Activity'), false);
    assert.equal(button(root, 'Confirm & send').disabled, true); assert.equal(button(root, 'Close').disabled, false);
    const attempts = calls.filter(([method]) => method === 'confirmNodusSend').length;
    await button(root, 'Confirm & send').onclick();
    assert.equal(calls.filter(([method]) => method === 'confirmNodusSend').length, attempts);
    button(root, 'Close').onclick();
    assert.equal(button(root, 'Close'), undefined); assert.ok(button(root, 'Review transaction'));
    button(navigation, 'Home').onclick();
  }
  assert.equal(calls.some(([method]) => method === 'getNodusHistory'), false);
});

// Proves failed confirmation closes the review, stays on the send form and preserves the original error plus Activity tracking note.
test('mounted Nodus confirm errors close review and show the tracked outcome without opening history', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p'), calls = [];
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses: { nodus: address }, nodus: { state: 'ready', tokens: [], activityError: 'Unreadable activity.' },
    preferences: { autoLockTimeLimit: 0 }, pendingApprovals: {} };
  let tracked = true;
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method) {
    calls.push(method);
    if (method === 'getState') return structuredClone(state);
    if (method === 'getNodusBalances') return [{ symbol: 'NODUS', balance: '3' }];
    if (method === 'getCpunkBalance') return { balance: '1' };
    if (method === 'prepareNodusSend') return { id: 'failed-review', expiresAt: Date.now() + 60000, review: [['To', address]] };
    if (method === 'confirmNodusSend') throw Object.assign(new Error('fixture confirm failure'), { data: { activityTracked: tracked } });
    if (method === 'discardNodusActivity') { state.nodus.activityError = ''; return 'Unreadable local history discarded.'; }
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  for (const hasRecord of [true, false]) {
    tracked = hasRecord; button(root, 'Send').onclick();
    const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = address; inputs[1].value = '1';
    await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    t.mock.timers.tick(600); await button(root, 'Confirm send').onclick();
    assert.equal(button(root, 'Confirm send'), undefined); assert.ok(button(root, 'Review transfer'));
    assert.ok(status.textContent.includes('fixture confirm failure'));
    assert.equal(status.textContent.includes('The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.'), hasRecord);
    assert.equal(calls.includes('getNodusHistory'), false);
    button(navigation, 'Home').onclick();
  }
  button(root, 'Settings').onclick(); await button(root, 'Discard unreadable history').onclick();
  assert.ok(calls.includes('discardNodusActivity')); assert.ok(status.textContent.includes('Unreadable local history discarded.'));
  assert.equal(button(root, 'Discard unreadable history'), undefined);
});

// Proves locking or disposing a mounted review cancels its enable timer; mock time never enables a detached confirm button.
test('mounted Nodus review timer stops on lock and disposal', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p');
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses: { nodus: address }, nodus: { state: 'ready', tokens: [] }, preferences: { autoLockTimeLimit: 0 }, pendingApprovals: {} };
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method) {
    if (method === 'getState') return structuredClone(state);
    if (method === 'prepareNodusSend') return { id: 'closing-review', expiresAt: Date.now() + 60000, review: [['To', address]] };
    if (method === 'getNodusBalances') return []; if (method === 'getCpunkBalance') return { balance: '1' };
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  for (const closing of ['lock', 'dispose']) {
    state.isUnlocked = true; await page.refresh(); button(root, 'Send').onclick();
    await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    const confirm = button(root, 'Confirm send'); assert.equal(confirm.disabled, true);
    if (closing === 'lock') { state.isUnlocked = false; await page.refresh(); } else page.dispose();
    t.mock.timers.tick(600); assert.equal(confirm.disabled, true);
  }
});
