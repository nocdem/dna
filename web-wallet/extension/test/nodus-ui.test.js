import test from 'node:test';
import assert from 'node:assert/strict';
import { renderNodusSend, renderNodusHistory, renderNodusContracts } from '../src/ui/nodus-screens.js';
import { renderHome } from '../src/ui/views.js';
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
  querySelectorAll(selector) { return find(this, node => node.tagName === 'input' && (selector === 'input' || node.type === 'password')); }
  querySelector() { return null; }
}
const document = { createElement: tag => new Node(tag) };
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
test('Nodus send uses explicit token identity and the decoded web-wallet review', async () => {
  const root = new Node('main'), prepared = [], confirmed = [];
  const actions = { prepare: fields => prepared.push(fields), confirm: id => confirmed.push(id), cancel() {} };
  renderNodusSend(document, root, { account: address, tokens: [] }, actions);
  const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = address; inputs[1].value = '1';
  await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(prepared, [{ to: address, amount: '1', tokenId: NODUS_TOKEN_ID }]);
  renderNodusSend(document, root, { account: address, review: { id: '7', review: [['To', address], ['Network fee', '0.1 NODUS'], ['Valid until block', '100'], ['Name check', '<img src=x>']] } }, actions);
  for (const text of [address, '0.1 NODUS', '100', '<img src=x>']) assert.ok(root.textContent.includes(text));
  assert.equal(find(root, node => node.tagName === 'img').length, 0);
  await button(root, 'Confirm send').onclick(); assert.deepEqual(confirmed, ['7']);
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
  state = { isUnlocked: true, addresses: { nodus: address } }; await ui.refresh(); await ui.loadNodusHistory();
  for (const method of ['getNodusBalances', 'getCpunkBalance', 'prepareNodusSend', 'confirmNodusSend', 'cancelNodusSend', 'getNodusHistory', 'resubmitNodusSend', 'readNodusContract', 'prepareNodusContract']) assert.ok(calls.some(([name]) => name === method));
});

// Pins mounted app navigation from returned balances through Nodus prepare/confirm/cancel and account history.
test('the mounted wallet routes Nodus screens through the trusted background methods', async t => {
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
    if (method === 'prepareNodusSend') return { id: 'mounted-review', review: [['To', address], ['Network fee', '0.1 NODUS']] };
    if (method === 'confirmNodusSend') return address;
    if (method === 'getNodusHistory') return { rows: [], local: [], status: 'Newest entries as reported by one Nodus node.' };
    return null;
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  await new Promise(resolve => setImmediate(resolve)); assert.ok(root.textContent.includes('3.0 NODUS'));
  async function prepare() {
    button(root, 'Send').onclick();
    const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = address; inputs[1].value = '1';
    await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    assert.ok(root.textContent.includes('0.1 NODUS'));
  }
  await prepare(); button(root, 'Cancel').onclick();
  assert.ok(calls.some(([method, params]) => method === 'cancelNodusSend' && params[0] === 'mounted-review'));
  await prepare(); await button(root, 'Confirm send').onclick();
  assert.ok(calls.some(([method, params]) => method === 'confirmNodusSend' && params[0] === 'mounted-review'));
  button(root, 'History').onclick(); await new Promise(resolve => setImmediate(resolve));
  assert.ok(root.textContent.includes('one Nodus node'));
  assert.equal(calls.some(([method]) => method === 'prepareEvmSend'), false);
});
