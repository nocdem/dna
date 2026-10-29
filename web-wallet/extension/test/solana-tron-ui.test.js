import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSolanaTronSend, renderSolanaTronHistory } from '../src/ui/solana-tron-screens.js';
import { renderHome, renderReceive, renderSettings } from '../src/ui/views.js';
import { displayAmount } from '../../src/portfolio.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { mountWalletPage } from '../src/ui/app.js';
import { CHAINS } from '../../src/config.js';

// Node >=22.14, no flags, no network or files. A minimal DOM records text and
// invokes real handlers. Assertions include routing/data, not just labels.
class Node extends EventTarget {
  constructor(tag) { super(); this.tagName = tag; this.children = []; this.text = ''; this.value = ''; this.attributes = {}; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  querySelectorAll(selector) { return find(this, n => n.tagName === 'input' && (selector === 'input' || n.type === 'password')); }
  querySelector() { return null; }
}
const document = { createElement: tag => new Node(tag), createElementNS: (_ns, tag) => new Node(tag) };
const find = (node, predicate) => node.children.flatMap(child => [...(predicate(child) ? [child] : []), ...find(child, predicate)]);
const button = (node, text) => find(node, n => n.tagName === 'button' && n.textContent === text)[0];
const addresses = { solana: '4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS', tron: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' };
const reviewFor = chain => ({ id: `${chain}-review`, expiresAt: Date.now() + 45000, review: [
  ['Network', `${CHAINS[chain].name} mainnet`], ['From', addresses[chain]], ['To', '<img src=x onerror=alert(1)>'],
  ['Asset', 'USDT'], ['Amount', '1'], ['Network fee', 'fee from adapter'],
] });

// Exact option lists and handlers prevent a label-only settings implementation
// from passing. The home assertion covers the operator's no-top-button rule.
test('settings lists each chain separately and home names non-mainnet networks without a switch button', () => {
  const root = new Node('main'), selections = [];
  const networks = { nodus: 'testnet', ethereum: 'mainnet', bsc: 'mainnet', solana: 'devnet', tron: 'nile', cellframe: 'mainnet' };
  renderSettings(document, root, { networks, preferences: { autoLockTimeLimit: 15 } }, {
    setChainNetwork: (chain, network) => selections.push([chain, network]),
  });
  const options = { nodus: ['Testnet'], ethereum: ['Mainnet'], bsc: ['Mainnet'], solana: ['Mainnet', 'Testnet', 'Devnet'], tron: ['Mainnet', 'Nile'], cellframe: ['Mainnet'] };
  for (const [chain, labels] of Object.entries(options)) {
    const selector = find(root, n => n.id === `network-${chain}`)[0];
    assert.ok(selector, chain); assert.deepEqual(selector.children.map(n => n.textContent), labels);
    assert.equal(selector.value, networks[chain]);
    assert.ok(selector.children.every(n => !n.disabled));
    selector.value = chain === 'solana' ? 'testnet' : networks[chain]; selector.onchange();
  }
  assert.ok(selections.some(([chain, network]) => chain === 'solana' && network === 'testnet'));
  renderHome(document, root, { addresses, networks }, () => {}, () => {});
  for (const text of ['Nodus · Testnet', 'Solana · Devnet', 'TRON · Nile']) assert.ok(root.textContent.includes(text), text);
  assert.equal(find(root, n => n.tagName === 'select').length, 0);
  assert.equal(find(root, n => n.tagName === 'button' && /network|mainnet|testnet/i.test(n.textContent)).length, 0);
});

test('history formats amounts and peer addresses like the web wallet and uses only the selected network explorer', () => {
  for (const [chain, network, expected] of [['solana', 'devnet', null], ['tron', 'nile', 'https://nile.tronscan.org/#/transaction/']]) {
    const root = new Node('main'), hash = chain === 'solana' ? '2'.repeat(88) : 'ab'.repeat(32), amount = '1234567.123456789';
    renderSolanaTronHistory(document, root, { chain, history: { network, rows: [
      { chain, hash, amount, symbol: CHAINS[chain].symbol, peer: addresses[chain], dir: 'out', status: 'confirmed', time: 1700000000000 },
    ], local: [] } }, { refresh() {} });
    assert.ok(root.textContent.includes(`−${displayAmount(amount)} ${CHAINS[chain].symbol}`));
    assert.ok(root.textContent.includes(`to ${addresses[chain].slice(0, 8)}…${addresses[chain].slice(-6)}`));
    assert.equal(root.textContent.includes(addresses[chain]), false);
    const links = find(root, n => n.tagName === 'a');
    if (expected) assert.deepEqual(links.map(n => n.href), [expected + hash]);
    else { assert.equal(links.length, 0); assert.ok(root.textContent.includes(hash)); }
  }
});

test('changing one network drops and re-reads only that chain and ignores its delayed old reads', async () => {
  const state = { isUnlocked: true, addresses, networks: { solana: 'mainnet', tron: 'mainnet' } }, calls = [];
  let finish;
  const client = { async request(method, params = []) {
    calls.push([method, params]);
    if (method === 'getState') return structuredClone(state);
    if (method === 'setChainNetwork') { state.networks[params[0]] = params[1]; return; }
    if (method === 'getSolanaBalances' && !finish) return new Promise(resolve => { finish = resolve; });
    if (method.endsWith('Balances')) return [{ symbol: method.includes('Solana') ? 'SOL' : 'TRX', balance: '2' }];
    if (method.endsWith('History')) return { network: state.networks[method.includes('Solana') ? 'solana' : 'tron'], rows: [], local: [] };
  } };
  const ui = createWalletUi(client); await ui.refresh();
  const reading = ui.loadSolanaTronBalances();
  await ui.loadSolanaTronHistory('tron');
  const tronHistory = ui.state.solanaTronHistory.tron;
  await ui.setChainNetwork('solana', 'devnet');
  finish([{ symbol: 'SOL', balance: '999' }]); await reading;
  assert.equal(ui.state.solanaTronBalances.solana[0].balance, '2');
  assert.equal(ui.state.solanaTronHistory.solana.network, 'devnet');
  assert.deepEqual(ui.state.solanaTronHistory.tron, tronHistory);
  assert.equal(calls.filter(([method]) => method === 'getTronHistory').length, 1);
});

// Mounted settings and another window's selection use the real UI wiring;
// a renderer-only test would miss an uncancelled review timer or stale page.
test('mounted settings route selection and a network notification closes the old review', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p'), calls = [];
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses, preferences: { autoLockTimeLimit: 0 }, pendingApprovals: {},
    networks: { solana: 'mainnet', tron: 'mainnet' } };
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method, params = []) {
    calls.push([method, params]);
    if (method === 'getState') return structuredClone(state);
    if (method === 'setChainNetwork') { state.networks[params[0]] = params[1]; return; }
    if (method.endsWith('Balances')) return [];
    if (method.endsWith('History')) return { network: state.networks.solana, rows: [], local: [] };
    if (method === 'prepareSolanaSend') return { ...reviewFor('solana'), network: state.networks.solana };
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  // This minimal-DOM mount uses the fallback adapter: session actions and
  // section buttons are separate. ui-layout.test.js pins the production tiles.
  assert.deepEqual(find(navigation, n => n.tagName === 'button').map(n => n.textContent), ['Lock']);
  assert.deepEqual(find(root, n => n.className === 'extension-section').map(n => n.textContent), ['Connected sites', 'Settings']);
  button(root, 'Settings').onclick();
  assert.deepEqual(find(navigation, n => n.tagName === 'button').map(n => n.textContent), ['Home', 'Lock']);
  const selector = find(root, n => n.id === 'network-solana')[0]; selector.value = 'devnet'; await selector.onchange();
  assert.ok(calls.some(([method, params]) => method === 'setChainNetwork' && params[0] === 'solana' && params[1] === 'devnet'));
  assert.ok(calls.some(([method]) => method === 'getSolanaHistory'));
  button(navigation, 'Home').onclick();
  const row = find(root, n => n.tagName === 'article' && n.textContent.includes(addresses.solana))[0];
  button(row, 'Send').onclick();
  assert.deepEqual(find(root, n => n.id === 'evm-send-asset')[0].children.map(n => n.value), ['SOL']);
  await find(root, n => n.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  const confirm = button(root, 'Confirm send');
  state.networks.solana = 'testnet'; await page.refresh(); t.mock.timers.tick(600);
  assert.equal(confirm.disabled, true); assert.equal(button(root, 'Confirm send'), undefined);
  assert.ok(calls.some(([method, params]) => method === 'cancelSolanaSend' && params[0] === 'solana-review'));
});

test('home rows show returned balances/errors and route Send Receive History by chain', () => {
  const root = new Node('main'), actions = [];
  renderHome(document, root, { addresses, solanaTronBalances: {
    solana: [{ symbol: 'SOL', balance: '9.25' }, { symbol: 'USDC', error: 'Balance unavailable' }], tron: { error: 'fixture TRON unavailable' },
  } }, c => actions.push(['receive', c]), c => actions.push(['send', c]), () => {}, () => {}, () => {}, c => actions.push(['history', c]));
  const rows = find(root, n => n.tagName === 'article');
  for (const chain of ['solana', 'tron']) {
    const row = rows.find(n => n.textContent.includes(addresses[chain]));
    for (const label of ['Send', 'Receive', 'History']) button(row, label).onclick();
  }
  assert.ok(root.textContent.includes('9.25 SOL')); assert.ok(root.textContent.includes('USDC: Balance unavailable'));
  assert.ok(root.textContent.includes('fixture TRON unavailable'));
  assert.deepEqual(actions, ['solana', 'tron'].flatMap(c => [['send', c], ['receive', c], ['history', c]]));
});

test('send forms list exactly the web assets; reviews show every returned field as text', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const chain of ['solana', 'tron']) {
    const root = new Node('main'), prepared = [], confirmed = [];
    const actions = { prepare: f => prepared.push(f), confirm: id => confirmed.push(id), cancel() {} };
    renderSolanaTronSend(document, root, { chain, account: addresses[chain] }, actions);
    const select = find(root, n => n.tagName === 'select')[0];
    assert.deepEqual(select.children.map(n => n.value), [CHAINS[chain].symbol, ...CHAINS[chain].tokens.map(t => t.symbol)]);
    select.value = 'USDT'; const inputs = find(root, n => n.tagName === 'input'); inputs[0].value = addresses[chain]; inputs[1].value = '1';
    await find(root, n => n.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    assert.deepEqual(prepared, [{ chain, symbol: 'USDT', to: addresses[chain], amount: '1' }]);
    const review = reviewFor(chain), stop = renderSolanaTronSend(document, root, { chain, review }, actions);
    for (const [label, value] of review.review) { assert.ok(root.textContent.includes(label)); assert.ok(root.textContent.includes(value)); }
    assert.ok(root.textContent.includes(new Date(review.expiresAt).toLocaleTimeString()));
    assert.equal(find(root, n => n.tagName === 'img').length, 0);
    const confirm = button(root, 'Confirm send'); await confirm.onclick(); assert.deepEqual(confirmed, []);
    t.mock.timers.tick(600); await confirm.onclick(); await confirm.onclick(); assert.deepEqual(confirmed, [review.id]);
    stop();
  }
});

test('receive copies the raw chain address and draws its QR with the existing renderer', t => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document'); globalThis.document = document;
  t.after(() => { if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
  const paths = [];
  for (const chain of ['solana', 'tron']) {
    const root = new Node('main'), copied = [];
    renderReceive(document, root, chain, addresses, address => copied.push(address));
    button(root, 'Copy').onclick(); assert.deepEqual(copied, [addresses[chain]]);
    assert.equal(find(root, n => n.tagName === 'code')[0].textContent, addresses[chain]);
    paths.push(find(find(root, n => n.className === 'receive-qr')[0], n => n.tagName === 'path')[0].attributes.d);
  }
  assert.notEqual(paths[0], paths[1]);
});

test('history keeps source errors and local outcomes visible with chain explorer links', () => {
  for (const chain of ['solana', 'tron']) {
    const root = new Node('main'), refreshes = [], hash = chain === 'solana' ? '2'.repeat(88) : 'ab'.repeat(32);
    renderSolanaTronHistory(document, root, { chain, history: { error: '<img src=x>', status: 'source read status',
      local: [{ hash, to: addresses[chain], amount: '2', symbol: CHAINS[chain].symbol, status: 'unknown', note: 'Broadcast outcome uncertain.', createdAt: '2026-10-28T00:00:00Z' }],
      rows: [{ chain, hash, amount: '1', symbol: 'USDT', status: 'confirmed', dir: 'in', peer: addresses[chain], time: 1700000000000 }],
    } }, { refresh: () => refreshes.push(chain) });
    for (const text of ['<img src=x>', 'Broadcast outcome uncertain.', '1 USDT', '2 ' + CHAINS[chain].symbol, hash]) assert.ok(root.textContent.includes(text));
    assert.equal(find(root, n => n.tagName === 'img').length, 0);
    for (const link of find(root, n => n.tagName === 'a')) assert.equal(link.href, CHAINS[chain].explorer + encodeURIComponent(hash));
    button(root, 'Refresh history').onclick(); assert.deepEqual(refreshes, [chain]);
  }
});

test('UI balance/history reads discard results that cross lock and route chain sends through trusted methods', async () => {
  const state = { isUnlocked: true, addresses }, calls = []; let finish, finishHistory, pauseHistory = false;
  const client = { async request(method, params = []) {
    calls.push([method, params]); if (method === 'getState') return structuredClone(state);
    if (method === 'getSolanaBalances') return new Promise(resolve => { finish = resolve; });
    if (method === 'getTronBalances') return [{ symbol: 'TRX', balance: '2' }];
    if (method === 'getSolanaHistory' && pauseHistory) return new Promise(resolve => { finishHistory = resolve; });
    if (method.endsWith('History')) return { rows: [], local: [] };
    return { id: 'public-review' };
  } };
  const ui = createWalletUi(client); await ui.refresh(); const pending = ui.loadSolanaTronBalances();
  state.isUnlocked = false; await ui.refresh(); finish([{ symbol: 'SOL', balance: '9' }]); await pending;
  assert.deepEqual(ui.state.solanaTronBalances, {});
  state.isUnlocked = true; await ui.refresh();
  pauseHistory = true; const historyPending = ui.loadSolanaTronHistory('solana');
  state.isUnlocked = false; await ui.refresh(); finishHistory({ rows: [{ amount: '9' }], local: [] }); await historyPending;
  assert.deepEqual(ui.state.solanaTronHistory, {});
  pauseHistory = false; state.isUnlocked = true; await ui.refresh();
  for (const chain of ['solana', 'tron']) {
    await ui.prepareSolanaTronSend({ chain, symbol: CHAINS[chain].symbol });
    await ui.confirmSolanaTronSend(chain, 'public-review'); await ui.cancelSolanaTronSend(chain, 'public-review');
    await ui.loadSolanaTronHistory(chain);
    const prefix = chain === 'solana' ? 'Solana' : 'Tron';
    for (const op of ['prepare', 'confirm', 'cancel']) assert.ok(calls.some(([method]) => method === `${op}${prefix}Send`));
    assert.ok(calls.some(([method]) => method === `get${prefix}History`));
  }
});

test('mounted pages wire both send/review/confirm and history; lock disposes review timer', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const root = new Node('main'), navigation = new Node('nav'), status = new Node('p'), calls = [];
  const pageDocument = Object.assign(new EventTarget(), document, { getElementById: id => ({ screen: root, 'wallet-navigation': navigation, 'wallet-status': status })[id] });
  const window = Object.assign(new EventTarget(), { navigator: {} });
  const state = { isInitialized: true, isUnlocked: true, addresses, preferences: { autoLockTimeLimit: 0 }, pendingApprovals: {} };
  let failConfirm = false;
  const client = { close() {}, onNotification: () => () => {}, onDisconnect: () => () => {}, async request(method, params = []) {
    calls.push([method, params]); if (method === 'getState') return structuredClone(state);
    if (/^get(Solana|Tron)Balances$/.test(method)) return [];
    if (/^prepare(Solana|Tron)Send$/.test(method)) return reviewFor(method.includes('Solana') ? 'solana' : 'tron');
    if (/^confirm(Solana|Tron)Send$/.test(method)) {
      if (failConfirm) throw Object.assign(new Error('fixture broadcast uncertain'), { data: { activityTracked: true } });
      return 'public-transaction-id';
    }
    if (/^get(Solana|Tron)History$/.test(method)) return { status: 'fixture chain history', rows: [], local: [] };
    return null;
  } };
  const page = await mountWalletPage({ document: pageDocument, window, client }); t.after(page.dispose);
  const row = chain => find(root, n => n.tagName === 'article' && n.textContent.includes(addresses[chain]))[0];
  for (const chain of ['solana', 'tron']) {
    const prefix = chain === 'solana' ? 'Solana' : 'Tron'; button(row(chain), 'Send').onclick();
    const inputs = find(root, n => n.tagName === 'input'); inputs[0].value = addresses[chain]; inputs[1].value = '1';
    await find(root, n => n.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    t.mock.timers.tick(600); await button(root, 'Confirm send').onclick();
    assert.ok(calls.some(([m, p]) => m === `confirm${prefix}Send` && p[0] === `${chain}-review`));
    assert.ok(status.textContent.includes('confirmation is pending'));
    await button(row(chain), 'History').onclick(); assert.ok(root.textContent.includes('fixture chain history'));
    button(navigation, 'Home').onclick();
  }
  failConfirm = true;
  for (const chain of ['solana', 'tron']) {
    button(row(chain), 'Send').onclick(); await find(root, n => n.tagName === 'form')[0].onsubmit({ preventDefault() {} });
    t.mock.timers.tick(600); await button(root, 'Confirm send').onclick();
    assert.ok(status.textContent.includes('fixture broadcast uncertain')); assert.ok(status.textContent.includes('Check your address on the chain explorer'));
    assert.equal(button(root, 'Confirm send'), undefined); assert.ok(button(root, 'Review transfer'));
    button(navigation, 'Home').onclick();
  }
  button(row('solana'), 'Send').onclick(); await find(root, n => n.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  const confirm = button(root, 'Confirm send'); state.isUnlocked = false; await page.refresh();
  t.mock.timers.tick(600); assert.equal(confirm.disabled, true); assert.equal(button(root, 'Confirm send'), undefined);
});
