import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderNodusSend, renderNodusHistory } from '../src/ui/nodus-screens.js';
import { renderHome, renderSettings } from '../src/ui/views.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { NODUS_TOKEN_ID } from '../../src/nodus/network.js';
import { mountWalletPage } from '../src/ui/app.js';
import { EvmAccount as RemoteAccount, Contract as RemoteContract, Interface as RemoteInterface } from '../src/ui/contracts-remote.js';

// Package G call inventory: ui.js account/account.waiting/ticket/deposit/
// withdraw/redeem; Contract.read -> simulate, estimate -> estimate,
// prepareSend/prepareDeploy -> background prepare. No flags/artifacts/network.
// A subset-only mock could silently omit a call: assert the complete list.
test('contract facade carries every account and contract operation over the trusted port', async () => {
  // Equivalent to grep -o for method calls in BOTH reference files. The
  // public account calls are exercised below; raw client calls and watch stay
  // in nodus-background.test.js. A new call must update this coverage.
  const reference = ['ui.js', 'contract.js'].map(file => readFileSync(new URL(`../../src/evm/${file}`, import.meta.url), 'utf8')).join('\n');
  const methods = owner => [...new Set([...reference.matchAll(new RegExp(`\\b${owner}\\.([A-Za-z]+)\\s*\\(`, 'g'))].map(match => match[1]))].sort();
  assert.deepEqual(methods('client'), ['balance', 'evmAccount', 'evmBuild', 'evmCall', 'evmEstimate', 'evmReceipt', 'evmTicket', 'list', 'rulesetInfo', 'submit']);
  assert.deepEqual(methods('account'), ['account', 'deposit', 'estimate', 'prepare', 'redeem', 'simulate', 'ticket', 'waiting', 'watch', 'withdraw']);
  const calls = [], client = { request: async (method, params) => {
    calls.push([method, params]);
    if (method === 'contractAccount') return { balanceWei: '1', nonce: '0', height: '1', pending: false };
    if (method === 'contractSimulate') return { success: true, output: '0'.repeat(64), gasUsed: '1', height: '1' };
    if (method === 'prepareNodusContract') return { id: String(calls.length), intentId: 'ab'.repeat(64), decoded: { op: params[0].action, amount: '1', fee: '1', valueWei: '0' }, review: [] };
    if (method === 'confirmNodusSend') return 'ab'.repeat(64);
    if (method === 'getNodusContractReceipt') return { status: 'applied-success' };
    return {};
  } };
  const account = new RemoteAccount({ client, fingerprint: 'ab'.repeat(64) });
  await account.account(); assert.equal(account.waiting(), false); await account.ticket('cd'.repeat(64));
  for (const review of [await account.deposit(1n), await account.withdraw(1n, 'cd'.repeat(64)), await account.redeem('ef'.repeat(64), 'cd'.repeat(64))]) review.cancel();
  const abi = JSON.stringify([{ type: 'function', name: 'value', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
    { type: 'function', name: 'set', inputs: [{ type: 'uint256' }], outputs: [] }]);
  const contract = new RemoteContract({ account, address: '0x' + '11'.repeat(32), abi });
  await contract.read('value'); await contract.estimate('set', ['7']); (await contract.prepareSend('set', ['7'])).cancel();
  const deployed = await RemoteContract.prepareDeploy({ account, abi: new RemoteInterface(abi), bytecode: '0x01' });
  const sent = await deployed.confirm(); assert.equal((await sent.receipt).status, 'applied-success');
  assert.deepEqual([...new Set(calls.map(call => call[0]))].sort(), ['cancelNodusSend', 'confirmNodusSend', 'contractAccount', 'contractEstimate', 'contractSimulate', 'contractTicket', 'getNodusContractReceipt', 'prepareNodusContract']);
  assert.deepEqual(calls.filter(call => call[0] === 'prepareNodusContract').map(call => call[1][0].action), ['deposit', 'withdraw', 'redeem', 'call', 'deploy']);
  const request = calls.find(([method, args]) => method === 'prepareNodusContract' && args[0].action === 'call')[1][0];
  assert.equal(request.fn, 'set(uint256)'); assert.deepEqual(request.args, ['7']);
  assert.doesNotMatch(JSON.stringify(calls), /envelope|recoveryPhrase/);
});

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

// Uses the mounted web-wallet contract page, rather than the removed fallback
// renderer. Pin decoded review rows, immediate one-shot confirmation and the
// unrecorded failure's retained error/Close control. No live RPC/artifacts.
test('mounted contract review confirms immediately and retains unrecorded failures', { timeout: 60_000 }, async () => {
  const { withPortfolioPage } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(async (page, origin) => {
    await page.goto(`${origin}/test/fixtures/functions.html?contracts`);
    await page.waitForFunction(() => window.fixture?.ready);
    await page.locator('#nav-evm').click();
    const deposit = page.locator('.evm-bridge-side').first();
    await deposit.locator('input').fill('1'); await deposit.getByRole('button', { name: 'Review', exact: true }).click();
    const dialog = page.locator('dialog.evm-review');
    await dialog.waitFor();
    assert.match(await dialog.textContent(), /1 NODUS/); assert.doesNotMatch(await dialog.textContent(), /Review expires/);
    assert.match(await dialog.textContent(), /<img src=x>/); assert.equal(await dialog.locator('img').count(), 0);
    const confirm = dialog.getByRole('button', { name: 'Confirm & send', exact: true });
    assert.equal(await confirm.isEnabled(), true);
    await page.evaluate(() => window.fixture.hold()); await confirm.click();
    assert.equal(await confirm.isDisabled(), true); assert.equal(await dialog.getByRole('button', { name: 'Cancel', exact: true }).isDisabled(), true);
    await page.evaluate(() => window.fixture.release());
    await page.waitForFunction(() => document.querySelector('dialog.evm-review [role="alert"]')?.textContent === 'fixture contract failure');
    assert.match(await dialog.textContent(), /1 NODUS/); assert.equal(await confirm.isDisabled(), true);
    const attempts = await page.evaluate(() => window.fixture.calls.filter(([method]) => method === 'confirmNodusSend').length);
    await confirm.evaluate(button => button.click());
    assert.equal(await page.evaluate(() => window.fixture.calls.filter(([method]) => method === 'confirmNodusSend').length), attempts);
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    // src/evm/ui.js:170,174 removes the dialog in the later close event.
    await dialog.waitFor({ state: 'detached' });
    assert.equal(await dialog.count(), 0);
    assert.ok(await page.evaluate(() => window.fixture.calls.some(([method, args]) => method === 'prepareNodusContract' && args[0].action === 'deposit' && args[0].amount === '1')));
    assert.equal(await page.evaluate(() => window.fixture.calls.some(([method]) => method === 'getNodusHistory')), false);
  });
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

// No flags/network/artifacts. Pins account rows, provenance, errors and refresh
// while a populated local fixture must produce neither rows nor retry controls.
// The mounted Activity assertions in ui-layout.test.js cover page wiring.
test('history preserves node provenance and read failures while omitting local sends', () => {
  const root = new Node('main'), refreshes = [];
  const local = [{ hash: address, amount: '2', symbol: 'NODUS', status: 'pending', note: 'Network busy.', canResubmit: true }];
  renderNodusHistory(document, root, { rows: [{ title: 'Received', sign: '+', amount: '1 NODUS', detail: 'from public peer', height: '9' }],
    status: 'Newest entries as reported by one Nodus node.', local }, { refresh: () => refreshes.push('refresh') });
  assert.ok(root.textContent.includes('one Nodus node')); assert.ok(root.textContent.includes('Received'));
  assert.doesNotMatch(root.textContent, /Network busy\.|Try again/u); assert.equal(root.textContent.includes(address), false);
  assert.equal(find(root, node => node.className === 'activity-list').length, 1);
  assert.equal(find(root, node => node.tagName === 'article').length, 1);
  button(root, 'Refresh history').onclick(); assert.deepEqual(refreshes, ['refresh']);
  renderNodusHistory(document, root, { rows: [], local, activityError: 'fixture activity unreadable', error: 'fixture node unavailable' }, { refresh() {} });
  assert.ok(root.textContent.includes('fixture node unavailable'));
  assert.ok(root.textContent.includes('fixture activity unreadable'));
  assert.doesNotMatch(root.textContent, /Network busy\.|Try again/u);
  assert.equal(find(root, node => node.tagName === 'article').length, 0);
});

// Public DOM fixtures, no flags/network/artifacts. Pins the reference row
// grouping, record explorer link, optional time and amount-less title. Geometry is
// checked in ui-layout.test.js; text assertions alone cannot prove placement.
test('Nodus account history keeps the row layout and links each network record to the explorer', () => {
  const root = new Node('main'), wire = 'cd'.repeat(64), time = 1700000000000;
  renderNodusHistory(document, root, { rows: [
    { title: 'Received', dir: 'in', sign: '+', amount: '1 NODUS', detail: 'from <img src=x>', height: '9', time, wire },
    { title: 'Witness update', dir: '', sign: '', amount: '', detail: '', height: '8', time: null, wire: '' },
  ], local: [] }, { refresh() {} });
  const rows = find(root, node => node.tagName === 'article');
  assert.equal(rows[0].className, 'activity-row nodus-history-row history-dir-in');
  assert.deepEqual(rows[0].children.map(node => node.className), ['activity-main', 'activity-side', 'activity-footer']);
  assert.deepEqual(rows[0].children[0].children.map(node => node.textContent), ['+1 NODUS', 'Received · from <img src=x>']);
  assert.equal(find(rows[0], node => node.className === 'status-badge')[0].attributes['data-status'], 'confirmed');
  assert.equal(find(rows[0], node => node.tagName === 'time')[0].dateTime, new Date(time).toISOString());
  const links = find(rows[0], node => node.tagName === 'a');
  assert.equal(links.length, 1);
  assert.equal(links[0].textContent, 'View transaction');
  assert.equal(links[0].href, `https://scan.nodusnetwork.io/tx.html?hash=${wire}&lang=en`);
  assert.equal(links[0].target, '_blank');
  assert.equal(links[0].rel, 'noopener noreferrer');
  assert.doesNotMatch(root.textContent, /Network record ID/u);
  assert.equal(rows[1].children[0].children[0].textContent, 'Witness update');
  assert.equal(find(rows[1], node => node.tagName === 'time').length, 0);
  assert.equal(find(rows[1], node => node.tagName === 'a').length, 0);
  assert.equal(find(root, node => node.tagName === 'img' || node.tagName === 'h2').length, 0);
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
