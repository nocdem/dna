import test from 'node:test';
import assert from 'node:assert/strict';
import { renderEvmApproval, renderEvmSend } from '../src/ui/evm-screens.js';
import { renderHome, renderSettings } from '../src/ui/views.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { CHAINS } from '../../src/config.js';

// Node >=22.14, no flags/network/files; minimal DOM and trusted-client fixtures stay in memory.
class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
}
const document = { createElement: tag => new Node(tag) };
const find = (node, predicate) => node.children.flatMap(child => [...(predicate(child) ? [child] : []), ...find(child, predicate)]);
const button = (node, text) => find(node, item => item.tagName === 'button' && item.textContent === text)[0];
const account = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb';

// Proves request fields are text and approval/rejection use its id; label-only checks miss origin/value or action substitution.
test('signature, transaction and switch screens show the actual request and answer its approval', async () => {
  for (const type of ['personal_sign', 'eth_signTypedData', 'transaction', 'wallet_switchEthereumChain']) {
    const root = new Node('main'), approved = [], rejected = [];
    const pending = { id: 'public-request', type, origin: 'https://site.example', requestData: {
      account, chain: 'ethereum', text: '<img src=x onerror=alert(1)>', to: account, value: '123', data: '0x1234', fee: 'Up to 0.001 ETH', targetChain: 'bsc',
    } };
    renderEvmApproval(document, root, pending, { approve: request => approved.push(request.id), reject: request => rejected.push(request.id) });
    assert.ok(root.textContent.includes(pending.origin)); assert.ok(root.textContent.includes(account));
    if (type === 'transaction') for (const value of ['123', '0x1234', 'Up to 0.001 ETH']) assert.ok(root.textContent.includes(value));
    if (type === 'personal_sign' || type === 'eth_signTypedData') assert.ok(root.textContent.includes(pending.requestData.text));
    assert.equal(find(root, node => node.tagName === 'img').length, 0);
    await button(root, 'Approve').onclick(); await button(root, 'Reject').onclick();
    assert.deepEqual(approved, [pending.id]); assert.deepEqual(rejected, [pending.id]);
  }
});

// Proves a send prepares entered fields, displays its fee and confirms only that review; clicking a confirm with no prepare could falsely pass.
test('internal send renders form then web-wallet review and confirms its id', async () => {
  const root = new Node('main'), prepared = [], sent = [];
  renderEvmSend(document, root, { chain: 'ethereum' }, {
    prepare: fields => prepared.push(fields), confirm: id => sent.push(id), cancel() {},
  });
  const inputs = find(root, node => node.tagName === 'input'); inputs[0].value = account; inputs[1].value = '0.01';
  await find(root, node => node.tagName === 'form')[0].onsubmit({ preventDefault() {} });
  assert.deepEqual(prepared, [{ chain: 'ethereum', symbol: 'ETH', to: account, amount: '0.01' }]);
  renderEvmSend(document, root, { chain: 'ethereum', review: { id: 'review', to: account, amount: '0.01', symbol: 'ETH', fee: 'Up to 0.001 ETH' } }, {
    prepare() {}, confirm: id => sent.push(id), cancel() {},
  });
  assert.ok(root.textContent.includes('Up to 0.001 ETH')); await button(root, 'Confirm send').onclick(); assert.deepEqual(sent, ['review']);
});

// Proves returned EVM balances/errors and chain actions survive the disabled
// Nodus/Solana/Tron controls when their addresses are absent; counts alone miss wrong-chain routing.
test('home shows returned EVM balances and unavailable token errors with send actions', () => {
  const root = new Node('main'), sent = [];
  renderHome(document, root, { addresses: { ethereum: account, bsc: account }, evmBalances: {
    ethereum: [{ symbol: 'ETH', balance: '12.34' }, { symbol: 'USDC', error: 'Balance unavailable' }], bsc: { error: 'RPC unavailable' },
  } }, () => {}, chain => sent.push(chain));
  assert.ok(root.textContent.includes('12.34 ETH')); assert.ok(root.textContent.includes('USDC: Balance unavailable'));
  assert.ok(root.textContent.includes('RPC unavailable')); assert.doesNotMatch(root.textContent, /0\.00/);
  const controls = find(root, node => node.tagName === 'button' && node.textContent === 'Send');
  assert.deepEqual(controls.map(control => control.disabled), [true, false, false, true, true]);
  for (const control of controls) if (!control.disabled) control.onclick();
  assert.deepEqual(sent, ['ethereum', 'bsc']);
});

// Proves shared selection and provider controls use config values and pass actual selections; checking only labels misses persistence wiring.
test('settings expose the shared EVM network and web-wallet RPC lists', async () => {
  const root = new Node('main'), changed = [], endpoints = [];
  renderSettings(document, root, { preferences: { autoLockTimeLimit: 15 }, evm: { selectedChain: 'ethereum', endpoints: {
    ethereum: CHAINS.ethereum.endpoint, bsc: CHAINS.bsc.endpoint,
  } } }, { setAutoLock() {}, reveal() {}, selectEvmNetwork: chain => changed.push(chain), setEvmEndpoint: (...args) => endpoints.push(args) });
  const selects = find(root, node => node.tagName === 'select'), network = selects.find(node => node.id === 'evm-network');
  assert.deepEqual(network.children.map(node => node.value), ['ethereum', 'bsc']); network.value = 'bsc'; await network.onchange(); assert.deepEqual(changed, ['bsc']);
  const rpc = selects.find(node => node.id === 'evm-rpc-ethereum');
  assert.deepEqual(rpc.children.map(node => node.value), CHAINS.ethereum.rpcOptions.map(option => option.url));
  rpc.value = CHAINS.ethereum.rpcOptions[1].url; await rpc.onchange(); assert.deepEqual(endpoints, [['ethereum', rpc.value]]);
});

// Proves UI operations reach trusted methods and refreshes follow mutations; local-only state could make renderer tests falsely pass.
test('wallet UI routes approvals, balances, send reviews and settings through the trusted API', async () => {
  const calls = [], state = { isUnlocked: true };
  const client = { async request(method, params = []) { calls.push({ method, params });
    if (method === 'getState') return state;
    if (method === 'getEvmBalances') return [{ symbol: 'ETH', balance: '1.0' }];
    if (method === 'prepareEvmSend') return { id: 'review', fee: 'fee' };
    if (method === 'confirmEvmSend') return 'public-hash';
    return null;
  } };
  const ui = createWalletUi(client); await ui.refresh();
  await ui.approveEvm({ id: 'approval' }); await ui.rejectEvm({ id: 'approval' }); await ui.loadEvmBalances();
  assert.deepEqual(ui.state.evmBalances.ethereum, [{ symbol: 'ETH', balance: '1.0' }]);
  const review = await ui.prepareEvmSend({ chain: 'ethereum', amount: '1' }); assert.equal(review.id, 'review');
  assert.equal(await ui.confirmEvmSend(review.id), 'public-hash'); await ui.selectEvmNetwork('bsc'); await ui.setEvmEndpoint('ethereum', CHAINS.ethereum.endpoint);
  for (const method of ['resolvePendingApproval', 'rejectPendingApproval', 'getEvmBalances', 'prepareEvmSend', 'confirmEvmSend', 'selectEvmNetwork', 'setEvmEndpoint']) assert.ok(calls.some(call => call.method === method));
});
