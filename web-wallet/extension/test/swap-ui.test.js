import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSwapPaymentApproval } from '../src/ui/nodus-site-screens.js';
import { renderEvmApproval } from '../src/ui/evm-screens.js';
import { renderSettings } from '../src/ui/views.js';
import { CHAINS } from '../../src/config.js';

// Screens of the swap payment approval and of the Sepolia network name (plan 2026-11-08-swap-bot-plan.nodus1.md section
// 18 changes 1 and 6). Environment: Node >=22.14, a minimal in-memory DOM (as evm-ui.test.js); no flags, no network, no
// files. How they could falsely pass: a text-only DOM cannot show layout or styling, so these prove the content and the
// buttons, not the look (the visual check is the orchestrator's).
class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); }
}
const document = { createElement: tag => new Node(tag), createElementNS: (_ns, tag) => new Node(tag) };
const find = (node, predicate) => node.children.flatMap(child => [...(predicate(child) ? [child] : []), ...find(child, predicate)]);
const button = (node, text) => find(node, item => item.tagName === 'button' && item.textContent === text)[0];

// Proves the payment screen shows the title, the site, every row (exact amount, destinations, token, fee, bot) and the
// note as text, and Approve and Reject answer that approval; a screen that hid a row would let a payment through unseen.
test('the swap payment screen shows every row as text and answers its approval', async () => {
  const root = new Node('main'), approved = [], rejected = [];
  const rows = [['Network', 'Ethereum Sepolia'], ['Pay to', '0xFoundation'], ['Token contract', '0xToken'], ['Amount', '25.0 USDT (25000000 units of 6 decimals)'],
    ['Network fee', 'Up to 0.0001 ETH'], ['Bot that received the request', 'https://swap.nodusnetwork.io'], ['Note', '<img src=x onerror=alert(1)>']];
  const pending = { id: 'swap-payment', type: 'nodus_swapPayment', origin: 'https://swap.nodusnetwork.io', requestData: { title: 'Pay USDT for a swap', rows, note: 'The bot has received your signed request.' } };
  renderSwapPaymentApproval(document, root, pending, { approve: request => approved.push(request.id), reject: request => rejected.push(request.id) });
  for (const text of ['Pay USDT for a swap', pending.origin, 'The bot has received your signed request.', ...rows.flat()]) assert.ok(root.textContent.includes(text), text);
  assert.equal(find(root, node => node.tagName === 'img').length, 0);
  await button(root, 'Approve').onclick(); await button(root, 'Reject').onclick();
  assert.deepEqual(approved, ['swap-payment']); assert.deepEqual(rejected, ['swap-payment']);
});

// Proves the signature and switch screens name Sepolia, not mainnet, when a site is on or asks for it.
test('the signature and switch screens name Ethereum Sepolia', () => {
  const account = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', root = new Node('main');
  renderEvmApproval(document, root, { id: 'a', type: 'wallet_switchEthereumChain', origin: 'https://site.example', requestData: { account, chain: 'ethereum', targetChain: 'sepolia' } }, { approve() {}, reject() {} });
  assert.ok(root.textContent.includes('Ethereum Sepolia')); assert.ok(root.textContent.includes('Ethereum'));
  renderEvmApproval(document, root, { id: 'b', type: 'eth_signTypedData', origin: 'https://site.example', requestData: { account, chain: 'sepolia', text: '{}' } }, { approve() {}, reject() {} });
  assert.ok(root.textContent.includes('Ethereum Sepolia'));
});

// Proves the settings always list every Ethereum and BNB Smart Chain network (the test networks included, plan 5.6),
// whichever is selected, and show one RPC provider list per chain for the network its selector is on. Can falsely pass
// if the list were fixed and the RPC lists ignored the selector; the second state moves both selectors to test networks.
test('settings list every EVM network and one RPC list per chain for its selected network', () => {
  const endpoints = { ethereum: CHAINS.ethereum.endpoint, bsc: CHAINS.bsc.endpoint, sepolia: 'https://ethereum-sepolia-rpc.publicnode.com', bsctestnet: 'https://bsc-testnet-rpc.publicnode.com' };
  const state = (selectedChain, networks) => ({ preferences: { autoLockTimeLimit: 15 }, networks, evm: { selectedChain, endpoints } });
  const handlers = { setAutoLock() {}, reveal() {}, selectEvmNetwork() {}, setEvmEndpoint() {} };
  for (const [selected, networks, rpcIds] of [['ethereum', undefined, ['evm-rpc-ethereum', 'evm-rpc-bsc']], ['sepolia', { ethereum: 'sepolia', bsc: 'testnet' }, ['evm-rpc-sepolia', 'evm-rpc-bsctestnet']]]) {
    const root = new Node('main'); renderSettings(document, root, state(selected, networks), handlers);
    const selects = find(root, node => node.tagName === 'select');
    assert.deepEqual(selects.find(node => node.id === 'evm-network').children.map(node => node.value), ['ethereum', 'bsc', 'sepolia', 'bsctestnet']);
    assert.deepEqual(selects.filter(node => node.id?.startsWith('evm-rpc-')).map(node => node.id), rpcIds);
    assert.deepEqual(selects.filter(node => node.id?.startsWith('network-') && ['network-ethereum', 'network-bsc'].includes(node.id)).map(node => node.children.map(option => option.value)), [['mainnet', 'sepolia'], ['mainnet', 'testnet']]);
  }
});
