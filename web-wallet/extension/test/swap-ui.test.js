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

// Proves the settings list Sepolia only while a site has switched the extension to it, so the selection is shown
// truthfully, and never offer it as a first choice or give it an RPC provider list.
test('settings list Sepolia only while it is the selected network', () => {
  const state = selectedChain => ({ preferences: { autoLockTimeLimit: 15 }, evm: { selectedChain, endpoints: { ethereum: CHAINS.ethereum.endpoint, bsc: CHAINS.bsc.endpoint } } });
  const handlers = { setAutoLock() {}, reveal() {}, selectEvmNetwork() {}, setEvmEndpoint() {} };
  for (const [selected, expected] of [['ethereum', ['ethereum', 'bsc']], ['bsc', ['ethereum', 'bsc']], ['sepolia', ['ethereum', 'bsc', 'sepolia']]]) {
    const root = new Node('main'); renderSettings(document, root, state(selected), handlers);
    const selects = find(root, node => node.tagName === 'select');
    assert.deepEqual(selects.find(node => node.id === 'evm-network').children.map(node => node.value), expected);
    assert.deepEqual(selects.filter(node => node.id?.startsWith('evm-rpc-')).map(node => node.id), ['evm-rpc-ethereum', 'evm-rpc-bsc']);
  }
});
