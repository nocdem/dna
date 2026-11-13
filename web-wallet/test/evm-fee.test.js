// Node >=22.14, no flags/network/artifacts. Mocked fetch answers the JSON-RPC reads of src/adapters/evm.js; the
// signing key is a real ethers key derived from a public test phrase. Nothing is written anywhere.
// Every fee-market fixture answers base fee, priority fee and gas price with three DISTINCT values (0x10, 0x5, 0x15),
// so a path that used gasPrice, or the base fee alone, produces a different number than 2 x base + tip = 0x25.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Transaction, formatUnits, keccak256 } from 'ethers';
import { deriveWallet } from '../src/keys.js';
import { CHAINS } from '../src/config.js';
import { prepare } from '../src/adapters/evm.js';

const phrase = 'abandon '.repeat(23) + 'art', to = '0x0000000000000000000000000000000000000001';
// assert.rejects with an object compares the error's own message exactly (a RegExp is tested against String(error), which starts "Error: ").
const FEE_MESSAGE = { message: 'Network fee could not be read from the RPC endpoint.' };
// The 18 fields the Block schema requires (a block without any of them is refused), plus the base fee where given.
function block(extra = {}) {
  return { hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32), sha3Uncles: '0x' + '33'.repeat(32), miner: to, stateRoot: '0x' + '44'.repeat(32),
    transactionsRoot: '0x' + '55'.repeat(32), receiptsRoot: '0x' + '66'.repeat(32), logsBloom: '0x' + '00'.repeat(256), number: '0x10', gasLimit: '0x1c9c380',
    gasUsed: '0x0', timestamp: '0x1', extraData: '0x', mixHash: '0x' + '77'.repeat(32), nonce: '0x0000000000000000', size: '0x200', transactions: [], uncles: [],
    difficulty: '0x0', ...extra };
}
// `latest` is the block answer (a function of nothing: tests replace it); `tip` / `price` the two quotes; each may be a JSON-RPC error marker.
function setup(t, chain = 'ethereum') {
  globalThis.fetch.mock?.restore();  // a test builds several fixtures in turn; only the newest answers
  const state = { latest: block({ baseFeePerGas: '0x10' }), tip: '0x5', price: '0x15', balance: '0x8ac7230489e80000', tipError: false }, calls = [], raw = [];
  const chainId = '0x' + CHAINS[chain].chainId.toString(16);
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const req = JSON.parse(typeof options.body === 'string' ? options.body : new TextDecoder().decode(options.body));
    assert.equal(Array.isArray(req), false); calls.push(req.method);
    let result;
    switch (req.method) {
      case 'eth_chainId': result = chainId; break;
      case 'eth_blockNumber': result = '0x10'; break;
      case 'eth_getBalance': result = state.balance; break;
      case 'eth_estimateGas': result = '0x5208'; break;
      case 'eth_getTransactionCount': result = '0x7'; break;
      case 'eth_getBlockByNumber': result = state.latest; break;
      case 'eth_maxPriorityFeePerGas':
        if (state.tipError) return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', error: { code: -32601, message: 'method not found' } }), { headers: { 'content-type': 'application/json' } });
        result = state.tip; break;
      case 'eth_gasPrice': result = state.price; break;
      case 'eth_sendRawTransaction': raw.push(req.params[0]); result = keccak256(req.params[0]); break;
      default: assert.fail(`Unexpected fixture method ${req.method}`);
    }
    return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', result }), { headers: { 'content-type': 'application/json' } });
  });
  const wallet = deriveWallet(phrase), signs = [];
  const key = wallet.evm;
  wallet.evm = { signTransaction: async tx => { signs.push(tx); return key.signTransaction(tx); } };
  const args = { chain, wallet, to, asset: { symbol: CHAINS[chain].symbol }, units: 1000n, endpoint: CHAINS[chain].endpoint };
  return { state, calls, raw, signs, wallet, args };
}
const maxFee = 2n * 0x10n + 0x5n; // 0x25
const gasLimit = 0x5208n * 120n / 100n;

// Proves the Ethereum path signs a type 2 transaction with tip = eth_maxPriorityFeePerGas and cap = 2 x base + tip, and the review shows the
// maximum. Could falsely pass only if the three fixture quotes were equal (they are distinct) or the check read the wrong decoded field.
test('a fee-market network signs type 2 with the tip and twice the base fee plus the tip, and shows the maximum', async t => {
  const { raw, args } = setup(t), prepared = await prepare(args);
  assert.equal(prepared.fee, `Up to ${formatUnits(gasLimit * maxFee, 18)} ETH`);
  const hash = await prepared.send(); assert.equal(raw.length, 1); assert.equal(hash, keccak256(raw[0]));
  const tx = Transaction.from(raw[0]);
  assert.equal(tx.type, 2); assert.equal(tx.maxPriorityFeePerGas, 5n); assert.equal(tx.maxFeePerGas, maxFee); assert.equal(tx.gasLimit, gasLimit);
  assert.equal(tx.nonce, 7); assert.equal(tx.chainId, 1n); assert.equal(tx.to, to); assert.equal(tx.value, 1000n);
});

// Proves a network whose latest block reports a base fee of 0 (BNB Smart Chain) keeps today's type 0 with gasPrice = eth_gasPrice (0x15, not the
// tip 0x5). Could falsely pass if gasPrice and tip were equal; they are not.
test('a network with a zero base fee keeps type 0 at eth_gasPrice', async t => {
  const { state, raw, args } = setup(t, 'bsc'); state.latest = block({ baseFeePerGas: '0x0' });
  const prepared = await prepare(args);
  assert.equal(prepared.fee, `Up to ${formatUnits(gasLimit * 0x15n, 18)} BNB`);
  await prepared.send(); const tx = Transaction.from(raw[0]);
  assert.equal(tx.type, 0); assert.equal(tx.gasPrice, 0x15n);
});

// Proves a complete block with no baseFeePerGas selects the legacy fields (presence check only), and that no tip read is needed there.
// Could falsely pass if the fixture block lacked a required field (then the fee message would appear instead; the assertion on the raw would fail).
test('a block naming every required field but no base fee selects type 0 and never reads the tip', async t => {
  const { state, calls, raw, args } = setup(t); state.latest = block(); state.tipError = true;
  const prepared = await prepare(args); await prepared.send();
  const tx = Transaction.from(raw[0]); assert.equal(tx.type, 0); assert.equal(tx.gasPrice, 0x15n);
  assert.equal(calls.includes('eth_maxPriorityFeePerGas'), false);
});

// Proves an unreadable tip is its own failure: the fee message, nothing signed, nothing broadcast. Before the change the tip read failure
// was replaced by a stand-in and the balance message covered every failure. Could falsely pass if prepare failed earlier for another reason;
// the exact message equality rules that out.
test('a failed tip read stops with the fee message, signs nothing and broadcasts nothing', async t => {
  const { state, raw, signs, args } = setup(t); state.tipError = true;
  await assert.rejects(prepare(args), FEE_MESSAGE);
  assert.equal(raw.length, 0); assert.equal(signs.length, 0);
});

// Proves the balance check uses the maximum: a balance that covers gasLimit x (base + tip) = 0x15 per gas but not gasLimit x 0x25 is refused
// with the balance message. Could falsely pass if the balance were below both figures; 600000 wei lies between 529200 and 932400.
test('a balance between the expected charge and the maximum is refused with the balance message', async t => {
  const { state, args } = setup(t); state.balance = '0x' + (600000n).toString(16);
  assert.ok(gasLimit * 0x15n + 1000n < 600000n && 600000n < gasLimit * maxFee + 1000n);
  await assert.rejects(prepare(args), { message: 'Insufficient native balance for amount and network fee.' });
});

// Proves every malformed answer of the shape rules (4.2 steps 0-2) is a fee-read failure before anything is signed. Each case changes one
// answer only; the fixture otherwise answers a valid fee-market quote, so a failure can only come from that answer.
test('malformed block and quantity answers are fee-read failures before any signing', async t => {
  const full = block({ baseFeePerGas: '0x10' }), without = field => { const copy = { ...full }; delete copy[field]; return copy; };
  const cases = [
    ['block null', s => { s.latest = null; }], ['block array', s => { s.latest = []; }], ['block empty object', s => { s.latest = {}; }],
    ['block missing mixHash', s => { s.latest = without('mixHash'); }], ['block missing size', s => { s.latest = without('size'); }],
    ['baseFeePerGas null', s => { s.latest = block({ baseFeePerGas: null }); }],
    ['baseFeePerGas number', s => { s.latest = block({ baseFeePerGas: 16 }); }], ['baseFeePerGas decimal string', s => { s.latest = block({ baseFeePerGas: '16' }); }],
    ['baseFeePerGas upper-case hex', s => { s.latest = block({ baseFeePerGas: '0xA' }); }], ['baseFeePerGas leading zero', s => { s.latest = block({ baseFeePerGas: '0x010' }); }],
    ['baseFeePerGas 65 hex digits', s => { s.latest = block({ baseFeePerGas: '0x1' + '0'.repeat(64) }); }],
    ['tip number', s => { s.tip = 5; }], ['tip decimal string', s => { s.tip = '5'; }], ['tip upper-case hex', s => { s.tip = '0xA'; }],
    ['tip leading zero', s => { s.tip = '0x05'; }], ['tip 65 hex digits', s => { s.tip = '0x1' + '0'.repeat(64); }], ['tip null', s => { s.tip = null; }],
    ['legacy price number', s => { s.latest = block(); s.price = 21; }], ['legacy price decimal string', s => { s.latest = block(); s.price = '21'; }],
    ['legacy price upper-case hex', s => { s.latest = block(); s.price = '0xA'; }], ['legacy price leading zero', s => { s.latest = block(); s.price = '0x015'; }],
    ['legacy price 65 hex digits', s => { s.latest = block(); s.price = '0x1' + '0'.repeat(64); }], ['legacy price zero', s => { s.latest = block(); s.price = '0x0'; }],
    // Each input is below 2^256 but 2 x base + tip is not: the computed cap is checked itself.
    ['cap reaches 2^256', s => { s.latest = block({ baseFeePerGas: '0x8' + '0'.repeat(63) }); s.tip = '0x8' + '0'.repeat(63); }],
    // The equality boundary: base = 2^255 - 1 and tip = 2 give 2 x base + tip == 2^256 exactly, both inputs below 2^256. A `>` instead of `>=` passes the case above and fails here.
    ['cap equals 2^256 exactly', s => { s.latest = block({ baseFeePerGas: '0x7' + 'f'.repeat(63) }); s.tip = '0x2'; }],
  ];
  for (const [name, change] of cases) {
    const { state, raw, signs, args } = setup(t); change(state);
    await assert.rejects(prepare(args), FEE_MESSAGE, name);
    assert.equal(raw.length, 0, name); assert.equal(signs.length, 0, name);
  }
});

// Proves the check at signing (plan 4.7). Approved at max fee 0x25: a base fee at signing at or below it signs the approved fields byte for byte
// (the raw decodes to the same cap and tip as at preparation, though the live tip quote has since changed); above it nothing is signed or
// broadcast and the message names the cause. Could falsely pass if the base fee never changed between prepare and send; the fixture moves it.
test('at signing a base fee above the approved maximum refuses before anything is signed; at or below it the approved fields are signed', async t => {
  const { state, raw, signs, args } = setup(t), prepared = await prepare(args);
  state.latest = block({ baseFeePerGas: '0x25' }); state.tip = '0x9';
  await prepared.send(); const tx = Transaction.from(raw[0]);
  // Every approved field is compared (not only the two fee fields): the signed raw is the approved transaction, whatever the quotes did since.
  assert.deepEqual({ type: tx.type, chainId: tx.chainId, nonce: tx.nonce, gasLimit: tx.gasLimit, maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, to: tx.to, value: tx.value, data: tx.data },
    { type: 2, chainId: 1n, nonce: 7, gasLimit, maxFeePerGas: maxFee, maxPriorityFeePerGas: 5n, to, value: 1000n, data: '0x' });
  assert.equal(signs.length, 1);
  state.latest = block({ baseFeePerGas: '0x10' }); state.tip = '0x5';  // the second preparation approves cap 0x25 again
  const second = await prepare(args); state.latest = block({ baseFeePerGas: '0x26' });
  await assert.rejects(second.send(), { message: 'Network fee rose above the approved maximum. Prepare the transfer again.' });
  assert.equal(raw.length, 1); assert.equal(signs.length, 1);
});

// Proves a failed base fee read at signing, and a latest block that has lost its base fee, both stop with the fee message (never a silent change
// of type), and that a type 0 send makes no extra block read. Could falsely pass if send never reached the check; the block-read counter shows it did.
test('at signing an unreadable or base-fee-less block stops with the fee message; a type 0 send reads no block', async t => {
  const one = setup(t), approved = await prepare(one.args);
  one.state.latest = null;
  await assert.rejects(approved.send(), FEE_MESSAGE); assert.equal(one.signs.length, 0); assert.equal(one.raw.length, 0);
  const two = setup(t), second = await prepare(two.args); two.state.latest = block();
  await assert.rejects(second.send(), FEE_MESSAGE); assert.equal(two.signs.length, 0); assert.equal(two.raw.length, 0);
  const legacy = setup(t, 'bsc'); legacy.state.latest = block({ baseFeePerGas: '0x0' });
  const prepared = await prepare(legacy.args), before = legacy.calls.filter(m => m === 'eth_getBlockByNumber').length;
  await prepared.send();
  assert.equal(legacy.calls.filter(m => m === 'eth_getBlockByNumber').length, before); assert.equal(legacy.raw.length, 1);
});
