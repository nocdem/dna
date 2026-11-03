// What this proves: the web CKB adapter (src/pq/ckb-transfer.js) runs the same
// sequence as the extension holder (extension/src/background/ckb.js:51-54):
// the durable record (onBroadcast) is handed over BEFORE any simulation or
// submission request; the hash handed over is the signed txid; the derived seed
// buffer is zeroed; ckbNotExposed is set only before the first disclosure; a
// reservation is refused while another review holds the outpoints or while a row
// is unresolved; and the review rows are the extension's CKB rows, in order.
// Mocks: a scripted CKB JSON-RPC fetcher (labelled fixture; no live request).
// Signing is real (ckb-slh-sign.wasm) with the public test phrase of
// test/fixtures/pq-receive.json. What it leaves behind: nothing.
// How it could falsely pass: the RPC mock accepts any well-formed transaction,
// so it proves ORDER and flags, not node admission; the extension rows are
// checked against literal strings AND against the extension source text, so a
// row renamed in both places at once would not be caught.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bech32m } from '@scure/base';
import { prepareCkbTransfer, CKB_SEND_LIMITS } from '../src/pq/ckb-transfer.js';
import { ckbNetwork } from '../src/pq/ckb.js';
import { pqChainSeed } from '../src/pq/receive.js';
import { CKB_FULL_RECIPIENT_SEND_ENABLED } from '../src/pq/ckb-recipient-policy.js';
import { formatUnits } from '../src/core.js';

const fx = JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json', import.meta.url))).vectors[0];
const address = fx.addresses.ckb.mainnet, net = ckbNetwork('mainnet');
const wasmBytes = readFileSync(new URL('../src/pq/ckb-slh-sign.wasm', import.meta.url));
const H = '0x' + 'ab'.repeat(32), T = '0x' + 'cd'.repeat(32), P = '0x' + 'ef'.repeat(32);
const payload = bech32m.fromWords(bech32m.decode(address, 1023).words);
const SIMULATION_ROW = 'The configured node receives the signed transaction and could relay it.';

// Scripted CKB node. `events` records every RPC method in order so the test can
// compare it with the moment the durable record is handed over.
function node({ events, simulate = 'ok' } = {}) {
  const lock = { code_hash: net.codeHash, hash_type: net.hashType, args: '0x' + Buffer.from(payload.slice(34)).toString('hex') };
  const out = { capacity: '0x' + (30000000000n).toString(16), lock, type: null };
  const state = { fee: 1000n, txid: undefined };
  const header = { hash: H, number: '0x64', timestamp: '0x' + Date.now().toString(16) };
  const fetcher = async (url, options) => {
    const q = JSON.parse(options.body);
    events.push('rpc:' + q.method);
    let result;
    switch (q.method) {
      case 'get_block_hash': result = q.params[0] === '0x0' ? net.genesisHash : H; break;
      case 'get_tip_header': result = header; break;
      case 'get_indexer_tip': result = { block_number: '0x64', block_hash: H }; break;
      case 'get_cells': result = { objects: [{ out_point: { tx_hash: T, index: '0x0' }, block_number: '0x63', tx_index: '0x1', output: out, output_data: '0x' }], last_cursor: '0x00' }; break;
      case 'get_transaction': result = q.params[0] === T
        ? { transaction: { hash: T, inputs: [{ previous_output: { tx_hash: P, index: '0x0' }, since: '0x0' }], outputs: [out], outputs_data: ['0x'] }, tx_status: { status: 'committed', block_hash: H, block_number: '0x63', tx_index: '0x1' } }
        : { transaction: null, tx_status: { status: 'unknown' } };
        break;
      case 'get_live_cell': result = { status: 'live', cell: { output: out, data: { content: '0x' } } }; break;
      case 'tx_pool_info': result = { tip_hash: H, tip_number: '0x64', min_fee_rate: '0x3e8', tx_size_limit: '0x7d000' }; break;
      case 'get_fee_rate_statistics': result = { mean: '0x103593', median: '0x81c6' }; break;
      case 'test_tx_pool_accept':
        if (simulate === 'network') throw Error('network down');
        result = { fee: '0x' + state.fee.toString(16), cycles: '0x193cc63' }; break;
      case 'send_transaction': result = state.txid; break;
      default: throw Error('Unexpected RPC ' + q.method);
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: q.id, result }));
  };
  return { fetcher, state };
}
const wallet = () => ({ addresses: { ckb: address }, recoveryPhrase: fx.phrase });
const args = (events, mode, extra = {}) => {
  const n = node({ events, simulate: mode });
  return { n, args: { wallet: extra.wallet ?? wallet(), to: address, amountAtoms: 10000000000n, fetcher: n.fetcher, wasmBytes, rnd: new Uint8Array(32).fill(7), ...extra } };
};

test('confirm hands the durable record over before any simulation or submission request', async () => {
  const events = [], { n, args: a } = args(events);
  let captured;
  const transfer = await prepareCkbTransfer({ ...a, deriveSeed: (p, c) => (captured = pqChainSeed(p, c)) });
  n.state.fee = BigInt(transfer.feeAtoms);
  const seenDetails = [];
  const hash = await transfer.confirm(async details => {
    events.push('persist'); seenDetails.push(details); n.state.txid = details.hash;
    return { submissionId: 'ab'.repeat(16) };
  });
  const persist = events.indexOf('persist');
  assert.ok(persist > 0);
  assert.ok(events.indexOf('rpc:test_tx_pool_accept') > persist, 'simulation is sent after the durable record');
  assert.ok(events.indexOf('rpc:send_transaction') > persist, 'submission is sent after the durable record');
  assert.equal(events.filter(x => x === 'persist').length, 1);
  assert.equal(seenDetails[0].state, 'signed-exposure-pending');
  assert.match(seenDetails[0].hash, /^0x[0-9a-f]{64}$/);
  assert.equal(seenDetails[0].hash, seenDetails[0].txid, 'details.hash is the signed txid');
  assert.equal(hash, seenDetails[0].txid);
  assert.ok(captured.length > 0 && captured.every(b => b === 0), 'the derived seed buffer is zeroed');
});

test('ckbNotExposed is set only before the first disclosure', async () => {
  // (i) the durable write fails: nothing was disclosed.
  const e1 = [], x1 = args(e1);
  const t1 = await prepareCkbTransfer(x1.args);
  await assert.rejects(t1.confirm(async () => { throw Error('storage'); }), error => error.message === 'storage' && error.ckbNotExposed === true);
  assert.ok(!e1.includes('rpc:test_tx_pool_accept') && !e1.includes('rpc:send_transaction'));
  // the cancelled attempt released its outpoints: the same wallet can prepare again.
  const again = await prepareCkbTransfer({ ...x1.args, fetcher: node({ events: [] }).fetcher });
  again.cancel();
  // (ii) the simulation request fails after the signed transaction left: not "not exposed".
  const e2 = [], x2 = args(e2, 'network');
  const t2 = await prepareCkbTransfer(x2.args);
  await assert.rejects(t2.confirm(async d => { x2.n.state.txid = d.hash; return { submissionId: 'cd'.repeat(16) }; }), error => /network down/.test(error.message) && error.ckbNotExposed !== true);
});

test('seed is zeroed and the review closed when the durable record fails', async () => {
  const events = [], { args: a } = args(events);
  let captured;
  const transfer = await prepareCkbTransfer({ ...a, deriveSeed: (p, c) => (captured = pqChainSeed(p, c)) });
  await assert.rejects(transfer.confirm(async () => { throw Error('storage'); }), /storage/);
  assert.ok(captured.every(b => b === 0));
  await assert.rejects(transfer.confirm(async () => ({ submissionId: 'ab'.repeat(16) })), /closed/);
});

test('reservation is refused while another review holds the outpoints or while a row is unresolved', async () => {
  const w = wallet();
  const first = await prepareCkbTransfer(args([], 'ok', { wallet: w }).args);
  await assert.rejects(prepareCkbTransfer(args([], 'ok', { wallet: w }).args), /already reserved/);
  first.cancel();
  const second = await prepareCkbTransfer(args([], 'ok', { wallet: w }).args);
  second.cancel();
  await assert.rejects(prepareCkbTransfer(args([], 'ok', { wallet: w, unresolved: () => true }).args), /already reserved/);
});

test('only mainnet is accepted and the limits are the extension limits', async () => {
  await assert.rejects(prepareCkbTransfer({ ...args([]).args, networkId: 'testnet' }), /mainnet/i);
  assert.deepEqual({ ...CKB_SEND_LIMITS }, { maxFee: 100000000n, maxRate: 100000n, cycleCeiling: 100000000n });
});

test('review rows are the extension rows, in the extension order', async () => {
  const transfer = await prepareCkbTransfer(args([]).args);
  const fee = `${formatUnits(BigInt(transfer.feeAtoms), 8)} CKB`;
  const scope = CKB_FULL_RECIPIENT_SEND_ENABLED
    ? 'Full-format Bech32m recipients only; non-cellbase empty-data quantum inputs. Check recipient control; address validity does not prove spendability.'
    : 'Quantum-lock recipients only; non-cellbase empty-data inputs.';
  assert.deepEqual(transfer.review.map(r => r[0]), ['Network', 'From', 'To', 'Amount', 'Fee', 'Fee rate', 'Scope', 'Simulation']);
  assert.deepEqual(transfer.review.filter(r => r[0] !== 'Fee rate'), [['Network', 'CKB Mainnet'], ['From', address], ['To', address], ['Amount', '100 CKB'], ['Fee', fee], ['Scope', scope], ['Simulation', SIMULATION_ROW]]);
  assert.match(transfer.review.find(r => r[0] === 'Fee rate')[1], /^\d+ shannons per 1000 weight$/);
  // The extension source carries the same row texts (extension/src/background/ckb.js:44).
  const extension = readFileSync(new URL('../extension/src/background/ckb.js', import.meta.url), 'utf8');
  for (const text of [scope, SIMULATION_ROW, 'shannons per 1000 weight', "['Network',`CKB ${s.network.label||s.network.id}`]"]) assert.ok(extension.includes(text), text);
  assert.equal(transfer.chain, 'ckb');
  assert.equal(transfer.symbol, 'CKB');
  assert.equal(transfer.amount, '100');
  assert.equal(transfer.networkId, 'mainnet');
  assert.equal(transfer.endpoint, net.rpc);
  assert.equal(transfer.from, address);
  transfer.cancel();
});
