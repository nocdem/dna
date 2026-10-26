// The SDK's write path: estimate -> build + sign -> fee -> confirm -> record
// -> submit -> receipt (src/review.js over web-wallet/src/evm/contract.js).
// What it proves:
//   - without a confirm function a write is refused BEFORE the module builds
//     or signs anything (no evmBuild call);
//   - a built fee above maxFee is refused and nothing is submitted; a fee at
//     maxFee is offered; a non-BigInt maxFee is refused before building;
//   - confirm must return exactly `true`: false / a truthy non-true value / a
//     throw send nothing;
//   - on `true` the record (onRecord) is written BEFORE the envelope is
//     submitted, the receipt is returned, and the record is released after
//     it; an onRecord that throws sends nothing;
//   - the review handed to confirm carries the fee as a BigInt, the
//     wallet's review lines and the decoded (read-back) fields;
//   - a node that does not run the EVM generation (before HF-5): reads and
//     writes say "not active", nothing is built;
//   - a call() through an ABI sends the full 32-byte high-byte address in the
//     call data the node receives, and decodes the node's output.
//   - transfer() sends positive EVM value with empty calldata through the
//     same review, fee and durable-record gates; unresolved records block it.
// Requires: `npm ci` in web-wallet/. No network, no wasm.
// How it can lie: the send module is the wallet's TEST-ONLY mock
// (web-wallet/test/nodus-mock-module.js) with canned evmQuery / evmBuild
// answers — no node, no CBOR, no real envelope, no signature. It proves the
// SDK's gate and its use of contract.js, not the module or the chain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NodusEvm, deriveIdentity, Interface, EMPTY_CODE_HASH } from '../src/index.js';
import { receiptDigest } from '../../../web-wallet/src/evm/rpc.js';
import { createMockNodusModule, CHAIN_ID } from '../../../web-wallet/test/nodus-mock-module.js';

const { vectors } = JSON.parse(readFileSync(new URL('../../../web-wallet/test/fixtures/nodus-addresses.json', import.meta.url), 'utf8'));
const PHRASE = vectors[0].phrase;
const ABI = JSON.parse(readFileSync(new URL('../../../nodus/tools/evm/examples/out/NodusToken.abi.json', import.meta.url), 'utf8'));
const HIGH = 'ff' + 'ee'.repeat(11) + '12'.repeat(20);

// A §18 receipt reply whose digest is the wallet's own §7 encoding.
function wireReceipt(op) {
  const r = { h: '1001', x: '0', s: '1', op: String(op), gu: '0', o: '', wd: '00'.repeat(32), logs: [], tk: [] };
  r.dg = receiptDigest({ success: true, op, gasUsed: 0n, created: null, output: '', logs: [], weiDestroyed: 0n, tickets: [] });
  return r;
}

async function connected({ fee = '1000', generation = '3', calls, receipt = true, pending = [] } = {}) {
  const { fingerprint } = await deriveIdentity(PHRASE);
  const mock = createMockNodusModule();
  mock.state.fingerprint = fingerprint;
  mock.module.evmGeneration = 3;
  mock.state.ruleset = { ...mock.state.ruleset, generation };
  const builds = [], events = [];
  mock.module.evmQuery = async ({ method, args }) => {
    calls?.push({ method, args });
    if (method === 'evm_account') return { n: '0', b: '00'.repeat(32), ch: EMPTY_CODE_HASH, cs: '0', h: '1000' };
    if (method === 'evm_receipt') return receipt ? wireReceipt(builds.at(-1)?.op === 'call' ? 1 : 3) : {};
    if (method === 'evm_call') {
      const out = new Interface(ABI).encodeFunctionData('transfer', [`0x${HIGH}`, 0n]);   // any 32-byte words
      return { s: '1', o: Buffer.from(out.subarray(4, 36)).toString('hex'), gu: '2400', h: '1000' };
    }
    return {};
  };
  mock.module.evmBuild = async req => {
    builds.push(req);
    const c = req.coins[0];
    const call = req.op === 'call';
    return {
      envelope: Uint8Array.of(1, 2, 3), intentId: '7'.repeat(128),
      decoded: {
        op: req.op, to: call ? req.to : '', valueWei: call ? req.valueWei : '', gasLimit: call ? req.gasLimit : '',
        nonce: req.nonce, units: '500', amount: call ? '' : req.amount, dest: '', ticketId: '',
        dataLength: req.data?.length ?? 0, recipient: fingerprint, fee, change: String(BigInt(c.amount) - (call ? 0n : BigInt(req.amount)) - BigInt(fee)),
        expiryHeight: req.expiryHeight, chainId: CHAIN_ID, inputs: [c.nullifier]
      }
    };
  };
  const submit = mock.module.submit;
  mock.module.submit = args => { events.push('submit'); return submit(args); };
  const evm = await NodusEvm.open({ phrase: PHRASE, moduleFactory: mock.factory, pending });
  await evm.connect();
  return { evm, mock, builds, events };
}

test('no confirm function: refused before anything is built or signed', async () => {
  const { evm, builds, mock } = await connected();
  await assert.rejects(evm.deposit(1000n), /confirm function is required.*Nothing was built/);
  await assert.rejects(evm.deposit(1000n, { maxFee: 5000n }), /confirm function is required/);
  await assert.rejects(evm.deposit(1000n, { confirm: true }), /confirm function is required/);
  assert.equal(builds.length, 0);
  assert.equal(mock.state.submitted, undefined);
  evm.close();
});

test('maxFee: a fee above it is refused (nothing sent); at it, offered; a non-BigInt is refused before building', async () => {
  const { evm, builds, mock } = await connected({ fee: '1000' });
  let asked = 0;
  await assert.rejects(evm.deposit(1000n, { maxFee: 999n, confirm: () => { asked++; return true; } }), /above maxFee 999.*Nothing was sent/);
  assert.equal(asked, 0, 'confirm is not asked for a fee above maxFee');
  assert.equal(builds.length, 1);
  assert.equal(mock.state.submitted, undefined);
  assert.deepEqual(evm.pending(), []);
  await assert.rejects(evm.deposit(1000n, { maxFee: 1000, confirm: () => true }), /maxFee is a non-negative BigInt/);
  assert.equal(builds.length, 1, 'a non-BigInt maxFee is refused before the module builds');
  assert.equal(mock.state.submitted, undefined);
  const result = await evm.deposit(1000n, { maxFee: 1000n, confirm: () => true });
  assert.equal(result.status, 'applied-success');
  assert.ok(mock.state.submitted instanceof Uint8Array);
  evm.close();
});

test('confirm must return exactly true', async () => {
  const { evm, mock } = await connected();
  for (const confirm of [() => false, () => 'yes', () => 1, () => undefined, async () => ({ ok: true })]) {
    await assert.rejects(evm.deposit(1000n, { confirm }), /Not confirmed.*Nothing was sent/);
  }
  await assert.rejects(evm.deposit(1000n, { confirm: () => { throw new Error('operator said no'); } }), /confirm function failed \(operator said no\).*Nothing was sent/);
  assert.equal(mock.state.submitted, undefined);
  assert.deepEqual(evm.pending(), []);
  evm.close();
});

test('confirmed: the record is written before submit, the receipt is returned, the record is released', async () => {
  const { evm, events } = await connected();
  let seen;
  const result = await evm.deposit(1000n, {
    maxFee: 5000n,
    confirm: review => { seen = review; return true; },
    onRecord: row => { events.push('record'); assert.equal(row.hash, '7'.repeat(128)); assert.equal(row.inputs.length, 1); }
  });
  assert.deepEqual(events, ['record', 'submit']);
  assert.equal(seen.op, 'deposit');
  assert.equal(seen.fee, 1000n);
  assert.equal(seen.decoded.amount, 1000n);
  assert.ok(seen.rows.some(([label]) => label === 'Network fee (most it can cost)'));
  assert.equal(result.intentId, '7'.repeat(128));
  assert.equal(result.status, 'applied-success');
  assert.equal(result.receipt.op, 3);
  assert.deepEqual(evm.pending(), []);
  evm.close();
});

test('an onRecord that throws sends nothing', async () => {
  const { evm, mock } = await connected();
  await assert.rejects(evm.deposit(1000n, { confirm: () => true, onRecord: () => { throw new Error('disk full'); } }), /disk full/);
  assert.equal(mock.state.submitted, undefined);
  assert.deepEqual(evm.pending(), []);
  evm.close();
});

test('a node without the EVM generation (before HF-5): not active, nothing built', async () => {
  const { evm, builds } = await connected({ generation: '2' });
  assert.equal(evm.evmActive, false);
  await assert.rejects(evm.account(), /not active/);
  await assert.rejects(evm.deposit(1000n, { confirm: () => true }), /not active/);
  assert.equal(builds.length, 0);
  evm.close();
});

test('call(): the full 32-byte address reaches the node in the call data; the output is decoded', async () => {
  const calls = [];
  const { evm } = await connected({ calls });
  const r = await evm.call({ to: `0x${HIGH}`, abi: ABI, fn: 'balanceOf', args: [`0x${HIGH}`] });
  const q = calls.find(c => c.method === 'evm_call');
  assert.equal(q.args.t[1], HIGH);
  assert.equal(q.args.f[1], evm.address);
  assert.equal(q.args.d[1], `70a08231${HIGH}`);       // balanceOf(address) + the whole word
  assert.equal(r.values[0], BigInt(`0x${HIGH}`));
  evm.close();
});

test('transfer: positive value, all 32 address bytes, empty calldata and the usual review/record order', async () => {
  const { evm, builds, events } = await connected();
  try {
    let review;
    const result = await evm.transfer({ to: `0x${HIGH}`, valueWei: 12345678901234567890n, gasLimit: 30000n }, {
      maxFee: 1000n,
      confirm: r => { review = r; return true; },
      onRecord: row => { assert.equal(row.hash, '7'.repeat(128)); events.push('record'); }
    });
    assert.equal(builds[0].op, 'call');
    assert.equal(builds[0].to, HIGH);
    assert.equal(builds[0].valueWei, (12345678901234567890n).toString(16).padStart(64, '0'));
    assert.deepEqual(builds[0].data, new Uint8Array(0));
    assert.equal(review.decoded.valueWei, 12345678901234567890n);
    assert.equal(review.decoded.to, HIGH);
    assert.equal(review.decoded.dataLength, 0);
    assert.deepEqual(events, ['record', 'submit']);
    assert.equal(result.receipt.op, 1);
    assert.equal(result.status, 'applied-success');
    assert.deepEqual(evm.pending(), []);
  } finally { evm.close(); }
});

test('transfer: validation, confirm, maxFee and failed persistence refuse submission', async () => {
  const { evm, builds, mock } = await connected();
  const request = { to: `0x${HIGH}`, valueWei: 1n, gasLimit: 30000n };
  try {
    for (const valueWei of [0n, -1n, 2n ** 256n, '1', 1]) {
      assert.throws(() => evm.transfer({ ...request, valueWei }, { confirm: () => true }), /positive BigInt/);
    }
    assert.throws(() => evm.transfer({ ...request, to: `0x${'11'.repeat(20)}` }, { confirm: () => true }), /20-byte/);
    assert.equal(builds.length, 0);
    await assert.rejects(evm.transfer(request), /confirm function is required/);
    assert.equal(builds.length, 0);
    await assert.rejects(evm.transfer(request, { confirm: () => true, maxFee: 999n }), /above maxFee/);
    await assert.rejects(evm.transfer(request, { confirm: () => false }), /Not confirmed/);
    await assert.rejects(evm.transfer(request, { confirm: () => true, onRecord: () => { throw new Error('disk full'); } }), /disk full/);
    assert.equal(mock.state.submitted, undefined);
    assert.deepEqual(evm.pending(), []);
  } finally { evm.close(); }
});

test('transfer: a restored unresolved transaction blocks a new build', async () => {
  const pending = [{ hash: '8'.repeat(128), expiryHeight: '1090', inputs: ['9'.repeat(128)] }];
  const { evm, builds, mock } = await connected({ receipt: false, pending });
  try {
    await assert.rejects(evm.transfer({ to: HIGH, valueWei: 1n, gasLimit: 30000n }, { confirm: () => true }), /still waiting/);
    assert.equal(builds.length, 0);
    assert.equal(mock.state.submitted, undefined);
    assert.equal(evm.pending()[0].hash, pending[0].hash);
  } finally { evm.close(); }
});
