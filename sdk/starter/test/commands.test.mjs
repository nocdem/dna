// Command behavior against a fake SDK account: actual argument validation and
// dispatch, no keys/signing/node. No flags/env. Leaves nothing. Real ABI/WASM
// and chain acceptance are separate coverage; these tests cannot prove either.
import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCommand, executeCommand } from '../src/commands.mjs';

const address = `0x${'1'.repeat(64)}`, recipient = `0x${'2'.repeat(64)}`;
const sdk = { parseAddress: text => {
  if (!/^0x[0-9a-f]{64}$/.test(text)) throw new Error('32-byte address required');
  return text.slice(2);
}, decodeLog: () => ({ name: 'example' }) };
const config = { vault: { address }, escrow: { address } };
const templates = { vault: { abi: [], runtimeBytecode: 'aabb' }, escrow: { abi: [], runtimeBytecode: 'aabb' } };
function account() {
  const writes = [], reads = [], emitted = [];
  return { writes, reads, emitted, sdk, templates, emit: row => emitted.push(row), options: { confirm: () => true, maxFee: 7n }, evm: {
    code: async () => ({ code: 'aabb' }),
    call: async request => { reads.push(request); return { values: [1230000000000n] }; },
    transfer: async (...args) => { writes.push(['transfer', ...args]); return { status: 'applied-success' }; },
    send: async (...args) => { writes.push(['send', ...args]); return { status: 'applied-success' }; }
  } };
}

test('vault funding uses empty-calldata SDK transfer; proposal payment value is an ABI argument', async () => {
  const ctx = account();
  await executeCommand(prepareCommand(['vault', 'fund', '10000000000'], config, sdk), ctx);
  assert.equal(ctx.writes[0][0], 'transfer');
  assert.deepEqual(ctx.writes[0][1], { to: address, valueWei: 10000000000n });
  assert.equal(ctx.writes[0][2], ctx.options);
  await executeCommand(prepareCommand(['vault', 'submit', recipient, '500'], config, sdk), ctx);
  assert.deepEqual(ctx.writes[1][1], { to: address, abi: [], fn: 'submit', args: [recipient, 500n, '0x'], valueWei: 0n });
});

test('escrow funding reads contract total; simulation never dispatches a write', async () => {
  const ctx = account();
  await executeCommand(prepareCommand(['escrow', 'fund'], config, sdk), ctx);
  assert.equal(ctx.reads[0].fn, 'total');
  assert.equal(ctx.writes[0][1].valueWei, 1230000000000n);
  await executeCommand(prepareCommand(['escrow', 'simulate-release', '0'], config, sdk), ctx);
  await executeCommand(prepareCommand(['vault', 'simulate-execute', '2'], config, sdk), ctx);
  assert.equal(ctx.writes.length, 1);
  assert.equal(ctx.reads[1].fn, 'release');
  assert.equal(ctx.reads[2].fn, 'execute');
});

test('wrong contract runtime refuses before any write; bad arguments fail before an account is used', async () => {
  const ctx = account();
  ctx.evm.code = async () => ({ code: 'different' });
  await assert.rejects(executeCommand(prepareCommand(['vault', 'fund', '1'], config, sdk), ctx), /packaged template/);
  assert.equal(ctx.writes.length, 0);
  for (const argv of [['escrow', 'resolve', '0', 'yes'], ['escrow', 'release', '32'], ['vault', 'fund', '1.5'], ['vault', 'events', '0', '10000'], ['deposit', '1', 'extra']]) {
    assert.throws(() => prepareCommand(argv, config, sdk));
  }
});

test('events follow a cursor through an empty page; a nonadvancing cursor fails', async () => {
  const ctx = account();
  const cursor = { height: 10n, index: 1n, logIndex: 0n };
  const queries = [];
  ctx.evm.logs = async query => {
    queries.push(query);
    return queries.length === 1 ? { logs: [], more: true, cursor } : { logs: [{ height: 11n }], more: false, cursor: null };
  };
  const command = prepareCommand(['vault', 'events', '10', '20'], config, sdk);
  await executeCommand(command, ctx);
  assert.deepEqual(queries[1].cursor, cursor);
  assert.equal(ctx.emitted[0].event.name, 'example');
  ctx.evm.logs = async () => ({ logs: [], more: true, cursor });
  await assert.rejects(executeCommand(command, ctx), /did not advance/);
});
