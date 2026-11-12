import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, address, input, intent } from './fixtures/wallet-session.js';
// Proves the background answers getOwnName from the name this session already confirmed, without waiting for the
// network, and refreshes the kept name from the network in the background (one read at a time). The real adapter and
// session are used; only the Nodus module's nameOf is a controllable fixture (no network, no flags, nothing left on
// disk). It falsely passes if the fixture's nameOf were never reached by the background refresh: the call counts below
// guard that. The first read (no kept name yet) must still wait for the network, as before.
const module = nameOf => ({
  nameOf,
  async nameLookup() { return { found: false, committedHeight: '10' }; },
  async profileAddress() { throw new Error('Unexpected profile read.'); },
  async namePrices() { return { prices: ['100', '100', '100', '100'], scheduled: [] }; },
  async rulesetInfo() { return { generation: '2', tip: '10', gen2Height: '0' }; },
  async nameBuild(request) { return { envelope: Uint8Array.of(1, 2), intentId: intent, decoded: { name: request.name, owner: address,
    chainId: '12'.repeat(32), inputs: [input], price: '100', fee: '1', change: '499999899', expiryHeight: request.expiryHeight } }; },
});
const turns = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };

test('a kept own name is served at once and refreshed from the network in the background', async t => {
  let reads = 0, release, name = 'first';
  const gate = () => new Promise(resolve => { release = resolve; });
  let hold = null;
  const { nodus, lockCoordinator } = await walletSession(t, { module: module(async () => {
    reads++; if (hold) await hold; return { found: true, name, committedHeight: '10' };
  }) });
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'first' }); assert.equal(reads, 1);
  // The network now stalls: the answer still comes at once from the kept name, and one background read is started.
  hold = gate(); name = 'second';
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'first' });
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'first' });
  await turns(); assert.equal(reads, 2, 'one background read while the first is still in flight');
  release(); await turns();
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'second' }, 'the background read refreshed the kept name');
  await turns(); assert.equal(reads, 3);
  await lockCoordinator.lock();
  await assert.rejects(nodus.getOwnName(), /locked/i);
});

test('a name that is not found is not kept, so the next read still waits for the network', async t => {
  let reads = 0, found = false;
  const { nodus } = await walletSession(t, { module: module(async () => { reads++; return { found, name: 'later', committedHeight: '10' }; }) });
  assert.deepEqual(await nodus.getOwnName(), { found: false }); assert.deepEqual(await nodus.getOwnName(), { found: false });
  assert.equal(reads, 2);
  found = true; assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'later' }); assert.equal(reads, 3);
});

// Proves the kept name outlives a failed background refresh (a refresh that rejects leaves it in place and the next read
// is still answered at once from it, a new refresh each time so the slot is not stuck), and that a refresh which ANSWERS
// not-found removes it (the lookup is the authority: the next read waits for the network). Falsely passes if the refresh
// never ran; the read counts guard that.
test('a kept own name survives a refresh that fails and is removed by one that finds nothing', async t => {
  let reads = 0, mode = 'ok';
  const { nodus } = await walletSession(t, { module: module(async () => {
    reads++;
    if (mode === 'fail') throw new Error('network error');
    return mode === 'missing' ? { found: false, committedHeight: '10' } : { found: true, name: 'kept', committedHeight: '10' };
  }) });
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'kept' }); assert.equal(reads, 1);
  mode = 'fail';
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'kept' }); await turns(); assert.equal(reads, 2);
  mode = 'missing';
  assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'kept' }); await turns(); assert.equal(reads, 3);
  assert.deepEqual(await nodus.getOwnName(), { found: false }); assert.equal(reads, 4, 'the not-found answer removed the kept name, so this read waited for the network');
});
