import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, address, input, intent } from './fixtures/wallet-session.js';
// Package E: real adapter quote/build/decode, including unavailable and taken
// branches. No flags/network/artifacts. Always-registrable mocks miss gating.
test('names reject taken names and return decoded registration reviews', async t => {
  let ownsName = false;
  const { nodus } = await walletSession(t, { module: {
    async nameOf() { return { found: ownsName, name: 'publicname', committedHeight: '10' }; },
    async nameLookup({ name }) { return name === 'taken' ? { found: true, owner: 'ab'.repeat(64), registeredHeight: '1', committedHeight: '10' } : { found: false, committedHeight: '10' }; },
    async profileAddress() { throw new Error('Unexpected profile read.'); },
    async namePrices() { return { prices: ['100', '100', '100', '100'], scheduled: [] }; },
    async rulesetInfo() { return { generation: '2', tip: '10', gen2Height: '0' }; },
    async nameBuild(request) { return { envelope: Uint8Array.of(1, 2), intentId: intent, decoded: { name: request.name, owner: address,
      chainId: '12'.repeat(32), inputs: [input], price: '100', fee: '1', change: '499999899', expiryHeight: request.expiryHeight } }; },
  } });
  assert.deepEqual(await nodus.getOwnName(), { found: false });
  assert.equal((await nodus.quoteName('taken')).status, 'taken'); await assert.rejects(nodus.prepareName('taken'), /already registered/);
  const review = await nodus.prepareName('available'); assert.ok(review.review.some(([label, value]) => label === 'Name' && value === 'available'));
  nodus.cancelSend(review.id);
  ownsName = true; assert.deepEqual(await nodus.getOwnName(), { found: true, name: 'publicname' });
  const bare = await walletSession(t); assert.equal(bare.nodus.getState().registrable, false);
  await assert.rejects(bare.nodus.prepareName('available'), /not available/);
});
