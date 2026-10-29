import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, input, intent } from './fixtures/wallet-session.js';
const validator = 'ab'.repeat(64);
function stakingModule() { return {
    stakingRules: { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '12', epochLength: '720', maxDelegators: '2048' },
    async validators() { return { validators: [{ fingerprint: validator, selfStake: '1000000000000000', delegated: '0', commissionBps: 500, status: 0 }], truncated: false }; },
    async delegations() { return []; }, async balance() { return { total: '20000000000', spendable: '20000000000' }; },
    async list() { return { tip: '10', coins: [{ nullifier: input, amount: '20000000000' }], truncated: false }; },
    async stakeBuild(request) { return { envelope: Uint8Array.of(7, 7), intentId: intent, decoded: { op: request.op, validator: request.validator, validatorId: '',
      amount: request.amount, commissionBps: request.commissionBps, fee: '1', change: (20000000000n - BigInt(request.amount) - 1n).toString(),
      expiryHeight: request.expiryHeight, chainId: '12'.repeat(32), inputs: request.coins.map(coin => coin.nullifier) } }; },
  }; }
// Package D: decoded module input controls the review; the recorded stake
// holds that input against Send. No flags/network/artifacts. Fixed review
// strings alone would miss the decoding and reservation checks.
test('staking review is decoded and its submitted input stays held', async t => {
  const { nodus, lockCoordinator } = await walletSession(t, { module: stakingModule() });
  const review = await nodus.prepareStake('delegate', { validator, amount: '100' });
  assert.ok(review.review.some(([label, value]) => label === 'Witness' && value === validator));
  await nodus.confirmSend(review.id); assert.equal(nodus.getLocalHistory()[0].kind, 'delegate');
  await assert.rejects(nodus.prepareSend({ to: validator, amount: '1', tokenId: '0'.repeat(128) }), /held/);
  await lockCoordinator.lock(); await assert.rejects(nodus.confirmSend(review.id), /locked/);
});

// D: cancel a review still open, rather than a consumed id. The module's
// submit log stays empty. No flags/network/artifacts; a previously sent id
// would miss this path.
test('lock cancels an open staking review before it can submit', async t => {
  const { nodus, lockCoordinator, calls } = await walletSession(t, { module: stakingModule() });
  const review = await nodus.prepareStake('delegate', { validator, amount: '100' });
  await lockCoordinator.lock(); await assert.rejects(nodus.confirmSend(review.id), /locked/);
  assert.deepEqual(calls, []);
});
