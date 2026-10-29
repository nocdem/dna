import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, address } from './fixtures/wallet-session.js';
import { mountClaimAction } from '../src/ui/claim-action.js';
// Package F: unresolved recorded claim hides the offer; failed reads propagate
// to the page's retry action. No flags/network/artifacts. An empty local list
// alone never exercises hiding an already submitted claim.
test('claim is offered once and remains hidden while its record is unresolved', async t => {
  let failure = false;
  const output = '77'.repeat(64), { nodus } = await walletSession(t, { module: {
    async claimStatus() { if (failure) throw new Error('Fixture status failure'); return { found: true, amount: '500000000', tip: '10', startHeight: '0', endHeight: '18446744073709551615', window: 'open', claimed: 'no-evidence', outputId: output }; },
    async claimBuild() { return { bytes: Uint8Array.of(9, 8, 7), claimId: '66'.repeat(64), decoded: { recipient: address, amount: '500000000', chainId: '12'.repeat(32), nullifier: '55'.repeat(64), outputId: output, leafIndex: '0' } }; },
    async claimSubmit() { return { accepted: true }; },
  } });
  assert.equal((await nodus.getClaimStatus()).claimable, true);
  const review = await nodus.prepareClaim(); await nodus.confirmSend(review.id);
  assert.equal((await nodus.getClaimStatus()).claimable, false);
  failure = true; await assert.rejects(nodus.getClaimStatus(), /Fixture status failure/);
});

// F: a failed status read must expose the reference retry action, whose
// second read can restore the claim. No flags/network/artifacts. A mock that
// never fails would miss the only recovery control on this path.
test('allocation read failure renders a retry action and unresolved status hides it', async () => {
  let fail = true, unresolved = false, action;
  const ui = { state: { addresses: { nodus: address }, nodus: { claimable: true } }, async request(method) {
    assert.equal(method, 'getClaimStatus'); if (fail) throw new Error('Fixture read failure');
    return { claimable: !unresolved, amountText: '5 NODUS' };
  } };
  const controller = mountClaimAction({ ui, portfolio: { setAction(_chain, value) { action = value; } }, run: work => work(), showReview() {} });
  await controller.refresh(); assert.equal(action.label, 'Check for a NODUS allocation again');
  fail = false; await action.run(); assert.equal(action.label, 'Claim your allocation (5 NODUS)');
  unresolved = true; await controller.refresh(); assert.equal(action, undefined); controller.dispose();
});
