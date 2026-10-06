// The review gate of every write — the wallet's review semantics for a
// script (web-wallet/src/evm/contract.js EvmAccount.prepare / confirm):
//
//   1. no `confirm` function            -> refused BEFORE anything is built
//                                          or signed;
//   2. build + sign for review          -> the module estimates, builds and
//                                          signs, and reads every shown value
//                                          back from the signed bytes;
//                                          contract.js refuses a fee above
//                                          EVM_MAX_FEE_RAW (50 NODUS);
//   3. `maxFee` (raw units)             -> a built fee above it is refused,
//                                          the review closed, nothing sent;
//   4. `confirm(review)` must return     -> anything else (false, undefined,
//      exactly `true`                      "yes", a throw) closes the review,
//                                          nothing sent;
//   5. the record (`onBroadcast`)        -> written BEFORE the envelope leaves
//                                          the process (contract.js F8);
//   6. submit, then the receipt          -> the result.
//
// The review expires NODUS_REVIEW_MS (60 s) after it was built
// (contract.js expiresAt): a confirm callback that waits longer gets "Review
// expired" and nothing is sent.

// prepare: () => Promise<view> (EvmAccount.prepare / Contract.prepareSend /
// Contract.prepareDeploy — called only after the options are checked).
// Resolves { intentId, status, receipt, createdCheck, createdExpected }:
// status 'applied-success' | 'applied-failed' (the item ran; the fee was
// paid) | 'refused' (never included: nothing charged).
export async function reviewAndSend(prepare, { confirm, maxFee, onBroadcast } = {}) {
  if (typeof confirm !== 'function') throw new Error('A confirm function is required: the SDK never signs and sends without the caller\'s confirmation. Nothing was built.');
  if (maxFee !== undefined && (typeof maxFee !== 'bigint' || maxFee < 0n)) throw new Error('maxFee is a non-negative BigInt of raw NODUS units (1 NODUS = 100000000n).');
  if (typeof onBroadcast !== 'function') throw new Error('Internal: no transaction record.');
  const view = await prepare();
  let answered = false;
  try {
    const fee = view.decoded.fee;
    if (maxFee !== undefined && fee > maxFee) {
      throw new Error(`The network fee for this transaction would be ${fee} raw units, above maxFee ${maxFee}. Nothing was sent.`);
    }
    const review = {
      op: view.op, intentId: view.intentId, fee, feeText: view.fee, expiresAt: view.expiresAt,
      rows: view.review.map(([label, value]) => [label, value]),
      decoded: { ...view.decoded, inputs: [...view.decoded.inputs] }
    };
    let ok;
    try { ok = await confirm(review); } catch (error) { throw new Error(`The confirm function failed (${error?.message || error}). Nothing was sent.`); }
    if (ok !== true) throw new Error('Not confirmed (the confirm function did not return true). Nothing was sent.');
    answered = true;
  } finally {
    if (!answered) view.cancel();
  }
  // From here contract.js owns the review: it records, submits and polls.
  // A refused or failed submission rejects with error.sent = { intentId,
  // receipt } (the outcome is uncertain; the receipt is still polled).
  const sent = await view.confirm(onBroadcast);
  let outcome;
  try { outcome = await sent.receipt; } catch (error) { throw Object.assign(error instanceof Error ? error : new Error(String(error)), { sent }); }
  return { intentId: sent.intentId, ...outcome };
}
