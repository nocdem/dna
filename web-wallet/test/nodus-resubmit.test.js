// A NODUS transaction the node answered "busy" at Confirm (web 0.1.124,
// src/nodus/resubmit.js). The node forwarded nothing; the envelope is
// already signed and its record holds the coins. These tests pin the
// re-submit decision and that "Try again" sends the SAME signed bytes:
//   - busy at the first submit   -> the bytes are kept on the record, pending;
//   - busy again                 -> the same bytes stay kept, same state;
//   - accepted                   -> the bytes are dropped, "submitted" note;
//   - final (expired / included) -> the bytes are dropped, nothing is sent,
//                                   and an expired record frees its coins
//                                   exactly as before (lockedInputs);
//   - any other refusal          -> the bytes are dropped, today's handling
//                                   ('unknown', coins held until expiry).
// With the TEST-ONLY mock module (test/nodus-mock-module.js) set to return
// different bytes per build (`hedged`, like the real module's hedged
// signature), the busy-then-accepted run proves the second submission is
// byte-for-byte the first and that nothing was built or signed again.
// NOT covered here (DOM wiring, no unit seam; no browser suite drives the
// NODUS send against a fake node): the Activity row's "Try again" button and
// the status-line text in src/app.js — absent coverage, not a pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient } from '../src/nodus/client.js';
import { keepBusyEnvelope, canResubmit, dropSettledEnvelope, resubmitKept, busyReadyText, NODUS_READY_PAYMENT_TEXT, NODUS_READY_TRANSACTION_TEXT, NODUS_UNCERTAIN_NOTE, NODUS_SUBMITTED_NOTE } from '../src/nodus/resubmit.js';
import { prepareTransfer } from '../src/wallet.js';
import { recordActivity } from '../src/activity.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
import { lockedInputs } from '../src/adapters/nodus.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, INTENT_ID, busyError, coin, NODUS_NATIVE } from './nodus-mock-module.js';

const ENVELOPE = Uint8Array.of(4, 5, 6, 7);
const INPUT = coin(2, '1').nullifier;
const pendingRow = (extra = {}) => ({ chain: 'nodus', address: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.5', hash: INTENT_ID, status: 'pending', note: 'Broadcast outcome pending.', expiryHeight: '1090', fromHeight: '1001', inputs: [INPUT], createdAt: new Date().toISOString(), ...extra });
const busyFor = (envelope = ENVELOPE, intentId = INTENT_ID) => Object.assign(busyError(), { envelope, intentId });

async function readyClient() {
  const mock = createMockNodusModule();
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 7, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}
const walletFor = client => ({ addresses: { nodus: FINGERPRINT }, nodusClient: client });

test('resubmit: the plain texts', () => {
  assert.equal(NODUS_READY_PAYMENT_TEXT, 'The network is busy. Your payment is ready — press Try again to send it.');
  assert.equal(busyReadyText(undefined), NODUS_READY_PAYMENT_TEXT);
  for (const kind of ['delegate', 'undelegate', 'stake', 'name']) assert.equal(busyReadyText(kind), NODUS_READY_TRANSACTION_TEXT);
});

test('resubmit: a busy answer at the first submit keeps the signed bytes on the record, pending', () => {
  const row = pendingRow();
  assert.equal(keepBusyEnvelope(row, busyFor()), true);
  assert.equal(row.envelope, ENVELOPE, 'the very bytes the adapter submitted');
  assert.equal(row.status, 'pending'); assert.equal(row.note, NODUS_READY_PAYMENT_TEXT);
  assert.equal(canResubmit(row), true);
  // its coins stay held for these bytes
  assert.ok(lockedInputs([row]).has(INPUT));
});

test('resubmit: nothing is kept for anything but a busy answer about THIS record', () => {
  const cases = [
    ['a refusal / other failure', new Error('The Nodus network did not accept this transfer.')],
    ['busy text without the mark', Object.assign(new Error('The network is busy right now. Try again in a few seconds.'), { envelope: ENVELOPE, intentId: INTENT_ID })],
    ['busy without the bytes', busyError()],
    ['busy with empty bytes', busyFor(new Uint8Array(0))],
    ['busy with bytes that are not a Uint8Array', busyFor([4, 5, 6])],
    ['busy for another intent', busyFor(ENVELOPE, '8'.repeat(128))]
  ];
  for (const [what, error] of cases) {
    const row = pendingRow();
    assert.equal(keepBusyEnvelope(row, error), false, what);
    assert.equal(row.envelope, undefined, what); assert.equal(row.note, 'Broadcast outcome pending.', what);
    assert.equal(canResubmit(row), false, what);
  }
  const final = pendingRow({ status: 'expired' });
  assert.equal(keepBusyEnvelope(final, busyFor()), false);
  assert.equal(keepBusyEnvelope(undefined, busyFor()), false);
});

test('resubmit: busy again keeps the same bytes and the same state', async () => {
  const row = pendingRow(); keepBusyEnvelope(row, busyFor());
  const sent = [];
  const result = await resubmitKept(row, async envelope => { sent.push(envelope); throw busyError(); });
  assert.equal(result.outcome, 'busy');
  assert.deepEqual(sent, [ENVELOPE]); assert.equal(sent[0], ENVELOPE);
  assert.equal(row.envelope, ENVELOPE); assert.equal(row.status, 'pending'); assert.equal(row.note, NODUS_READY_PAYMENT_TEXT);
  assert.equal(canResubmit(row), true);
  // and once more
  assert.equal((await resubmitKept(row, async () => { throw busyError(); })).outcome, 'busy');
  assert.equal(row.envelope, ENVELOPE);
});

test('resubmit: accepted clears the kept bytes; the record is tracked as any submitted send', async () => {
  const row = pendingRow({ kind: 'delegate' }); keepBusyEnvelope(row, busyFor());
  assert.equal(row.note, NODUS_READY_TRANSACTION_TEXT);
  const sent = [];
  const result = await resubmitKept(row, async envelope => { sent.push(envelope); return { accepted: true }; });
  assert.equal(result.outcome, 'sent'); assert.equal(sent[0], ENVELOPE);
  assert.equal(row.envelope, undefined); assert.equal(row.status, 'pending'); assert.equal(row.note, NODUS_SUBMITTED_NOTE);
  assert.equal(canResubmit(row), false);
  assert.ok(lockedInputs([row]).has(INPUT), 'still held until included or expired');
  assert.equal((await resubmitKept(row, async () => assert.fail('nothing kept, nothing sent'))).outcome, 'none');
});

test('resubmit: past expiry the bytes are released, nothing is sent, and the coins are free as before', async () => {
  const row = pendingRow(); keepBusyEnvelope(row, busyFor());
  // the tracker's scan saw the chain pass the expiry block
  Object.assign(row, { status: 'expired', note: 'Not included before block 1090; it can no longer be included and its coins are free again.' });
  assert.equal(canResubmit(row), false);
  assert.equal(lockedInputs([row]).has(INPUT), false);
  const result = await resubmitKept(row, async () => assert.fail('an expired envelope is never sent'));
  assert.equal(result.outcome, 'settled'); assert.equal(row.envelope, undefined);
  // the render path drops them too
  const included = pendingRow(); keepBusyEnvelope(included, busyFor());
  included.status = 'confirmed'; dropSettledEnvelope(included);
  assert.equal(included.envelope, undefined);
  const open = pendingRow(); keepBusyEnvelope(open, busyFor()); dropSettledEnvelope(open);
  assert.equal(open.envelope, ENVELOPE, 'a pending record keeps them');
  // final while the node was being asked (busy answer): released, not kept
  const racing = pendingRow(); keepBusyEnvelope(racing, busyFor());
  assert.equal((await resubmitKept(racing, async () => { racing.status = 'expired'; throw busyError(); })).outcome, 'settled');
  assert.equal(racing.envelope, undefined);
});

test('resubmit: any non-busy answer releases the bytes and applies today\'s handling', async () => {
  for (const [what, submit, expected] of [
    ['refused (CheckTx)', async () => ({ accepted: false, message: 'mempool refused' }), { message: 'mempool refused' }],
    ['refused without a message', async () => ({ accepted: false }), { message: '' }],
    ['no answer object', async () => undefined, { message: '' }],
    ['failed otherwise', async () => { throw new Error('Nodus connection is not ready.'); }, { error: 'Nodus connection is not ready.' }]
  ]) {
    const row = pendingRow(); keepBusyEnvelope(row, busyFor());
    const result = await resubmitKept(row, submit);
    assert.equal(result.outcome, 'refused', what);
    if ('message' in expected) assert.equal(result.message, expected.message, what);
    else assert.equal(result.error.message, expected.error, what);
    assert.equal(row.envelope, undefined, what);
    assert.equal(row.status, 'unknown', what); assert.equal(row.note, NODUS_UNCERTAIN_NOTE, what);
    assert.equal(canResubmit(row), false, what);
    assert.ok(lockedInputs([row]).has(INPUT), `${what}: coins held until the expiry block passes`);
  }
});

test('resubmit: the kept bytes never reach the saved Activity', async () => {
  const row = pendingRow(); keepBusyEnvelope(row, busyFor());
  const id = btoa(String.fromCharCode(...new Uint8Array(16).fill(3)));
  const key = await activityKeyFor('abandon '.repeat(23) + 'art', id);
  const [back] = await parseActivity(await serializeActivity(id, [row], key), id, { nodus: FINGERPRINT }, key);
  assert.equal(back.envelope, undefined);
  assert.deepEqual({ hash: back.hash, inputs: back.inputs, expiryHeight: back.expiryHeight }, { hash: INTENT_ID, inputs: [INPUT], expiryHeight: '1090' });
});

test('resubmit, send path: busy at Confirm, busy again, then accepted — three submissions of the SAME bytes, one signing', async () => {
  const { mock, client } = await readyClient();
  mock.state.hedged = true;            // each build signs different bytes
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', asset: NODUS_NATIVE, to: RECIPIENT, amount: '1.5' });
  assert.equal(mock.state.builds, 1);
  mock.state.busy.add('submit');
  let record;
  const error = await transfer.confirm(async details => { record = recordActivity(transfer, details); }).then(() => assert.fail('busy must reject'), e => e);
  assert.equal(error.busy, true);
  assert.equal(mock.state.submissions.length, 1);
  assert.deepEqual(error.envelope, mock.state.submissions[0]); assert.equal(error.intentId, INTENT_ID);
  assert.equal(keepBusyEnvelope(record, error), true);
  assert.equal(record.hash, INTENT_ID); assert.equal(record.status, 'pending');
  // "Try again" while still busy
  const submit = envelope => client.submit({ envelope });
  assert.equal((await resubmitKept(record, submit)).outcome, 'busy');
  assert.equal(canResubmit(record), true);
  // the node answers again
  mock.state.busy.delete('submit');
  assert.equal((await resubmitKept(record, submit)).outcome, 'sent');
  assert.equal(mock.state.submissions.length, 3);
  for (const bytes of mock.state.submissions) assert.deepEqual(bytes, mock.state.submissions[0]);
  assert.deepEqual(mock.state.submitted, mock.state.submissions[0]);
  assert.deepEqual([...mock.state.submissions[0]], [1, 2, 3, 1], 'the first build\'s bytes');
  assert.equal(mock.state.builds, 1, 'nothing was built or signed again');
  assert.equal(record.envelope, undefined); assert.equal(record.note, NODUS_SUBMITTED_NOTE);
  assert.equal(client.state, 'ready');
  client.lock();
});

test('resubmit, send path: a refusal at Confirm keeps nothing (today\'s handling)', async () => {
  const { mock, client } = await readyClient();
  mock.state.accepted = false;
  const transfer = await prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', asset: NODUS_NATIVE, to: RECIPIENT, amount: '1.5' });
  let record;
  const error = await transfer.confirm(async details => { record = recordActivity(transfer, details); }).then(() => assert.fail('a refusal must reject'), e => e);
  assert.match(error.message, /did not accept/);
  assert.equal(error.envelope, undefined);
  assert.equal(keepBusyEnvelope(record, error), false);
  assert.equal(canResubmit(record), false);
  client.lock();
});
