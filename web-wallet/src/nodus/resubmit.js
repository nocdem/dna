// A NODUS transaction the node answered "busy" at Confirm (web 0.1.124).
//
// Since 0.1.119 a node's RATE_LIMITED answer reaches the wallet as an Error
// marked `busy` (./client.js isNodusBusy): the node forwarded NOTHING and the
// same request may be made again. At Confirm the envelope is already signed
// and its Activity record — whose inputs hold the coins (src/adapters/
// nodus.js lockedInputs) — is already durable. Building a new envelope cannot
// help: it could not use the held coins, and a new signing gives different
// bytes (the ML-DSA-87 signature is hedged). So the adapter puts the SAME
// signed bytes and their intent id on the busy error (src/adapters/nodus.js
// submitSigned), and the wallet keeps them on the record and offers "Try
// again", which sends exactly those bytes again — same intent id, same wire
// id — until the record is final:
//   - accepted          -> bytes dropped; tracked to confirmed as any send;
//   - busy again        -> bytes kept, same state;
//   - any other answer  -> bytes dropped; today's handling: 'unknown',
//                          coins held until the scan sees the expiry block;
//   - record final      -> bytes dropped (included, or expired: the scan saw
//                          the chain pass its expiry block and its coins are
//                          free again, as before).
// The bytes live on the record in memory only (`envelope`, like `wire`):
// src/activity-storage.js serializeActivity writes an explicit field list
// that does not include them, and the lock empties the record list. After a
// reload the record stays pending until its expiry block, as before 0.1.124.
import { isNodusBusy } from './client.js';
import { terminal } from '../activity.js';

export const NODUS_READY_PAYMENT_TEXT = 'The network is busy. Your payment is ready — press Try again to send it.';
export const NODUS_READY_TRANSACTION_TEXT = 'The network is busy. Your transaction is ready — press Try again to send it.';
// `kind`: the record's action (src/activity.js recordActivity); none = a
// plain transfer.
export const busyReadyText = kind => (kind ? NODUS_READY_TRANSACTION_TEXT : NODUS_READY_PAYMENT_TEXT);
export const NODUS_UNCERTAIN_NOTE = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.';
export const NODUS_SUBMITTED_NOTE = 'Broadcast submitted; awaiting confirmation.';

// After the first submission of `record`'s envelope failed with `error`:
// when the node answered busy for THIS record's envelope, keep its signed
// bytes on the record, leave it pending and return true. Otherwise change
// nothing and return false (the caller applies today's handling).
export function keepBusyEnvelope(record, error) {
  if (!record || terminal(record.status) || !isNodusBusy(error)) return false;
  if (!(error.envelope instanceof Uint8Array) || error.envelope.length === 0 || error.intentId !== record.hash) return false;
  record.envelope = error.envelope;
  record.status = 'pending';
  record.note = busyReadyText(record.kind);
  return true;
}

// Whether `row` offers "Try again" now.
export const canResubmit = row => !!row && row.envelope instanceof Uint8Array && row.envelope.length > 0 && !terminal(row.status);

// Drops the kept bytes of a record that became final (included or expired).
export function dropSettledEnvelope(row) {
  if (row && row.envelope !== undefined && terminal(row.status)) delete row.envelope;
}

// Sends the kept bytes of `record` again through `submit` (envelope ->
// Promise<{ accepted, message? }>, the NODUS client's submit) and applies the
// outcome to the record. Resolves { outcome, error?, message? } with outcome
//   'sent'     accepted: bytes dropped, note "submitted";
//   'busy'     answered busy again: bytes kept, status unchanged;
//   'refused'  refused or failed otherwise: bytes dropped, 'unknown';
//   'settled'  the record is already final: bytes dropped, nothing sent;
//   'none'     no kept bytes: nothing sent.
export async function resubmitKept(record, submit) {
  if (!record || !(record.envelope instanceof Uint8Array)) return { outcome: 'none' };
  if (terminal(record.status)) { delete record.envelope; return { outcome: 'settled' }; }
  const envelope = record.envelope;
  let result;
  try { result = await submit(envelope); }
  catch (error) {
    if (isNodusBusy(error)) {
      // The record may have become final while the node was asked.
      if (terminal(record.status)) { delete record.envelope; return { outcome: 'settled' }; }
      record.note = busyReadyText(record.kind);
      return { outcome: 'busy', error };
    }
    delete record.envelope;
    if (!terminal(record.status)) { record.status = 'unknown'; record.note = NODUS_UNCERTAIN_NOTE; }
    return { outcome: 'refused', error };
  }
  delete record.envelope;
  if (result?.accepted === true) {
    if (!terminal(record.status)) record.note = NODUS_SUBMITTED_NOTE;
    return { outcome: 'sent' };
  }
  if (!terminal(record.status)) { record.status = 'unknown'; record.note = NODUS_UNCERTAIN_NOTE; }
  return { outcome: 'refused', message: typeof result?.message === 'string' ? result.message : '' };
}
