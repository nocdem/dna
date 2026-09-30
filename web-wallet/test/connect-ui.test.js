// Package NC-4c: the Messages preview's pure parts — the history record
// encoding (src/connect/store.js, decision 2026-09-30-nodus-connect-thin-core.md
// Ek 2: separate id / nonce / ct / tag fields, one decimal counter record per
// vault) and the UI helpers (src/connect/ui/text.js, design rev 5 §1.9).
// fake-indexeddb is not a dependency, so the IndexedDB transactions
// themselves are covered by the browser tests, not here.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  databaseNameForVault, messageRecordId, plaintextBytes, parsePlaintext, PLAINTEXT_MAX,
  encodeRecord, decodeRecord, encodeCounter, decodeCounter, nextCounter, budgetAllows, MAX_INVOCATIONS,
  COUNTER_ID, emptyState, checkState, memoryHistoryStore
} from '../src/connect/store.js';
import {
  parseContactId, shortId, inspectUntrusted, httpsLink, profilePatch, profileStatusText, senderClockLabel,
  recentDays, isDelivered, pendingOutbox, OUTBOX_MAX, compareLocal, receivedKey
} from '../src/connect/ui/text.js';

const FP = 'ab'.repeat(64), OTHER = 'cd'.repeat(64);
const bytes = (value, length) => new Uint8Array(length).fill(value);

test('database name is the vault id as 32 lowercase hex characters (S8)', () => {
  const id = btoa(String.fromCharCode(...Array.from({ length: 16 }, (_, i) => i * 17)));
  assert.equal(databaseNameForVault(id), '00112233445566778899aabbccddeeff');
  assert.throws(() => databaseNameForVault(btoa('short')));
  assert.throws(() => databaseNameForVault(undefined));
  assert.throws(() => databaseNameForVault(btoa('0123456789abcdef').replace('=', '')));
});

test('a stored record keeps id, nonce (12), ct and tag (16) as separate byte fields (own copies) and round-trips', () => {
  const sealed = { nonce: bytes(1, 12), ct: Uint8Array.from([0xff, 0x00, 0xaa]), tag: bytes(2, 16), counter: '1' };
  const record = encodeRecord('m00000000000000000001', sealed);
  assert.deepEqual(Object.keys(record).sort(), ['ct', 'id', 'nonce', 'tag']);
  assert.deepEqual(record.nonce, bytes(1, 12));
  assert.deepEqual(record.tag, bytes(2, 16));
  assert.deepEqual([...record.ct], [0xff, 0x00, 0xaa]);
  sealed.ct.fill(0);
  assert.deepEqual([...record.ct], [0xff, 0x00, 0xaa]);
  const args = decodeRecord(record);
  assert.deepEqual(Object.keys(args).sort(), ['ct', 'id', 'nonce', 'tag']);
  assert.equal(args.id, 'm00000000000000000001');
});

test('malformed records are refused on both sides', () => {
  assert.throws(() => encodeRecord('x', { nonce: bytes(1, 11), ct: bytes(0, 1), tag: bytes(2, 16) }));
  assert.throws(() => encodeRecord('x', { nonce: bytes(1, 12), ct: new Uint8Array(0), tag: bytes(2, 16) }));
  assert.throws(() => encodeRecord('x', { nonce: bytes(1, 12), ct: bytes(0, 1), tag: bytes(2, 15) }));
  assert.throws(() => encodeRecord('', { nonce: bytes(1, 12), ct: bytes(0, 1), tag: bytes(2, 16) }));
  assert.throws(() => encodeRecord('x', { nonce: '01'.repeat(12), ct: bytes(0, 1), tag: bytes(2, 16) }));
  const good = encodeRecord('x', { nonce: bytes(1, 12), ct: bytes(0, 1), tag: bytes(2, 16) });
  assert.throws(() => decodeRecord({ ...good, extra: 1 }));
  assert.throws(() => decodeRecord({ ...good, tag: new Uint8Array(15) }));
  assert.throws(() => decodeRecord({ ...good, nonce: [1, 2, 3] }));
  // A plaintext field next to the sealed ones is refused, never read.
  assert.throws(() => decodeRecord({ ...good, text: 'hello' }));
});

test('the counter record is one decimal string, bounded by 2^32 (SP 800-38D §8.3)', () => {
  assert.deepEqual(encodeCounter(0n), { id: COUNTER_ID, value: '0' });
  assert.deepEqual(encodeCounter(123456789n), { id: COUNTER_ID, value: '123456789' });
  assert.equal(decodeCounter(undefined), 0n);
  assert.equal(decodeCounter({ id: COUNTER_ID, value: '42' }), 42n);
  assert.equal(decodeCounter(encodeCounter(MAX_INVOCATIONS)), MAX_INVOCATIONS);
  for (const bad of [{ id: COUNTER_ID, value: 42 }, { id: COUNTER_ID, value: '042' }, { id: COUNTER_ID, value: '-1' },
    { id: 'other', value: '1' }, { id: COUNTER_ID, value: '1', x: 1 }, { id: COUNTER_ID, value: (MAX_INVOCATIONS + 1n).toString() }, null]) {
    assert.throws(() => decodeCounter(bad));
  }
  assert.throws(() => encodeCounter(MAX_INVOCATIONS + 1n));
  assert.throws(() => encodeCounter(1));
  assert.equal(nextCounter(5n, '6'), 6n);
  assert.throws(() => nextCounter(5n, '5'));
  assert.throws(() => nextCounter(5n, '7'));
  assert.throws(() => nextCounter(5n, 6));
  assert.equal(budgetAllows(MAX_INVOCATIONS - 2n, 2), true);
  assert.equal(budgetAllows(MAX_INVOCATIONS - 2n, 3), false);
});

test('record ids are opaque and ordered by the local sequence', () => {
  assert.equal(messageRecordId('1'), 'm00000000000000000001');
  assert.equal(messageRecordId('18446744073709551615'), 'm18446744073709551615');
  assert.ok(messageRecordId('9') < messageRecordId('10'));
  assert.throws(() => messageRecordId('01'));
  assert.throws(() => messageRecordId(1));
});

test('plaintext crosses to the core as UTF-8 JSON bytes, at most 65536, and back (wiped after parsing)', () => {
  const value = { text: 'merhaba ğüşİ 👋', fp: FP };
  const plain = plaintextBytes(value);
  assert.ok(plain instanceof Uint8Array);
  assert.deepEqual(parsePlaintext(plain), value);
  assert.ok(plain.every(b => b === 0));
  assert.throws(() => parsePlaintext(Uint8Array.from([0xff])));
  assert.throws(() => parsePlaintext('7b7d'));
  assert.equal(PLAINTEXT_MAX, 65536);
  assert.throws(() => plaintextBytes({ text: 'x'.repeat(PLAINTEXT_MAX) }), /too large/);
});

test('state shape is checked; the memory store keeps nothing and refuses after close', async () => {
  assert.deepEqual(checkState(emptyState()), emptyState());
  assert.throws(() => checkState({ ...emptyState(), version: 2 }));
  assert.throws(() => checkState({ ...emptyState(), contacts: {} }));
  assert.throws(() => checkState({ ...emptyState(), nextSeq: 'x' }));
  const store = memoryHistoryStore();
  assert.equal(store.persistent, false);
  await store.save(emptyState(), [{ seq: '1' }]);
  assert.deepEqual(store.messages, []);
  store.close();
  await assert.rejects(store.save(emptyState()));
});

test('contact IDs are 128 hex; shown shortened', () => {
  assert.equal(parseContactId(` ${FP.toUpperCase().slice(0, 64)}\n${FP.slice(64)} `), FP);
  assert.throws(() => parseContactId(FP.slice(1)), /not a valid ID/);
  assert.throws(() => parseContactId('zz'.repeat(64)));
  assert.equal(shortId(FP), 'ID abababab…abab');
  assert.equal(shortId('nope'), 'ID ?');
});

test('untrusted text: direction controls and invisible characters removed and flagged; mixed look-alike scripts flagged', () => {
  assert.deepEqual(inspectUntrusted('hello'), { text: 'hello', unusual: false });
  assert.deepEqual(inspectUntrusted('Merhaba dünya'), { text: 'Merhaba dünya', unusual: false });
  assert.deepEqual(inspectUntrusted('Привет'), { text: 'Привет', unusual: false });
  assert.deepEqual(inspectUntrusted('abc‮gpj.exe'), { text: 'abcgpj.exe', unusual: true });
  assert.deepEqual(inspectUntrusted('no​de'), { text: 'node', unusual: true });
  assert.equal(inspectUntrusted('pаypal').unusual, true); // Cyrillic a inside Latin
  assert.deepEqual(inspectUntrusted(undefined), { text: '', unusual: false });
});

test('websites are links only for https: URLs', () => {
  assert.equal(httpsLink('https://nodusnetwork.io/x'), 'https://nodusnetwork.io/x');
  for (const bad of ['http://a.b', 'javascript:alert(1)', 'data:text/html,x', 'https://u:p@a.b', 'nodus', '', null]) assert.equal(httpsLink(bad), null);
  assert.deepEqual(profilePatch({ bio: 'b', location: 'l', website: ' https://a.b ' }), { bio: 'b', location: 'l', website: 'https://a.b' });
  assert.deepEqual(profilePatch({ bio: 'b' }), { bio: 'b', location: '', website: '' });
  assert.throws(() => profilePatch({ website: 'http://a.b' }), /https/);
  assert.throws(() => profilePatch({ bio: 5 }));
});

test('profile statuses are plain words; "taken" says it cannot be changed here', () => {
  assert.match(profileStatusText('taken'), /cannot be changed/);
  assert.match(profileStatusText('wait'), /nothing was changed/);
  for (const s of ['published', 'wait', 'taken', 'failed', 'bad_patch', undefined]) {
    assert.doesNotMatch(profileStatusText(s), /DHT|fingerprint|salt|nonce|EXCLUSIVE/i);
  }
});

test("the sender's time is labelled as the sender's clock", () => {
  assert.equal(senderClockLabel('0'), "sender's clock: 1970-01-01 00:00 UTC");
  assert.equal(senderClockLabel('86400'), "sender's clock: 1970-01-02 00:00 UTC");
  assert.equal(senderClockLabel('x'), "sender's clock: unknown");
  assert.equal(senderClockLabel(5), "sender's clock: unknown");
});

test('routine fetch reads yesterday, today and tomorrow', () => {
  assert.deepEqual(recentDays('20000'), ['19999', '20000', '20001']);
  assert.deepEqual(recentDays('0'), ['0', '1']);
  assert.throws(() => recentDays('-1'));
});

test('pending set: own undelivered messages to that contact within 7 days, in local order, capped at 1000', () => {
  const now = '1000000';
  const msgs = [
    { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '999990' },
    { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '999000' },
    { seq: '2', fp: FP, dir: 'in', text: 'x', senderTs: '999500' },
    { seq: '4', fp: OTHER, dir: 'out', text: 'o', ts: '999999' },
    { seq: '5', fp: FP, dir: 'out', text: 'old', ts: String(1000000 - 7 * 86400) }
  ];
  assert.deepEqual(pendingOutbox(msgs, FP, now, undefined), [{ seq: '1', ts: '999000', text: 'a' }, { seq: '3', ts: '999990', text: 'c' }]);
  assert.deepEqual(pendingOutbox(msgs, FP, now, '999000'), [{ seq: '3', ts: '999990', text: 'c' }]);
  assert.deepEqual(pendingOutbox(msgs, FP, now, '999990'), []);
  const many = Array.from({ length: OUTBOX_MAX + 5 }, (_, i) => ({ seq: String(i + 1), fp: FP, dir: 'out', text: 't', ts: now }));
  const capped = pendingOutbox(many, FP, now, undefined);
  assert.equal(capped.length, OUTBOX_MAX);
  assert.equal(capped[0].seq, '6');
  assert.equal(isDelivered({ ts: '5' }, '0'), false);
  assert.equal(isDelivered({ ts: '5' }, '5'), true);
});

test('local order is the local sequence, not the sender clock; received messages de-duplicate', () => {
  const list = [{ seq: '10' }, { seq: '9' }, { seq: '100' }].sort(compareLocal);
  assert.deepEqual(list.map(m => m.seq), ['9', '10', '100']);
  const a = receivedKey(FP, { seq: '1', senderTs: '5', text: 'hi' });
  assert.equal(a, receivedKey(FP, { seq: 1, senderTs: 5, text: 'hi' }));
  assert.notEqual(a, receivedKey(OTHER, { seq: '1', senderTs: '5', text: 'hi' }));
  assert.notEqual(a, receivedKey(FP, { seq: '1', senderTs: '5', text: 'hi!' }));
});
