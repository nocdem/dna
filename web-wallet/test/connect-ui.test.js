// Package NC-4c: the Messages preview's pure parts — the history record
// encoding (src/connect/store.js, decision 2026-09-30-nodus-connect-thin-core.md
// Ek 2: separate id / nonce / ct / tag fields, one decimal counter record per
// vault) and the UI helpers (src/connect/ui/text.js, design rev 5 §1.9).
// NOT COVERED ANYWHERE YET: the IndexedDB transactions of openHistoryStore
// (readAll / writeAll / oncomplete / onabort, the counter record written in
// the same transaction). fake-indexeddb is not a dependency and no browser
// test opens the Messages page, so those paths have no automated test.
// deleteVaultHistory is covered below against a minimal stub of
// indexedDB.deleteDatabase (the request's events only, not a database).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  databaseNameForVault, messageRecordId, plaintextBytes, parsePlaintext, PLAINTEXT_MAX,
  encodeRecord, decodeRecord, encodeCounter, decodeCounter, nextCounter, budgetAllows, MAX_INVOCATIONS,
  COUNTER_ID, emptyState, checkState, memoryHistoryStore,
  counterStorageKey, readStoredCounter, writeStoredCounter, openingCounter, deleteVaultHistory, HistoryDeleteBlocked,
  openHistoryStore, StorageError, HISTORY_SLOW_TEXT
} from '../src/connect/store.js';
import {
  parseContactId, parseContactInput, requestRefusal, shortId, inspectUntrusted, httpsLink, profilePatch, profileStatusText, senderClockLabel,
  recentDays, isDelivered, pendingOutbox, OUTBOX_MAX, compareLocal, receivedKey,
  publishedSeqs, markPublished, markDelivered, ackToSend, messageStatus,
  hasUndelivered, DELIVERED_GRACE_SECONDS, avatarSource, AVATAR_MAX_B64, avatarPatch, AVATAR_UPLOAD_MAX_B64,
  needFullSync, fullDays, SMART_SYNC_FULL_SECONDS, contactNeedsFullSync, contactDays, checkOrder, profileFresh, PROFILE_CACHE_SECONDS,
  CHECK_STAGES, updatingStageText, checkingContactsText, roundStartLine, stageLine, stageStartLine, contactStartLine, contactStepLine,
  saltShortText, daysRead, contactLine, roundDoneLine
} from '../src/connect/ui/text.js';
import { scrubLogText } from '../src/session-log.js';
import {
  keptChainName, chainLookupNeeded, chainLookupSpaced, CHAIN_LOOKUP_SPACING_MS, chainNameAfterLookup, shownOwnName, profileEntryText, PROFILE_ENTRY_TEXT,
  resolveContactName, NAME_NOT_READY_TEXT, NAME_UNREGISTERED_TEXT, NAME_LOOKUP_FAILED_TEXT, NAME_CHECK_TEXT
} from '../src/connect/ui/chain-names.js';
import { NAME_CHECK_ROW } from '../src/adapters/nodus.js';
import { newDiag, diagSalt, diagDay, errorText, diagText } from '../src/connect/ui/diag.js';
import { ownIdText, OWN_ID_WAITING_TEXT, OWN_ID_CLOSED_TEXT } from '../src/connect/ui/messages.js';

// A localStorage stand-in (getItem / setItem / removeItem).
function memoryStorage() {
  const map = new Map();
  return {
    getItem: key => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    removeItem: key => { map.delete(key); },
    map
  };
}

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

// Add contact by chain name (2026-10-07): the box takes an ID or a chain
// name, read with the wallet's own name rule (src/nodus/names.js chainName).
test('add-contact input: an ID stays an ID; a chain name is a name; anything else is one plain error', () => {
  // An ID — whitespace and case as parseContactId — is never read as a name.
  assert.deepEqual(parseContactInput(` ${FP.toUpperCase().slice(0, 64)}\n${FP.slice(64)} `), { fp: FP });
  // A name: trimmed, A-Z lowered (the wallet's send rule).
  assert.deepEqual(parseContactInput('  Punk '), { name: 'punk' });
  assert.deepEqual(parseContactInput('jarvis2'), { name: 'jarvis2' });
  assert.deepEqual(parseContactInput('dead'), { name: 'dead' });          // all-hex but shorter than 8: a name
  assert.deepEqual(parseContactInput('z'.repeat(36)), { name: 'z'.repeat(36) });
  // Neither (an all-hex name of 8+ — at any length up to 36 — reads as an ID prefix).
  for (const bad of ['', 'ab', 'pu-nk', 'pu nk', 'z'.repeat(37), 'a'.repeat(36), 'deadbeef', FP.slice(1), 'zz'.repeat(64), 'ünal', null]) {
    assert.throws(() => parseContactInput(bad), /not a valid ID or chain name/, String(bad));
  }
});

test('add-contact refusals: own ID, existing contact, already requested — the same words for a typed ID and a name owner', () => {
  assert.equal(requestRefusal(FP, { ownFp: FP }), 'That is your own ID.');
  assert.equal(requestRefusal(OTHER, { ownFp: FP, isContact: true }), 'This person is already a contact.');
  assert.equal(requestRefusal(OTHER, { ownFp: FP, isRequested: true }), 'You already sent this person a request.');
  assert.equal(requestRefusal(OTHER, { ownFp: FP }), '');
});

// A stand-in for the wallet's NODUS client (src/nodus/client.js): only what
// resolveChainName reads. Answers are shaped as test/nodus-mock-module.js
// nameLookup (decimal-string heights).
function nameClient(names, { state = 'ready', nameable = true, error } = {}) {
  const asked = [];
  return {
    state, nameable, asked,
    async nameLookup({ name }) {
      asked.push(name);
      if (error) throw error;
      return names[name] ? { found: true, committedHeight: '1000', owner: names[name], registeredHeight: '900' } : { found: false, committedHeight: '1000' };
    }
  };
}

test('add-contact by name: resolved through the wallet lookup to the owner ID', async () => {
  const client = nameClient({ punk: OTHER });
  assert.deepEqual(await resolveContactName(client, 'punk'), { name: 'punk', owner: OTHER, committedHeight: 1000n });
  assert.deepEqual(client.asked, ['punk']);
  // The caution shown under a resolved name is the wallet's own text.
  assert.equal(NAME_CHECK_TEXT, NAME_CHECK_ROW[1]);
  assert.match(NAME_CHECK_TEXT, /look alike/);
});

test('add-contact by name: unregistered, network not ready and a failed lookup are plain errors; nothing falls back', async () => {
  // Unregistered: mapped from the real resolveChainName error (src/adapters/nodus.js).
  await assert.rejects(resolveContactName(nameClient({ punk: OTHER }), 'nobody'), new Error(NAME_UNREGISTERED_TEXT));
  assert.equal(NAME_UNREGISTERED_TEXT, 'No one has registered that name.');
  // Not ready: no client, a client that is not ready, a module without names — nothing is asked.
  for (const client of [undefined, nameClient({ punk: OTHER }, { state: 'connecting' }), nameClient({ punk: OTHER }, { nameable: false })]) {
    await assert.rejects(resolveContactName(client, 'punk'), new Error(NAME_NOT_READY_TEXT));
    if (client) assert.deepEqual(client.asked, []);
  }
  // The node failed, or answered something malformed.
  await assert.rejects(resolveContactName(nameClient({}, { error: new Error('rc=7') }), 'punk'), new Error(NAME_LOOKUP_FAILED_TEXT));
  const malformed = nameClient({ punk: 'xyz' });
  await assert.rejects(resolveContactName(malformed, 'punk'), new Error(NAME_LOOKUP_FAILED_TEXT));
});

test('add-contact by name: an owner that is this wallet, a contact or already requested gets the ID refusals', async () => {
  // 'mine', not 'me': a chain name is 3..36 characters, so 'me' never reaches the owner check.
  const client = nameClient({ mine: FP, friend: OTHER });
  const own = await resolveContactName(client, 'mine');
  assert.equal(requestRefusal(own.owner, { ownFp: FP }), 'That is your own ID.');
  const friend = await resolveContactName(client, 'friend');
  assert.equal(requestRefusal(friend.owner, { ownFp: FP, isContact: true }), 'This person is already a contact.');
  assert.equal(requestRefusal(friend.owner, { ownFp: FP, isRequested: true }), 'You already sent this person a request.');
});

test('untrusted text: direction controls and invisible characters removed and flagged; mixed look-alike scripts flagged', () => {
  assert.deepEqual(inspectUntrusted('hello'), { text: 'hello', unusual: false, check: false });
  assert.deepEqual(inspectUntrusted('Merhaba dünya'), { text: 'Merhaba dünya', unusual: false, check: false });
  assert.deepEqual(inspectUntrusted('Привет'), { text: 'Привет', unusual: false, check: false });
  assert.deepEqual(inspectUntrusted('abc‮gpj.exe'), { text: 'abcgpj.exe', unusual: true, check: false });
  assert.deepEqual(inspectUntrusted('no​de'), { text: 'node', unusual: true, check: false });
  assert.equal(inspectUntrusted('pаypal').unusual, true); // Cyrillic a inside Latin
  assert.deepEqual(inspectUntrusted(undefined), { text: '', unusual: false, check: false });
});

test('the wider invisible set is removed and flagged: tag characters, variation selectors, deprecated format controls, CGJ, line/paragraph separators', () => {
  for (const hidden of ['\u{E0020}', '\u{E0041}', '\u{E007F}', '︀', '️', '⁪', '⁯', '͏', ' ', ' ']) {
    assert.deepEqual(inspectUntrusted(`no${hidden}de`), { text: 'node', unusual: true, check: false }, `U+${hidden.codePointAt(0).toString(16)}`);
  }
  // RT2 L2 F4: the whole Default_Ignorable_Code_Point set, not a hand list
  for (const cp of [0xE0080, 0xE0100, 0xE01EF, 0xE0001, 0x180B, 0x180F, 0xFFF0, 0x1D173, 0x2065, 0x1BCA0]) {
    assert.deepEqual(inspectUntrusted(`no${String.fromCodePoint(cp)}de`), { text: 'node', unusual: true, check: false }, `U+${cp.toString(16)}`);
  }
  // a visible character next to the ranges: kept, not flagged
  assert.equal(inspectUntrusted('a︐b').unusual, false);
});

test('names: one letter of another script inside a Latin name is unusual; mixed-language message text is not', () => {
  const name = value => inspectUntrusted(value, { name: true });
  assert.equal(name('aliօe').unusual, true);        // Armenian oh
  assert.equal(name('payᎢal').unusual, true);       // Cherokee
  assert.equal(name('Ali 王').unusual, true);        // Han inside a Latin name
  assert.equal(name('Çağrı').unusual, false);
  assert.equal(inspectUntrusted('hello 世界').unusual, false); // message text
});

test('sender clock: a safe integer past the Date range is "unknown", never a thrown render', () => {
  assert.equal(senderClockLabel('8640000000001'), "sender's clock: unknown");
  assert.equal(senderClockLabel('9007199254740'), "sender's clock: unknown");
  assert.match(senderClockLabel('1790000000'), /^sender's clock: 2026-/);
});

test('names: a whole-script non-Latin name and fullwidth Latin are marked "check carefully"; message text is not', () => {
  const name = value => inspectUntrusted(value, { name: true });
  assert.deepEqual(name('alice'), { text: 'alice', unusual: false, check: false });
  assert.deepEqual(name('Çağrı'), { text: 'Çağrı', unusual: false, check: false });
  assert.equal(name('Привет').check, true);             // Cyrillic only
  assert.equal(name('ραypal').unusual, true);            // mixed: already unusual
  assert.equal(name('αλφα').check, true);                // Greek only
  assert.equal(name('李明').check, true);                // no Latin letter at all
  assert.equal(name('ｐａｙｐａｌ').check, true);          // fullwidth Latin
  assert.equal(name('payｐal').check, true);         // one fullwidth letter
  assert.equal(name('1234').check, false);               // no letters
  assert.equal(inspectUntrusted('Привет').check, false);  // not a name
  assert.equal(inspectUntrusted('ｐａｙｐａｌ').check, false);
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

test('pending set: own undelivered messages to that contact within 7 days, in local order, capped at 50 (the app per-bucket cap)', () => {
  assert.equal(OUTBOX_MAX, 50);
  const now = '1000000';
  const msgs = [
    { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '999990' },
    { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '999000' },
    { seq: '2', fp: FP, dir: 'in', text: 'x', senderTs: '999500' },
    { seq: '4', fp: OTHER, dir: 'out', text: 'o', ts: '999999' },
    { seq: '5', fp: FP, dir: 'out', text: 'old', ts: String(1000000 - 7 * 86400) }
  ];
  assert.deepEqual(pendingOutbox(msgs, FP, now), [{ seq: '1', ts: '999000', text: 'a' }, { seq: '3', ts: '999990', text: 'c' }]);
  // delivered is a per-message flag, never derived from an ACK time alone
  msgs[1].delivered = true;
  assert.deepEqual(pendingOutbox(msgs, FP, now), [{ seq: '3', ts: '999990', text: 'c' }]);
  msgs[0].delivered = true;
  assert.deepEqual(pendingOutbox(msgs, FP, now), []);
  const many = Array.from({ length: OUTBOX_MAX + 5 }, (_, i) => ({ seq: String(i + 1), fp: FP, dir: 'out', text: 't', ts: now }));
  const capped = pendingOutbox(many, FP, now);
  assert.equal(capped.length, OUTBOX_MAX);
  assert.equal(capped[0].seq, '6');
  assert.equal(isDelivered({ ts: '5' }), false);
  assert.equal(isDelivered({ ts: '5', published: true }), false);
  assert.equal(isDelivered({ ts: '5', delivered: true }), true);
});

test('delivered only if the message was in a successfully published blob BEFORE the ACK was read', () => {
  const msgs = [
    { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '100', published: true },
    { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '100' },                    // never published
    { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '200', published: true },  // after the ACK value
    { seq: '4', fp: FP, dir: 'in', text: 'x', senderTs: '50' },
    { seq: '5', fp: OTHER, dir: 'out', text: 'o', ts: '10', published: true },
    { seq: '6', fp: FP, dir: 'out', text: 'd', ts: '90', published: true, delivered: true }
  ];
  // the snapshot is taken before the ACK read is issued
  const before = publishedSeqs(msgs, FP);
  assert.deepEqual([...before].sort(), ['1', '3', '6']);
  // a publish that completes after the snapshot does not count for this read
  msgs[1].published = true;
  const marked = markDelivered(msgs, FP, '150', before, '5000');
  assert.deepEqual(marked.map(m => m.seq), ['1']);
  assert.equal(marked[0].delivered, true);
  assert.equal(marked[0].deliveredAt, '5000');
  assert.equal(msgs[0].delivered, undefined, 'returns copies; the caller applies them after saving');
  // an ACK of 0, a malformed one or none marks nothing
  for (const bad of ['0', '', 'x', undefined, '-1', 150]) assert.deepEqual(markDelivered(msgs, FP, bad, before, '5000'), []);
  assert.throws(() => markDelivered(msgs, FP, '150', before, undefined));
});

test('RT2 L2 F1: a message in the ACK\'s own second is not delivered; a delivered message stays in the blob for one hour', () => {
  const msgs = [
    { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '150', published: true },
    { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '149', published: true }
  ];
  const marked = markDelivered(msgs, FP, '150', publishedSeqs(msgs, FP), '1000');
  assert.deepEqual(marked.map(m => m.seq), ['2'], 'ts == ack is not covered (seconds watermark)');
  assert.equal(DELIVERED_GRACE_SECONDS, 3600n);
  const now = 1000 + 100;
  const withDelivered = [msgs[0], marked[0]];
  // inside the grace: still published in the blob
  assert.deepEqual(pendingOutbox(withDelivered, FP, String(now)).map(m => m.seq).sort(), ['1', '2']);
  // one second before the end of the grace: still in; at the end: out
  assert.deepEqual(pendingOutbox(withDelivered, FP, String(1000 + 3599)).map(m => m.seq).sort(), ['1', '2']);
  assert.deepEqual(pendingOutbox(withDelivered, FP, String(1000 + 3600)).map(m => m.seq), ['1']);
  // a delivered record with no deliveredAt (older versions) is not in the blob
  assert.deepEqual(pendingOutbox([{ ...marked[0], deliveredAt: undefined }], FP, String(now)), []);
  // grace copies alone do not make a contact "unpublished" on open
  assert.equal(hasUndelivered([marked[0]], FP, String(now)), false);
  assert.equal(hasUndelivered(withDelivered, FP, String(now)), true);
});

test('published flags: only messages of that contact in the published set that were not flagged yet', () => {
  const msgs = [
    { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '1', published: true },
    { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '2' },
    { seq: '3', fp: OTHER, dir: 'out', text: 'c', ts: '3' }
  ];
  const set = [{ seq: '1' }, { seq: '2' }, { seq: '3' }];
  const updated = markPublished(msgs, FP, set);
  assert.deepEqual(updated.map(m => [m.seq, m.published]), [['2', true]]);
  assert.equal(msgs[1].published, undefined);
});

test('the status shown for an own message follows its flags', () => {
  assert.equal(messageStatus({}), 'waiting to send');
  assert.equal(messageStatus({ published: true }), 'sent');
  assert.equal(messageStatus({ published: true, delivered: true }), 'delivered');
});

test('the ACK value is the newest stored sender timestamp of that contact, sent only when it is new', () => {
  const msgs = [
    { seq: '1', fp: FP, dir: 'in', text: 'a', senderTs: '900' },
    { seq: '2', fp: FP, dir: 'in', text: 'b', senderTs: '1000' },
    { seq: '3', fp: FP, dir: 'in', text: 'c', senderTs: '950' },              // later on this device, older clock
    { seq: '4', fp: FP, dir: 'out', text: 'mine', ts: '99999' },             // own messages never count
    { seq: '5', fp: OTHER, dir: 'in', text: 'o', senderTs: '5000' }          // another contact never counts
  ];
  assert.equal(ackToSend(msgs, FP, undefined), '1000');
  assert.equal(ackToSend(msgs, FP, '999'), '1000');
  assert.equal(ackToSend(msgs, FP, '1000'), null, 'nothing new stored: no re-ACK');
  assert.equal(ackToSend(msgs, FP, '2000'), null);
  assert.equal(ackToSend([], FP, undefined), null, 'nothing stored: nothing to ACK');
  assert.equal(ackToSend([{ seq: '1', fp: FP, dir: 'in', text: 'z', senderTs: '0' }], FP, undefined), null);
  assert.equal(ackToSend([{ seq: '1', fp: FP, dir: 'in', text: 'z', senderTs: 'bad' }], FP, undefined), null);
  // 2^64 - 1 compares as a big integer, not as a float
  assert.equal(ackToSend([...msgs, { seq: '9', fp: FP, dir: 'in', text: 'm', senderTs: '18446744073709551615' }], FP, '18446744073709551614'), '18446744073709551615');
});

test('the per-vault counter survives a history delete: localStorage copy, max on open, strict parse', () => {
  const name = '00112233445566778899aabbccddeeff';
  const storage = memoryStorage();
  assert.equal(counterStorageKey(name), 'nodus.connect.counter.v1.' + name);
  assert.notEqual(counterStorageKey(name), 'nodus.wallet.v1');
  assert.equal(readStoredCounter(storage, name), 0n);
  writeStoredCounter(storage, name, 41n);
  assert.equal(storage.getItem(counterStorageKey(name)), '41');
  assert.equal(readStoredCounter(storage, name), 41n);
  // the database was deleted (counter record gone -> 0): the copy wins
  assert.equal(openingCounter(0n, readStoredCounter(storage, name)), 41n);
  assert.equal(openingCounter(50n, 41n), 50n);
  for (const bad of ['', '-1', '01', 'x', (MAX_INVOCATIONS + 1n).toString(), '1.5']) {
    storage.setItem(counterStorageKey(name), bad);
    assert.throws(() => readStoredCounter(storage, name), /counter/);
  }
  assert.throws(() => writeStoredCounter(storage, name, MAX_INVOCATIONS + 1n));
  assert.throws(() => readStoredCounter(undefined, name), /cannot/);
  // a storage that refuses the write fails the save (enforced, not assumed)
  assert.throws(() => writeStoredCounter({ setItem() { throw new Error('quota'); } }, name, 1n), /counter/);
});

test('deleting a saved wallet deletes its Messages database and counter; a blocked delete is reported as pending', async () => {
  const id = btoa(String.fromCharCode(...Array.from({ length: 16 }, (_, i) => i * 17)));
  const name = '00112233445566778899aabbccddeeff';
  const saved = globalThis.indexedDB;
  try {
    const storage = memoryStorage();
    storage.setItem(counterStorageKey(name), '7');
    storage.setItem(counterStorageKey('ff'.repeat(16)), '3');
    let deleted;
    globalThis.indexedDB = { deleteDatabase(n) { deleted = n; const r = {}; queueMicrotask(() => r.onsuccess?.()); return r; } };
    await deleteVaultHistory(id, storage);
    assert.equal(deleted, name);
    assert.equal(storage.getItem(counterStorageKey(name)), null);
    assert.equal(storage.getItem(counterStorageKey('ff'.repeat(16))), '3', 'another vault is untouched');

    globalThis.indexedDB = { deleteDatabase() { const r = {}; queueMicrotask(() => r.onblocked?.()); return r; } };
    await assert.rejects(deleteVaultHistory(id, memoryStorage()), HistoryDeleteBlocked);
    globalThis.indexedDB = { deleteDatabase() { const r = {}; queueMicrotask(() => r.onerror?.()); return r; } };
    await assert.rejects(deleteVaultHistory(id, memoryStorage()), /could not be deleted/);
    await assert.rejects(deleteVaultHistory('bad', memoryStorage()), /saved wallet id/);
  } finally { globalThis.indexedDB = saved; }
});

test('state: the per-contact "ACK sent" record defaults for a state saved before it existed', () => {
  const old = { version: 1, nextSeq: '1', contacts: [], outgoing: [], declined: [], acks: {} };
  assert.deepEqual(checkState(old).ackSent, {});
  assert.deepEqual(emptyState().ackSent, {});
  assert.throws(() => checkState({ ...emptyState(), ackSent: 'x' }));
  assert.throws(() => checkState({ ...emptyState(), ackSent: null }));
});

test('local order is the local sequence, not the sender clock; received messages de-duplicate', () => {
  const list = [{ seq: '10' }, { seq: '9' }, { seq: '100' }].sort(compareLocal);
  assert.deepEqual(list.map(m => m.seq), ['9', '10', '100']);
  const a = receivedKey(FP, { seq: '1', senderTs: '5', text: 'hi' });
  assert.equal(a, receivedKey(FP, { seq: 1, senderTs: 5, text: 'hi' }));
  assert.notEqual(a, receivedKey(OTHER, { seq: '1', senderTs: '5', text: 'hi' }));
  assert.notEqual(a, receivedKey(FP, { seq: '1', senderTs: '5', text: 'hi!' }));
});

test('profile picture: only bounded base64 that starts like a JPEG or PNG is shown; the type comes from the bytes', () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2]).toString('base64');
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]).toString('base64');
  assert.equal(avatarSource(jpeg), `data:image/jpeg;base64,${jpeg}`);
  assert.equal(avatarSource(png), `data:image/png;base64,${png}`);
  const gif = Buffer.from('GIF89a').toString('base64');
  for (const bad of [undefined, null, 42, '', gif, `${jpeg}"`, `${jpeg} `, jpeg.slice(0, -1), 'data:image/jpeg;base64,/9j/', `/9j/${'A'.repeat(AVATAR_MAX_B64)}`]) assert.equal(avatarSource(bad), null);
  assert.equal(avatarSource(`/9j/${'A'.repeat(AVATAR_MAX_B64 - 4)}`)?.length, 'data:image/jpeg;base64,'.length + AVATAR_MAX_B64);
});

test('profile picture patch: within the app limit, a picture, or removal', () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2]).toString('base64');
  assert.deepEqual(avatarPatch(jpeg), { avatar_base64: jpeg });
  assert.deepEqual(avatarPatch(''), { avatar_base64: '' });
  assert.throws(() => avatarPatch(`/9j/${'A'.repeat(AVATAR_UPLOAD_MAX_B64)}`), /Invalid profile picture/);
  assert.throws(() => avatarPatch(Buffer.from('GIF89a').toString('base64')), /Invalid profile picture/);
  assert.throws(() => avatarPatch(null), /Invalid profile picture/);
});

test('state: the profile cache index and message-check times default for an older state and are checked', () => {
  const old = { version: 1, nextSeq: '1', contacts: [], outgoing: [], declined: [], acks: {}, ackSent: {} };
  const s = checkState(old);
  assert.deepEqual(s.profileCache, {});
  assert.deepEqual(s.dmSync, {});
  const fp = 'a'.repeat(128);
  assert.doesNotThrow(() => checkState({ ...emptyState(), profileCache: { [fp]: { id: `p${'1'.padStart(20, '0')}`, at: '1790000000', name: '' } }, dmSync: { [fp]: '1790000000' } }));
  assert.throws(() => checkState({ ...emptyState(), profileCache: { [fp]: { id: 'state', at: '1', name: '' } } }));
  assert.throws(() => checkState({ ...emptyState(), profileCache: { [fp]: { id: `p${'1'.padStart(20, '0')}`, at: 'x', name: '' } } }));
  assert.throws(() => checkState({ ...emptyState(), dmSync: { [fp]: '-1' } }));
  assert.throws(() => checkState({ ...emptyState(), dmSync: [] }));
});

test('smart sync: 8 buckets when a contact was never checked or the oldest check is over 3 days old, else 3', () => {
  const a = 'a'.repeat(128), b = 'b'.repeat(128), now = '1790000000';
  assert.equal(needFullSync([a], {}, now), true);
  assert.equal(needFullSync([a], { [a]: now }, now), false);
  assert.equal(needFullSync([a], { [a]: String(1790000000 - SMART_SYNC_FULL_SECONDS) }, now), false);
  assert.equal(needFullSync([a], { [a]: String(1790000000 - SMART_SYNC_FULL_SECONDS - 1) }, now), true);
  assert.equal(needFullSync([a, b], { [a]: now }, now), true);
  assert.equal(needFullSync([], {}, now), false);
  assert.deepEqual(fullDays('20000'), ['19994', '19995', '19996', '19997', '19998', '19999', '20000', '20001']);
  assert.deepEqual(fullDays('3'), ['0', '1', '2', '3', '4']);
  assert.deepEqual(recentDays('20000'), ['19999', '20000', '20001']);
  assert.throws(() => fullDays('x'));
});

test('smart sync per contact (0.1.72): only a contact never checked, or checked over 3 days ago, reads 8 buckets', () => {
  const a = 'a'.repeat(128), b = 'b'.repeat(128), c = 'c'.repeat(128), now = '1790000000', today = '20000';
  const dmSync = { [a]: now, [b]: String(1790000000 - SMART_SYNC_FULL_SECONDS - 1), [c]: '0' };
  assert.equal(contactNeedsFullSync(a, dmSync, now), false);
  assert.equal(contactNeedsFullSync(a, { [a]: String(1790000000 - SMART_SYNC_FULL_SECONDS) }, now), false, 'exactly 3 days: recent');
  assert.equal(contactNeedsFullSync(b, dmSync, now), true, 'over 3 days: full');
  assert.equal(contactNeedsFullSync(c, dmSync, now), true, '0 counts as never checked');
  assert.equal(contactNeedsFullSync('d'.repeat(128), dmSync, now), true, 'no entry: full');
  assert.equal(contactNeedsFullSync(a, undefined, now), true);
  assert.throws(() => contactNeedsFullSync(a, dmSync, 'x'), /Invalid time/);
  // One unchecked contact no longer sends the others through 8 buckets.
  assert.deepEqual(contactDays(a, dmSync, now, today), recentDays(today));
  assert.deepEqual(contactDays(b, dmSync, now, today), fullDays(today));
  assert.equal(needFullSync([a, b], dmSync, now), true, 'the list-wide answer stays as before');
  assert.equal(needFullSync([a], dmSync, now), false);
  assert.throws(() => needFullSync([], {}, 'x'), /Invalid time/);
});

test('check order (0.1.72): never checked first, then the newest message on this device, then the rest; ties keep the list order', () => {
  const fp = ch => ch.repeat(128), now = '1790000000';
  const contacts = ['1', '2', '3', '4', '5', '6'].map(ch => ({ fp: fp(ch) }));
  const dmSync = { [fp('1')]: now, [fp('2')]: now, [fp('3')]: now, [fp('5')]: '0', [fp('6')]: now };
  // 4: no entry, 5: '0' — never checked. 3 has the newest message (in), 1 an
  // older one (out), 6 a message with an unreadable seq (ignored), 2 none.
  const messages = [
    { fp: fp('1'), dir: 'out', seq: '7' },
    { fp: fp('3'), dir: 'in', seq: '9' },
    { fp: fp('1'), dir: 'in', seq: '8' },
    { fp: fp('6'), dir: 'in', seq: 'x' },
    { fp: fp('9'), dir: 'in', seq: '99' }   // not a contact
  ];
  const before = contacts.map(c => c.fp);
  const order = checkOrder(contacts, dmSync, messages).map(c => c.fp);
  assert.deepEqual(order, [fp('4'), fp('5'), fp('3'), fp('1'), fp('2'), fp('6')]);
  assert.deepEqual(contacts.map(c => c.fp), before, 'the list itself is not reordered');
  assert.notEqual(checkOrder(contacts, dmSync, messages), contacts, 'a new array');
  // Same newest seq (cannot happen for one device, but the order stays total): list order.
  const tie = checkOrder([{ fp: fp('2') }, { fp: fp('1') }], { [fp('1')]: now, [fp('2')]: now }, [{ fp: fp('1'), seq: '5' }, { fp: fp('2'), seq: '5' }]);
  assert.deepEqual(tie.map(c => c.fp), [fp('2'), fp('1')]);
  // seq compared as integers, not text ('10' after '9')
  const big = checkOrder([{ fp: fp('1') }, { fp: fp('2') }], { [fp('1')]: now, [fp('2')]: now }, [{ fp: fp('1'), seq: '9' }, { fp: fp('2'), seq: '10' }]);
  assert.deepEqual(big.map(c => c.fp), [fp('2'), fp('1')]);
  // Nothing checked yet, no messages: the list order.
  assert.deepEqual(checkOrder(contacts, {}, []).map(c => c.fp), before);
  assert.deepEqual(checkOrder(contacts, undefined, undefined).map(c => c.fp), before);
  assert.deepEqual(checkOrder([], {}, messages), []);
});

test('profile cache: a kept profile is used for 7 days', () => {
  const at = 1790000000;
  assert.equal(profileFresh({ at: String(at) }, String(at)), true);
  assert.equal(profileFresh({ at: String(at) }, String(at + PROFILE_CACHE_SECONDS - 1)), true);
  assert.equal(profileFresh({ at: String(at) }, String(at + PROFILE_CACHE_SECONDS)), false);
  assert.equal(profileFresh({ at: String(at + 10) }, String(at)), false);
  assert.equal(profileFresh(undefined, String(at)), false);
});

// src/connect/ui/chain-names.js (2026-10-03): a chain name is permanent
// (decision 2026-10-02-onchain-names.md item 4), so a kept one never expires.
test('chain names: a kept name is used however old it is; anything malformed counts as none', () => {
  assert.equal(keptChainName({ name: 'jarvis', at: '1' }), 'jarvis');
  assert.equal(keptChainName({ name: 'jarvis', at: '1790000000' }), 'jarvis');
  assert.equal(keptChainName(undefined), '');
  assert.equal(keptChainName({ name: 'Jarvis', at: '1' }), '');           // uppercase is not a name byte
  assert.equal(keptChainName({ name: 'jar vis', at: '1' }), '');     // a line separator is not a name byte
  assert.equal(keptChainName({ name: 'deadbeef', at: '1' }), '');         // reads as an ID prefix
  assert.equal(keptChainName({ name: 'ab', at: '1' }), '');
  // The state checker refuses such an entry too (store.js checkState).
  assert.throws(() => checkState({ ...emptyState(), chainNames: { [FP]: { name: 'jar\nvis', at: '1' } } }));
  assert.doesNotThrow(() => checkState({ ...emptyState(), chainNames: { [FP]: { name: 'jarvis', at: '1' } } }));
});

test('chain names: a contact with a kept name is not asked again; the own ID is asked once per session', () => {
  // contact, name kept or found: no lookup
  assert.equal(chainLookupNeeded({ asked: false, known: true, recheck: false }), false);
  // contact (or a request) without a name: asked once per session
  assert.equal(chainLookupNeeded({ asked: false, known: false, recheck: false }), true);
  assert.equal(chainLookupNeeded({ asked: true, known: false, recheck: false }), false);
  // this wallet's own ID: asked once per session even with a kept name
  assert.equal(chainLookupNeeded({ asked: false, known: true, recheck: true }), true);
  assert.equal(chainLookupNeeded({ asked: true, known: true, recheck: true }), false);
});

test('chain names: opening a conversation asks again for a contact without a name, never sooner than the spacing', () => {
  const t = 1790000000000;
  assert.equal(CHAIN_LOOKUP_SPACING_MS, 60000);
  // opened, no name known: asked again even though the sync round got "no name" earlier
  assert.equal(chainLookupNeeded({ asked: true, known: false, recheck: false, opened: true }), true);
  assert.equal(chainLookupNeeded({ asked: true, known: false, recheck: false, opened: true, lastTry: t - CHAIN_LOOKUP_SPACING_MS, now: t }), true);
  // opened, but the same ID was looked up less than 60 s ago: not yet
  assert.equal(chainLookupNeeded({ asked: true, known: false, recheck: false, opened: true, lastTry: t - CHAIN_LOOKUP_SPACING_MS + 1, now: t }), false);
  // opened, a name kept or found: a contact's name is never asked again
  assert.equal(chainLookupNeeded({ asked: false, known: true, recheck: false, opened: true }), false);
  assert.equal(chainLookupNeeded({ asked: true, known: true, recheck: false, opened: true, lastTry: undefined, now: t }), false);
});

test('chain names: a failed lookup is not "asked" — the sync round tries again, spaced by 60 s', () => {
  const t = 1790000000000;
  // a failed lookup leaves asked false; only the spacing holds it back
  assert.equal(chainLookupNeeded({ asked: false, known: false, recheck: false, lastTry: t, now: t + 1000 }), false);
  assert.equal(chainLookupNeeded({ asked: false, known: false, recheck: false, lastTry: t, now: t + CHAIN_LOOKUP_SPACING_MS }), true);
  // the own ID after a failed lookup: tried again after the spacing
  assert.equal(chainLookupNeeded({ asked: false, known: true, recheck: true, lastTry: t, now: t + CHAIN_LOOKUP_SPACING_MS - 1 }), false);
  assert.equal(chainLookupNeeded({ asked: false, known: true, recheck: true, lastTry: t, now: t + CHAIN_LOOKUP_SPACING_MS }), true);
  // an answered "no name" stays answered for the sync round, however long ago
  assert.equal(chainLookupNeeded({ asked: true, known: false, recheck: false, lastTry: t, now: t + 10 * CHAIN_LOOKUP_SPACING_MS }), false);
  // spacing rule itself
  assert.equal(chainLookupSpaced(undefined, t), true);                   // never looked up this session
  assert.equal(chainLookupSpaced(t, t), false);
  assert.equal(chainLookupSpaced(t, t + CHAIN_LOOKUP_SPACING_MS - 1), false);
  assert.equal(chainLookupSpaced(t, t + CHAIN_LOOKUP_SPACING_MS), true);
  assert.equal(chainLookupSpaced(t, t - 1), true);                       // the clock went back: not blocked for good
  assert.equal(chainLookupSpaced(t, NaN), false);
});

test('chain names: a confirmed answer replaces, keeps or removes the kept entry', () => {
  const now = '1790000000', before = { name: 'jarvis', at: '1700000000' };
  // same name: the entry is kept as it is (no write on every open)
  assert.deepEqual(chainNameAfterLookup(before, { found: true, name: 'jarvis' }, { keep: true, now }), { name: 'jarvis', entry: before, changed: false });
  // another name: replaced
  assert.deepEqual(chainNameAfterLookup(before, { found: true, name: 'other' }, { keep: true, now }), { name: 'other', entry: { name: 'other', at: now }, changed: true });
  // first found: kept
  assert.deepEqual(chainNameAfterLookup(undefined, { found: true, name: 'jarvis' }, { keep: true, now }), { name: 'jarvis', entry: { name: 'jarvis', at: now }, changed: true });
  // confirmed no name: removed
  assert.deepEqual(chainNameAfterLookup(before, { found: false }, { keep: true, now }), { name: '', entry: null, changed: true });
  assert.deepEqual(chainNameAfterLookup(undefined, { found: false }, { keep: true, now }), { name: '', entry: null, changed: false });
  // a stranger (keep false): shown this session, nothing kept
  assert.deepEqual(chainNameAfterLookup(undefined, { found: true, name: 'jarvis' }, { keep: false, now }), { name: 'jarvis', entry: null, changed: false });
  // a malformed answer is no answer: nothing moves
  assert.deepEqual(chainNameAfterLookup(before, { found: true, name: 'BAD NAME' }, { keep: true, now }), { name: 'jarvis', entry: before, changed: false });
  assert.deepEqual(chainNameAfterLookup(before, undefined, { keep: true, now }), { name: 'jarvis', entry: before, changed: false });
});

test('own name: the wallet\'s answered lookup wins; until then the name Messages knows; More entry text', () => {
  assert.equal(shownOwnName(null, ''), '');
  assert.equal(shownOwnName(null, 'jarvis'), 'jarvis');                    // kept on this device, before the wallet's lookup answered
  assert.equal(shownOwnName({ name: 'other' }, 'jarvis'), 'other');        // the lookup confirmed another name
  assert.equal(shownOwnName({ name: '' }, 'jarvis'), '');                  // the lookup confirmed no name
  assert.equal(shownOwnName(null, 'jar‮vis'), '');                    // never anything but name bytes
  assert.equal(profileEntryText(''), 'Your ID & profile');                // the exact no-name text (test/connect-smoke.js)
  assert.equal(PROFILE_ENTRY_TEXT, 'Your ID & profile');
  assert.equal(profileEntryText('jarvis'), 'jarvis — ID & profile');
  assert.equal(profileEntryText('x\ny'), 'Your ID & profile');
});

// The Home / More own-ID line (src/connect/ui/messages.js ownIdText, from
// host.onIdentity): with no ID, "could not open" only while Messages is
// closed with the wallet open; locked or opening keeps the waiting text.
test('own ID line: name and short ID while open; closed and waiting placeholders told apart', () => {
  const fp = 'ab'.repeat(64);
  assert.equal(OWN_ID_WAITING_TEXT, 'Appears when your wallet is open');   // the exact text (test/connect-smoke.js)
  assert.equal(OWN_ID_CLOSED_TEXT, 'Messages could not open');
  assert.equal(ownIdText({ id: fp, name: 'jarvis' }), `jarvis · ${shortId(fp)}`);
  assert.equal(ownIdText({ id: fp, name: '' }), shortId(fp));
  // An ID wins over a stale closed flag.
  assert.equal(ownIdText({ id: fp, name: '', closed: true }), shortId(fp));
  // Locked / waiting / opening.
  assert.equal(ownIdText({ id: null, name: '', closed: false }), OWN_ID_WAITING_TEXT);
  assert.equal(ownIdText({ id: null, name: 'jarvis' }), OWN_ID_WAITING_TEXT);
  assert.equal(ownIdText(), OWN_ID_WAITING_TEXT);
  // Closed with a reason while the wallet is open (history slow, local open
  // or identity unlock failed, connection lost).
  assert.equal(ownIdText({ id: null, name: '', closed: true }), OWN_ID_CLOSED_TEXT);
  // Only a literal true counts as closed.
  assert.equal(ownIdText({ id: null, closed: 'yes' }), OWN_ID_WAITING_TEXT);
});

// The conversation's "Details" line (src/connect/ui/diag.js): the last
// message check of one contact, memory only, never a salt / blob / text.
test('diagnostics: one short line per check; empty days folded; no salt, blob or text kept', () => {
  const saltHex = 'c'.repeat(64), blobHex = 'ab'.repeat(32);
  const empty = { outcome: 'empty', why: 'none', messages: [], dropped: '0', other: '0', unchanged: false };
  const diag = newDiag(1000);
  diag.profile = 'ok';
  diag.salt = diagSalt({ result: { status: 'nothing_to_write', outcome: 'found', why: 'none', salt: saltHex } });
  diag.days = [
    diagDay('20728', empty),
    diagDay('20729', { outcome: 'found', why: 'none', blob: blobHex, messages: [], dropped: '1', other: '0', unchanged: false }),
    diagDay('20730', empty)
  ];
  assert.equal(diagText(diag, () => '08:31'),
    'Last check 08:31 · profile ok · salt ok · day 20729: found, 0 read, 1 not checked, 0 other · 2 empty days');
  const kept = JSON.stringify(diag);
  assert.ok(!kept.includes(saltHex) && !kept.includes(blobHex));
  // the message text is never kept, only the count
  const withText = diagDay('20729', { outcome: 'found', why: 'none', messages: [{ seq: '1', senderTs: '5', text: 'secret words' }], dropped: '0', other: '2' });
  assert.ok(!JSON.stringify(withText).includes('secret words'));
  assert.deepEqual(withText, { day: '20729', outcome: 'found', why: 'none', count: 1, dropped: 0, other: 2, unchanged: false });
  assert.equal(diagText(undefined), '');
});

test('diagnostics: profile, salt and day states in plain words; malformed fields shown as unknown', () => {
  const at = () => '08:31';
  const failed = newDiag(1); failed.profile = 'failed';
  assert.equal(diagText(failed, at), 'Last check 08:31 · profile could not be read');
  const wait = newDiag(1); wait.profile = 'ok';
  wait.salt = diagSalt({ result: { status: 'wait', outcome: 'unreadable', why: 'timeout' } });
  wait.noSalt = true;
  assert.equal(diagText(wait, at), 'Last check 08:31 · profile ok · salt wait (unreadable, timeout) · no salt yet, messages not read');
  const moved = newDiag(1); moved.profile = 'ok';
  moved.salt = diagSalt({ result: { status: 'published', outcome: 'empty', why: 'none' }, changed: true });
  moved.days = [diagDay('20729', { outcome: 'found', why: 'none', unchanged: true, dropped: '0', other: '0' }),
    diagDay('20730', { outcome: 'unreadable', why: 'timeout' })];
  assert.equal(diagText(moved, at),
    'Last check 08:31 · profile ok · salt ok (changed) · day 20729: found, unchanged · day 20730: unreadable (timeout), 0 read, 0 not checked, 0 other');
  const earlier = newDiag(1); earlier.profile = 'ok'; earlier.salt = diagSalt({ earlier: true });
  assert.equal(diagText(earlier, at), 'Last check 08:31 · profile ok · salt ok');
  // a failed salt step carried into a later check keeps its status (messages.js syncContact)
  const carried = newDiag(2); carried.profile = 'ok';
  carried.salt = diagSalt({ result: { status: 'failed', outcome: 'unreadable', why: 'timeout' } });
  assert.equal(diagText(carried, at), 'Last check 08:31 · profile ok · salt failed (unreadable, timeout)');
  assert.deepEqual(diagDay('x', { outcome: '<b>', why: 'Timeout!', dropped: '-1', other: 'many', messages: 'no' }),
    { day: '?', outcome: 'unknown', why: 'unknown', count: 0, dropped: 0, other: 0, unchanged: false });
});

test('diagnostics: a failed check is shown with a bounded message that never carries hex', () => {
  const diag = newDiag(1); diag.profile = 'ok';
  diag.error = errorText(new Error("Load this contact's profile first."));
  assert.equal(diagText(diag, () => '08:31'), "Last check 08:31 · profile ok\nLast check failed: Load this contact's profile first.");
  assert.equal(errorText(new Error(`bad ${'a1'.repeat(32)} end`)), 'bad … end');
  assert.equal(errorText(new SyntaxError(`Unexpected token in {"salt":"${'c'.repeat(64)}"}`)), 'the answer could not be read');
  assert.equal(errorText(new Error('a\nb\u0007c')), 'a b c');
  const long = errorText(new Error('x '.repeat(200)));
  assert.equal(long.length, 120);
  assert.ok(long.endsWith('…'));
  assert.equal(errorText('plain'), 'plain');
  assert.equal(errorText(undefined), 'unknown error');
  assert.equal(errorText(new Error('')), 'unknown error');
});

// LOCAL FIRST: the wallet's connection waits for Messages' local open, so
// the IndexedDB open of a saved wallet's history is bounded (messages.js
// openLocal passes AbortSignal.timeout). Driven here by a manual
// AbortController and a stub indexedDB whose open never answers until the
// test says so — no clock.
test('history open: an aborted bound rejects with the plain text; a database that answers later is closed', async () => {
  const vaultId = btoa(String.fromCharCode(...Array.from({ length: 16 }, (_, i) => i * 17)));
  const core = { historyKey: async () => ({}) };
  const closed = [];
  let request;
  const before = globalThis.indexedDB;
  globalThis.indexedDB = { open: () => (request = {}) };
  try {
    const controller = new AbortController();
    const opening = openHistoryStore({ core, vaultId, storage: memoryStorage(), signal: controller.signal });
    for (let i = 0; i < 10 && !request; i++) await new Promise(resolve => setImmediate(resolve));
    assert.ok(request, 'the database open was requested');
    controller.abort();
    await assert.rejects(opening, error => error instanceof StorageError && error.message === HISTORY_SLOW_TEXT);
    request.result = { close: () => closed.push('closed') };
    request.onsuccess();
    // bounded() hands the late handle over inside the open promise's .then
    // (a microtask later): let that turn run first.
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(closed, ['closed'], 'the late handle is closed, never used');
    // Already expired before the open: refused at once.
    await assert.rejects(openHistoryStore({ core, vaultId, storage: memoryStorage(), signal: AbortSignal.abort() }), error => error.message === HISTORY_SLOW_TEXT);
  } finally {
    if (before === undefined) delete globalThis.indexedDB; else globalThis.indexedDB = before;
  }
});

// Message check progress (web 0.1.71, operator 2026-10-07: "Updating…" for
// minutes on a phone with nothing to show which step ran).
const PROGRESS_FP = `1a2b3c4d${'0'.repeat(116)}9f0e`;
const PROGRESS_ID = shortId(PROGRESS_FP);

test('progress status line: the first round names its step; every round counts its contacts', () => {
  assert.equal(PROGRESS_ID, 'ID 1a2b3c4d…9f0e');
  assert.equal(updatingStageText('account'), 'Updating: your account…');
  assert.equal(updatingStageText('contacts'), 'Updating: contact list…');
  assert.equal(updatingStageText('requests'), 'Updating: contact requests…');
  assert.equal(updatingStageText('publish'), 'Updating: contact list…');
  assert.equal(updatingStageText('names'), 'Updating: names…');
  assert.equal(updatingStageText('nope'), 'Updating: messages…');
  assert.deepEqual(Object.keys(CHECK_STAGES), ['account', 'contacts', 'requests', 'publish', 'names']);
  assert.equal(checkingContactsText(5, 31), 'Checking messages: 5 of 31 contacts…');
  assert.equal(checkingContactsText(1, 1), 'Checking messages: 1 of 1 contact…');
  assert.equal(checkingContactsText(7, 3), 'Checking messages: 3 of 3 contacts…', 'never more than the total');
  assert.equal(checkingContactsText(undefined, undefined), 'Checking messages: 0 of 0 contacts…');
});

test('progress log: round, stage and per-step lines are exact', () => {
  assert.equal(roundStartLine(3, { first: false, contacts: 31, full: 2, recent: 29 }), 'check round 3 started (regular): 31 contacts, 2 full (8 days), 29 recent (3 days)');
  assert.equal(roundStartLine(1, { first: true, contacts: 12, full: 12, recent: 0 }), 'check round 1 started (first): 12 contacts, 12 full (8 days), 0 recent (3 days)');
  assert.equal(roundStartLine(2, {}), 'check round 2 started (regular): 0 contacts, 0 full (8 days), 0 recent (3 days)');
  assert.equal(stageStartLine(1, 'names'), 'check round 1 stage names started');
  assert.equal(stageLine(1, 'account', 812.4), 'check round 1 stage account: 812 ms');
  assert.equal(stageLine(1, 'contacts', 0), 'check round 1 stage contact list: 0 ms');
  assert.equal(stageLine(1, 'requests', 7), 'check round 1 stage requests: 7 ms');
  assert.equal(stageLine(1, 'publish', 5), 'check round 1 stage publish contacts: 5 ms');
  assert.equal(stageLine(2, 'nope', -4), 'check round 2 stage unknown: 0 ms');
  assert.equal(contactStartLine(PROGRESS_ID), 'contact ID 1a2b3c4d…9f0e check started');
  assert.equal(contactStepLine(PROGRESS_ID, 'profile'), 'contact ID 1a2b3c4d…9f0e: profile');
  assert.equal(contactStepLine(PROGRESS_ID, 'salt'), 'contact ID 1a2b3c4d…9f0e: salt');
  assert.equal(contactStepLine(PROGRESS_ID, 'ack'), 'contact ID 1a2b3c4d…9f0e: ack');
  assert.equal(contactStepLine(PROGRESS_ID, 'publish'), 'contact ID 1a2b3c4d…9f0e: outbox publish');
  // One line for the contact's whole pipelined bucket read (web 0.1.73).
  assert.equal(contactStepLine(PROGRESS_ID, 'days', 8), 'contact ID 1a2b3c4d…9f0e: outbox days 8');
  assert.equal(contactStepLine(PROGRESS_ID, 'days', 3), 'contact ID 1a2b3c4d…9f0e: outbox days 3');
  assert.equal(contactStepLine(PROGRESS_ID, 'days', 'x'), 'contact ID 1a2b3c4d…9f0e: outbox days ?');
  assert.equal(contactStepLine(PROGRESS_ID, 'days', -1), 'contact ID 1a2b3c4d…9f0e: outbox days ?');
  // The per-day step is gone: an unknown step, not a day line.
  assert.equal(contactStepLine(PROGRESS_ID, 'day', '20368'), 'contact ID 1a2b3c4d…9f0e: unknown step');
  assert.equal(contactStepLine(PROGRESS_ID, 'ack publish'), 'contact ID 1a2b3c4d…9f0e: ack publish');
  assert.equal(contactStepLine(PROGRESS_ID, 'name'), 'contact ID 1a2b3c4d…9f0e: chain name');
  assert.equal(contactStepLine(undefined, 'nope'), 'contact ID ?: unknown step');
});

test('progress log: a contact line carries counts, the profile and salt words and the days read — never more', () => {
  assert.equal(saltShortText(null), 'salt not checked');
  assert.equal(saltShortText({ salt: diagSalt({ earlier: true }) }), 'salt ok (earlier)');
  assert.equal(saltShortText({ salt: diagSalt({ result: { status: 'nothing_to_write', outcome: 'found', why: 'none' } }) }), 'salt ok');
  assert.equal(saltShortText({ salt: diagSalt({ result: { status: 'published', outcome: 'empty', why: 'none' }, changed: true }) }), 'salt ok (changed)');
  assert.equal(saltShortText({ salt: diagSalt({ result: { status: 'wait', outcome: 'unreadable', why: 'timeout' } }), noSalt: true }), 'salt wait, no salt');
  assert.equal(saltShortText({ salt: { status: 'Not A Word' } }), 'salt unknown');

  const diag = newDiag(0);
  diag.profile = 'ok';
  diag.salt = diagSalt({ earlier: true });
  diag.days.push(diagDay('20367', { outcome: 'found', why: 'none', messages: [{}] }));
  diag.days.push(diagDay('20368', { outcome: 'empty', why: 'none' }));
  diag.days.push(diagDay('20369', { outcome: 'unreadable', why: 'timeout' }));
  assert.equal(daysRead(diag), 2, "an 'unreadable' day is not read");
  assert.equal(daysRead(undefined), 0);
  assert.equal(contactLine(PROGRESS_ID, { ms: 1834, fresh: 2, diag, days: 3 }),
    'contact ID 1a2b3c4d…9f0e checked in 1834 ms: 2 new, profile ok, salt ok (earlier), 2/3');
  // An exception before the profile step finished: no diagnostics yet.
  assert.equal(contactLine(PROGRESS_ID, { ms: 40, diag: undefined, days: 8, failed: true }),
    'contact ID 1a2b3c4d…9f0e checked in 40 ms: 0 new, profile failed, salt not checked, 0/8, check failed');
  const noProfile = newDiag(0);
  noProfile.profile = 'failed';
  assert.equal(contactLine(PROGRESS_ID, { ms: 20500, diag: noProfile, days: 3 }),
    'contact ID 1a2b3c4d…9f0e checked in 20500 ms: 0 new, profile failed, salt not checked, 0/3');
});

test('progress log: the round end is in whole seconds (the log scrub turns a fraction into "#")', () => {
  assert.equal(roundDoneLine(3, { ms: 12345, fresh: 1, failed: 0 }), 'check round 3 done in 12 s: 1 new message, 0 failed');
  assert.equal(roundDoneLine(4, { ms: 1500, fresh: 0, failed: 2 }), 'check round 4 done in 2 s: 0 new messages, 2 failed');
  assert.equal(roundDoneLine(5, { ms: 400 }), 'check round 5 done in 0 s: 0 new messages, 0 failed');
});

test('progress log lines pass the session log scrub unchanged (short ID, counts, day numbers)', () => {
  const diag = newDiag(0);
  diag.profile = 'ok';
  diag.salt = diagSalt({ result: { status: 'published', outcome: 'found', why: 'none' }, changed: true });
  for (const day of ['20362', '20363', '20364', '20365', '20366', '20367', '20368', '20369']) diag.days.push(diagDay(day, { outcome: 'empty', why: 'none' }));
  const lines = [
    roundStartLine(12, { first: true, contacts: 15, full: 4, recent: 11 }),
    stageStartLine(12, 'account'), stageLine(12, 'account', 98765),
    stageStartLine(12, 'publish'), stageLine(12, 'publish', 3),
    contactStartLine(PROGRESS_ID),
    contactStepLine(PROGRESS_ID, 'profile'), contactStepLine(PROGRESS_ID, 'days', 8), contactStepLine(PROGRESS_ID, 'ack publish'),
    contactLine(PROGRESS_ID, { ms: 61234, fresh: 3, diag, days: 8 }),
    contactLine(PROGRESS_ID, { ms: 5, diag: undefined, days: 3, failed: true }),
    roundDoneLine(12, { ms: 1234567, fresh: 3, failed: 1 })
  ];
  for (const line of lines) assert.equal(scrubLogText(line), line);
  assert.ok(!lines.some(line => line.includes(PROGRESS_FP)), 'never the full ID');
});
