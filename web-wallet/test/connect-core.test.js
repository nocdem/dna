// LOCAL FIRST — src/connect/core.js's split between the calls that need only
// the identity (run on the wallet's IDENTIFIED client: nodus.connectLocal)
// and the calls that reach the network (nodus.connect, 'ready' only).
// Against a fake wallet client that records which slot each export used:
// proves the JS routing and the constructor gate, nothing about the module
// (connect/nc_wasm.c refuses a network call before the connect on its own,
// session_ok).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusConnectCore } from '../src/connect/core.js';

const FP = 'ab'.repeat(64), OTHER = 'cd'.repeat(64);

function fakeNodus() {
  const calls = [], heap = new Uint8Array(4096);
  let last;
  const results = {
    nc_unlock: { fingerprint: FP, fresh: false },
    nc_profile_load: { profile: { fingerprint: OTHER } },
    nc_hist_key: {},
    nc_profile_get: { outcome: 'empty', why: 'none' }
  };
  const api = route => ({
    num: name => { calls.push(`${route}:${name}`); last = name; return name === 'nc_words_alloc' ? 64 : 0; },
    call: async name => { calls.push(`${route}:${name}`); last = name; return 0; },
    str: name => (name === 'nc_result' ? JSON.stringify(results[last] ?? {}) : ''),
    heap: () => heap
  });
  const nodus = {
    state: 'identified',
    fingerprint: FP,
    localConnectable: true,
    connect: async run => { if (nodus.state !== 'ready') throw new Error('Nodus connection is not ready.'); return run(api('net')); },
    connectLocal: async run => run(api('local')),
    connectSync: run => run(api('sync'))
  };
  return { nodus, calls, heap };
}

test('core: unlock, kept profiles and the history key run on the identified client; network reads wait for ready', async () => {
  const { nodus, calls, heap } = fakeNodus();
  const core = createNodusConnectCore({ nodus });
  const words = new TextEncoder().encode('alpha beta gamma');
  assert.deepEqual(await core.unlock({ words }), { fingerprint: FP, fresh: false });
  assert.ok(words.every(b => b === 0), 'the JS copy of the words is zeroed');
  assert.equal(new TextDecoder().decode(heap.subarray(64, 64 + 16)), 'alpha beta gamma', 'the words reached the module buffer');
  assert.equal(core.state, 'ready');
  assert.deepEqual((await core.profileLoad(OTHER, '{"kept":1}', '')).profile, { fingerprint: OTHER });
  await core.historyKey('00'.repeat(16));
  // The network is not there yet: refused by the wallet client, nothing ran.
  await assert.rejects(core.profileGet(OTHER), /not ready/);
  assert.deepEqual(calls, ['local:nc_words_alloc', 'local:nc_unlock', 'local:nc_profile_load', 'local:nc_hist_key']);
  nodus.state = 'ready';
  assert.equal((await core.profileGet(OTHER)).outcome, 'empty');
  assert.equal(calls.at(-1), 'net:nc_profile_get');
  core.lock();
  assert.equal(calls.at(-1), 'sync:nc_lock');
  await assert.rejects(core.historyKey('00'.repeat(16)), /not connected|locked/);
});

test('core: refuses a wallet client that is not identified, or one without the local slot', () => {
  const base = { connect() {}, connectLocal() {}, connectSync() {} };
  assert.throws(() => createNodusConnectCore({ nodus: { ...base, localConnectable: false } }), /not open/);
  const { connectLocal, ...noLocal } = base;
  assert.equal(typeof connectLocal, 'function');
  assert.throws(() => createNodusConnectCore({ nodus: { ...noLocal, localConnectable: true } }), /not available/);
});

// outboxFetchDays (web 0.1.73): ONE network export (nc_outbox_get_days) for
// all of a contact's day buckets, handed the days and skip hashes in order;
// each day of its answer is mapped exactly as outboxFetchDay maps
// nc_outbox_get's. Against a fake module that echoes a fixed answer —
// proves the JS argument shape, the mapping and the refusals, nothing
// about the module's reads (connect/nc_read.c nc_read_owner_many).
function fakeDaysNodus(answers) {
  const calls = [];
  let last;
  const api = {
    num: name => { calls.push({ name }); last = name; return name === 'nc_words_alloc' ? 64 : 0; },
    call: async (name, types, args) => { calls.push({ name, types, args }); last = name; return 0; },
    str: name => (name === 'nc_result' ? JSON.stringify(answers[last] ?? {}) : ''),
    heap: () => new Uint8Array(4096)
  };
  const nodus = {
    state: 'ready',
    fingerprint: FP,
    localConnectable: true,
    connect: async run => run(api),
    connectLocal: async run => run(api),
    connectSync: run => run(api)
  };
  return { nodus, calls };
}

const SALT = '11'.repeat(32), BLOB = '22'.repeat(32);
const dayAnswer = (day, extra = {}) => ({ outcome: 'empty', why: 'none', day, unchanged: false, dropped: '0', other: '0', messages: [], ...extra });

test('core: outboxFetchDays sends every day in one call and maps each answer as outboxFetchDay does', async () => {
  const hello = Buffer.from('hello').toString('hex');
  const one = dayAnswer('20368', { outcome: 'found', blob: BLOB, messages: [{ seq: '7', sender_ts: '1700000000', text_hex: hello }] });
  const { nodus, calls } = fakeDaysNodus({
    nc_unlock: { fingerprint: FP, fresh: false },
    nc_outbox_get_days: { days: [dayAnswer('20367'), one, dayAnswer('20369', { outcome: 'unreadable', why: 'timeout' })] },
    nc_outbox_get: one
  });
  const core = createNodusConnectCore({ nodus });
  await core.unlock({ words: new TextEncoder().encode('alpha beta gamma') });
  const r = await core.outboxFetchDays(OTHER, SALT, [{ day: '20367' }, { day: '20368', skipBlob: BLOB }, { day: 20369, skipBlob: '' }]);
  const sent = calls.filter(c => c.name === 'nc_outbox_get_days');
  assert.equal(sent.length, 1, 'one export for every day');
  assert.deepEqual(sent[0].args.slice(0, 2), [OTHER, SALT]);
  assert.deepEqual(JSON.parse(sent[0].args[2]), [{ day: '20367', skip: '' }, { day: '20368', skip: BLOB }, { day: '20369', skip: '' }]);
  assert.ok(Array.isArray(r.days) && r.days.length === 3);
  assert.deepEqual(r.days.map(d => d.day), ['20367', '20368', '20369'], 'the order asked');
  assert.deepEqual(r.days[1].messages, [{ seq: '7', senderTs: '1700000000', text: 'hello' }]);
  assert.equal(r.days[2].outcome, 'unreadable');
  assert.equal(r.days[2].why, 'timeout');
  // The same answer through the single call maps to the same object.
  const single = await core.outboxFetchDay(OTHER, SALT, '20368', BLOB);
  const { generation, requestId, ...singleDay } = single;
  assert.equal(typeof generation, 'number');
  assert.equal(typeof requestId, 'number');
  assert.deepEqual(r.days[1], singleDay);
});

// contactReads (web 0.1.74): ONE network export (nc_contact_reads) for the
// ACK and the day buckets of up to 4 contacts; per contact the ack answer
// passes through as ackGet returns it and each day is mapped exactly as
// outboxFetchDays maps it; a per-contact { error } stays that contact's.
// Against the same fake module — proves the JS argument shape, the mapping
// and the refusals, nothing about the module's reads.
test('core: contactReads sends every contact in one call; ack as ackGet, days as outboxFetchDays, an error stays its contact\'s', async () => {
  const hello = Buffer.from('hello').toString('hex');
  const THIRD = 'ef'.repeat(64), SALT2 = '33'.repeat(32);
  const one = dayAnswer('20368', { outcome: 'found', blob: BLOB, messages: [{ seq: '7', sender_ts: '1700000000', text_hex: hello }] });
  const ackFound = { outcome: 'found', why: 'none', ack_ts: '1700000001' };
  const ackEmpty = { outcome: 'empty', why: 'none', ack_ts: null };
  const { nodus, calls } = fakeDaysNodus({
    nc_unlock: { fingerprint: FP, fresh: false },
    nc_contact_reads: { contacts: [
      { ack: ackFound, days: [dayAnswer('20367'), one] },
      { error: 'Load this contact\'s profile first.' },
      { ack: ackEmpty, days: [dayAnswer('20369', { outcome: 'unreadable', why: 'timeout' })] }
    ] },
    nc_outbox_get_days: { days: [dayAnswer('20367'), one] },
    nc_ack_get: ackFound
  });
  const core = createNodusConnectCore({ nodus });
  await core.unlock({ words: new TextEncoder().encode('alpha beta gamma') });
  const r = await core.contactReads([
    { fp: OTHER, salt: SALT, days: [{ day: '20367' }, { day: '20368', skipBlob: BLOB }] },
    { fp: THIRD, salt: SALT2, days: [{ day: 20368 }] },
    { fp: FP, salt: SALT, days: [{ day: '20369', skipBlob: '' }] }
  ]);
  const sent = calls.filter(c => c.name === 'nc_contact_reads');
  assert.equal(sent.length, 1, 'one export for every contact');
  assert.deepEqual(sent[0].types, ['string']);
  assert.deepEqual(JSON.parse(sent[0].args[0]), [
    { fp: OTHER, salt: SALT, days: [{ day: '20367', skip: '' }, { day: '20368', skip: BLOB }] },
    { fp: THIRD, salt: SALT2, days: [{ day: '20368', skip: '' }] },
    { fp: FP, salt: SALT, days: [{ day: '20369', skip: '' }] }
  ]);
  assert.equal(r.contacts.length, 3);
  assert.deepEqual(r.contacts[1], { error: 'Load this contact\'s profile first.' });
  assert.deepEqual(r.contacts[2].ack, ackEmpty);
  assert.equal(r.contacts[2].days[0].why, 'timeout');
  // The same answers through the single calls map to the same objects.
  const { generation: g1, requestId: q1, ...ack } = await core.ackGet(OTHER, SALT);
  assert.deepEqual(r.contacts[0].ack, ack);
  const { generation: g2, requestId: q2, ...days } = await core.outboxFetchDays(OTHER, SALT, [{ day: '20367' }, { day: '20368', skipBlob: BLOB }]);
  assert.deepEqual({ days: r.contacts[0].days }, days);
  assert.deepEqual(r.contacts[0].days[1].messages, [{ seq: '7', senderTs: '1700000000', text: 'hello' }]);
  for (const v of [g1, q1, g2, q2]) assert.equal(typeof v, 'number');
});

test('core: contactReads refuses a bad contact list before the module, and an answer of the wrong shape', async () => {
  const answers = { nc_unlock: { fingerprint: FP, fresh: false }, nc_contact_reads: { contacts: [{ ack: { outcome: 'empty', why: 'none', ack_ts: null }, days: [dayAnswer('1')] }] } };
  const { nodus, calls } = fakeDaysNodus(answers);
  const core = createNodusConnectCore({ nodus });
  await core.unlock({ words: new TextEncoder().encode('alpha beta gamma') });
  const ok = { fp: OTHER, salt: SALT, days: [{ day: '1' }] };
  const nine = Array.from({ length: 9 }, (_, i) => ({ day: String(i) }));
  await assert.rejects(core.contactReads([]), /contact list/);
  await assert.rejects(core.contactReads([ok, ok, ok, ok, ok]), /contact list/, 'at most 4 contacts');
  await assert.rejects(core.contactReads('x'), /contact list/);
  await assert.rejects(core.contactReads([{ ...ok, fp: 'nope' }]), /Invalid Nodus address/);
  await assert.rejects(core.contactReads([{ ...ok, salt: '' }]), /Invalid salt/, 'a contact without a salt is never read');
  await assert.rejects(core.contactReads([{ ...ok, days: [] }]), /day list/);
  await assert.rejects(core.contactReads([{ ...ok, days: nine }]), /day list/);
  await assert.rejects(core.contactReads([{ ...ok, days: [{ day: 'x' }] }]), /Invalid day/);
  await assert.rejects(core.contactReads([{ ...ok, days: [{ day: '1', skipBlob: 'zz' }] }]), /Invalid blob/);
  await assert.rejects(core.contactReads([null]), /Invalid Nodus address/);
  assert.equal(calls.filter(c => c.name === 'nc_contact_reads').length, 0, 'nothing reached the module');
  // the answer must match the request: as many contacts, as many days each
  await assert.rejects(core.contactReads([ok, ok]), /invalid answer/);
  await assert.rejects(core.contactReads([{ ...ok, days: [{ day: '1' }, { day: '2' }] }]), /invalid answer/);
  answers.nc_contact_reads = { contacts: [{ days: [dayAnswer('1')] }] };
  await assert.rejects(core.contactReads([ok]), /invalid answer/, 'no ack and no error');
  answers.nc_contact_reads = { nope: true };
  await assert.rejects(core.contactReads([ok]), /invalid answer/);
});

test('core: outboxFetchDays refuses a bad day list before the module, and an answer of the wrong length', async () => {
  const { nodus, calls } = fakeDaysNodus({ nc_unlock: { fingerprint: FP, fresh: false }, nc_outbox_get_days: { days: [dayAnswer('1')] } });
  const core = createNodusConnectCore({ nodus });
  await core.unlock({ words: new TextEncoder().encode('alpha beta gamma') });
  const nine = Array.from({ length: 9 }, (_, i) => ({ day: String(i) }));
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, []), /day list/);
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, nine), /day list/);
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, [{ day: 'x' }]), /Invalid day/);
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, [{}]), /Invalid day/);
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, [{ day: '1', skipBlob: 'zz' }]), /Invalid blob/);
  await assert.rejects(core.outboxFetchDays(OTHER, 'nope', [{ day: '1' }]), /Invalid salt/);
  assert.equal(calls.filter(c => c.name === 'nc_outbox_get_days').length, 0, 'nothing reached the module');
  await assert.rejects(core.outboxFetchDays(OTHER, SALT, [{ day: '1' }, { day: '2' }]), /invalid answer/);
});

// W-04 (web 0.1.88): the first-time record permission crosses into the
// module as one number per gated write — 1 only when the page passes
// firstOk: true (nc_wasm.c first_begin). The default is 0: a caller that
// does not ask never lets an EMPTY read create the own profile or list.
test('core: profileUpdate and contactsAdd pass firstOk to the module as 0 / 1', async () => {
  const { nodus, calls } = fakeDaysNodus({
    nc_unlock: { fingerprint: FP, fresh: false },
    nc_profile_update: { status: 'published', read: { outcome: 'empty', why: 'none' }, created: true, put_rc: 0, version: '1' },
    nc_contacts_add: { status: 'published', outcome: 'empty', why: 'none', created: true, count_before: '0', count_after: '1', salt_kept: '0', put_rc: 0 }
  });
  const core = createNodusConnectCore({ nodus });
  await core.unlock({ words: new TextEncoder().encode('alpha beta gamma') });
  await core.profileUpdate({});
  await core.profileUpdate({}, { firstOk: true });
  await core.profileUpdate({ bio: 'x' }, { firstOk: 'yes' });
  await core.contactsAdd([{ fp: OTHER }]);
  await core.contactsAdd([{ fp: OTHER, salt: SALT }], { firstOk: true });
  const prof = calls.filter(c => c.name === 'nc_profile_update');
  assert.deepEqual(prof.map(c => c.types), [['string', 'number'], ['string', 'number'], ['string', 'number']]);
  assert.deepEqual(prof.map(c => c.args[1]), [0, 1, 0], 'only a literal true allows the first record');
  const list = calls.filter(c => c.name === 'nc_contacts_add');
  assert.deepEqual(list.map(c => c.types), [['string', 'number'], ['string', 'number']]);
  assert.deepEqual(list.map(c => c.args[1]), [0, 1]);
  assert.equal(JSON.parse(list[1].args[0])[0].salt, SALT);
});
