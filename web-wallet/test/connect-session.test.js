// Shared Connect session in a DOM-free host, as used by the MV3 worker.
// Real JS core adapter/state machine/action codecs; fake native exports and
// memory history. This proves host separation and public projection, NOT
// native crypto, live delivery, or IndexedDB durability. Node 22, no flags,
// network, credentials or files. Each test closes the session/timers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createMessagesSession } from '../src/connect/ui/messages.js';
import { buildReaction, messageHash } from '../src/connect/ui/actions.js';

const OWN = '1a'.repeat(64), PEER = '2b'.repeat(64), REQUEST = '3c'.repeat(64);
const SALT = 'd1'.repeat(32), GROUP_KEY = 'e2'.repeat(32), GROUP_ADDR = 'f3'.repeat(32), GROUP_ID = 'a4'.repeat(32);
const DIGEST = 'b5'.repeat(64), SECRET_FIELD = 'fixture-private-material-must-not-cross';
const PHRASE = 'public fixture words only';
const hex = text => Buffer.from(text).toString('hex');

function fakeClient() {
  const calls = [], published = [], unknown = [], heap = new Uint8Array(4096);
  const today = String(Math.floor(Date.now() / 86400000));
  const profile = fp => ({ outcome: 'found', why: 'none', record: '{}', profile: {
    fingerprint: fp, name: '', claimed_name: '', avatar_base64: '', bio: 'Public fixture profile',
    location: '', website: '', has_mlkem: true, secret: SECRET_FIELD,
  } });
  let last, args = [], serial = Promise.resolve();
  const day = d => ({ outcome: d === today ? 'found' : 'empty', why: 'none', day: d,
    blob: d === today ? 'a1'.repeat(32) : undefined, unchanged: false, dropped: '0', other: '0',
    messages: d === today ? [
      { seq: '7', sender_ts: '1793400000', text_hex: hex('Hello from the fixture peer'), kind: 'chat' },
      { seq: '8', sender_ts: '1793400001', text_hex: hex(JSON.stringify({ type: 'nodus_group_welcome', group_key: GROUP_KEY })), kind: 'chat' }
    ] : [] });
  const answers = {
    nc_unlock: () => ({ fingerprint: OWN, fresh: false }),
    nc_profile_get: a => profile(a[0]),
    nc_profile_update: () => ({ status: 'published', read: 'found', created: false, put_rc: 0 }),
    nc_contacts_get: () => ({ outcome: 'found', contacts: [{ fp: PEER, salt: SALT }], timestamp: '1' }),
    nc_contacts_add: () => ({ status: 'unchanged', outcome: 'found', created: false, count_before: '1', count_after: '1', salt_kept: '0', put_rc: 0 }),
    nc_requests_get: () => ({ requests: [{ sender: REQUEST, salt: SALT, timestamp: '1793400001', message: 'Hello', private_key: SECRET_FIELD }] }),
    nc_salt_reconcile: () => ({ status: 'nothing_to_write', outcome: 'found', choice: 'keep_local', salt: SALT }),
    nc_contact_reads: a => ({ contacts: JSON.parse(a[0]).map(c => ({ ack: { outcome: 'empty' }, days: c.days.map(d => day(d.day)) })) }),
    nc_outbox_send: a => ({ day: today, alg: 1, count: String(JSON.parse(a[2]).length) }),
    nc_request_approve: () => ({}), nc_request_withdraw: () => ({}), nc_ack_send: () => ({}),
    nc_group_random: () => ({ group_id: GROUP_ID, group_key: GROUP_KEY, addr_secret: GROUP_ADDR }),
    nc_group_json_read: () => ({ status: 'refused' }),
    nc_group_record_new: () => ({ record: '11', digest: DIGEST }),
    nc_group_kp_new: () => ({ packet: '22', digest: DIGEST }),
    nc_group_head_new: () => ({ head: '33' }),
    nc_group_salt: () => ({ salt: SALT }),
    nc_group_put: () => ({ status: 'published' }),
  };
  const api = {
    num(name, _types, values) {
      calls.push(name); last = name; args = values || [];
      if (name === 'nc_words_alloc' || name === 'nc_group_in_alloc') return 64;
      if (name === 'nc_lock' || name === 'nc_error_busy') return 0;
      if (!answers[name]) unknown.push(name);
      return 0;
    },
    async call(name, _types, values) {
      calls.push(name); last = name; args = values || [];
      if (!answers[name]) unknown.push(name);
      if (name === 'nc_outbox_send') published.push(JSON.parse(args[2]));
      return 0;
    },
    str(name) { return name === 'nc_day_today' ? today : name === 'nc_result' ? JSON.stringify(answers[last]?.(args) || {}) : ''; },
    heap: () => heap,
  };
  const queued = run => { const job = serial.then(() => run(api)); serial = job.catch(() => {}); return job; };
  const client = { state: 'identified', fingerprint: OWN, localConnectable: true, nameable: true,
    connect: queued, connectLocal: queued, connectSync: run => run(api),
    async nameOf({ owner } = {}) { return { found: true, name: owner === OWN ? 'fixtureowner' : 'fixturepeer', committedHeight: '10' }; },
  };
  return { client, calls, published, unknown };
}

async function until(predicate, diagnostic) {
  for (let turn = 0; turn < 100; turn++) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail(diagnostic());
}

async function opened(t) {
  const f = fakeClient(), session = createMessagesSession();
  t.after(() => session.close());
  await session.open({ client: f.client, phrase: PHRASE });
  assert.equal(session.snapshot().phase, 'open', session.snapshot().text);
  assert.equal(session.snapshot().online, false);
  f.client.state = 'ready'; session.ready({ client: f.client });
  await until(() => session.snapshot().caughtUp, () => JSON.stringify(session.snapshot()));
  assert.deepEqual(f.unknown, [], 'Every simulated native call has a declared fixture answer');
  return { ...f, session };
}

function noSecrets(value) {
  const text = JSON.stringify(value);
  for (const secret of [PHRASE, SALT, GROUP_KEY, GROUP_ADDR, SECRET_FIELD]) assert.equal(text.includes(secret), false, 'Public state leaked a sentinel');
  const walk = x => {
    if (!x || typeof x !== 'object') return;
    for (const [key, val] of Object.entries(x)) {
      assert.ok(!['phrase', 'words', 'seed', 'salt', 'group_key', 'addr_secret', 'private_key', 'item'].includes(key), key);
      walk(val);
    }
  };
  walk(value);
}

test('headless session opens locally, syncs contacts/messages/requests, and exposes no key material', async t => {
  assert.equal(typeof document, 'undefined');
  const { session } = await opened(t);
  const state = session.snapshot();
  assert.equal(state.ownFp, OWN);
  assert.equal(state.online, true);
  assert.equal(state.contacts[0].fp, PEER);
  assert.equal(state.contacts[0].ready, true);
  assert.equal(state.requests[0].sender, REQUEST);
  assert.ok(state.messages.some(m => m.text === 'Hello from the fixture peer'));
  assert.ok(state.messages.every(m => !m.text.includes('nodus_group_welcome')), 'Even malformed control packets stay out of the public view');
  noSecrets(state);
});

test('headless actions reuse message/reaction/profile and contact operations without DOM', async t => {
  const { session, published, calls, unknown } = await opened(t);
  await session.action('messageSend', { fp: PEER, text: 'A new message' });
  assert.ok(published.flat().some(m => m.text === 'A new message'));
  const incoming = session.snapshot().messages.find(m => m.dir === 'in');
  await session.action('messageReact', { fp: PEER, seq: incoming.seq, emoji: '👍' });
  assert.ok(published.flat().some(m => m.text === buildReaction(messageHash(incoming, OWN), '👍', 'add')),
    'Existing reaction codec is used');
  await session.action('profileSave', { bio: 'Updated in background', location: 'Istanbul', website: 'https://example.test' });
  assert.equal(session.snapshot().ownProfile.bio, 'Updated in background');
  await session.action('contactAccept', { fp: REQUEST });
  assert.ok(calls.includes('nc_request_approve'));
  assert.ok(session.snapshot().contacts.some(c => c.fp === REQUEST));
  assert.equal(session.snapshot().requests.some(c => c.sender === REQUEST), false);
  noSecrets(session.snapshot());
  assert.deepEqual(unknown, []);
});

test('group keys and address secret remain behind the public session projection', async t => {
  const { session, calls, unknown } = await opened(t);
  const created = await session.action('groupCreate', { name: 'Fixture group', fps: [] });
  assert.equal(created.gid, GROUP_ID);
  assert.ok(calls.includes('nc_group_kp_new'));
  const group = session.snapshot().groups.find(g => g.gid === GROUP_ID);
  assert.equal(group.name, 'Fixture group');
  assert.equal(group.ready, true);
  noSecrets(session.snapshot());
  noSecrets(created);
  assert.deepEqual(unknown, []);
});

test('headless lock clears contacts/messages/profile and rejects all actions', async t => {
  const { session, calls } = await opened(t);
  session.close();
  const after = session.snapshot();
  assert.equal(after.ownFp, null);
  assert.deepEqual(after.contacts, []);
  assert.deepEqual(after.messages, []);
  assert.deepEqual(after.groups, []);
  assert.equal(after.ownProfile, null);
  assert.ok(calls.includes('nc_lock'));
  await assert.rejects(session.action('messageSend', { fp: PEER, text: 'after lock' }), /not open|locked/u);
  for (const name of ['constructor', '__proto__', 'unlock', 'historyKey', 'connectSync', 'groupRandom']) {
    await assert.rejects(session.action(name, {}));
  }
  noSecrets(after);
});

test('contact removal requires explicit confirmation from the requesting view', async t => {
  const { session } = await opened(t);
  for (const fields of [{ fp: PEER }, { fp: PEER, confirmed: false }, { fp: PEER, confirmed: 'true' }]) {
    await assert.rejects(session.action('contactRemove', fields), /confirm/i);
    assert.ok(session.snapshot().contacts.some(c => c.fp === PEER));
  }
  await session.action('contactRemove', { fp: PEER, confirmed: true });
  assert.equal(session.snapshot().contacts.some(c => c.fp === PEER), false);
  assert.ok(session.snapshot().messages.some(m => m.fp === PEER), 'Existing history is retained after local contact removal');
});
