// Package G3 — the groups state machine of the Nodus Connect page
// (src/connect/groups/engine.js) and its pure rules (model.js), against a
// MOCKED core: no module, no network, no browser.
//
// What it proves (each test names its rule):
//   - invite -> accept -> owner rotation -> welcome -> the member joins at the
//     welcomed version (opened against the welcome's digest, no older packet),
//     and the owner's writes of that version go record, packet, HEAD — HEAD
//     LAST — with the welcome sent only after the HEAD (design §3, §7, R2-7);
//   - the leave flow (decision 13): the member hides the group and tells the
//     owner; the owner lists the member as leaving until the rotation's HEAD
//     is out, then not;
//   - removal: a HEAD that cannot be written leaves the member listed (never
//     "removed" before the HEAD is published); the removed member's own check
//     finds no entry and shows "removed";
//   - the late-mail rule (decision 6): once a receiver holds version N+1, a
//     message under N from someone not in N+1 is dropped, from someone in
//     N+1 kept;
//   - read failure -> wait: with every read unreadable nothing is written
//     (no PUT is made by the mock at all), the stage and the unsent message
//     stay, and both go out once the network answers (thin-core S3);
//   - the double-send guard: a second send while the first is being kept is
//     refused ('busy'), one message is kept;
//   - catch-up: a member walks every version up to the HEAD; a packet whose
//     predecessor digest differs is refused and the member stays where it
//     was (R2-7);
//   - owner gone (decision 7): after 30 days without a new key a member sees
//     "key is old" and can still send under the last key;
//   - who may send which control message (design §7, R2-7): an invite whose
//     owner is not its sender, from a non-contact, a welcome from someone
//     other than the pinned owner, an accept with another invite_id — all
//     ignored;
//   - a join the owner refused (no ML-KEM key) leaves the member 'accepting';
//     the same owner's NEW invite reopens it as 'invited', a welcome for the
//     old invite_id and invites from other senders stay ignored (R2-7,
//     decision 8);
//   - the device keeps everything: a fresh engine loaded from what was saved
//     shows the same group, versions and messages;
//   - the store's `groups` index and the split of group messages from 1:1.
//
// How it can lie: the mock core is NOT the module. Its "packets", "records",
// "HEADs" and "items" are JSON in hex, its digests SHA-512 of that hex, its
// signature check is "the owner field equals the pinned owner": it encodes
// the module's verdicts (connect/nc_wasm.c, nc_group.h) as this file reads
// them, and proves the PAGE's sequencing and rules — never the bytes, the
// cryptography or the module's own checks (those are
// connect/tests/test_nc_group.c, native). The DHT is one Map: no paging, no
// partial answer, no foreign rows except where a test adds them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createGroupsEngine } from '../src/connect/groups/engine.js';
import {
  controlType, acceptRule, nextMembers, rotationDue, keyIsOld, bucketVersions, orderIncoming, pendingBuckets,
  splitPieces, BLOB_PIECE, checkGroup, newGroup, storedGroup, textProblem, nameProblem, ROTATE_MS, DAY_MS
} from '../src/connect/groups/model.js';
import { emptyState, checkState, memoryHistoryStore, GROUP_RECORD_ID } from '../src/connect/store.js';

const FA = 'a1'.repeat(64), FB = 'b2'.repeat(64), FC = 'c3'.repeat(64), FD = 'd4'.repeat(64);
const T0 = Date.UTC(2026, 9, 5, 12, 0, 0);
const sha512 = s => createHash('sha512').update(s).digest('hex');
const sha256 = s => createHash('sha256').update(s).digest('hex');
const toHex = s => Buffer.from(s, 'utf8').toString('hex');
const fromHex = h => Buffer.from(h, 'hex').toString('utf8');
const bytesHex = u8 => Buffer.from(u8).toString('hex');

// ── the mocked network and core ─────────────────────────────────────────
function world() {
  return {
    rows: new Map(),            // address -> Map(owner -> value hex | item list)
    unreadable: false,          // every read answers "could not read"
    headWait: false,            // HEAD writes answer "wait" (nothing written)
    log: [],                    // 'put:<purpose>:<x>:<owner>' and 'send:<type>:<from>-><to>'
    clock: { t: T0 },
    counter: 0
  };
}
const addr = (purpose, secret, x) => `${purpose}|${secret}|${x}`;
function row(net, key) { if (!net.rows.has(key)) net.rows.set(key, new Map()); return net.rows.get(key); }

function fakeCore(net, me) {
  const rnd = n => { net.counter++; return sha512(`${me}|${net.counter}`).slice(0, n); };
  const jsonOf = hex => JSON.parse(fromHex(hex));
  return {
    groupRandom: () => ({ group_id: rnd(64), group_key: rnd(64), addr_secret: rnd(64) }),
    groupSalt: (gid, key, v) => sha256(`${gid}|${key}|${v}`),
    groupAcceptJson: (gid, inviteId) => JSON.stringify({ type: 'nodus_group_accept', v: 1, group_id: gid, invite_id: inviteId }),
    groupLeaveJson: gid => JSON.stringify({ type: 'nodus_group_leave', v: 1, group_id: gid }),
    groupJsonRead(text) {
      let j;
      try { j = JSON.parse(text); } catch { return { status: 'refused' }; }
      const type = { nodus_group_invite: 'invite', nodus_group_accept: 'accept', nodus_group_welcome: 'welcome', nodus_group_leave: 'leave' }[j.type];
      if (!type || j.v !== 1) return { status: 'refused' };
      return { status: 'ok', type, group_id: j.group_id, invite_id: j.invite_id, owner: j.owner, name: j.name, addr_secret: j.addr_secret, key_version: j.key_version === undefined ? undefined : String(j.key_version), kp_digest: j.kp_digest };
    },
    async groupInvite(gid, name) {
      const inviteId = rnd(32);
      return { json: JSON.stringify({ type: 'nodus_group_invite', v: 1, group_id: gid, owner: me, name, invite_id: inviteId }), invite_id: inviteId };
    },
    async groupWelcome({ gid, addr: secret, v, digest, inviteId }) {
      return JSON.stringify({ type: 'nodus_group_welcome', v: 1, group_id: gid, owner: me, addr_secret: secret, key_version: Number(v), kp_digest: digest, invite_id: inviteId });
    },
    async groupRecordNew({ gid, v, key, name, members, created }) {
      const record = toHex(JSON.stringify({ gid, v: Number(v), key, name, members: [...members].sort(), created }));
      return { record, digest: sha512(record) };
    },
    async groupKpNew({ gid, v, prev, rdigest, issued, key, members }) {
      const packet = toHex(JSON.stringify({ gid, v: Number(v), owner: me, prev, rdigest, issued, key, members: [...members].sort() }));
      return { packet, digest: sha512(packet), count: String(members.length) };
    },
    async groupHeadNew({ gid, v, digest, issued }) {
      return { head: toHex(JSON.stringify({ gid, v: Number(v), owner: me, digest, issued })) };
    },
    // The gated write of nc_group_put: read the own row, then write at most once.
    async groupPut({ purpose, gid, secret, x, value }) {
      if (net.unreadable) return { status: 'wait', outcome: 'unreadable', why: 'timeout' };
      if (purpose === 'head' && net.headWait) return { status: 'wait', outcome: 'unreadable', why: 'timeout' };
      const hex = bytesHex(value), r = row(net, addr(purpose, secret, x)), mine = r.get(me);
      if (mine === hex) return { status: 'unchanged', outcome: 'found' };
      if (mine !== undefined) {
        if (purpose !== 'head') return { status: 'conflict', outcome: 'found' };
        const found = jsonOf(mine), next = jsonOf(hex);
        if (found.v > next.v) return { status: 'stale', outcome: 'found' };
      }
      r.set(me, hex);
      net.log.push(`put:${purpose}:${x}:${me.slice(0, 2)}`);
      return { status: 'published', outcome: mine === undefined ? 'empty' : 'found', putRc: 0 };
    },
    async groupGet({ purpose, secret, x, owner }) {
      if (net.unreadable) return { outcome: 'unreadable', why: 'timeout', foreign: '0' };
      const value = net.rows.get(addr(purpose, secret, x))?.get(owner);
      return value === undefined ? { outcome: 'empty', why: 'none', foreign: '0' } : { outcome: 'found', why: 'none', foreign: '0', data: value };
    },
    async groupKpRead({ packet, owner, gid, v, prev = '', pinned = '' }) {
      const p = jsonOf(packet), digest = sha512(packet);
      if (p.owner !== owner) return { status: 'bad_sig' };
      const common = { v: String(p.v), count: String(p.members.length), digest, prev_digest: p.prev, record_digest: p.rdigest, issued_at_ms: p.issued };
      if (p.gid !== gid || p.v !== Number(v)) return { status: 'mismatch', ...common };
      if (pinned) { if (digest !== pinned) return { status: 'prev_conflict', ...common }; }
      else if (p.v > 1) { if (!prev) return { status: 'prev_unavailable', ...common }; if (prev !== p.prev) return { status: 'prev_conflict', ...common }; }
      if (!p.members.includes(me)) return { status: 'no_entry', ...common };
      return { status: 'ok', ...common, group_key: p.key };
    },
    groupRecordRead({ record, key, gid, v, digest, count, owner }) {
      if (sha512(record) !== digest) return { status: 'bad_digest' };
      const r = jsonOf(record);
      if (r.key !== key || r.gid !== gid || r.v !== Number(v)) return { status: 'bad_auth' };
      if (String(r.members.length) !== String(count)) return { status: 'count' };
      if (!r.members.includes(owner)) return { status: 'no_owner' };
      return { status: 'ok', name_hex: toHex(r.name), members: r.members, created_at_ms: r.created };
    },
    async groupHeadRead({ head, owner, gid }) {
      const h = jsonOf(head);
      if (h.owner !== owner) return { status: 'bad_sig' };
      if (h.gid !== gid) return { status: 'mismatch' };
      return { status: 'ok', v: String(h.v), kp_digest: h.digest, issued_at_ms: h.issued };
    },
    async groupMsgNew({ key, gid, v, ts, text }) {
      const mid = rnd(32), day = String(Math.floor(Number(ts) / DAY_MS));
      return { item: toHex(JSON.stringify({ gid, v: Number(v), sender: me, mid, ts, day, text, key })), message_id: mid, day };
    },
    // nc_group_bucket_send: own row read first; union by message_id.
    async groupBucketSend({ salt, v, day, items }) {
      if (net.unreadable) return { status: 'wait', outcome: 'unreadable', ids: [] };
      const r = row(net, addr('bucket', salt, day)), base = r.get(me) || [];
      const ids = new Set(base.map(i => jsonOf(i).mid));
      const add = items.filter(i => { const m = jsonOf(i); if (m.v !== Number(v) || m.day !== String(day) || m.sender !== me || ids.has(m.mid)) return false; ids.add(m.mid); return true; });
      if (!add.length) return { status: 'unchanged', ids: [...ids] };
      r.set(me, [...base, ...add]);
      net.log.push(`put:bucket:${day}:${me.slice(0, 2)}`);
      return { status: 'published', ids: [...ids] };
    },
    // nc_group_bucket_fetch: owner-less; the row's owner must be the sender; the key opens.
    async groupBucketFetch({ salt, day, key }) {
      if (net.unreadable) return { outcome: 'unreadable', why: 'timeout', buckets: [] };
      const r = net.rows.get(addr('bucket', salt, day));
      if (!r) return { outcome: 'empty', why: 'none', buckets: [] };
      return {
        outcome: 'found', why: 'none',
        buckets: [...r.entries()].map(([owner, items]) => {
          const parsed = items.map(jsonOf);
          if (parsed.some(m => m.sender !== owner)) return { owner, status: 'wrong_owner', sender: parsed[0]?.sender, messages: [] };
          return { owner, status: 'ok', sender: owner, messages: parsed.map(m => (m.key === key ? { messageId: m.mid, timestampMs: m.ts, status: 'ok', text: m.text } : { messageId: m.mid, timestampMs: m.ts, status: 'bad_auth' })) };
        })
      };
    }
  };
}

// One identity: its engine, its saved records, its 1:1 outbox.
function party(net, fp, { contacts = [], kem = () => true } = {}) {
  const state = emptyState();
  const db = new Map(), kept = new Map();
  const outbox = [];
  const p = { fp, state, db, kept, outbox, contacts: [...contacts], failSave: false };
  p.deps = {
    core: fakeCore(net, fp), ownFp: fp, now: () => net.clock.t, state: () => state,
    takeSeq: () => { const s = state.nextSeq; state.nextSeq = String(BigInt(s) + 1n); return s; },
    saveAll: async ({ records = [], messages = [] }) => {
      if (p.failSave) throw new Error('save failed');
      for (const r of records) db.set(r.id, structuredClone(r.value));
      for (const m of messages) kept.set(m.seq, structuredClone(m));
    },
    sendDirect: async (to, text) => { outbox.push({ to, text }); net.log.push(`send:${JSON.parse(text).type.replace('nodus_group_', '')}:${fp.slice(0, 2)}->${to.slice(0, 2)}`); },
    isContact: x => p.contacts.includes(x),
    ensureProfile: async () => true,
    reloadProfile: async () => true,
    hasKemKey: x => kem(x),
    // every identity has a chain name here (decision 17 is pinned in
    // test/connect-groups-names.test.js)
    nameStatus: () => 'found',
    lookupName: async () => {}
  };
  p.engine = createGroupsEngine(p.deps);
  return p;
}
// Hands every 1:1 message from `from` to `to` (the authenticated sender = from).
async function deliver(from, to) {
  const mine = from.outbox.filter(m => m.to === to.fp);
  from.outbox.splice(0, from.outbox.length, ...from.outbox.filter(m => m.to !== to.fp));
  for (const m of mine) assert.equal(await to.engine.onDirect(from.fp, m.text), true, 'a group control message is taken off the chat');
}
const texts = (p, gid) => p.engine.conversation(gid).map(m => m.text);

// A group of the owner A and the members given, all active at the version
// that added them.
async function groupOf(net, members) {
  const A = party(net, FA, { contacts: members.map(m => m.fp) });
  const { gid } = await A.engine.create('Team', members.map(m => m.fp));
  for (const m of members) { await deliver(A, m); await m.engine.acceptInvite(gid); await deliver(m, A); }
  await A.engine.syncAll();
  for (const m of members) { await deliver(A, m); await m.engine.syncAll(); }
  return { A, gid };
}

// ── the flows ────────────────────────────────────────────────────────────
test('invite -> accept -> rotation (record, packet, HEAD last) -> welcome -> the member joins at the welcomed version', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  assert.deepEqual(net.log.filter(e => e.startsWith('put:')), ['put:record:1:a1', 'put:packet:1:a1', 'put:head:0:a1'], 'version 1 is published HEAD last');
  assert.equal(A.engine.view(gid).ready, true);
  assert.deepEqual(A.engine.view(gid).members, [FA]);

  await deliver(A, B);
  assert.deepEqual(B.engine.invitations().map(i => [i.gid, i.name, i.owner]), [[gid, 'Team', FA]]);
  assert.equal(B.engine.list().length, 0, 'an invitation is not a group yet');
  await B.engine.acceptInvite(gid);
  assert.equal(B.engine.group(gid).status, 'accepting');
  await deliver(B, A);
  assert.deepEqual(A.engine.view(gid).joining, [FB], 'accepted, added at the next update');
  assert.deepEqual(A.engine.view(gid).members, [FA]);

  net.log.length = 0;
  await A.engine.syncAll();
  assert.deepEqual(net.log, ['put:record:2:a1', 'put:packet:2:a1', 'put:head:0:a1', 'send:welcome:a1->b2'],
    'the new version: record, packet, HEAD last; the welcome only after the HEAD');
  assert.deepEqual(A.engine.view(gid).members, [FA, FB]);

  await deliver(A, B);
  assert.equal(B.engine.group(gid).status, 'joining');
  assert.equal(B.engine.group(gid).join.v, 2);
  await B.engine.syncAll();
  const b = B.engine.group(gid);
  assert.equal(b.status, 'active');
  assert.equal(b.hw.v, 2);
  assert.equal(b.first, 2, 'no pre-join history (decision 12)');
  assert.equal(b.keys.has(1), false, 'version 1 was never read');
  assert.deepEqual(B.engine.view(gid).members, [FA, FB]);
  assert.deepEqual(bucketVersions(b), [2]);

  assert.equal(await A.engine.send(gid, 'hello group'), 'sent');
  await B.engine.syncAll();
  assert.deepEqual(texts(B, gid), ['hello group']);
  assert.equal(B.engine.view(gid).unread, 1);
  B.engine.markRead(gid);
  assert.equal(B.engine.view(gid).unread, 0);
  assert.equal(await B.engine.send(gid, 'hi back'), 'sent');
  await A.engine.syncAll();
  assert.deepEqual(texts(A, gid), ['hello group', 'hi back']);
});

test('a welcome is opened against its own digest: a packet that differs is refused, the member keeps waiting', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B); await B.engine.acceptInvite(gid); await deliver(B, A);
  await A.engine.syncAll();
  await deliver(A, B);
  const g = A.engine.group(gid);
  // another packet for version 2 at its address, owner A (same members)
  const packetKey = addr('packet', g.addr, '2');
  const original = net.rows.get(packetKey).get(FA);
  const forged = toHex(JSON.stringify({ ...JSON.parse(fromHex(original)), issued: '1' }));
  net.rows.get(packetKey).set(FA, forged);
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).status, 'joining', 'refused, nothing taken');
  assert.equal(B.engine.group(gid).hw, null);
  net.rows.get(packetKey).set(FA, original);
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).status, 'active');
});

test('leave (decision 13): hidden at once, the owner told; listed as leaving until the rotation, then gone', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  await B.engine.leave(gid);
  assert.equal(B.engine.group(gid).status, 'left');
  assert.deepEqual(B.engine.list(), [], 'a group that was left is hidden');
  assert.equal(B.outbox[0].to, FA);
  assert.equal(controlType(B.outbox[0].text), 'leave');
  await deliver(B, A);
  assert.deepEqual(A.engine.view(gid).leaving, [FB]);
  assert.deepEqual(A.engine.view(gid).members, [FA, FB], 'still listed until the change is out');
  net.log.length = 0;
  await A.engine.syncAll();
  assert.deepEqual(net.log.filter(e => e.startsWith('put:') && !e.startsWith('put:bucket')), ['put:record:3:a1', 'put:packet:3:a1', 'put:head:0:a1']);
  assert.deepEqual(A.engine.view(gid).members, [FA]);
  assert.deepEqual(A.engine.view(gid).leaving, []);
  // a second leave from someone no longer a member is ignored
  await A.engine.onDirect(FB, JSON.stringify({ type: 'nodus_group_leave', v: 1, group_id: gid }));
  assert.deepEqual(A.engine.group(gid).removals, []);
});

test('removal: never shown as removed before the HEAD is out; the removed member finds no entry', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  assert.deepEqual(A.engine.view(gid).members, [FA, FB, FC].sort());
  await A.engine.removeMember(gid, FC);
  assert.deepEqual(A.engine.view(gid).leaving, [FC]);
  net.headWait = true;
  net.log.length = 0;
  await A.engine.syncAll();
  const v = A.engine.group(gid).hw.v;
  assert.deepEqual(net.log.filter(e => e.startsWith('put:') && !e.startsWith('put:bucket')), [`put:record:${v + 1}:a1`, `put:packet:${v + 1}:a1`], 'record and packet out, HEAD not');
  assert.ok(A.engine.group(gid).stage, 'the change stays staged on the device');
  assert.deepEqual(A.engine.view(gid).members, [FA, FB, FC].sort(), 'still listed: the HEAD is not out');
  // the removed member, meanwhile: the HEAD still says the old version
  await C.engine.syncAll();
  assert.equal(C.engine.group(gid).status, 'active');
  net.headWait = false;
  net.log.length = 0;
  await A.engine.syncAll();
  assert.deepEqual(net.log.filter(e => e.startsWith('put:') && !e.startsWith('put:bucket')), ['put:head:0:a1'], 'only the HEAD remained; record and packet are not written again');
  assert.equal(A.engine.group(gid).stage, null);
  assert.deepEqual(A.engine.view(gid).members, [FA, FB].sort());
  await C.engine.syncAll();
  assert.equal(C.engine.group(gid).status, 'removed');
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).hw.v, v + 1);
  assert.deepEqual(B.engine.view(gid).members, [FA, FB].sort());
});

test('late mail (decision 6): under the old version, a member removed in the next one is dropped, a remaining one kept', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  const v = A.engine.group(gid).hw.v;
  assert.equal(await A.engine.send(gid, 'from A, old key'), 'sent');
  assert.equal(await C.engine.send(gid, 'from C, old key'), 'sent');
  await A.engine.removeMember(gid, FC);
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v + 1);
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).hw.v, v + 1, 'B holds the next version');
  assert.deepEqual(bucketVersions(B.engine.group(gid)), [v + 1, v]);
  assert.deepEqual(texts(B, gid), ['from A, old key'], 'C\'s old-key message is dropped, A\'s kept');
  assert.ok(B.engine.view(gid).note, 'the drop is reported in plain words');
  assert.deepEqual(texts(A, gid).filter(t => t.startsWith('from C')), [], 'the owner drops it too');
});

test('read failure -> wait: nothing is written while reads fail; the change and the message go out afterwards', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), D = party(net, FD, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  A.contacts.push(FD);
  await A.engine.invite(gid, FD);
  await deliver(A, D); await D.engine.acceptInvite(gid); await deliver(D, A);
  const v = A.engine.group(gid).hw.v;
  net.unreadable = true;
  const before = net.log.length;
  assert.equal(await B.engine.send(gid, 'while offline'), 'kept');
  await A.engine.syncAll();
  await B.engine.syncAll();
  assert.equal(net.log.length, before, 'no write of any kind');
  assert.ok(A.engine.group(gid).stage, 'the owner\'s change is staged and waits');
  assert.equal(A.engine.group(gid).hw.v, v);
  assert.deepEqual(A.engine.view(gid).joining, [], 'the joiner moved into the staged change');
  assert.equal(B.engine.messages().find(m => m.text === 'while offline').published, undefined);
  net.unreadable = false;
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v + 1);
  assert.deepEqual(A.engine.view(gid).members, [FA, FB, FD].sort());
  await B.engine.syncAll();
  assert.equal(B.engine.messages().find(m => m.text === 'while offline').published, true);
});

test('double send: a second send while the first is being kept is refused; one message is kept', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  const first = A.engine.send(gid, 'once');
  assert.equal(A.engine.sending, true);
  const second = A.engine.send(gid, 'once');
  assert.equal(await second, 'busy');
  assert.equal(await first, 'sent');
  assert.equal(A.engine.sending, false);
  assert.deepEqual(texts(A, gid), ['once']);
  let kept = 0;
  assert.equal(await A.engine.send(gid, 'twice', { onKept: () => { kept++; } }), 'sent');
  assert.equal(kept, 1, 'onKept runs once the message is kept');
  await assert.rejects(A.engine.send(gid, ''), /Write a message/);
  await assert.rejects(A.engine.send(gid, 'x'.repeat(4001)), /at most 4000 bytes/);
});

test('catch-up: a member walks every version up to the HEAD; a predecessor that differs is refused', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  const v = A.engine.group(gid).hw.v;
  net.clock.t += ROTATE_MS;                       // decision 5: the owner rotates every 30 days
  await A.engine.syncAll();
  net.clock.t += ROTATE_MS;
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v + 2);
  await B.engine.syncAll();
  const b = B.engine.group(gid);
  assert.equal(b.hw.v, v + 2);
  assert.ok(b.keys.has(v + 1) && b.keys.has(v + 2), 'every version on the way is kept (decision 14)');
  assert.equal(b.keys.get(v + 2).prev, b.keys.get(v + 1).digest);

  // a forged next version whose prev_digest is not the held digest
  net.clock.t += ROTATE_MS;
  await A.engine.syncAll();
  const g = A.engine.group(gid);
  const packetKey = addr('packet', g.addr, String(v + 3));
  const real = net.rows.get(packetKey).get(FA);
  net.rows.get(packetKey).set(FA, toHex(JSON.stringify({ ...JSON.parse(fromHex(real)), prev: 'ee'.repeat(64) })));
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).hw.v, v + 2, 'refused: the member stays where it was');
  net.rows.get(packetKey).set(FA, real);
  await B.engine.syncAll();
  assert.equal(B.engine.group(gid).hw.v, v + 3);
});

test('owner gone (decision 7): after 30 days a member sees "key is old" and still sends under the last key', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  const v = B.engine.group(gid).hw.v;
  assert.equal(B.engine.view(gid).keyOld, false);
  net.clock.t += ROTATE_MS + 1;                   // the owner (A) does not run
  assert.equal(B.engine.view(gid).keyOld, true);
  assert.equal(await B.engine.send(gid, 'still here'), 'sent');
  assert.equal(B.engine.messages().find(m => m.text === 'still here').v, v);
  await C.engine.syncAll();
  assert.deepEqual(texts(C, gid), ['still here']);
  assert.equal(A.engine.view(gid).keyOld, true, 'the owner sees it too until it rotates');
});

test('who may send which: an invite not from its owner, a non-contact\'s invite, a welcome from someone else, an accept for another invite — ignored', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA, FC] });
  const A = party(net, FA, { contacts: [FB, FC] });
  const { gid } = await A.engine.create('Team', [FB]);
  const invite = JSON.parse(A.outbox[0].text);
  // C forwards A's invite: the owner field is not the sender
  assert.equal(await B.engine.onDirect(FC, JSON.stringify(invite)), true);
  assert.deepEqual(B.engine.invitations(), []);
  // D (not a contact) invites in its own name
  assert.equal(await B.engine.onDirect(FD, JSON.stringify({ ...invite, owner: FD })), true);
  assert.deepEqual(B.engine.invitations(), []);
  // the real one
  await deliver(A, B);
  assert.equal(B.engine.invitations().length, 1);
  await B.engine.acceptInvite(gid);
  // C answers with B's invite id
  await A.engine.onDirect(FC, JSON.stringify({ type: 'nodus_group_accept', v: 1, group_id: gid, invite_id: invite.invite_id }));
  assert.deepEqual(A.engine.view(gid).joining, []);
  // B answers with another invite id
  await A.engine.onDirect(FB, JSON.stringify({ type: 'nodus_group_accept', v: 1, group_id: gid, invite_id: 'ff'.repeat(16) }));
  assert.deepEqual(A.engine.view(gid).joining, []);
  await deliver(B, A);
  assert.deepEqual(A.engine.view(gid).joining, [FB]);
  // the accept is consumed once
  await A.engine.onDirect(FB, JSON.stringify({ type: 'nodus_group_accept', v: 1, group_id: gid, invite_id: invite.invite_id }));
  assert.deepEqual(A.engine.group(gid).invites, []);
  await A.engine.syncAll();
  const welcome = A.outbox.find(m => m.to === FB).text;
  // the same welcome from C: not the pinned owner
  await B.engine.onDirect(FC, welcome);
  assert.equal(B.engine.group(gid).status, 'accepting');
  await deliver(A, B);
  assert.equal(B.engine.group(gid).status, 'joining');
  // a text that only claims a group type is still taken off the chat
  assert.equal(await B.engine.onDirect(FA, '{"type":"nodus_group_invite","v":2}'), true);
  assert.equal(await B.engine.onDirect(FA, 'hello'), false);
});

test('a joiner without the key type groups need is refused in plain words; the others still join', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB, FC], kem: fp => fp !== FC });
  const { gid } = await A.engine.create('Team', [FB, FC]);
  for (const m of [B, C]) { await deliver(A, m); await m.engine.acceptInvite(gid); await deliver(m, A); }
  await A.engine.syncAll();
  assert.deepEqual(A.engine.view(gid).members, [FA, FB].sort());
  assert.deepEqual(A.engine.view(gid).refused, [FC]);
  assert.equal(A.outbox.filter(m => controlType(m.text) === 'welcome').map(m => m.to).join(), FB);
});

test('a refused joiner is reopened by the same owner\'s new invite; a welcome for the old invite and another sender stay ignored', async () => {
  const net = world();
  let cHasKey = false;
  const C = party(net, FC, { contacts: [FA, FB, FD] });
  const A = party(net, FA, { contacts: [FC], kem: fp => fp !== FC || cHasKey });
  const { gid } = await A.engine.create('Team', [FC]);
  await deliver(A, C);
  const first = C.engine.group(gid).invite.id;
  await C.engine.acceptInvite(gid);
  await deliver(C, A);
  await A.engine.syncAll();
  assert.deepEqual(A.engine.view(gid).refused, [FC], 'the owner refused the join');
  assert.deepEqual(A.engine.view(gid).joining, []);
  assert.equal(A.outbox.filter(m => m.to === FC).length, 0, 'nothing is sent to the refused joiner');
  assert.equal(C.engine.group(gid).status, 'accepting', 'the member still waits');

  // the same invite delivered again changes nothing
  const firstJson = JSON.stringify({ type: 'nodus_group_invite', v: 1, group_id: gid, owner: FA, name: 'Team', invite_id: first });
  await C.engine.onDirect(FA, firstJson);
  assert.equal(C.engine.group(gid).status, 'accepting');

  // another sender for this group, in its own name or forwarding A's: ignored
  await C.engine.onDirect(FD, JSON.stringify({ type: 'nodus_group_invite', v: 1, group_id: gid, owner: FD, name: 'Team', invite_id: 'dd'.repeat(16) }));
  await C.engine.onDirect(FB, JSON.stringify({ type: 'nodus_group_invite', v: 1, group_id: gid, owner: FA, name: 'Team', invite_id: 'bb'.repeat(16) }));
  assert.equal(C.engine.group(gid).status, 'accepting');
  assert.equal(C.engine.group(gid).owner, FA);

  // the owner invites again: a new invite_id; the member is invited again
  cHasKey = true;
  await A.engine.invite(gid, FC);
  await deliver(A, C);
  const g = C.engine.group(gid);
  assert.equal(g.status, 'invited');
  assert.equal(g.owner, FA, 'the pinned owner is kept');
  assert.notEqual(g.invite.id, first);
  assert.deepEqual(C.engine.invitations().map(i => i.gid), [gid]);
  assert.equal(C.engine.list().length, 0, 'shown as an invitation, not as "Joining…"');

  // a welcome for the old invite is not honoured
  const stale = JSON.stringify({ type: 'nodus_group_welcome', v: 1, group_id: gid, owner: FA, addr_secret: A.engine.group(gid).addr, key_version: 1, kp_digest: A.engine.group(gid).hw.digest, invite_id: first });
  await C.engine.onDirect(FA, stale);
  assert.equal(C.engine.group(gid).status, 'invited');
  assert.equal(C.engine.group(gid).addr, null);

  // accept the new invite: the owner adds the member and welcomes it
  await C.engine.acceptInvite(gid);
  await deliver(C, A);
  assert.deepEqual(A.engine.view(gid).joining, [FC]);
  await A.engine.syncAll();
  assert.deepEqual(A.engine.view(gid).members, [FA, FC]);
  await deliver(A, C);
  assert.equal(C.engine.group(gid).status, 'joining');
  await C.engine.syncAll();
  assert.equal(C.engine.group(gid).status, 'active');
});

test('everything is kept on the device: a fresh engine loaded from the saved records shows the same group', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  await A.engine.send(gid, 'kept text');
  net.clock.t += ROTATE_MS;
  await A.engine.syncAll();
  const v = A.engine.group(gid).hw.v;
  for (const id of A.db.keys()) assert.match(id, GROUP_RECORD_ID);
  const again = createGroupsEngine({ ...A.deps });
  again.load({ records: [...A.db.entries()].map(([id, value]) => ({ id, value })), messages: [...A.kept.values()] });
  const g = again.group(gid);
  assert.ok(g, 'the group loads');
  assert.equal(g.hw.v, v);
  assert.deepEqual([...g.keys.keys()].sort(), [...A.engine.group(gid).keys.keys()].sort(), 'every key version');
  assert.deepEqual(again.conversation(gid).map(m => m.text), ['kept text']);
  assert.equal(again.view(gid).unread, 0, 'history from earlier sessions is not new');
  // a staged change survives too (the packet in pieces)
  await A.engine.removeMember(gid, FB);
  net.headWait = true;
  await A.engine.syncAll();
  const staged = createGroupsEngine({ ...A.deps });
  staged.load({ records: [...A.db.entries()].map(([id, value]) => ({ id, value })), messages: [] });
  assert.ok(staged.group(gid).stage);
  net.headWait = false;
  await staged.syncAll();
  assert.equal(staged.group(gid).hw.v, v + 1, 'the reloaded stage is published from the kept pieces');
});

test('a failed save leaves the group as it was', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  A.failSave = true;
  await assert.rejects(A.engine.removeMember(gid, FB));
  assert.deepEqual(A.engine.group(gid).removals, []);
  A.failSave = false;
});

// ── pure rules ───────────────────────────────────────────────────────────
test('control messages: the four group types are recognised, anything else is chat', () => {
  assert.equal(controlType('{"type":"nodus_group_invite"}'), 'invite');
  assert.equal(controlType('{"type":"nodus_group_accept"}'), 'accept');
  assert.equal(controlType('{"type":"nodus_group_welcome"}'), 'welcome');
  assert.equal(controlType('{"type":"nodus_group_leave","v":1,"group_id":"00"}'), 'leave');
  assert.equal(controlType('{"type":"group_invite"}'), null, 'the old app type is not ours (nc_outbox.c drops it)');
  assert.equal(controlType('{"type":"nodus_vault"}'), null);
  assert.equal(controlType('hello nodus_group_invite'), null);
  assert.equal(controlType('{not json nodus_group_invite'), null);
  assert.equal(controlType(undefined), null);
});

test('accept rule (decision 6) and the next member list', () => {
  assert.equal(acceptRule(FB, [FA, FB], undefined), true);
  assert.equal(acceptRule(FB, [FA, FB], [FA, FB]), true);
  assert.equal(acceptRule(FC, [FA, FB, FC], [FA, FB]), false, 'removed in N+1: dropped, whatever its time');
  assert.equal(acceptRule(FD, [FA, FB], undefined), false);
  assert.deepEqual(nextMembers([FA, FB, FC], [FD], [FC], FA), [FA, FB, FD].sort());
  assert.deepEqual(nextMembers([FA, FB], [], [FA], FA), [FA, FB], 'the owner is never removed');
});

test('rotation and "key is old" follow the 30-day rule; bucket versions never go below the first', () => {
  assert.equal(rotationDue(String(T0), T0 + ROTATE_MS - 1), false);
  assert.equal(rotationDue(String(T0), T0 + ROTATE_MS), true);
  assert.equal(keyIsOld('x', T0), false);
  const g = { hw: { v: 5 }, first: 5, keys: new Map([[4, {}], [5, {}]]) };
  assert.deepEqual(bucketVersions(g), [5], 'no pre-join history (decision 12)');
  g.first = 3;
  assert.deepEqual(bucketVersions(g), [5, 4]);
  assert.deepEqual(bucketVersions({ hw: null }), []);
});

test('incoming order is (version, day, sender, message id); pending buckets expire after 7 days', () => {
  const list = [
    { v: 2, day: '10', fp: FB, mid: '02' }, { v: 1, day: '11', fp: FC, mid: '01' },
    { v: 2, day: '9', fp: FC, mid: '00' }, { v: 2, day: '10', fp: FA, mid: '05' }
  ];
  assert.deepEqual(orderIncoming(list).map(m => `${m.v}/${m.day}/${m.fp.slice(0, 2)}`), ['1/11/c3', '2/9/c3', '2/10/a1', '2/10/b2']);
  const today = Math.floor(T0 / DAY_MS);
  const msgs = [
    { group: 'g', dir: 'out', v: 1, day: String(today), item: 'aa', seq: '1' },
    { group: 'g', dir: 'out', v: 1, day: String(today - 7), item: 'bb', seq: '2' },
    { group: 'g', dir: 'out', v: 1, day: String(today), item: 'cc', seq: '3', published: true }
  ];
  const p = pendingBuckets(msgs, 'g', T0);
  assert.deepEqual(p.buckets, [{ v: 1, day: String(today) }]);
  assert.deepEqual(p.expired.map(m => m.seq), ['2']);
});

test('text and name limits; packet pieces; the stored group record', () => {
  assert.equal(textProblem('ok'), null);
  assert.match(textProblem('   '), /Write a message/);
  assert.match(textProblem('é'.repeat(2001)), /4000 bytes/);
  assert.match(textProblem('a\u0000b'), /cannot be sent/);
  assert.equal(nameProblem('Team'), null);
  assert.match(nameProblem('x'.repeat(65)), /64 bytes/);
  const hex = 'ab'.repeat(107795);
  const pieces = splitPieces(hex);
  assert.ok(pieces.every(p => p.length <= BLOB_PIECE));
  assert.equal(pieces.join(''), hex);
  const g = newGroup({ gid: 'ee'.repeat(32), owner: FA, name: 'Team', role: 'owner', status: 'active' });
  g.keys = new Map([[1, {}]]);
  const stored = storedGroup(g);
  assert.equal(stored.keys, undefined, 'key versions are separate records');
  assert.ok(checkGroup(stored));
  assert.equal(checkGroup({ ...stored, owner: 'zz' }), null);
  assert.equal(checkGroup({ ...stored, status: 'unknown' }), null);
});

test('store: the groups index defaults for an older state and is checked; the memory store has no group records', () => {
  const older = emptyState();
  delete older.groups;
  assert.deepEqual(checkState(older).groups, {});
  const s = emptyState();
  s.groups['ee'.repeat(32)] = { id: 'g00000000000000000001', at: '1' };
  assert.ok(checkState(s));
  s.groups['ee'.repeat(32)] = { id: 'v00000000000000000001', at: '1' };
  assert.throws(() => checkState(s));
  const mem = memoryHistoryStore();
  assert.deepEqual(mem.groupRecords, []);
  assert.deepEqual(mem.groupMessages, []);
  assert.match('k00000000000000000001', GROUP_RECORD_ID);
  assert.doesNotMatch('p00000000000000000001', GROUP_RECORD_ID);
});
