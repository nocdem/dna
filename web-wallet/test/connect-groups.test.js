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
//   - the store's `groups` index and the split of group messages from 1:1;
//   - a failed save's undo takes back only its own index entry: a second
//     change of the same group made while it waited stands (web 0.1.118);
//   - W-16 / P7 design §2.6: accept, invite, leave and welcome each make
//     exactly ONE save holding both the group record and the 1:1 control
//     message; a crash right after that save (the outbox never reached)
//     leaves the message kept and selected by the 1:1 outbox (text.js
//     hasUndelivered / pendingOutbox, which messages.js uses after a
//     reload); one that cannot be prepared (offline, no salt) saves nothing
//     and leaves the state as it was (accept: still 'invited', Join works);
//     a failed accept save leaves a newer invitation committed meanwhile;
//   - decision 14: leave -> re-invite -> re-join keeps every earlier key
//     version record (the invitation carries the old keyIds forward); after
//     a reload the earlier version is held but inert (buckets of the new
//     membership only, an old unsent message not published under it).
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
  splitPieces, BLOB_PIECE, checkGroup, newGroup, storedGroup, textProblem, nameProblem, ROTATE_MS, DAY_MS, GroupError
} from '../src/connect/groups/model.js';
import { emptyState, checkState, memoryHistoryStore, GROUP_RECORD_ID } from '../src/connect/store.js';
import { hasUndelivered, pendingOutbox } from '../src/connect/ui/text.js';

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
  // holdNext: { wait, fail } — the NEXT save waits for `wait`, then fails
  // (fail true) or goes on; other saves run meanwhile.
  // failSend: the next 1:1 control message cannot be prepared
  // (messages.js prepareControl: Messages closed, offline, no salt — it
  // throws, nothing is kept).
  // crash: every save resolves (written) but the page dies before the
  // control message is handed to the 1:1 outbox (kept() never runs) — the
  // W-16 window between "kept" and "published".
  // saves: every saveAll call, in order: { records: [ids], messages: [copies] }.
  const p = { fp, state, db, kept, outbox, contacts: [...contacts], failSave: false, holdNext: null, failSend: false, crash: false, saves: [] };
  p.deps = {
    core: fakeCore(net, fp), ownFp: fp, now: () => net.clock.t, state: () => state,
    takeSeq: () => { const s = state.nextSeq; state.nextSeq = String(BigInt(s) + 1n); return s; },
    // A failure runs the caller's `undo` before it rejects, as store.js
    // save does (P7 rev 2.2 item 1).
    saveAll: async ({ records = [], messages = [], undo }) => {
      const hold = p.holdNext;
      p.holdNext = null;
      if (hold) { await hold.wait; if (hold.fail) { undo?.(); throw new Error('save failed'); } }
      if (p.failSave) { undo?.(); throw new Error('save failed'); }
      p.saves.push({ records: records.map(r => r.id), messages: messages.map(m => structuredClone(m)) });
      for (const r of records) db.set(r.id, structuredClone(r.value));
      for (const m of messages) kept.set(m.seq, structuredClone(m));
    },
    // The shape of messages.js prepareControl: a 1:1 record (no `group`)
    // flagged `control`, `ts` in unix seconds; kept() = the 1:1 outbox.
    prepareDirect: (to, text) => {
      if (p.failSend) { p.failSend = false; throw new Error('Sending opens once Messages is connected to the network.'); }
      const message = { seq: p.deps.takeSeq(), fp: to, dir: 'out', text, ts: String(Math.floor(net.clock.t / 1000)), at: net.clock.t, control: true };
      return {
        message,
        kept: async () => {
          if (p.crash) return;
          outbox.push({ to, text }); net.log.push(`send:${JSON.parse(text).type.replace('nodus_group_', '')}:${fp.slice(0, 2)}->${to.slice(0, 2)}`);
        }
      };
    },
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

test('decision 14: leave -> re-invite -> re-join keeps every earlier key version on the device; an earlier membership\'s unsent message stays unsent', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  const first = structuredClone(B.engine.group(gid).keyIds);
  assert.deepEqual(Object.keys(first), ['2']);
  // an own message kept but not published (the network could not be read), then leave
  net.unreadable = true;
  assert.equal(await B.engine.send(gid, 'old unsent'), 'kept');
  net.unreadable = false;
  await B.engine.leave(gid);
  await deliver(B, A);
  await A.engine.syncAll();                                  // version 3 without B
  await A.engine.invite(gid, FB);
  await deliver(A, B);
  const rec = B.state.groups[gid].id;
  assert.equal(B.engine.group(gid).status, 'invited');
  assert.deepEqual(B.db.get(rec).keyIds, first, 'the fresh invitation record still lists the earlier key version');
  await B.engine.acceptInvite(gid);
  await deliver(B, A);
  await A.engine.syncAll();                                  // version 4 with B, welcome
  await deliver(A, B);
  await B.engine.syncAll();
  const b = B.engine.group(gid);
  assert.equal(b.status, 'active');
  assert.equal(b.first, 4);
  const saved = B.db.get(rec).keyIds;
  assert.deepEqual(Object.keys(saved).sort(), ['2', '4']);
  assert.equal(saved[2], first[2], 'the earlier key version id is the same record');
  for (const id of Object.values(saved)) assert.ok(B.db.has(id), `key version record ${id} kept`);
  // reloaded: the earlier version is held again but stays inert — buckets of
  // the new membership only, the old unsent message is not published under it
  const again = createGroupsEngine({ ...B.deps });
  again.load({ records: [...B.db.entries()].map(([id, value]) => ({ id, value })), messages: [...B.kept.values()] });
  const g = again.group(gid);
  assert.ok(g.keys.has(2) && g.keys.has(4));
  assert.equal(g.problem ?? null, null);
  assert.deepEqual(bucketVersions(g), [4]);
  net.log.length = 0;
  await again.syncAll();
  assert.deepEqual(net.log.filter(e => e.startsWith('put:bucket') && e.endsWith(':b2')), [], 'nothing published under the earlier membership\'s key');
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

// W-16 / P7 design §2.6: a transition and the 1:1 control message it implies
// are ONE save. `controlsIn(save)`: the 1:1 control messages a save carried.
const controlsIn = save => save.messages.filter(m => m.group === undefined && m.control === true);
const keptControls = p => [...p.kept.values()].filter(m => m.group === undefined && m.control === true);
const nowSec = net => String(Math.floor(net.clock.t / 1000));

test('W-16: an accept that cannot be prepared commits nothing; the invitation stays and Join works again', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B);
  const invited = B.engine.group(gid).invite.id;
  const rec = B.state.groups[gid].id;
  const indexBefore = B.state.groups[gid];
  const savesBefore = B.saves.length;
  B.failSend = true;
  await assert.rejects(B.engine.acceptInvite(gid), err => err instanceof GroupError && err.message === 'Could not send — try again.');
  assert.equal(B.saves.length, savesBefore, 'nothing was saved: no "accepting" without its message');
  assert.equal(B.engine.group(gid).status, 'invited');
  assert.equal(B.db.get(rec).status, 'invited', 'the device still holds the invitation');
  assert.equal(B.db.get(rec).invite.id, invited, 'the same invitation');
  assert.equal(B.state.groups[gid], indexBefore, 'the state index is untouched');
  assert.deepEqual(B.engine.invitations().map(i => i.gid), [gid], 'listed: Join is offered');
  assert.deepEqual(keptControls(B), [], 'nothing was kept for sending');
  assert.equal(B.outbox.length, 0);
  // Join again: the group record and the accept go out in ONE save
  await B.engine.acceptInvite(gid);
  assert.equal(B.saves.length, savesBefore + 1, 'exactly one save for the accept');
  const save = B.saves.at(-1);
  assert.deepEqual(save.records, [rec], 'the save carries the group record');
  assert.deepEqual(controlsIn(save).map(m => [m.fp, controlType(m.text)]), [[FA, 'accept']], 'and the accept message, in the same save');
  assert.equal(B.db.get(rec).status, 'accepting');
  assert.deepEqual(B.outbox.map(m => controlType(m.text)), ['accept'], 'handed to the 1:1 outbox after the save');
  await deliver(B, A);
  assert.deepEqual(A.engine.view(gid).joining, [FB]);
});

test('W-16: a crash right after the accept\'s save leaves the accept kept and pending: the 1:1 outbox publishes it after the reload', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B);
  B.crash = true;                          // the page dies before kept() runs
  await B.engine.acceptInvite(gid);
  assert.equal(B.outbox.length, 0, 'never handed to the outbox in that session');
  const rec = B.state.groups[gid].id;
  assert.equal(B.db.get(rec).status, 'accepting');
  const controls = keptControls(B);
  assert.deepEqual(controls.map(m => [m.fp, m.dir, controlType(m.text)]), [[FA, 'out', 'accept']], 'the accept is on the device');
  assert.notEqual(controls[0].published, true, 'not published yet');
  // after the reload: messages.js openLocal marks every contact with an
  // undelivered own message `unpublished` (text.js hasUndelivered) and the
  // check publishes the contact's pending set (publishOutbox -> pendingOutbox)
  const oneToOne = [...B.kept.values()].filter(m => m.group === undefined);
  assert.equal(hasUndelivered(oneToOne, FA, nowSec(net)), true);
  assert.deepEqual(pendingOutbox(oneToOne, FA, nowSec(net)).map(m => m.seq), [controls[0].seq]);
  // and the group, loaded again, still waits as 'accepting' for its welcome
  const again = createGroupsEngine({ ...B.deps });
  again.load({ records: [...B.db.entries()].map(([id, value]) => ({ id, value })), messages: [...B.kept.values()] });
  assert.equal(again.group(gid).status, 'accepting');
  assert.deepEqual(again.messages(), [], 'the 1:1 control message is not a group message');
  // the republished accept is honoured by the owner, and the welcome joins B
  await A.engine.onDirect(FB, controls[0].text);
  assert.deepEqual(A.engine.view(gid).joining, [FB]);
  await A.engine.syncAll();
  for (const m of A.outbox.filter(x => x.to === FB)) await again.onDirect(FA, m.text);
  assert.equal(again.group(gid).status, 'joining');
});

test('W-16: a failed accept save commits nothing; a new invitation committed during it stands', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B);
  const fresh = 'cd'.repeat(16);
  let release;
  B.holdNext = { wait: new Promise(resolve => { release = resolve; }), fail: true };
  const accepting = B.engine.acceptInvite(gid);           // its save waits, then fails
  // the accept reaches its save after its name checks (microtasks only, the
  // mocked core does no I/O): the hold is taken by the accept's save, not
  // by the invite's below
  for (let i = 0; B.holdNext && i < 100; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(B.holdNext, null, 'the accept\'s save is the one held');
  await B.engine.onDirect(FA, JSON.stringify({ type: 'nodus_group_invite', v: 1, group_id: gid, owner: FA, name: 'Team', invite_id: fresh }));
  release();
  await assert.rejects(accepting, /save failed/);
  assert.equal(B.engine.group(gid).status, 'invited');
  assert.equal(B.engine.group(gid).invite.id, fresh, 'the newer invitation is kept');
  assert.equal(B.db.get(B.state.groups[gid].id).invite.id, fresh);
  assert.deepEqual(keptControls(B), [], 'no accept was kept');
  assert.equal(B.outbox.length, 0);
});

test('§2.6: invite — the pending invite and its message are one save; one that cannot be prepared records no invite', async () => {
  const net = world();
  const A = party(net, FA, { contacts: [FB, FC] });
  const { gid } = await A.engine.create('Team', []);
  const before = A.saves.length;
  A.failSend = true;
  await assert.rejects(A.engine.invite(gid, FB), /connected to the network/);
  assert.equal(A.saves.length, before, 'nothing saved');
  assert.deepEqual(A.engine.group(gid).invites, [], 'no invitation recorded without its message');
  assert.deepEqual(keptControls(A), []);
  await A.engine.invite(gid, FB);
  assert.equal(A.saves.length, before + 1, 'exactly one save');
  const save = A.saves.at(-1);
  assert.deepEqual(save.records, [A.state.groups[gid].id]);
  assert.deepEqual(controlsIn(save).map(m => [m.fp, controlType(m.text)]), [[FB, 'invite']]);
  assert.deepEqual(A.db.get(A.state.groups[gid].id).invites.map(i => i.fp), [FB]);
  // crash after the save: the invite is kept and pending for the outbox
  A.crash = true;
  await A.engine.invite(gid, FC);
  assert.equal(A.outbox.filter(m => m.to === FC).length, 0);
  const oneToOne = [...A.kept.values()].filter(m => m.group === undefined);
  assert.equal(hasUndelivered(oneToOne, FC, nowSec(net)), true);
  assert.deepEqual(pendingOutbox(oneToOne, FC, nowSec(net)).map(m => controlType(m.text)), ['invite']);
});

test('§2.6: leave — "left" and the leave message are one save; one that cannot be prepared changes nothing', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B]);
  const before = B.saves.length;
  B.failSend = true;
  await assert.rejects(B.engine.leave(gid), /connected to the network/);
  assert.equal(B.saves.length, before, 'nothing saved');
  assert.equal(B.engine.group(gid).status, 'active', 'still a member');
  assert.equal(B.db.get(B.state.groups[gid].id).status, 'active');
  B.crash = true;
  await B.engine.leave(gid);
  assert.equal(B.saves.length, before + 1, 'exactly one save');
  const save = B.saves.at(-1);
  assert.deepEqual(save.records, [B.state.groups[gid].id]);
  assert.deepEqual(controlsIn(save).map(m => [m.fp, controlType(m.text)]), [[FA, 'leave']]);
  assert.equal(B.db.get(B.state.groups[gid].id).status, 'left');
  assert.equal(B.outbox.length, 0, 'the page died before the outbox');
  const oneToOne = [...B.kept.values()].filter(m => m.group === undefined);
  assert.deepEqual(pendingOutbox(oneToOne, FA, nowSec(net)).filter(m => controlType(m.text) === 'leave').length, 1, 'the leave is pending for the outbox');
  // the republished leave reaches the owner
  await A.engine.onDirect(FB, save.messages.find(m => m.control).text);
  assert.deepEqual(A.engine.view(gid).leaving, [FB]);
});

test('§2.6: welcome — it leaves the owner\'s queue in the save that keeps its message; one that cannot be prepared stays queued', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B);
  await B.engine.acceptInvite(gid);
  await deliver(B, A);
  // the rotation is published, then the welcome cannot be prepared
  A.failSend = true;
  assert.equal(await A.engine.syncAll(), 1, 'the check reports this group');
  assert.deepEqual(A.engine.group(gid).welcomes.map(w => w.fp), [FB], 'still queued');
  assert.deepEqual(A.db.get(A.state.groups[gid].id).welcomes.map(w => w.fp), [FB], 'queued on the device');
  assert.deepEqual(keptControls(A).filter(m => controlType(m.text) === 'welcome'), []);
  // next check: one save drops it from the queue AND keeps its message; the page dies after it
  A.crash = true;
  const before = A.saves.length;
  await A.engine.syncAll();
  const withWelcome = A.saves.slice(before).filter(s => controlsIn(s).length);
  assert.equal(withWelcome.length, 1, 'exactly one save carries the welcome');
  assert.deepEqual(withWelcome[0].records, [A.state.groups[gid].id], 'together with the group record');
  assert.deepEqual(controlsIn(withWelcome[0]).map(m => [m.fp, controlType(m.text)]), [[FB, 'welcome']]);
  assert.deepEqual(A.db.get(A.state.groups[gid].id).welcomes, [], 'the queue is empty on the device');
  assert.equal(A.outbox.length, 0, 'the page died before the outbox');
  const oneToOne = [...A.kept.values()].filter(m => m.group === undefined);
  const pending = pendingOutbox(oneToOne, FB, nowSec(net)).filter(m => controlType(m.text) === 'welcome');
  assert.equal(pending.length, 1, 'the welcome is pending for the outbox');
  // the republished welcome joins the member
  await B.engine.onDirect(FA, pending[0].text);
  assert.equal(B.engine.group(gid).status, 'joining');
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
  const indexBefore = structuredClone(A.state.groups[gid]);
  A.failSave = true;
  await assert.rejects(A.engine.removeMember(gid, FB));
  assert.deepEqual(A.engine.group(gid).removals, []);
  assert.deepEqual(A.state.groups[gid], indexBefore, 'the state index entry is rolled back (by the undo handed to saveAll)');
  A.failSave = false;
});

test('a failed save takes back only its own index entry: a second change of the same group made during it stands', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  const indexBefore = A.state.groups[gid];
  let release;
  A.holdNext = { wait: new Promise(resolve => { release = resolve; }), fail: true };
  const first = A.engine.removeMember(gid, FB);           // its save waits, then fails
  await A.engine.removeMember(gid, FC);                   // runs meanwhile; its save succeeds
  const secondEntry = A.state.groups[gid];
  assert.notEqual(secondEntry, indexBefore, 'the second change set its own index entry');
  release();
  await assert.rejects(first, /save failed/);
  assert.equal(A.state.groups[gid], secondEntry, 'the first save\'s undo left the second change\'s entry in place');
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
