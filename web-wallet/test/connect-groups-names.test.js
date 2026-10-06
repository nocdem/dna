// Nodus Connect groups — only identities with an on-chain name (decisions
// docs/plans/decisions/2026-10-04-connect-groups.md items 17 + 18;
// 2026-10-02-onchain-names.md item 4: a chain name is permanent). The groups
// state machine (src/connect/groups/engine.js) against a MOCKED core and a
// MOCKED chain name lookup: no module, no network, no browser.
//
// What it proves (each test names its rule):
//   (a) a client without a confirmed own chain name cannot create a group —
//       "no name" and "could not check" both refuse, nothing is published;
//   (b) the owner invites only contacts whose chain name is confirmed; an
//       invitee answered "no name" or not answered is refused in plain words;
//   (c) a member's client refuses to join a group whose owner has no chain
//       name (no accept is sent); the invitation says so;
//   (d) a confirmed name is looked up once and never again; an answered "no
//       name" is not final: it is asked again on the next check;
//   (e) the OWNER's client removes a member answered "no name" through the
//       owner's own removal path (a new key version), once: exactly one new
//       version, no second removal while the change waits for the network
//       or after it is out; a FAILED lookup removes nothing and changes
//       nothing; a joiner without a name is not added;
//   (f) every member's client hides a nameless member's messages (not shown,
//       not counted unread, marked in the member list) while the group keeps
//       working; an unanswered lookup makes the messages wait, shown once
//       the name is confirmed;
//   (g) one lookup per unconfirmed ID per check, however many groups it is in.
//
// How it can lie: the core mock is the one of test/connect-groups.test.js
// (copied — importing that file would run its tests again here), with the
// same limits: it encodes the module's verdicts as JSON, never the bytes or
// the cryptography. The name lookup is a Map answering 'found' / 'none' or
// throwing ('fail'); the page's real lookup (src/connect/ui/messages.js
// groupNameStatus / groupNameLookup over ensureChainName, its 60-second
// spacing per ID and the kept state.chainNames) is NOT exercised here. A
// party's cache can be emptied by a test to stand in for a group made by
// web 0.1.59 or a modified client, which this rule did not yet guard.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createGroupsEngine } from '../src/connect/groups/engine.js';
import { DAY_MS } from '../src/connect/groups/model.js';
import { emptyState } from '../src/connect/store.js';

const FA = 'a1'.repeat(64), FB = 'b2'.repeat(64), FC = 'c3'.repeat(64), FD = 'd4'.repeat(64);
const T0 = Date.UTC(2026, 9, 6, 12, 0, 0);
const sha512 = s => createHash('sha512').update(s).digest('hex');
const sha256 = s => createHash('sha256').update(s).digest('hex');
const toHex = s => Buffer.from(s, 'utf8').toString('hex');
const fromHex = h => Buffer.from(h, 'hex').toString('utf8');
const bytesHex = u8 => Buffer.from(u8).toString('hex');

// ── the mocked network, core and chain names ────────────────────────────
function world() {
  return {
    rows: new Map(), unreadable: false, headWait: false, log: [], clock: { t: T0 }, counter: 0,
    // the chain's answer per ID: 'found' | 'none' | 'fail' (the lookup throws)
    names: new Map([FA, FB, FC, FD].map(fp => [fp, 'found'])),
    lookups: []                 // '<asker 2 hex>-><asked 2 hex>' per lookup made
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
    async groupPut({ purpose, secret, x, value }) {
      if (net.unreadable) return { status: 'wait', outcome: 'unreadable', why: 'timeout' };
      if (purpose === 'head' && net.headWait) return { status: 'wait', outcome: 'unreadable', why: 'timeout' };
      const hex = bytesHex(value), r = row(net, addr(purpose, secret, x)), mine = r.get(me);
      if (mine === hex) return { status: 'unchanged', outcome: 'found' };
      if (mine !== undefined) {
        if (purpose !== 'head') return { status: 'conflict', outcome: 'found' };
        if (jsonOf(mine).v > jsonOf(hex).v) return { status: 'stale', outcome: 'found' };
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

// One identity. `known`: what its page holds about chain names ('found' is
// kept for good — a name is permanent; 'none' = the last lookup answered "no
// name"). The lookup asks net.names; 'fail' throws (not an answer: nothing
// changes).
function party(net, fp, { contacts = [] } = {}) {
  const state = emptyState();
  const known = new Map();
  const outbox = [];
  const p = { fp, state, known, outbox, contacts: [...contacts] };
  p.deps = {
    core: fakeCore(net, fp), ownFp: fp, now: () => net.clock.t, state: () => state,
    takeSeq: () => { const s = state.nextSeq; state.nextSeq = String(BigInt(s) + 1n); return s; },
    saveAll: async () => {},
    sendDirect: async (to, text) => { outbox.push({ to, text }); net.log.push(`send:${JSON.parse(text).type.replace('nodus_group_', '')}:${fp.slice(0, 2)}->${to.slice(0, 2)}`); },
    isContact: x => p.contacts.includes(x),
    ensureProfile: async () => true,
    reloadProfile: async () => true,
    hasKemKey: () => true,
    nameStatus: x => known.get(x) || 'unknown',
    lookupName: async x => {
      net.lookups.push(`${fp.slice(0, 2)}->${x.slice(0, 2)}`);
      const answer = net.names.get(x);
      if (answer !== 'found' && answer !== 'none') throw new Error('the node could not be reached');
      if (known.get(x) !== 'found') known.set(x, answer);
    }
  };
  p.engine = createGroupsEngine(p.deps);
  return p;
}
async function deliver(from, to) {
  const mine = from.outbox.filter(m => m.to === to.fp);
  from.outbox.splice(0, from.outbox.length, ...from.outbox.filter(m => m.to !== to.fp));
  for (const m of mine) await to.engine.onDirect(from.fp, m.text);
}
const texts = (p, gid) => p.engine.conversation(gid).map(m => m.text);
const versionPuts = net => net.log.filter(e => e.startsWith('put:record'));
const lookupsOf = (net, asker, asked) => net.lookups.filter(l => l === `${asker.slice(0, 2)}->${asked.slice(0, 2)}`).length;

// A group of the owner A and the members given, all named, all active.
async function groupOf(net, members, name = 'Team') {
  const A = party(net, FA, { contacts: members.map(m => m.fp) });
  const { gid } = await A.engine.create(name, members.map(m => m.fp));
  for (const m of members) { await deliver(A, m); await m.engine.acceptInvite(gid); await deliver(m, A); }
  await A.engine.syncAll();
  for (const m of members) { await deliver(A, m); await m.engine.syncAll(); }
  return { A, gid };
}

// ── (a) create ──────────────────────────────────────────────────────────
test('(a) no own chain name: a group cannot be created, nothing is published; a lookup that fails refuses too', async () => {
  const net = world();
  const A = party(net, FA);
  net.names.set(FA, 'none');
  await assert.rejects(A.engine.create('Team'), /You need a chain name before you can create a group/);
  assert.deepEqual(net.log, [], 'nothing published');
  assert.deepEqual(A.engine.list(), []);
  // a failed lookup after that answer keeps the answer ("no name")
  net.names.set(FA, 'fail');
  await assert.rejects(A.engine.create('Team'), /You need a chain name/);
  // with no earlier answer, a failed lookup refuses as "could not check"
  A.known.delete(FA);
  await assert.rejects(A.engine.create('Team'), /could not be checked right now/);
  assert.deepEqual(net.log, []);
  net.names.set(FA, 'found');
  const { gid } = await A.engine.create('Team');
  assert.equal(A.engine.view(gid).ready, true, 'with a confirmed name the group is created');
});

// ── (b) invite ──────────────────────────────────────────────────────────
test('(b) the owner invites only contacts with a confirmed chain name', async () => {
  const net = world();
  const A = party(net, FA, { contacts: [FB, FC, FD] });
  net.names.set(FC, 'none');
  net.names.set(FD, 'fail');
  const { gid, notInvited } = await A.engine.create('Team', [FB, FC, FD]);
  assert.deepEqual(notInvited.sort(), [FC, FD].sort(), 'the nameless and the unchecked are not invited');
  assert.deepEqual(A.engine.view(gid).invited, [FB]);
  assert.deepEqual(A.outbox.map(m => m.to), [FB], 'one invitation sent');
  await assert.rejects(A.engine.invite(gid, FC), /Only contacts with a chain name can be invited/);
  await assert.rejects(A.engine.invite(gid, FD), /could not be checked right now/);
  assert.equal(A.engine.nameStatus(FC), 'none');
  assert.equal(A.engine.nameStatus(FD), 'unknown', 'a failed lookup is not an answer');
  net.names.set(FD, 'found');
  await A.engine.invite(gid, FD);
  assert.deepEqual(A.engine.view(gid).invited.sort(), [FB, FD].sort());
  // the UI's check of the Invite list
  const names = await A.engine.checkPeople([FB, FC, FD]);
  assert.deepEqual([...names.entries()].sort(), [[FB, 'found'], [FC, 'none'], [FD, 'found']].sort());
});

// ── (c) accept ──────────────────────────────────────────────────────────
test('(c) an invitation from an owner without a chain name is not joined; no accept is sent', async () => {
  const net = world();
  const A = party(net, FA, { contacts: [FB] });
  const B = party(net, FB, { contacts: [FA] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B);
  // A's name, as B's node answers it (a modified client, or web 0.1.59)
  net.names.set(FA, 'none');
  await assert.rejects(B.engine.acceptInvite(gid), /the person who sent it has no chain name/);
  assert.equal(B.engine.group(gid).status, 'invited', 'still only an invitation');
  assert.deepEqual(B.outbox, [], 'no accept sent');
  assert.equal(B.engine.invitations()[0].ownerName, 'none', 'the invitation says so');
  net.names.set(FA, 'fail');
  B.known.delete(FA);
  await assert.rejects(B.engine.acceptInvite(gid), /could not be checked right now/);
  assert.deepEqual(B.outbox, []);
  // the member's own name is needed too (decision 17)
  net.names.set(FA, 'found');
  net.names.set(FB, 'none');
  await assert.rejects(B.engine.acceptInvite(gid), /You need a chain name before you can join a group/);
  assert.deepEqual(B.outbox, []);
  net.names.set(FB, 'found');
  await B.engine.acceptInvite(gid);
  assert.equal(B.engine.group(gid).status, 'accepting');
  assert.equal(B.outbox.length, 1);
});

// ── (d) caching ─────────────────────────────────────────────────────────
test('(d) a confirmed name is asked once and never again; "no name" is asked again on the next check', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A } = await groupOf(net, [B, C]);
  net.lookups.length = 0;
  await A.engine.syncAll();
  await A.engine.syncAll();
  assert.deepEqual(net.lookups, [], 'every name confirmed: no lookup at all');
  // C's name answered "no name" (as if never confirmed here before)
  B.known.delete(FC);
  net.names.set(FC, 'none');
  await B.engine.syncAll();
  await B.engine.syncAll();
  assert.equal(lookupsOf(net, FB, FC), 2, 'asked again on each check — a "no name" is never final');
  net.names.set(FC, 'found');
  await B.engine.syncAll();
  await B.engine.syncAll();
  assert.equal(lookupsOf(net, FB, FC), 3, 'once found, not asked again');
  assert.equal(B.engine.nameStatus(FC), 'found');
});

// ── (e) the owner's automatic removal ───────────────────────────────────
test('(e) found:false -> the owner removes the member once, through the owner\'s own removal path (one new version)', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  const v = A.engine.group(gid).hw.v;
  // a member whose name was never confirmed (a group of web 0.1.59)
  A.known.delete(FC);
  net.names.set(FC, 'none');
  net.headWait = true;                              // the change cannot be finished yet
  net.log.length = 0;
  await A.engine.syncAll();
  assert.deepEqual(versionPuts(net), [`put:record:${v + 1}:a1`], 'one new version staged for the removal');
  const staged = A.engine.group(gid).stage;
  assert.ok(staged && !staged.members.includes(FC) && staged.removed.includes(FC), 'the staged change removes C');
  assert.deepEqual(A.engine.view(gid).members, [FA, FB, FC].sort(), 'still listed until the change is out');
  // more checks while it waits: no second removal, no second version
  await A.engine.syncAll();
  await A.engine.syncAll();
  assert.deepEqual(A.engine.group(gid).removals, [], 'not queued again');
  assert.deepEqual(versionPuts(net), [`put:record:${v + 1}:a1`]);
  net.headWait = false;
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v + 1, 'exactly one new version');
  assert.deepEqual(A.engine.view(gid).members, [FA, FB].sort());
  await A.engine.syncAll();
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v + 1, 'nothing more after it is out');
  assert.deepEqual(A.engine.group(gid).removals, []);
  assert.deepEqual(versionPuts(net), [`put:record:${v + 1}:a1`]);
  await C.engine.syncAll();
  assert.equal(C.engine.group(gid).status, 'removed', 'C finds no entry in the new version');
  await B.engine.syncAll();
  assert.deepEqual(B.engine.view(gid).members, [FA, FB].sort());
});

test('(e) the automatic removal is the same as the owner\'s Remove: same version, same members', async () => {
  const run = async auto => {
    const net = world();
    const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
    const { A, gid } = await groupOf(net, [B, C]);
    if (auto) { A.known.delete(FC); net.names.set(FC, 'none'); } else await A.engine.removeMember(gid, FC);
    await A.engine.syncAll();
    const g = A.engine.group(gid);
    return { v: g.hw.v, members: g.keys.get(g.hw.v).members };
  };
  assert.deepEqual(await run(true), await run(false));
});

test('(e) a lookup that fails removes nothing and changes nothing', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  const v = A.engine.group(gid).hw.v;
  A.known.delete(FC);
  net.names.set(FC, 'fail');
  net.log.length = 0;
  await A.engine.syncAll();
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, v);
  assert.equal(A.engine.group(gid).stage, null);
  assert.deepEqual(A.engine.group(gid).removals, []);
  assert.deepEqual(versionPuts(net), [], 'no new version');
  assert.deepEqual(A.engine.view(gid).unconfirmed, [FC], 'C is shown as not checked yet');
  assert.ok(lookupsOf(net, FA, FC) >= 1, 'it was asked');
});

test('(e) a joiner without a chain name is not added; once it has one, it is', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB] });
  const { gid } = await A.engine.create('Team', [FB]);
  await deliver(A, B); await B.engine.acceptInvite(gid); await deliver(B, A);
  assert.deepEqual(A.engine.view(gid).joining, [FB]);
  // B's name, as A's node now answers it (the joiner of a modified client)
  A.known.delete(FB);
  net.names.set(FB, 'none');
  await A.engine.syncAll();
  assert.equal(A.engine.group(gid).hw.v, 1, 'no version adds B');
  assert.deepEqual(A.engine.view(gid).joining, [FB], 'still listed as a joiner');
  assert.deepEqual(A.engine.view(gid).nameless, [FB]);
  assert.deepEqual(A.outbox, [], 'no welcome');
  net.names.set(FB, 'found');
  await A.engine.syncAll();
  assert.deepEqual(A.engine.view(gid).members, [FA, FB].sort());
});

// ── (f) every member ignores a nameless member ──────────────────────────
test('(f) a member\'s client hides a nameless member\'s messages and marks it; the group keeps working', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { A, gid } = await groupOf(net, [B, C]);
  assert.equal(await C.engine.send(gid, 'from C'), 'sent');
  assert.equal(await A.engine.send(gid, 'from A'), 'sent');
  B.known.delete(FC);
  net.names.set(FC, 'none');
  await B.engine.syncAll();
  assert.deepEqual(texts(B, gid), ['from A'], 'C\'s message is not shown');
  assert.equal(B.engine.view(gid).unread, 1, 'only shown messages count');
  assert.equal(B.engine.lastMessage(gid).text, 'from A');
  assert.deepEqual(B.engine.view(gid).nameless, [FC], 'marked in the member list');
  assert.deepEqual(B.engine.view(gid).members, [FA, FB, FC].sort(), 'still a member until the owner removes it');
  assert.equal(B.engine.view(gid).hidden, 1);
  assert.equal(await B.engine.send(gid, 'from B'), 'sent', 'the group keeps working');
  await A.engine.syncAll();
  assert.ok(texts(A, gid).includes('from B'));
});

test('(f) an unanswered lookup: the messages wait unshown, and show once the name is confirmed', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const { gid } = await groupOf(net, [B, C]);
  assert.equal(await C.engine.send(gid, 'from C'), 'sent');
  B.known.delete(FC);
  net.names.set(FC, 'fail');
  await B.engine.syncAll();
  assert.deepEqual(texts(B, gid), [], 'waits');
  assert.equal(B.engine.view(gid).unread, 0);
  assert.equal(B.engine.view(gid).waiting, 1);
  assert.deepEqual(B.engine.view(gid).unconfirmed, [FC]);
  assert.equal(B.engine.messages().filter(m => m.text === 'from C').length, 1, 'kept on the device meanwhile');
  net.names.set(FC, 'found');
  await B.engine.syncAll();
  assert.deepEqual(texts(B, gid), ['from C'], 'shown once confirmed');
  assert.equal(B.engine.view(gid).unread, 1, 'and counted as new then');
  assert.deepEqual(B.engine.view(gid).unconfirmed, []);
});

// ── (g) lookups do not hammer the node ──────────────────────────────────
test('(g) one lookup per unconfirmed ID per check, however many groups it is in', async () => {
  const net = world();
  const B = party(net, FB, { contacts: [FA] }), C = party(net, FC, { contacts: [FA] });
  const A = party(net, FA, { contacts: [FB, FC] });
  const gids = [];
  for (const name of ['One', 'Two', 'Three']) {
    const { gid } = await A.engine.create(name, [FB, FC]);
    gids.push(gid);
    for (const m of [B, C]) { await deliver(A, m); await m.engine.acceptInvite(gid); await deliver(m, A); }
  }
  await A.engine.syncAll();
  for (const m of [B, C]) { await deliver(A, m); await m.engine.syncAll(); }
  for (const gid of gids) assert.equal(B.engine.group(gid).status, 'active');
  B.known.delete(FC);
  net.names.set(FC, 'fail');
  net.lookups.length = 0;
  await B.engine.syncAll();
  assert.equal(lookupsOf(net, FB, FC), 1, 'C is in three groups: asked once in this check');
  assert.equal(net.lookups.length, 1, 'confirmed names are not asked');
  await B.engine.syncAll();
  assert.equal(lookupsOf(net, FB, FC), 2, 'and once more on the next check');
});
