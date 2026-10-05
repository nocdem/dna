// Nodus Connect groups — the page's state machine (package G3).
//
// Governing records:
//   docs/plans/2026-10-04-connect-groups-design.md rev 1;
//   docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 + REV 2
//     (approved: docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md);
//   docs/plans/decisions/2026-10-04-connect-groups.md items 1-14;
//   docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md (S3: a read
//     that could not be made never leads to a write — every network write
//     here is a gated module export that reads first, in the same call;
//     Q3: one device = a warning only; Q4: history at rest);
//   docs/plans/decisions/2026-10-04-connect-local-first.md (the view opens
//     from what the device keeps; only sending waits for the network).
//
// NO UI, NO DOM. Everything that touches the outside comes in through
// `deps`, so test/connect-groups.test.js runs this file against a mocked
// core:
//   core             src/connect/core.js (the group* calls)
//   ownFp            this identity
//   now()            the page clock, ms — schedules rotation and stamps own
//                    messages; it never decides whether anything received is
//                    accepted (design §9)
//   state()          the Messages state record (store.js emptyState): its
//                    `groups` index and `nextSeq` live there
//   takeSeq()        the next local sequence (state.nextSeq)
//   saveAll({ records, messages })   one store.save of the state, these
//                    group records ({ id, value }) and group messages;
//                    resolves once written (or kept in memory: unsaved wallet)
//   sendDirect(fp, text)   a 1:1 message carrying an invite / accept /
//                    welcome / leave: kept on the device and published by the
//                    1:1 outbox (src/connect/ui/messages.js)
//   isContact(fp)    a contact whose 1:1 messaging is ready (decision 8)
//   ensureProfile(fp)    the verified profile, read once per session
//   reloadProfile(fp)    a fresh owner-filtered profile read (puts the keys
//                    back into the module's verified peer cache, which holds
//                    64 peers)
//   hasKemKey(fp)    whether that verified profile carries an ML-KEM-1024 key
//
// STATES of one group (record `status`; role 'owner' | 'member'):
//   member: invited --accept--> accepting --welcome from the pinned owner-->
//           joining --packet N (welcome's digest) + record N read--> active
//           active --a packet without our entry (HEAD-announced)--> removed
//           invited --ignore--> (record deleted)
//           accepting | joining | active --leave--> left (hidden; the owner
//           is told, decision 13)
//   owner:  active from creation (hw empty until version 1's HEAD is out);
//           a STAGE (key packet + record + HEAD of the next version, staged
//           durably) is published record -> packet -> HEAD (HEAD LAST); only
//           then is the version applied: members added / removed in the view,
//           welcomes sent. Triggers: accepts (joins), leaves and removals,
//           and the key reaching 30 days (decision 5).
//   active member each check: HEAD (pinned owner) -> walk v+1 .. HEAD.v
//           (each packet's prev_digest = the held digest, R2-7) -> publish own
//           pending messages -> read today's and yesterday's buckets of the
//           newest version and the one before it.
// Every read that is "empty" or "unreadable" ends that step for this check
// with nothing written ("wait"); the next check (30 s) tries again.
import {
  MAX_MEMBERS, controlType, acceptRule, nextMembers, rotationDue, keyIsOld, dayOf, syncDays,
  bucketVersions, messageKey, orderIncoming, textProblem, nameProblem, bucketItems, pendingBuckets,
  splitPieces, checkGroup, checkKey, checkPiece, newGroup, storedGroup, GroupError
} from './model.js';

const HEX128 = /^[0-9a-f]{128}$/;
const BUCKET_ITEMS_MAX = 100;              // bytes item 5: <= 100 items per sender per day
const HARD = new Set(['conflict', 'stale', 'taken']);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function hexToText(hex) {
  try { return new TextDecoder('utf-8', { fatal: false }).decode(hexToBytes(hex)); } catch { return ''; }
}
const clone = g => structuredClone(g);
// The module's answer when a key it needs fell out of its 64-entry peer
// cache (connect/nc_wasm.c peer_need).
const needsProfile = error => /profile first/i.test(String(error?.message || ''));

export function createGroupsEngine(deps) {
  const { core, ownFp, now = () => Date.now(), state, takeSeq, saveAll, sendDirect, isContact, ensureProfile, reloadProfile, hasKemKey } = deps;
  const groups = new Map();                // gid -> group (with `keys`: Map v -> key record)
  const recIds = new Map();                // gid -> its 'g' record id
  const stagePackets = new Map();          // gid -> staged key packet (hex), from its pieces
  const stageKeys = new Map();             // gid -> the staged version's key record
  const salts = new Map();                 // 'gid|v' -> salt_v (derived, memory only)
  let messages = [];                       // group messages (store.js: records with `group`)
  const seen = new Set();                  // messageKey of every stored message
  const notes = new Map();                 // gid -> the last check's plain-words note (memory only)
  const lastRead = new Map();              // gid -> highest local seq shown (this session)
  let sending = false;                     // a group send is being kept on this device

  const newId = prefix => prefix + takeSeq().padStart(20, '0');
  const seconds = () => String(Math.floor(now() / 1000));
  const keyOf = (g, v) => g.keys.get(v);
  const current = g => (g.hw && keyOf(g, g.hw.v)?.members) || [g.owner];
  function saltOf(gid, key, v) {
    const k = `${gid}|${v}`;
    if (!salts.has(k)) salts.set(k, core.groupSalt(gid, key, String(v)));
    return salts.get(k);
  }
  // A module call that needs a peer's verified keys: when the module's
  // 64-entry cache lost them, the profiles are read again and it is tried
  // once more.
  async function withPeers(fps, run) {
    try { return await run(); }
    catch (error) {
      if (!needsProfile(error)) throw error;
      for (const fp of fps) if (fp !== ownFp) await reloadProfile(fp);
      return run();
    }
  }

  // ── persistence ──────────────────────────────────────────────────────
  // The next version of a group is written first, then put in place; a
  // failed save leaves the group as it was (and the state index too).
  async function commit(gid, next, { keys = [], pieces = [], messages: msgs = [] } = {}) {
    const st = state();
    const before = st.groups[gid];
    const id = recIds.get(gid) || newId('g');
    st.groups[gid] = { id, at: seconds() };
    try { await saveAll({ records: [{ id, value: storedGroup(next) }, ...keys, ...pieces], messages: msgs }); }
    catch (error) { if (before) st.groups[gid] = before; else delete st.groups[gid]; throw error; }
    recIds.set(gid, id);
    groups.set(gid, next);
    return next;
  }
  async function forget(gid) {
    const st = state(), before = st.groups[gid];
    delete st.groups[gid];
    try { await saveAll({ records: [], messages: [] }); }
    catch (error) { if (before) st.groups[gid] = before; throw error; }
    groups.delete(gid); recIds.delete(gid); stagePackets.delete(gid); stageKeys.delete(gid);
  }
  function note(gid, text) { if (text) notes.set(gid, text); else notes.delete(gid); }

  // What the device kept (store.js openHistoryStore groupRecords /
  // groupMessages). A record that fails its shape check is not used.
  function load({ records = [], messages: kept = [] } = {}) {
    const byId = new Map(records.map(r => [r.id, r.value]));
    for (const [gid, entry] of Object.entries(state().groups || {}).sort(([a], [b]) => (a < b ? -1 : 1))) {
      const g = checkGroup(structuredClone(byId.get(entry.id)));
      if (!g || g.gid !== gid) continue;
      g.keys = new Map();
      for (const [v, id] of Object.entries(g.keyIds)) {
        const k = checkKey(byId.get(id), gid);
        if (k && k.v === Number(v)) g.keys.set(k.v, k);
      }
      if (g.hw && !g.keys.has(g.hw.v)) g.problem = 'damaged';
      if (g.stage) {
        const pieces = g.stage.pieceIds.map(id => checkPiece(byId.get(id), gid));
        const key = checkKey(byId.get(g.stage.keyId), gid);
        if (pieces.every(Boolean) && key && key.v === g.stage.v) { stagePackets.set(gid, pieces.map(p => p.data).join('')); stageKeys.set(gid, key); }
        else g.problem = 'damaged';
      }
      groups.set(gid, g);
      recIds.set(gid, entry.id);
    }
    messages = kept.filter(m => m && groups.has(m.group) && typeof m.text === 'string' && (m.dir === 'in' || m.dir === 'out'));
    for (const m of messages) seen.add(messageKey(m.group, m.dir === 'out' ? ownFp : m.fp, m.mid));
    // History from earlier sessions is not "new".
    for (const gid of groups.keys()) markRead(gid);
  }

  // ── 1:1 control messages (design §7, R2-7, decision 13) ──────────────
  // `from` is the AUTHENTICATED 1:1 sender (the contact whose outbox the
  // message came from, nc_outbox.c authorship gate). Returns true when the
  // text is a group control message (the page then keeps it off the chat),
  // whether or not it was honoured.
  async function onDirect(from, text) {
    if (!controlType(text)) return false;
    let r;
    try { r = core.groupJsonRead(text); } catch { return true; }
    if (!r || r.status !== 'ok' || !HEX128.test(from) || from === ownFp) return true;
    const g = groups.get(r.group_id);
    if (r.type === 'invite') await onInvite(from, r, g);
    else if (r.type === 'accept') await onAccept(from, r, g);
    else if (r.type === 'welcome') await onWelcome(from, r, g);
    else if (r.type === 'leave') await onLeave(from, r, g);
    return true;
  }
  // An invite: only from a contact who names ITSELF the owner (decision 8,
  // design §2: the owner is pinned from the authenticated invite). A group
  // this device already knows keeps its pinned owner.
  async function onInvite(from, r, g) {
    if (r.owner !== from || !isContact(from)) return;
    if (g && (g.owner !== from || !['invited', 'left', 'removed'].includes(g.status))) return;
    if (g?.status === 'invited' && g.invite?.id === r.invite_id) return;
    const next = newGroup({ gid: r.group_id, owner: from, name: r.name, role: 'member', status: 'invited', invite: { id: r.invite_id, at: seconds() } });
    next.keys = new Map();
    await commit(r.group_id, next);
  }
  // An accept: honoured only for a pending invite of THAT contact with THAT
  // invite_id, consumed once (R2-7).
  async function onAccept(from, r, g) {
    if (!g || g.role !== 'owner') return;
    const invite = g.invites.find(i => i.fp === from && i.id === r.invite_id);
    if (!invite) return;
    const next = clone(g);
    next.invites = next.invites.filter(i => i !== next.invites.find(x => x.fp === from && x.id === r.invite_id));
    if (!next.joins.some(j => j.fp === from)) next.joins.push({ fp: from, id: invite.id });
    await commit(g.gid, next);
  }
  // A welcome: only from the pinned owner, for the invite this device
  // accepted (R2-7). It pins the first version and its packet digest.
  async function onWelcome(from, r, g) {
    if (!g || g.role !== 'member' || g.status !== 'accepting' || g.owner !== from || r.owner !== from || g.invite?.id !== r.invite_id) return;
    const next = clone(g);
    next.addr = r.addr_secret;
    next.join = { v: Number(r.key_version), digest: r.kp_digest };
    next.status = 'joining';
    await commit(g.gid, next);
  }
  // A leave (decision 13): only from a current member (or one still waiting
  // to be added), over the authenticated 1:1 channel; the owner removes it
  // at the next rotation.
  async function onLeave(from, r, g) {
    if (!g || g.role !== 'owner' || from === g.owner) return;
    const member = current(g).includes(from), waiting = g.joins.some(j => j.fp === from);
    if (!member && !waiting) return;
    const next = clone(g);
    next.joins = next.joins.filter(j => j.fp !== from);
    if (member && !next.removals.includes(from)) next.removals.push(from);
    await commit(g.gid, next);
  }

  // ── owner: stage, publish (HEAD last), apply ──────────────────────────
  // Builds the next version's record, key packet and HEAD (design §3: one
  // durable transition) and returns the group with the stage, plus the
  // records to write: the key version and the packet in pieces (R2-2: the
  // exact bytes are kept and republished).
  async function buildStage(g, { key, members, joined, removed }) {
    const gid = g.gid, v = g.hw ? g.hw.v + 1 : 1, t = String(now());
    const rec = await core.groupRecordNew({ gid, v, key, name: g.name, members, created: t });
    const kp = await withPeers(members, () => core.groupKpNew({ gid, v, prev: g.hw ? g.hw.digest : '', rdigest: rec.digest, issued: t, key, members }));
    const head = await core.groupHeadNew({ gid, v, digest: kp.digest, issued: t });
    const keyId = newId('k');
    const K = { kind: 'nodus-group-key', gid, v, key, digest: kp.digest, rdigest: rec.digest, prev: g.hw ? g.hw.digest : '', issued: t, members: [...members].sort(), name: g.name };
    const pieces = splitPieces(kp.packet).map(data => ({ id: newId('x'), value: { kind: 'nodus-group-piece', gid, v, data } }));
    const next = clone(g);
    next.stage = { v, members: K.members, record: rec.record, rdigest: rec.digest, pdigest: kp.digest, head: head.head, keyId, pieceIds: pieces.map(p => p.id), done: { record: false, packet: false, head: false }, joined, removed };
    return { next, keys: [{ id: keyId, value: K }], pieces, packet: kp.packet, K };
  }
  async function commitStage(gid, built) {
    await commit(gid, built.next, { keys: built.keys, pieces: built.pieces });
    stagePackets.set(gid, built.packet);
    stageKeys.set(gid, built.K);
  }
  // Publishes the staged version: record, packet, then HEAD (design §3:
  // HEAD LAST). Each step is a gated write (core.groupPut reads the own row
  // first): 'wait' / 'failed' stop here for this check; 'conflict' /
  // 'stale' / 'taken' stop it with a problem shown to the owner. Once the
  // HEAD is out the version is applied — members added / removed in the
  // view only now — and the joiners' welcomes are queued. true = applied.
  async function continueStage(gid) {
    let g = groups.get(gid);
    const s = g.stage, K = stageKeys.get(gid), packet = stagePackets.get(gid);
    if (!K || !packet) { note(gid, 'The prepared group change could not be read on this device.'); return false; }
    const salt = saltOf(gid, K.key, s.v);
    for (const step of ['record', 'packet', 'head']) {
      if (g.stage.done[step]) continue;
      const req = step === 'record' ? { purpose: 'record', secret: salt, x: String(s.v), value: hexToBytes(s.record) }
        : step === 'packet' ? { purpose: 'packet', secret: g.addr, x: String(s.v), value: hexToBytes(packet) }
          : { purpose: 'head', secret: g.addr, x: '0', value: hexToBytes(s.head) };
      const r = await core.groupPut({ gid, ...req });
      if (r.status === 'published' || r.status === 'unchanged') {
        const next = clone(g);
        next.stage.done[step] = true;
        next.problem = null;
        g = await commit(gid, next);
        continue;
      }
      if (HARD.has(r.status)) {
        const next = clone(g);
        next.problem = r.status;
        await commit(gid, next);
      }
      note(gid, r.status === 'wait' ? 'The network could not be read; the group change is tried again automatically.' : null);
      return false;
    }
    const next = clone(g);
    next.keys.set(s.v, K);
    next.keyIds[s.v] = s.keyId;
    next.hw = { v: s.v, digest: s.pdigest };
    if (!next.first) next.first = s.v;
    for (const j of s.joined) next.welcomes.push({ fp: j.fp, id: j.id, v: s.v, digest: s.pdigest });
    next.stage = null;
    next.problem = null;
    await commit(gid, next);
    stagePackets.delete(gid); stageKeys.delete(gid);
    note(gid, null);
    return true;
  }
  // The owner's check: finish a staged change; stage a new one when people
  // accepted, asked to leave or were removed, or the key is 30 days old
  // (decision 5); then send the welcomes.
  async function ownerSync(gid) {
    let g = groups.get(gid);
    // 'taken' (the HEAD address is held by someone else) and 'damaged' are
    // terminal; 'member_key' waits for the owner to remove that member
    // (removeMember clears it) instead of re-reading every profile each check.
    if (g.problem === 'taken' || g.problem === 'damaged' || g.problem === 'member_key') return;
    if (g.stage && !await continueStage(gid)) return;
    g = groups.get(gid);
    const K = g.hw && keyOf(g, g.hw.v);
    if (!K) return;
    const removals = g.removals.filter(fp => K.members.includes(fp) && fp !== ownFp);
    let joins = g.joins.filter(j => !K.members.includes(j.fp));
    const due = rotationDue(K.issued, now());
    if (joins.length || removals.length || due) {
      // design §4: a member without an ML-KEM-1024 key cannot be added (an
      // explicit refusal, shown to the owner); a key that cannot be READ
      // (the network) makes the whole change wait — never skipped (§3).
      const refused = [];
      for (const j of joins) {
        if (!await reloadProfile(j.fp)) { note(gid, 'A new member\'s account could not be read right now; the change waits.'); return; }
        if (!hasKemKey(j.fp)) refused.push(j.fp);
      }
      joins = joins.filter(j => !refused.includes(j.fp));
      let members = nextMembers(K.members, joins.map(j => j.fp), removals, ownFp);
      while (members.length > MAX_MEMBERS && joins.length) { refused.push(joins.pop().fp); members = nextMembers(K.members, joins.map(j => j.fp), removals, ownFp); }
      for (const fp of members) {
        if (fp === ownFp) continue;
        if (!await reloadProfile(fp)) { note(gid, 'A member\'s account could not be read right now; the change waits.'); return; }
        if (!hasKemKey(fp)) { const next = clone(g); next.problem = 'member_key'; next.problemFp = fp; await commit(gid, next); return; }
      }
      const keep = clone(g);
      keep.joins = g.joins.filter(j => !joins.includes(j) && !refused.includes(j.fp) && !K.members.includes(j.fp));
      keep.removals = [];
      keep.refused = [...new Set([...(g.refused || []), ...refused])];
      if (joins.length || removals.length || due) {
        const { group_key: key } = core.groupRandom();
        const built = await buildStage(keep, { key, members, joined: joins.map(j => ({ fp: j.fp, id: j.id })), removed: removals });
        await commitStage(gid, built);
        if (!await continueStage(gid)) return;
      } else await commit(gid, keep);
    }
    await sendWelcomes(gid);
  }
  async function sendWelcomes(gid) {
    for (const w of [...groups.get(gid).welcomes]) {
      const g = groups.get(gid);
      const json = await core.groupWelcome({ gid, addr: g.addr, v: String(w.v), digest: w.digest, inviteId: w.id });
      await sendDirect(w.fp, json);
      const next = clone(groups.get(gid));
      next.welcomes = next.welcomes.filter(x => x.id !== w.id);
      await commit(gid, next);
    }
  }

  // ── member: join, catch up ────────────────────────────────────────────
  // The record of version v, after its packet opened (`r`, core.groupKpRead
  // ok): read with the pinned owner, its digest and count bound by the
  // packet (R2-3). null = not now (unreadable / refused).
  async function openRecord(g, v, r) {
    const salt = saltOf(g.gid, r.group_key, v);
    const rec = await core.groupGet({ purpose: 'record', gid: g.gid, secret: salt, x: String(v), owner: g.owner });
    if (rec.outcome !== 'found') return null;
    const rr = core.groupRecordRead({ record: rec.data, key: r.group_key, gid: g.gid, v: String(v), digest: r.record_digest, count: r.count, owner: g.owner });
    if (rr.status !== 'ok' || !Array.isArray(rr.members) || !rr.members.includes(ownFp)) return null;
    return { kind: 'nodus-group-key', gid: g.gid, v, key: r.group_key, digest: r.digest, rdigest: r.record_digest, prev: r.prev_digest, issued: String(r.issued_at_ms), members: rr.members, name: hexToText(rr.name_hex) };
  }
  async function addVersion(g, K, extra = {}) {
    const next = clone(g);
    const keyId = newId('k');
    next.keys.set(K.v, K);
    next.keyIds[K.v] = keyId;
    next.hw = { v: K.v, digest: K.digest };
    if (K.name) next.name = K.name;
    Object.assign(next, extra);
    return commit(g.gid, next, { keys: [{ id: keyId, value: K }] });
  }
  // joining: the welcome pinned version N and its packet digest (R2-7) —
  // the packet is opened against that digest (no packet of N-1 is held,
  // decision 12), then its record.
  async function join(gid) {
    const g = groups.get(gid), { v, digest } = g.join;
    const p = await core.groupGet({ purpose: 'packet', gid, secret: g.addr, x: String(v), owner: g.owner });
    if (p.outcome !== 'found') { note(gid, 'Waiting for the group to become readable.'); return; }
    const r = await withPeers([g.owner], () => core.groupKpRead({ packet: p.data, owner: g.owner, gid, v: String(v), pinned: digest }));
    if (r.status === 'no_entry') { note(gid, 'The group\'s key was not prepared for you. Ask the owner to invite you again.'); return; }
    if (r.status !== 'ok') { note(gid, 'The group could not be checked yet. Trying again automatically.'); return; }
    const K = await openRecord(g, v, r);
    if (!K) { note(gid, 'Waiting for the group to become readable.'); return; }
    await addVersion(g, K, { first: v, status: 'active', problem: null });
    note(gid, null);
  }
  // active member: HEAD from the pinned owner (forward only), then walk
  // v+1 .. HEAD.v — each packet bound to the held digest (prev_digest,
  // R2-7); a packet without our entry means we were removed (that version
  // is announced by the owner's HEAD, so "removed" is never shown early).
  async function catchUp(gid) {
    let g = groups.get(gid);
    const h = await core.groupGet({ purpose: 'head', gid, secret: g.addr, x: '0', owner: g.owner });
    if (h.outcome !== 'found') return;
    const hr = await withPeers([g.owner], () => core.groupHeadRead({ head: h.data, owner: g.owner, gid }));
    if (hr.status !== 'ok') return;
    const target = Number(hr.v);
    if (target <= g.hw.v) {
      if (target === g.hw.v && hr.kp_digest !== g.hw.digest) note(gid, 'This group\'s announcement does not match what this device holds. Nothing was changed.');
      return;
    }
    for (let w = g.hw.v + 1; w <= target; w++) {
      g = groups.get(gid);
      const p = await core.groupGet({ purpose: 'packet', gid, secret: g.addr, x: String(w), owner: g.owner });
      if (p.outcome !== 'found') return;
      const r = await withPeers([g.owner], () => core.groupKpRead({ packet: p.data, owner: g.owner, gid, v: String(w), prev: g.hw.digest }));
      if (r.status === 'no_entry') { const next = clone(g); next.status = 'removed'; await commit(gid, next); return; }
      if (r.status !== 'ok') { note(gid, r.status === 'prev_conflict' ? 'This group\'s history does not match what this device holds. Nothing was changed.' : null); return; }
      if (w === target && r.digest !== hr.kp_digest) { note(gid, 'This group\'s announcement does not match its newest key. Nothing was changed.'); return; }
      const K = await openRecord(g, w, r);
      if (!K) return;
      await addVersion(g, K);
    }
  }

  // ── messages ──────────────────────────────────────────────────────────
  // Publishes own messages not yet on the network: per (version, day) the
  // module merges EVERY own item this device keeps for that bucket with the
  // row it reads in the same call (core.groupBucketSend).
  async function publishPending(gid) {
    const g = groups.get(gid);
    const { buckets, expired } = pendingBuckets(messages, gid, now());
    if (expired.length) await updateMessages(expired.map(m => ({ ...m, failed: true })));
    for (const { v, day } of buckets) {
      const K = keyOf(g, v);
      if (!K) continue;
      const items = bucketItems(messages, gid, v, day).slice(-BUCKET_ITEMS_MAX);
      const r = await core.groupBucketSend({ gid, salt: saltOf(gid, K.key, v), v: String(v), day, items });
      const mine = messages.filter(m => m.group === gid && m.dir === 'out' && m.v === v && m.day === day && m.published !== true);
      if (r.status === 'published' || r.status === 'unchanged') {
        const ids = new Set(r.ids);
        await updateMessages(mine.filter(m => ids.has(m.mid)).map(m => ({ ...m, published: true })));
      } else if (r.status === 'full' || r.status === 'refused') {
        await updateMessages(mine.map(m => ({ ...m, failed: true })));
      }
    }
  }
  async function updateMessages(updated) {
    if (!updated.length) return;
    await saveAll({ records: [], messages: updated });
    for (const u of updated) { const i = messages.findIndex(m => m.seq === u.seq); if (i >= 0) messages[i] = u; }
  }
  // Reads today's and yesterday's buckets of the newest version and the one
  // before it. Each received message: the module checked the row's owner ==
  // the sender, the signature and the decryption; here the membership rule
  // (decision 6) and deduplication; new ones are stored in a deterministic
  // order (design §9) and shown in local order.
  async function readBuckets(gid) {
    const g = groups.get(gid);
    const arrived = [];
    let dropped = 0, unreadable = 0;
    for (const v of bucketVersions(g)) {
      const K = keyOf(g, v), next = keyOf(g, v + 1)?.members;
      for (const fp of K.members) if (fp !== ownFp) { try { await ensureProfile(fp); } catch { /* read again next check */ } }
      const salt = saltOf(gid, K.key, v);
      for (const day of syncDays(now())) {
        const fetch = () => core.groupBucketFetch({ gid, salt, v: String(v), day, key: K.key });
        let r = await fetch();
        const unknown = r.buckets.filter(b => b.status === 'sender_unknown' && K.members.includes(b.sender));
        if (unknown.length) { for (const b of unknown) await reloadProfile(b.sender); r = await fetch(); }
        if (r.outcome === 'unreadable') unreadable++;
        for (const b of r.buckets) {
          if (b.status !== 'ok' || !b.sender || b.sender === ownFp) { if (b.status !== 'ok') dropped++; continue; }
          if (!acceptRule(b.sender, K.members, next)) { dropped += b.messages.length; continue; }
          for (const m of b.messages) {
            if (m.status !== 'ok' || typeof m.text !== 'string') { dropped++; continue; }
            const key = messageKey(gid, b.sender, m.messageId);
            if (seen.has(key) || arrived.some(a => messageKey(gid, a.fp, a.mid) === key)) continue;
            arrived.push({ group: gid, fp: b.sender, dir: 'in', text: m.text, v, day, mid: m.messageId, ts: String(m.timestampMs), at: now() });
          }
        }
      }
    }
    if (arrived.length) {
      const ordered = orderIncoming(arrived);
      for (const m of ordered) m.seq = takeSeq();
      await saveAll({ records: [], messages: ordered });
      for (const m of ordered) { messages.push(m); seen.add(messageKey(gid, m.fp, m.mid)); }
    }
    const parts = [];
    if (dropped) parts.push('Some messages in this group could not be checked and are not shown.');
    if (unreadable) parts.push('Part of this group could not be read right now; it is checked again automatically.');
    if (parts.length) note(gid, [notes.get(gid), ...parts].filter(Boolean).join(' '));
    return arrived.length;
  }

  // One check of every group (the page's 30-second check calls this after
  // the 1:1 contacts). One group's failure does not stop the others; its
  // note says what happened. `isCurrent()`: false once Messages closed.
  async function syncAll(isCurrent = () => true) {
    let failed = 0;
    for (const gid of [...groups.keys()].sort()) {
      if (!isCurrent()) return failed;
      try {
        let g = groups.get(gid);
        if (!g) continue;
        note(gid, null);                   // each check writes its own note
        if (g.role === 'owner') await ownerSync(gid);
        else if (g.status === 'joining') await join(gid);
        if (!isCurrent()) return failed;
        g = groups.get(gid);
        if (g && g.status === 'active' && g.hw) {
          if (g.role === 'member') await catchUp(gid);
          if (!isCurrent()) return failed;
          if (groups.get(gid)?.status === 'active') {
            await publishPending(gid);
            if (!isCurrent()) return failed;
            await readBuckets(gid);
          }
        }
      } catch (error) {
        if (!isCurrent()) return failed;
        failed++;
        note(gid, 'This group could not be checked right now. Trying again automatically.');
      }
    }
    return failed;
  }

  // ── user actions ──────────────────────────────────────────────────────
  // Create (owner): version 1 holds the owner alone; the chosen contacts
  // are invited (decision 8) and join through accept -> rotation -> welcome
  // (design §7). Nothing is published before the stage is kept on the device.
  async function create(name, invitees = []) {
    const problem = nameProblem(name);
    if (problem) throw new GroupError(problem);
    const people = [...new Set(invitees)];
    if (people.some(fp => fp === ownFp || !isContact(fp))) throw new GroupError('Only your contacts can be invited.');
    if (people.length > MAX_MEMBERS - 1) throw new GroupError(`A group can have at most ${MAX_MEMBERS} members.`);
    const r = core.groupRandom();
    const g = newGroup({ gid: r.group_id, owner: ownFp, name: name.trim(), role: 'owner', status: 'active' });
    g.addr = r.addr_secret;
    g.keys = new Map();
    const built = await buildStage(g, { key: r.group_key, members: [ownFp], joined: [], removed: [] });
    await commitStage(g.gid, built);
    markRead(g.gid);
    const notInvited = [];
    for (const fp of people) { try { await invite(g.gid, fp); } catch { notInvited.push(fp); } }
    try { await continueStage(g.gid); } catch { /* tried again by the next check */ }
    return { gid: g.gid, notInvited };
  }
  async function invite(gid, fp) {
    const g = groups.get(gid);
    if (!g || g.role !== 'owner' || g.status !== 'active') throw new GroupError('Only the group\'s owner can invite.');
    if (!isContact(fp) || fp === ownFp) throw new GroupError('Only your contacts can be invited.');
    const members = current(g);
    if (members.includes(fp) || g.joins.some(j => j.fp === fp)) throw new GroupError('This person is already in the group.');
    const others = g.invites.filter(i => i.fp !== fp).length;
    if (members.length + g.joins.length + others >= MAX_MEMBERS) throw new GroupError(`A group can have at most ${MAX_MEMBERS} members.`);
    const r = await core.groupInvite(gid, g.name);
    const next = clone(g);
    next.invites = [...next.invites.filter(i => i.fp !== fp), { fp, id: r.invite_id, at: seconds() }];
    next.refused = (next.refused || []).filter(x => x !== fp);
    await commit(gid, next);
    await sendDirect(fp, r.json);
  }
  async function acceptInvite(gid) {
    const g = groups.get(gid);
    if (!g || g.role !== 'member' || g.status !== 'invited' || !g.invite) throw new GroupError('This invitation is no longer open.');
    if (!isContact(g.owner)) throw new GroupError('Messaging with the person who invited you is not ready yet.');
    const json = core.groupAcceptJson(gid, g.invite.id);
    const next = clone(g);
    next.status = 'accepting';
    await commit(gid, next);
    await sendDirect(g.owner, json);
  }
  // Decline = no reply (design §7): the invitation is forgotten here.
  async function ignoreInvite(gid) {
    const g = groups.get(gid);
    if (!g || g.status !== 'invited') return;
    await forget(gid);
  }
  // Leave (decision 13): hidden here at once; the owner is told and removes
  // this member at its next rotation (until then the owner's list still
  // shows it).
  async function leave(gid) {
    const g = groups.get(gid);
    if (!g || g.role !== 'member' || !['accepting', 'joining', 'active'].includes(g.status)) throw new GroupError('You cannot leave this group.');
    const json = core.groupLeaveJson(gid);
    const next = clone(g);
    next.status = 'left';
    await commit(gid, next);
    if (isContact(g.owner)) await sendDirect(g.owner, json);
  }
  // Owner: remove a member (or withdraw an invitation). Applied at the next
  // rotation, HEAD last; until then the member is still listed.
  async function removeMember(gid, fp) {
    const g = groups.get(gid);
    if (!g || g.role !== 'owner') throw new GroupError('Only the group\'s owner can remove members.');
    if (fp === ownFp) throw new GroupError('The owner cannot be removed.');
    const next = clone(g);
    next.invites = next.invites.filter(i => i.fp !== fp);
    next.joins = next.joins.filter(j => j.fp !== fp);
    if (current(g).includes(fp) && !next.removals.includes(fp)) next.removals.push(fp);
    if (next.problem === 'member_key') next.problem = null;
    await commit(gid, next);
  }
  // Send: one at a time (the composer's text is taken once — the 0.1.55
  // double-send rule of 1:1); kept on this device first, then published.
  // Returns 'busy' (another send is being kept), 'sent' or 'kept' (kept,
  // published by a later check). `onKept()`: called once the message is
  // kept on this device (the composer is emptied then, as in 1:1).
  async function send(gid, text, { onKept } = {}) {
    if (sending) return 'busy';
    const g = groups.get(gid);
    if (!g || g.status !== 'active' || !g.hw) throw new GroupError('This group is not ready for messages yet.');
    const problem = textProblem(text);
    if (problem) throw new GroupError(problem);
    const K = keyOf(g, g.hw.v), ts = now(), day = dayOf(ts);
    if (bucketItems(messages, gid, g.hw.v, day).length >= BUCKET_ITEMS_MAX) throw new GroupError(`You can send at most ${BUCKET_ITEMS_MAX} messages a day to one group.`);
    sending = true;
    try {
      const r = await core.groupMsgNew({ key: K.key, gid, v: String(g.hw.v), ts: String(ts), text });
      const m = { seq: takeSeq(), group: gid, fp: ownFp, dir: 'out', text, v: g.hw.v, day: String(r.day), mid: r.message_id, ts: String(ts), at: now(), item: r.item };
      await saveAll({ records: [], messages: [m] });
      messages.push(m);
      seen.add(messageKey(gid, ownFp, m.mid));
      markRead(gid);
    } finally { sending = false; }
    try { onKept?.(); } catch { /* the view only */ }
    try { await publishPending(gid); } catch { return 'kept'; }
    return messages.some(m => m.group === gid && m.dir === 'out' && m.published !== true && m.failed !== true) ? 'kept' : 'sent';
  }

  // ── read marks and the view ───────────────────────────────────────────
  function newestSeq(gid) {
    let newest = -1n;
    for (const m of messages) if (m.group === gid && BigInt(m.seq) > newest) newest = BigInt(m.seq);
    return newest;
  }
  function markRead(gid) { lastRead.set(gid, newestSeq(gid)); }
  function unread(gid) {
    const seenSeq = lastRead.get(gid) ?? -1n;
    return messages.filter(m => m.group === gid && m.dir === 'in' && BigInt(m.seq) > seenSeq).length;
  }
  // A plain summary of one group for the screens.
  function view(gid) {
    const g = groups.get(gid);
    if (!g) return null;
    const K = g.hw && keyOf(g, g.hw.v);
    return {
      gid, name: g.name, role: g.role, status: g.status, owner: g.owner,
      ready: g.status === 'active' && !!g.hw,
      members: K ? [...K.members] : [g.owner],
      joining: g.joins.map(j => j.fp), invited: g.invites.map(i => i.fp), leaving: [...g.removals],
      refused: [...(g.refused || [])],
      settingUp: g.role === 'owner' && !!g.stage,
      keyOld: !!K && keyIsOld(K.issued, now()),
      problem: g.problem || null, problemFp: g.problemFp || null, note: notes.get(gid) || null,
      unread: unread(gid)
    };
  }
  // Groups shown in Chats (left ones are hidden, decision 13) and the open
  // invitations.
  function list() { return [...groups.values()].filter(g => g.status !== 'left' && g.status !== 'invited').map(g => view(g.gid)); }
  function invitations() { return [...groups.values()].filter(g => g.status === 'invited').map(g => ({ gid: g.gid, name: g.name, owner: g.owner })); }
  function conversation(gid) { return messages.filter(m => m.group === gid).sort((a, b) => (BigInt(a.seq) < BigInt(b.seq) ? -1 : 1)); }
  function lastMessage(gid) { let last; for (const m of messages) if (m.group === gid && (!last || BigInt(m.seq) > BigInt(last.seq))) last = m; return last; }

  return {
    load, onDirect, syncAll, create, invite, acceptInvite, ignoreInvite, leave, removeMember, send,
    markRead, unread, view, list, invitations, conversation, lastMessage,
    get sending() { return sending; },
    // for the tests and the page's diagnostics
    group: gid => groups.get(gid), messages: () => messages
  };
}
