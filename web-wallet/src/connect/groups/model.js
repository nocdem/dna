// Nodus Connect groups — the pure rules of the page side (package G3).
// No DOM, no network, no storage, no clock: every function here is a
// function of its arguments (test/connect-groups.test.js pins them).
//
// Governing records:
//   docs/plans/2026-10-04-connect-groups-design.md rev 1 (§2 owner pin,
//     §3 versions / rotation / HEAD last, §6 accept rules, §7 invites);
//   docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 + REV 2
//     (R2-7 invite_id / welcome pin / catch-up, R2-8 caps);
//   docs/plans/decisions/2026-10-04-connect-groups.md items 1-14 (3: 64
//     members; 4: one owner; 5: rotation on change + 30 days; 6: late-mail
//     rule; 7: owner gone -> "key is old"; 8: contacts only; 11: text >= 1
//     byte; 12: no pre-join history; 13: leave = notify the owner; 14:
//     unlimited history on the device).

export const MAX_MEMBERS = 64;                     // decision 3
export const ROTATE_MS = 30 * 86400000;            // decision 5: every 30 days
export const DAY_MS = 86400000;                    // bytes item 5: day = floor(ms / 86,400,000)
export const BUCKET_LIFE_DAYS = 7;                 // decision 10: buckets EPHEMERAL 7 days
export const TEXT_MAX_BYTES = 4000;                // bytes item 5 / R2-8
export const NAME_MAX_BYTES = 64;                  // bytes item 3
export const BLOB_PIECE = 60000;                   // hex characters per staged packet piece (< the 64 KiB record)

// A refusal of the groups module in plain words, meant for the user (the
// screens show its message; any other error gets the screen's own words).
export class GroupError extends Error {}

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/;
const U64 = /^(0|[1-9]\d{0,19})$/;
const isMap = value => value && typeof value === 'object' && !Array.isArray(value);
const utf8Length = text => new TextEncoder().encode(text).length;

// ── 1:1 control messages ────────────────────────────────────────────────
// The four group messages that travel over the 1:1 channel (bytes item 7,
// R2-7; decision 13). Their "type" values; nc_plaintext_is_chat
// (connect/nc_outbox.c) returns them as text, so the page routes them here
// and never shows them as chat text.
export const CONTROL_TYPES = new Map([
  ['nodus_group_invite', 'invite'], ['nodus_group_accept', 'accept'],
  ['nodus_group_welcome', 'welcome'], ['nodus_group_leave', 'leave']
]);
// The control type of a 1:1 text, or null. Loose on purpose: anything that
// CLAIMS one of the four types is taken off the chat (and then strictly
// parsed by the module, core.groupJsonRead — a refused one is ignored).
export function controlType(text) {
  if (typeof text !== 'string' || text.length > 4096 || text[0] !== '{' || !text.includes('nodus_group_')) return null;
  let value;
  try { value = JSON.parse(text); } catch { return null; }
  return isMap(value) && typeof value.type === 'string' ? CONTROL_TYPES.get(value.type) || null : null;
}

// ── membership ──────────────────────────────────────────────────────────
// Decision 6 (design §6): a message under version v is accepted only from a
// member of record(v); when this device also holds record(v+1), only from a
// member of that too — a removed member's old-key mail is dropped, with no
// time check. Lists need not be sorted.
export function acceptRule(sender, membersV, membersNext) {
  if (typeof sender !== 'string' || !Array.isArray(membersV) || !membersV.includes(sender)) return false;
  return !membersNext || (Array.isArray(membersNext) && membersNext.includes(sender));
}

// The member list of the next version: the current one minus `removals`,
// plus `joins`, sorted (the codec's order, nc_group.h: ascending — for
// lowercase hex of equal length, string order is byte order), unique, the
// owner always kept.
export function nextMembers(current, joins, removals, owner) {
  const out = new Set((current || []).filter(fp => !(removals || []).includes(fp) || fp === owner));
  for (const fp of joins || []) out.add(fp);
  out.add(owner);
  return [...out].sort();
}

// Decision 5: the owner rotates every 30 days while online; decision 7: a
// member whose newest key is older than that shows "key is old". `issued`:
// the packet's issued_at_ms (decimal string) — the OWNER's clock, used only
// to schedule and to warn, never to accept or refuse anything (design §9).
export function keyAge(issued, now) {
  if (!U64.test(String(issued)) || typeof now !== 'number' || !Number.isFinite(now)) return null;
  return now - Number(issued);
}
export function rotationDue(issued, now) { const age = keyAge(issued, now); return age !== null && age >= ROTATE_MS; }
export function keyIsOld(issued, now) { return rotationDue(issued, now); }

export function dayOf(ms) {
  if (typeof ms !== 'number' || !Number.isSafeInteger(ms) || ms < 0) throw new Error('Invalid time.');
  return String(Math.floor(ms / DAY_MS));
}
// The buckets a routine check reads: today and yesterday (the dispatch's
// rule; a bucket lives 7 days).
export function syncDays(nowMs) {
  const today = BigInt(dayOf(nowMs));
  return today > 0n ? [String(today), String(today - 1n)] : [String(today)];
}

// The versions whose buckets are read: the newest one held and the one
// before it (decision 6's residual: members not yet synced still send under
// it), never one below the first version that included this device
// (decision 12: no pre-join history).
export function bucketVersions(group) {
  if (!group?.hw) return [];
  const v = group.hw.v, out = [v];
  if (v - 1 >= (group.first || 1) && group.keys?.has(v - 1)) out.push(v - 1);
  return out;
}

// Deduplication of received group messages (design §6), recorded only
// after full validation.
export function messageKey(gid, sender, messageId) { return `${gid}|${sender}|${messageId}`; }

// One check's new messages in a deterministic order (design §9:
// key_version, day, sender, message_id) before local sequence numbers are
// given; the conversation is then shown in local order (the 1:1 rule,
// src/connect/ui/text.js compareLocal) — the sender's clock is displayed,
// never trusted for order.
export function orderIncoming(list) {
  return [...list].sort((a, b) => (a.v - b.v) || cmp(a.day, b.day) || cmp(a.fp, b.fp) || cmp(a.mid, b.mid));
}
function cmp(a, b) {
  const x = String(a), y = String(b);
  if (x.length !== y.length && /^\d+$/.test(x) && /^\d+$/.test(y)) return x.length - y.length;
  return x < y ? -1 : x > y ? 1 : 0;
}

// A group message text the page may send: 1..4,000 UTF-8 bytes (decision
// 11, bytes item 5), no NUL (the C string would end there).
export function textProblem(text) {
  if (typeof text !== 'string' || text.length === 0 || !text.trim()) return 'Write a message first.';
  if (text.includes('\u0000')) return 'This message has a character that cannot be sent.';
  if (utf8Length(text) > TEXT_MAX_BYTES) return `A group message can be at most ${TEXT_MAX_BYTES} bytes.`;
  return null;
}
export function nameProblem(name) {
  if (typeof name !== 'string' || !name.trim()) return 'Give the group a name.';
  if (name.includes('\u0000') || utf8Length(name) > NAME_MAX_BYTES) return `A group name can be at most ${NAME_MAX_BYTES} bytes.`;
  return null;
}

// The own messages of one bucket (group, version, day) this device keeps,
// published or not: the module merges them with what the network holds
// (core.groupBucketSend). Oldest first.
export function bucketItems(messages, gid, v, day) {
  return messages.filter(m => m.group === gid && m.dir === 'out' && m.v === v && m.day === day && typeof m.item === 'string')
    .sort((a, b) => cmp(a.seq, b.seq)).map(m => m.item);
}
// The buckets that hold own messages not yet published: [{ v, day }],
// within the 7-day life of a bucket; older ones are reported as `expired`.
export function pendingBuckets(messages, gid, nowMs) {
  const today = BigInt(dayOf(nowMs)), seen = new Map(), expired = [];
  for (const m of messages) {
    if (m.group !== gid || m.dir !== 'out' || m.published === true || m.failed === true || typeof m.item !== 'string') continue;
    if (today - BigInt(m.day) >= BigInt(BUCKET_LIFE_DAYS)) { expired.push(m); continue; }
    seen.set(`${m.v}|${m.day}`, { v: m.v, day: m.day });
  }
  return { buckets: [...seen.values()], expired };
}

// Staged packet hex -> pieces small enough for one stored record, and back.
export function splitPieces(hex) {
  const out = [];
  for (let i = 0; i < hex.length; i += BLOB_PIECE) out.push(hex.slice(i, i + BLOB_PIECE));
  return out;
}

// ── the stored group record (state.groups -> 'g' record) ────────────────
// Shape checked on load; a record that fails is not used (the group is
// shown as damaged, nothing is written for it).
export const STATUSES = new Set(['invited', 'accepting', 'joining', 'active', 'left', 'removed']);
export function checkGroup(g) {
  if (!isMap(g) || g.kind !== 'nodus-group' || g.fmt !== 1 || !HEX64.test(g.gid) || !HEX128.test(g.owner) ||
      typeof g.name !== 'string' || (g.role !== 'owner' && g.role !== 'member') || !STATUSES.has(g.status) ||
      (g.addr !== null && !HEX64.test(g.addr)) ||
      (g.invite !== null && !(isMap(g.invite) && HEX32.test(g.invite.id))) ||
      (g.join !== null && !(isMap(g.join) && isVersion(g.join.v) && HEX128.test(g.join.digest))) ||
      (g.hw !== null && !(isMap(g.hw) && isVersion(g.hw.v) && HEX128.test(g.hw.digest))) ||
      (g.first !== null && !isVersion(g.first)) ||
      !isMap(g.keyIds) || Object.entries(g.keyIds).some(([v, id]) => !isVersion(Number(v)) || !/^k\d{20}$/.test(id)) ||
      !Array.isArray(g.invites) || g.invites.some(i => !isMap(i) || !HEX128.test(i.fp) || !HEX32.test(i.id)) ||
      !Array.isArray(g.joins) || g.joins.some(i => !isMap(i) || !HEX128.test(i.fp) || !HEX32.test(i.id)) ||
      !Array.isArray(g.removals) || g.removals.some(fp => !HEX128.test(fp)) ||
      !Array.isArray(g.welcomes) || g.welcomes.some(w => !isMap(w) || !HEX128.test(w.fp) || !HEX32.test(w.id)) ||
      (g.stage !== null && !checkStage(g.stage))) return null;
  return g;
}
function checkStage(s) {
  return isMap(s) && isVersion(s.v) && Array.isArray(s.members) && s.members.length >= 1 && s.members.length <= MAX_MEMBERS &&
    s.members.every(fp => HEX128.test(fp)) && typeof s.record === 'string' && typeof s.head === 'string' &&
    HEX128.test(s.pdigest) && HEX128.test(s.rdigest) && /^k\d{20}$/.test(s.keyId) &&
    Array.isArray(s.pieceIds) && s.pieceIds.length >= 1 && s.pieceIds.every(id => /^x\d{20}$/.test(id)) &&
    isMap(s.done) && Array.isArray(s.joined) && Array.isArray(s.removed);
}
function isVersion(v) { return Number.isSafeInteger(v) && v >= 1 && v <= 4294967295; }

// A key version record ('k').
export function checkKey(k, gid) {
  if (!isMap(k) || k.kind !== 'nodus-group-key' || k.gid !== gid || !isVersion(k.v) || !HEX64.test(k.key) ||
      !HEX128.test(k.digest) || !HEX128.test(k.rdigest) || !U64.test(String(k.issued)) ||
      !Array.isArray(k.members) || k.members.length < 1 || k.members.length > MAX_MEMBERS || k.members.some(fp => !HEX128.test(fp)) ||
      typeof k.name !== 'string') return null;
  return k;
}
// A staged packet piece ('x').
export function checkPiece(x, gid) {
  return isMap(x) && x.kind === 'nodus-group-piece' && x.gid === gid && typeof x.data === 'string' && /^[0-9a-f]+$/.test(x.data) ? x : null;
}

// A new group record (owner at creation, or a member at an invite).
export function newGroup({ gid, owner, name, role, status, invite = null }) {
  return {
    kind: 'nodus-group', fmt: 1, gid, owner, name, role, status,
    addr: null, invite, join: null, hw: null, first: null, keyIds: {},
    invites: [], joins: [], removals: [], welcomes: [], stage: null, problem: null
  };
}

// The record as stored: the in-memory `keys` map and diagnostics stay out.
export function storedGroup(g) {
  const { keys, ...rest } = g;
  return structuredClone(rest);
}
